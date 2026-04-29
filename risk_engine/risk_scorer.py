"""Risk scoring engine that fuses feature, entropy, and drift signals."""

from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
import threading

logger = logging.getLogger(__name__)


class RiskScorer:
    """Tail event streams and compute unified ransomware risk scores."""

    DRIFT_MAP = {
        "NONE": 0.0,
        "LOW": 0.3,
        "MEDIUM": 0.6,
        "HIGH": 1.0,
    }

    def __init__(
        self,
        feature_stream_path: str | None = None,
        entropy_alerts_path: str | None = None,
        risk_stream_path: str | None = None,
        drift_stream_path: str | None = None,
        iforest_stream_path: str | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self.feature_stream_path = Path(feature_stream_path) if feature_stream_path else project_root / "feature_stream.jsonl"
        self.entropy_alerts_path = Path(entropy_alerts_path) if entropy_alerts_path else project_root / "entropy_alerts.jsonl"
        self.risk_stream_path = Path(risk_stream_path) if risk_stream_path else project_root / "risk_stream.jsonl"
        self.drift_stream_path = Path(drift_stream_path) if drift_stream_path else project_root / "drift_stream.jsonl"
        self.iforest_stream_path = Path(iforest_stream_path) if iforest_stream_path else project_root / "iforest_stream.jsonl"
        self.stop_event = stop_event or threading.Event()
        self._entropy_flag = 0
        self._last_entropy_ts = 0.0
        self._entropy_ttl_seconds = 60.0
        self._last_drift_severity = "NONE"
        self._last_iforest_confidence = 0.0
        for path in (self.feature_stream_path, self.entropy_alerts_path,
                     self.risk_stream_path, self.drift_stream_path,
                     self.iforest_stream_path):
            self._ensure_file(path)

    @staticmethod
    def _ensure_file(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)

    @classmethod
    def _score_level(cls, score: float) -> str:
        if score < 30:
            return "NORMAL"
        if score <= 59:
            return "SUSPICIOUS"
        if score <= 79:
            return "HIGH_RISK"
        return "CRITICAL"

    def _update_entropy_flag(self, entropy_record: dict) -> None:
        entropy_flag = entropy_record.get("entropy_flag")
        alert = str(entropy_record.get("alert", "")).upper()
        if entropy_flag is True or alert == "HIGH_ENTROPY":
            self._entropy_flag = 1
            self._last_entropy_ts = time.time()

    def _effective_entropy_flag(self) -> int:
        if self._entropy_flag and (time.time() - self._last_entropy_ts > self._entropy_ttl_seconds):
            self._entropy_flag = 0
        return self._entropy_flag

    def _update_drift_severity(self, drift_record: dict) -> None:
        self._last_drift_severity = str(drift_record.get("severity", "NONE")).upper()

    def _update_iforest_confidence(self, iforest_record: dict) -> None:
        if iforest_record.get("anomaly"):
            self._last_iforest_confidence = float(iforest_record.get("confidence", 0.0))
        else:
            self._last_iforest_confidence = max(0.0, self._last_iforest_confidence - 0.1)

    def _compute_score(self, feature_vector: dict) -> dict:
        write_rate = float(feature_vector.get("write_rate", 0.0))
        rename_count = int(feature_vector.get("rename_count", 0))
        drift_value = self.DRIFT_MAP.get(self._last_drift_severity, 0.0)
        entropy_flag = self._effective_entropy_flag()
        iforest_conf = min(1.0, max(0.0, self._last_iforest_confidence))

        score = (
            25.0 * entropy_flag
            + 20.0 * min(write_rate / 20.0, 1.0)
            + 20.0 * min(rename_count / 30.0, 1.0)
            + 20.0 * drift_value
            + 15.0 * iforest_conf
        )
        score = round(score, 4)
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": score,
            "level": self._score_level(score),
            "entropy_flag": entropy_flag,
            "write_rate": write_rate,
            "rename_count": rename_count,
            "drift_severity": self._last_drift_severity,
            "drift_severity_value": drift_value,
            "iforest_confidence": iforest_conf,
            "triggered_response": 0,
        }

    def _append_risk(self, result: dict) -> None:
        with self.risk_stream_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(result, separators=(",", ":")) + "\n")

    def run(self) -> None:
        logger.info("RiskScorer started.")
        with (
            self.feature_stream_path.open("r", encoding="utf-8") as feature_file,
            self.entropy_alerts_path.open("r", encoding="utf-8") as entropy_file,
            self.drift_stream_path.open("r", encoding="utf-8") as drift_file,
            self.iforest_stream_path.open("r", encoding="utf-8") as iforest_file,
        ):
            feature_file.seek(0, 2)
            entropy_file.seek(0, 2)
            drift_file.seek(0, 2)
            iforest_file.seek(0, 2)
            while not self.stop_event.is_set():
                while True:
                    line = entropy_file.readline()
                    if not line:
                        break
                    try:
                        self._update_entropy_flag(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass
                while True:
                    line = drift_file.readline()
                    if not line:
                        break
                    try:
                        self._update_drift_severity(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass
                while True:
                    line = iforest_file.readline()
                    if not line:
                        break
                    try:
                        self._update_iforest_confidence(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass
                feature_line = feature_file.readline()
                if not feature_line:
                    time.sleep(0.5)
                    continue
                stripped = feature_line.strip()
                if not stripped:
                    continue
                try:
                    feature_vector = json.loads(stripped)
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed feature vector.")
                    continue
                result = self._compute_score(feature_vector)
                self._append_risk(result)
                logger.info("Risk score %.2f [%s]", result["score"], result["level"])

    def run_demo(self) -> None:
        """Feed synthetic vectors and print scored output."""
        vectors = [
            {"write_rate": 1.5,  "rename_count": 1},
            {"write_rate": 8.0,  "rename_count": 10},
            {"write_rate": 19.0, "rename_count": 28},
        ]
        severities = ["NONE", "MEDIUM", "HIGH"]
        self._entropy_flag = 1
        self._last_entropy_ts = time.time()
        for vector, sev in zip(vectors, severities):
            self._last_drift_severity = sev
            result = self._compute_score(vector)
            print(json.dumps(result, indent=2))


def main() -> None:
    """CLI entry point for scoring and demo execution."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="Risk scoring engine")
    parser.add_argument("--mode", choices=["realtime", "demo"], default="realtime")
    args = parser.parse_args()

    scorer = RiskScorer()
    if args.mode == "demo":
        scorer.run_demo()
    else:
        try:
            scorer.run()
        except KeyboardInterrupt:
            scorer.stop_event.set()


if __name__ == "__main__":
    main()

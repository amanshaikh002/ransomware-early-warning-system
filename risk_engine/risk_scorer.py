"""Risk scoring engine that fuses feature, entropy, and drift signals."""

from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
import threading

from drift.drift_detector import DriftDetector

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
        stop_event: threading.Event | None = None,
    ) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self.feature_stream_path = Path(feature_stream_path) if feature_stream_path else project_root / "feature_stream.jsonl"
        self.entropy_alerts_path = Path(entropy_alerts_path) if entropy_alerts_path else project_root / "entropy_alerts.jsonl"
        self.risk_stream_path = Path(risk_stream_path) if risk_stream_path else project_root / "risk_stream.jsonl"
        self.stop_event = stop_event or threading.Event()

        self._entropy_flag = 0
        self._last_entropy_ts = 0.0
        self._entropy_ttl_seconds = 60.0
        self._drift_detector = DriftDetector()

        self._ensure_file(self.feature_stream_path)
        self._ensure_file(self.entropy_alerts_path)
        self._ensure_file(self.risk_stream_path)

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

    def _compute_score(self, feature_vector: dict) -> dict:
        write_rate = float(feature_vector.get("write_rate", 0.0))
        rename_count = int(feature_vector.get("rename_count", 0))

        drift_severity = str(feature_vector.get("drift_severity", "")).upper()
        if drift_severity not in self.DRIFT_MAP:
            drift_result = self._drift_detector.update(feature_vector)
            drift_severity = str(drift_result.get("severity", "NONE")).upper()

        drift_value = self.DRIFT_MAP.get(drift_severity, 0.0)
        entropy_flag = self._effective_entropy_flag()

        score = (
            30 * entropy_flag
            + 25 * min(write_rate / 20.0, 1.0)
            + 25 * min(rename_count / 30.0, 1.0)
            + 20 * drift_value
        )

        score = round(score, 4)
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": score,
            "level": self._score_level(score),
            "entropy_flag": entropy_flag,
            "write_rate": write_rate,
            "rename_count": rename_count,
            "drift_severity": drift_severity,
            "drift_severity_value": drift_value,
            "triggered_response": 0,
        }
        return result

    def _append_risk(self, result: dict) -> None:
        with self.risk_stream_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(result, separators=(",", ":")) + "\n")

    def run(self) -> None:
        """Tail streams continuously and emit risk scores."""
        logger.info("RiskScorer started.")

        with self.feature_stream_path.open("r", encoding="utf-8") as feature_file, self.entropy_alerts_path.open(
            "r", encoding="utf-8"
        ) as entropy_file:
            feature_file.seek(0, 2)
            entropy_file.seek(0, 2)

            while not self.stop_event.is_set():
                entropy_line = entropy_file.readline()
                if entropy_line:
                    try:
                        self._update_entropy_flag(json.loads(entropy_line.strip()))
                    except json.JSONDecodeError:
                        logger.warning("Skipping malformed entropy alert line.")

                feature_line = feature_file.readline()
                if not feature_line:
                    time.sleep(0.5)
                    continue

                line = feature_line.strip()
                if not line:
                    continue

                try:
                    feature_vector = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed feature vector line.")
                    continue

                result = self._compute_score(feature_vector)
                self._append_risk(result)
                logger.info("Risk score %.2f [%s]", result["score"], result["level"])

    def run_demo(self) -> None:
        """Feed synthetic vectors and print scored output."""
        vectors = [
            {"write_rate": 1.5, "rename_count": 1, "drift_severity": "NONE"},
            {"write_rate": 8.0, "rename_count": 10, "drift_severity": "MEDIUM"},
            {"write_rate": 19.0, "rename_count": 28, "drift_severity": "HIGH"},
        ]
        self._entropy_flag = 1
        self._last_entropy_ts = time.time()

        for vector in vectors:
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

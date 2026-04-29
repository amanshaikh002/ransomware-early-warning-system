"""
Re-verification module.

After a ransomware run completes, walk the sandbox and check every
.locked file against the three detector streams (entropy, drift,
isolation forest). Files that none of them flagged are reported as
"missed" along with a human-readable reason for each detector that
failed to catch it.

This is a forensic / self-audit tool. It does not prevent damage; it
quantifies blind spots so you can see exactly where each layer of the
pipeline fell short during a real burst.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class Reverifier:
    """Audit sandbox state against detection streams."""

    def __init__(
        self,
        sandbox_dir: str | Path | None = None,
        entropy_alerts_path: str | Path | None = None,
        drift_stream_path: str | Path | None = None,
        iforest_stream_path: str | Path | None = None,
        feature_stream_path: str | Path | None = None,
        report_path: str | Path | None = None,
    ) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self.sandbox_dir = Path(sandbox_dir) if sandbox_dir else (
            Path.home() / "Documents" / "ransomware_test"
        )
        self.entropy_alerts_path = Path(entropy_alerts_path) if entropy_alerts_path else (
            project_root / "entropy_alerts.jsonl"
        )
        self.drift_stream_path = Path(drift_stream_path) if drift_stream_path else (
            project_root / "drift_stream.jsonl"
        )
        self.iforest_stream_path = Path(iforest_stream_path) if iforest_stream_path else (
            project_root / "iforest_stream.jsonl"
        )
        self.feature_stream_path = Path(feature_stream_path) if feature_stream_path else (
            project_root / "feature_stream.jsonl"
        )
        self.report_path = Path(report_path) if report_path else (
            project_root / "reverification_report.jsonl"
        )

    @staticmethod
    def _load_jsonl(path: Path) -> list[dict]:
        if not path.exists():
            return []
        records: list[dict] = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records

    def _list_locked_files(self) -> list[Path]:
        if not self.sandbox_dir.is_dir():
            return []
        return sorted(p for p in self.sandbox_dir.rglob("*.locked") if p.is_file())

    def audit(self) -> dict:
        locked_files = self._list_locked_files()
        entropy_alerts = self._load_jsonl(self.entropy_alerts_path)
        drift_records = self._load_jsonl(self.drift_stream_path)
        iforest_records = self._load_jsonl(self.iforest_stream_path)

        # Index entropy alerts by absolute path (case-insensitive on Windows).
        entropy_by_path: dict[str, dict] = {}
        for record in entropy_alerts:
            fp = str(record.get("file_path", ""))
            if fp:
                entropy_by_path[fp.lower()] = record

        drift_fired_count = sum(
            1 for r in drift_records
            if str(r.get("severity", "")).upper() not in {"", "NONE"}
        )
        iforest_fired_count = sum(1 for r in iforest_records if r.get("anomaly"))
        entropy_high_count = sum(
            1 for r in entropy_alerts
            if str(r.get("alert", "")).upper() == "HIGH_ENTROPY"
        )

        caught: list[dict] = []
        missed: list[dict] = []

        for fp in locked_files:
            path_str = str(fp)
            path_lower = path_str.lower()
            entropy_record = entropy_by_path.get(path_lower)

            entropy_caught = bool(
                entropy_record
                and str(entropy_record.get("alert", "")).upper() == "HIGH_ENTROPY"
            )
            entropy_skipped_reason = (
                entropy_record.get("skipped_reason") if entropy_record else None
            )
            entropy_error = entropy_record.get("error") if entropy_record else None

            # Per-file timestamp correlation is fragile (.locked file mtime can
            # shift after rename). We use session-wide proxies: did drift fire
            # at any point during the attack? Did IF flag any window?
            drift_caught = drift_fired_count > 0
            iforest_caught = iforest_fired_count > 0

            file_info = {
                "file_path": path_str,
                "size": fp.stat().st_size if fp.exists() else 0,
                "caught_by": {
                    "entropy": entropy_caught,
                    "drift": drift_caught,
                    "iforest": iforest_caught,
                },
                "any_caught": entropy_caught or drift_caught or iforest_caught,
            }

            if file_info["any_caught"]:
                caught.append(file_info)
                continue

            # Compose specific reasons for each detector that missed.
            reasons: list[str] = []
            if entropy_record is None:
                reasons.append(
                    "entropy: no alert recorded — file may have been renamed/deleted "
                    "before the analyzer could read it, or the watcher dropped the event"
                )
            elif entropy_skipped_reason:
                reasons.append(
                    f"entropy: skipped ({entropy_skipped_reason}) — extension is on "
                    f"the naturally-high-entropy whitelist"
                )
            elif entropy_error:
                reasons.append(f"entropy: read error ({entropy_error})")
            else:
                ent_value = entropy_record.get("entropy")
                threshold = entropy_record.get("threshold", "n/a")
                reasons.append(
                    f"entropy: {ent_value} bits/byte was at or below threshold "
                    f"{threshold} — file content was not random enough to flag"
                )

            if not drift_caught:
                reasons.append(
                    "drift: no detector fired during this session — activity volume "
                    "may have been below the burst threshold, or the baseline (10 "
                    "windows minimum) had not yet been established"
                )

            if not iforest_caught:
                reasons.append(
                    "iforest: no anomaly flagged — model may still be in training "
                    "phase (needs 50 samples), or the burst pattern was within the "
                    "learned normal envelope"
                )

            file_info["reasons"] = reasons
            missed.append(file_info)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sandbox_dir": str(self.sandbox_dir),
            "total_locked_files": len(locked_files),
            "caught_count": len(caught),
            "missed_count": len(missed),
            "coverage_percent": (
                round(100.0 * len(caught) / len(locked_files), 1)
                if locked_files else 0.0
            ),
            "detector_summary": {
                "entropy_alerts_high": entropy_high_count,
                "drift_alerts_fired": drift_fired_count,
                "iforest_anomalies": iforest_fired_count,
            },
            "missed_files": missed,
            "caught_sample": caught[:5],
        }

    def run(self) -> dict:
        """Run the audit and append the report to disk."""
        report = self.audit()
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        with self.report_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(report, separators=(",", ":")) + "\n")

        logger.info(
            "Re-verification: %d locked files, %d caught (%.1f%%), %d missed",
            report["total_locked_files"],
            report["caught_count"],
            report["coverage_percent"],
            report["missed_count"],
        )
        return report


def main() -> None:
    """CLI entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    parser = argparse.ArgumentParser(description="Post-attack re-verification audit")
    parser.add_argument(
        "--sandbox",
        default=None,
        help="Path to the sandbox directory (default: ~/Documents/ransomware_test)",
    )
    args = parser.parse_args()

    rev = Reverifier(sandbox_dir=args.sandbox)
    report = rev.run()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

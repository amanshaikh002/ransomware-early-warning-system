"""Local SHA-256 Merkle-chain evidence logger for alerts."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ChainTamperError(Exception):
    """Raised when evidence chain validation fails."""


class BlockchainEvidenceLogger:
    """Append-only local chain ledger for alert evidence."""

    def __init__(
        self,
        chain_path: str | None = None,
        risk_stream_path: str | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self.chain_path = Path(chain_path) if chain_path else project_root / "evidence_chain.jsonl"
        self.risk_stream_path = Path(risk_stream_path) if risk_stream_path else project_root / "risk_stream.jsonl"
        self.stop_event = stop_event or threading.Event()

        self.chain_path.parent.mkdir(parents=True, exist_ok=True)
        self.chain_path.touch(exist_ok=True)
        self.risk_stream_path.parent.mkdir(parents=True, exist_ok=True)
        self.risk_stream_path.touch(exist_ok=True)

    @staticmethod
    def _sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _payload_hash(self, payload: dict[str, Any]) -> str:
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return self._sha256(payload_json)

    def _block_hash(self, block_without_hash: dict[str, Any]) -> str:
        canonical = json.dumps(block_without_hash, sort_keys=True, separators=(",", ":"))
        return self._sha256(canonical)

    def _read_all_blocks(self) -> list[dict[str, Any]]:
        blocks: list[dict[str, Any]] = []
        with self.chain_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                blocks.append(json.loads(line))
        return blocks

    def add_alert(self, alert_type: str, severity: str, payload: dict[str, Any]) -> dict[str, Any]:
        blocks = self._read_all_blocks()
        prev_hash = "0" * 64 if not blocks else str(blocks[-1]["block_hash"])
        index = len(blocks)

        block = {
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "severity": severity,
            "payload": payload,
            "payload_hash": self._payload_hash(payload),
            "prev_hash": prev_hash,
        }
        block["block_hash"] = self._block_hash(block)

        with self.chain_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(block, separators=(",", ":")) + "\n")

        return block

    def verify_chain(self) -> bool:
        blocks = self._read_all_blocks()
        expected_prev = "0" * 64

        for block in blocks:
            idx = int(block.get("index", -1))
            actual_prev = str(block.get("prev_hash", ""))
            if actual_prev != expected_prev:
                raise ChainTamperError(f"Broken prev_hash at block index {idx}")

            payload_hash = self._payload_hash(block.get("payload", {}))
            if payload_hash != str(block.get("payload_hash", "")):
                raise ChainTamperError(f"Payload hash mismatch at block index {idx}")

            candidate = dict(block)
            candidate.pop("block_hash", None)
            expected_hash = self._block_hash(candidate)
            if expected_hash != str(block.get("block_hash", "")):
                raise ChainTamperError(f"Block hash mismatch at block index {idx}")

            expected_prev = expected_hash

        return True

    def run(self) -> None:
        """Subscribe to risk stream and log suspicious alerts to the chain."""
        with self.risk_stream_path.open("r", encoding="utf-8") as handle:
            handle.seek(0, 2)
            while not self.stop_event.is_set():
                line = handle.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    risk_record = json.loads(line.strip())
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed risk line in evidence logger.")
                    continue

                level = str(risk_record.get("level", "NORMAL")).upper()
                if level in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}:
                    self.add_alert("RISK_SCORE", level, risk_record)

    def run_demo(self) -> None:
        for idx in range(5):
            self.add_alert(
                alert_type="DEMO_ALERT",
                severity="LOW" if idx < 3 else "HIGH",
                payload={"seq": idx, "message": f"synthetic alert {idx}"},
            )
        print(f"Chain valid: {self.verify_chain()}")


def main() -> None:
    """CLI entry point for evidence ledger operations."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="Blockchain evidence logger")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()

    logger_instance = BlockchainEvidenceLogger()

    if args.verify:
        try:
            print(f"Chain valid: {logger_instance.verify_chain()}")
        except ChainTamperError as exc:
            print(str(exc))
        return

    if args.demo:
        logger_instance.run_demo()
        return

    try:
        logger_instance.run()
    except KeyboardInterrupt:
        logger_instance.stop_event.set()


if __name__ == "__main__":
    main()

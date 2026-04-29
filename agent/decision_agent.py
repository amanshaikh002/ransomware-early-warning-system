"""Finite-state decision agent that responds to risk stream levels."""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import stat
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class DecisionAgent:
    """Risk-driven response FSM for ransomware early warning."""

    MONITORING = "MONITORING"
    ALERT = "ALERT"
    RESPONDING = "RESPONDING"
    RECOVERING = "RECOVERING"

    def __init__(
        self,
        risk_stream_path: str | None = None,
        incidents_path: str | None = None,
        monitored_paths: list[str] | None = None,
        process_names_getter=None,
        stop_event: threading.Event | None = None,
    ) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self.risk_stream_path = Path(risk_stream_path) if risk_stream_path else project_root / "risk_stream.jsonl"
        self.incidents_path = Path(incidents_path) if incidents_path else project_root / "incidents.jsonl"
        self.monitored_paths = (
            [Path(p) for p in monitored_paths]
            if monitored_paths
            else [Path.home() / "Documents" / "ransomware_test"]
        )
        self._get_process_names = process_names_getter or (lambda: set())
        self._suspended_pids: list[int] = []
        self.stop_event = stop_event or threading.Event()
        self._state = self.MONITORING
        self._consecutive_high = 0
        self._consecutive_below_30 = 0
        self._recovering_normal_windows = 0
        self._ensure_file(self.risk_stream_path)
        self._ensure_file(self.incidents_path)

    @staticmethod
    def _ensure_file(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)

    def get_state(self) -> str:
        return self._state

    def _write_incident(self, event: str, payload: dict) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "state": self._state,
            "payload": payload,
        }
        with self.incidents_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    def _warning_banner(self, payload: dict) -> None:
        print("\n" + "=" * 68)
        print("  RANSOMWARE EARLY WARNING ALERT")
        print("-" * 68)
        print(f"  Level : {payload.get('level')}")
        print(f"  Score : {payload.get('score')}")
        print("=" * 68 + "\n")

    def _suspend_suspicious_processes(self) -> None:
        """Suspend processes identified as suspicious via the shared tracker."""
        import psutil
        names = self._get_process_names()
        if not names:
            logger.warning("No suspicious process names available for suspension.")
            return
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"] in names:
                    proc.suspend()
                    self._suspended_pids.append(proc.info["pid"])
                    logger.warning("Suspended PID %d (%s)", proc.info["pid"], proc.info["name"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _resume_suspended_processes(self) -> None:
        """Resume all previously suspended processes."""
        import psutil
        for pid in self._suspended_pids:
            try:
                psutil.Process(pid).resume()
                logger.info("Resumed PID %d", pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self._suspended_pids.clear()

    def _lock_directory_windows(self, path: Path) -> bool:
        try:
            result = subprocess.run(
                ["icacls", str(path), "/deny", "Everyone:(W,D,DC)", "/T"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                logger.error("icacls lock failed: %s", result.stderr.strip())
                return False
            logger.info("icacls locked: %s", path)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("icacls unavailable: %s", exc)
            return False

    def _unlock_directory_windows(self, path: Path) -> bool:
        try:
            result = subprocess.run(
                ["icacls", str(path), "/remove:d", "Everyone", "/T"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _take_vss_snapshot(self) -> None:
        """Attempt a Volume Shadow Copy of C:\\ on Windows for recovery capability."""
        if platform.system() != "Windows":
            return
        try:
            result = subprocess.run(
                ["wmic", "shadowcopy", "call", "create", "Volume='C:\\\\'"],
                capture_output=True, text=True, timeout=30,
            )
            logger.info("VSS snapshot: %s", result.stdout.strip())
        except Exception as exc:
            logger.warning("VSS snapshot failed (non-fatal): %s", exc)

    def _lock_sandbox(self) -> None:
        for path in self.monitored_paths:
            path.mkdir(parents=True, exist_ok=True)
            if platform.system() == "Windows":
                self._lock_directory_windows(path)
            else:
                for target in [path, *path.rglob("*")]:
                    try:
                        m = target.stat().st_mode
                        target.chmod(m & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
                    except OSError:
                        pass
            logger.info("Locked: %s", path)

    def _unlock_sandbox(self) -> None:
        for path in self.monitored_paths:
            if not path.exists():
                continue
            if platform.system() == "Windows":
                self._unlock_directory_windows(path)
            else:
                for target in [path, *path.rglob("*")]:
                    try:
                        m = target.stat().st_mode
                        target.chmod(m | stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
                    except OSError:
                        pass
            logger.info("Unlocked: %s", path)

    def _transition(self, new_state: str, reason: str, payload: dict) -> None:
        previous = self._state
        self._state = new_state
        logger.info("DecisionAgent state %s -> %s (%s)", previous, new_state, reason)
        if new_state == self.ALERT:
            self._warning_banner(payload)
            self._write_incident("ALERT", payload)
            self._take_vss_snapshot()
        elif new_state == self.RESPONDING:
            self._lock_sandbox()
            self._suspend_suspicious_processes()
            self._write_incident("RESPONDING", payload)
        elif new_state == self.RECOVERING:
            self._unlock_sandbox()
            self._resume_suspended_processes()
            self._write_incident("RECOVERING", payload)

    def _handle_window(self, risk_record: dict) -> None:
        level = str(risk_record.get("level", "NORMAL")).upper()
        score = float(risk_record.get("score", 0.0))
        is_high = level in {"HIGH_RISK", "CRITICAL"}
        is_normal = score < 30.0

        if is_high:
            self._consecutive_high += 1
        else:
            self._consecutive_high = 0

        if is_normal:
            self._consecutive_below_30 += 1
        else:
            self._consecutive_below_30 = 0

        if self._state == self.MONITORING:
            if is_high:
                self._transition(self.ALERT, "high risk detected", risk_record)
                self._consecutive_high = 1

        elif self._state == self.ALERT:
            if is_high and self._consecutive_high >= 2:
                self._transition(self.RESPONDING, "two consecutive high windows", risk_record)
            elif not is_high:
                self._consecutive_high = 0

        elif self._state == self.RESPONDING:
            if self._consecutive_below_30 >= 3:
                self._transition(self.RECOVERING, "risk dropped below 30 for 3 windows", risk_record)
                self._recovering_normal_windows = 0

        elif self._state == self.RECOVERING:
            if is_normal:
                self._recovering_normal_windows += 1
            else:
                self._recovering_normal_windows = 0
                if is_high:
                    self._transition(self.ALERT, "risk rose again during recovery", risk_record)
                    self._consecutive_high = 1
                    return

            if self._recovering_normal_windows >= 5:
                self._state = self.MONITORING
                self._write_incident("MONITORING", risk_record)
                logger.info("DecisionAgent transitioned RECOVERING -> MONITORING")
                self._recovering_normal_windows = 0

    def run(self) -> None:
        """Tail risk stream and drive the finite-state machine."""
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
                    logger.warning("Skipping malformed risk line.")
                    continue
                self._handle_window(risk_record)

    def run_demo(self) -> None:
        samples = [
            {"score": 10, "level": "NORMAL"},
            {"score": 65, "level": "HIGH_RISK"},
            {"score": 82, "level": "CRITICAL"},
            {"score": 20, "level": "NORMAL"},
            {"score": 18, "level": "NORMAL"},
            {"score": 12, "level": "NORMAL"},
            {"score": 8, "level": "NORMAL"},
            {"score": 5, "level": "NORMAL"},
        ]
        for sample in samples:
            self._handle_window(sample)
            print(f"state={self.get_state()} sample={sample}")


def main() -> None:
    """CLI entry point for the decision agent."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="Decision agent FSM")
    parser.add_argument("--mode", choices=["realtime", "demo"], default="realtime")
    args = parser.parse_args()

    agent = DecisionAgent()
    if args.mode == "demo":
        agent.run_demo()
    else:
        try:
            agent.run()
        except KeyboardInterrupt:
            agent.stop_event.set()


if __name__ == "__main__":
    main()

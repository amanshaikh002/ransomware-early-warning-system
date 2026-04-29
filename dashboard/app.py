"""Flask dashboard application for ransomware monitoring status."""

from __future__ import annotations

import argparse
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_file

from blockchain.evidence_logger import BlockchainEvidenceLogger, ChainTamperError
from database.db_manager import DatabaseManager
from testing.ransomware_simulator import cleanup_sandbox, run_bulk, run_normal, run_ransomware
from verification.reverifier import Reverifier

logger = logging.getLogger(__name__)


def _get_agent_state(project_root: Path) -> str:
    incidents_path = project_root / "incidents.jsonl"
    incidents_path.touch(exist_ok=True)

    last_state = "MONITORING"
    with incidents_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                last_state = str(json.loads(line).get("state", last_state))
            except json.JSONDecodeError:
                continue
    return last_state


def create_app(db_path: str | None = None) -> Flask:
    """Factory for dashboard Flask app."""
    project_root = Path(__file__).resolve().parent.parent
    index_path = Path(__file__).resolve().parent / "index.html"

    db = DatabaseManager(db_path=db_path)
    chain_logger = BlockchainEvidenceLogger(chain_path=str(project_root / "evidence_chain.jsonl"))
    simulation_lock = threading.Lock()
    simulation_state = {
        "running": False,
        "mode": None,
        "started_at": None,
        "last_error": None,
        "stop_event": None,
    }

    import time as _time
    _chain_cache: dict = {"valid": True, "checked_at": 0.0}
    _CHAIN_CACHE_TTL = 30.0

    app = Flask(__name__, static_folder=str(Path(__file__).resolve().parent), static_url_path="")

    def _run_simulation(mode: str, count: int, duration: int, stop_event: threading.Event) -> None:
        try:
            if mode == "normal":
                run_normal(duration_seconds=duration, stop_event=stop_event)
            elif mode == "bulk":
                run_bulk(file_count=count, stop_event=stop_event)
            elif mode == "ransomware":
                run_ransomware(file_count=count, stop_event=stop_event)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Simulation failed: %s", exc)
            with simulation_lock:
                simulation_state["last_error"] = str(exc)
        finally:
            # Always run re-verification BEFORE cleanup so the audit can
            # see the final sandbox state. Only meaningful for ransomware
            # mode (which actually creates .locked files), but harmless
            # for the others.
            if mode == "ransomware":
                try:
                    Reverifier().run()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Re-verification failed: %s", exc)

            if stop_event.is_set():
                try:
                    cleanup_sandbox()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Sandbox cleanup after stop failed: %s", exc)
            with simulation_lock:
                simulation_state["running"] = False
                simulation_state["mode"] = None
                simulation_state["stop_event"] = None

    @app.get("/")
    def index() -> object:
        return send_file(index_path)

    @app.post("/api/simulate")
    def start_simulation() -> object:
        data = request.get_json(silent=True) or {}
        mode = str(data.get("mode", "ransomware")).lower()
        count = int(data.get("count", 25))
        duration = int(data.get("duration", 60))

        if mode not in {"normal", "bulk", "ransomware"}:
            return jsonify({"ok": False, "error": "invalid_mode"}), 400
        if count < 1 or duration < 1:
            return jsonify({"ok": False, "error": "invalid_parameters"}), 400

        with simulation_lock:
            if simulation_state["running"]:
                return jsonify({"ok": False, "error": "simulation_already_running"}), 409
            sim_stop_event = threading.Event()
            simulation_state["running"] = True
            simulation_state["mode"] = mode
            simulation_state["started_at"] = datetime.now(timezone.utc).isoformat()
            simulation_state["last_error"] = None
            simulation_state["stop_event"] = sim_stop_event

        simulation_thread = threading.Thread(
            target=_run_simulation,
            args=(mode, count, duration, sim_stop_event),
            daemon=True,
            name="DashboardSimulationThread",
        )
        simulation_thread.start()
        return jsonify({"ok": True, "mode": mode, "count": count, "duration": duration})

    @app.get("/api/reverification")
    def reverification() -> object:
        """Return the latest re-verification report (last line of the JSONL)."""
        report_path = project_root / "reverification_report.jsonl"
        if not report_path.exists() or report_path.stat().st_size == 0:
            return jsonify({"ok": True, "report": None})

        last_line = ""
        with report_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_line = stripped

        if not last_line:
            return jsonify({"ok": True, "report": None})

        try:
            report = json.loads(last_line)
        except json.JSONDecodeError:
            return jsonify({"ok": False, "error": "report_parse_failed"}), 500
        return jsonify({"ok": True, "report": report})

    @app.post("/api/reverify_now")
    def reverify_now() -> object:
        """On-demand re-verification (run without waiting for sim completion)."""
        try:
            report = Reverifier().run()
        except Exception as exc:  # noqa: BLE001
            logger.exception("On-demand re-verification failed: %s", exc)
            return jsonify({"ok": False, "error": str(exc)}), 500
        return jsonify({"ok": True, "report": report})

    @app.post("/api/inject_decoy_missed")
    def inject_decoy_missed() -> object:
        """
        Drop a low-entropy `.locked` file into the sandbox so the
        reverifier has something to report as MISSED.

        Real text content (~3 bits/byte) sits well below the 7.2
        entropy threshold, so the entropy analyzer will record it
        as NORMAL rather than HIGH_ENTROPY. The file is still
        named `.locked`, so the reverifier will see it during the
        sandbox walk and flag it as a missed detection — exactly
        the scenario this dashboard panel is meant to demonstrate.
        """
        import secrets
        import string
        sandbox = Path.home() / "Documents" / "ransomware_test"
        sandbox.mkdir(parents=True, exist_ok=True)
        slug = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
        decoy = sandbox / f"decoy_{slug}.txt.locked"
        text = ("This is plain English text. Ransomware-grade encryption would "
                "produce uniformly random bytes, not readable words. Because "
                "entropy stays low here, the analyzer will not flag this file "
                "as encrypted — and the re-verification audit will correctly "
                "report it as a missed detection.\n") * 20
        try:
            decoy.write_text(text, encoding="utf-8")
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500
        logger.info("Decoy injected: %s", decoy)
        return jsonify({"ok": True, "file": str(decoy)})

    @app.post("/api/stop_simulation")
    def stop_simulation() -> object:
        with simulation_lock:
            if not simulation_state["running"]:
                return jsonify({"ok": False, "error": "no_simulation_running"}), 409
            sim_stop_event = simulation_state["stop_event"]
            mode = simulation_state["mode"]

        if sim_stop_event is not None:
            sim_stop_event.set()
        logger.info("Stop request received for simulation mode=%s", mode)
        return jsonify({"ok": True, "stopped_mode": mode})

    @app.get("/api/status")
    def status() -> object:
        risk_history = db.query_recent("risk_scores", limit=50)
        recent_alerts = db.query_recent("drift_alerts", limit=20)

        current = risk_history[0] if risk_history else {
            "score": 0.0,
            "level": "NORMAL",
            "entropy_flag": 0,
        }

        now = _time.time()
        if now - _chain_cache["checked_at"] >= _CHAIN_CACHE_TTL:
            try:
                _chain_cache["valid"] = chain_logger.verify_chain()
            except ChainTamperError:
                _chain_cache["valid"] = False
            _chain_cache["checked_at"] = now
        chain_valid = _chain_cache["valid"]

        with simulation_lock:
            simulator_running = bool(simulation_state["running"])
            simulator_mode = simulation_state["mode"]
            simulator_started_at = simulation_state["started_at"]
            simulator_last_error = simulation_state["last_error"]

        payload = {
            "current_risk_score": float(current.get("score", 0.0)),
            "current_level": str(current.get("level", "NORMAL")),
            "agent_state": _get_agent_state(project_root),
            "last_entropy_flag": int(current.get("entropy_flag", 0)),
            "recent_alerts": recent_alerts,
            "risk_history": list(reversed(risk_history)),
            "chain_valid": chain_valid,
            "simulator_running": simulator_running,
            "simulator_mode": simulator_mode,
            "simulator_started_at": simulator_started_at,
            "simulator_last_error": simulator_last_error,
        }
        return jsonify(payload)

    return app


def main() -> None:
    """CLI entry point for dashboard service."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    parser = argparse.ArgumentParser(description="Run ransomware dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()

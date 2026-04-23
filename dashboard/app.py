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
from testing.ransomware_simulator import run_bulk, run_normal, run_ransomware

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
    }

    app = Flask(__name__, static_folder=str(Path(__file__).resolve().parent), static_url_path="")

    def _run_simulation(mode: str, count: int, duration: int) -> None:
        try:
            if mode == "normal":
                run_normal(duration_seconds=duration)
            elif mode == "bulk":
                run_bulk(file_count=count)
            elif mode == "ransomware":
                run_ransomware(file_count=count)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Simulation failed: %s", exc)
            with simulation_lock:
                simulation_state["last_error"] = str(exc)
        finally:
            with simulation_lock:
                simulation_state["running"] = False
                simulation_state["mode"] = None

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
            simulation_state["running"] = True
            simulation_state["mode"] = mode
            simulation_state["started_at"] = datetime.now(timezone.utc).isoformat()
            simulation_state["last_error"] = None

        simulation_thread = threading.Thread(
            target=_run_simulation,
            args=(mode, count, duration),
            daemon=True,
            name="DashboardSimulationThread",
        )
        simulation_thread.start()
        return jsonify({"ok": True, "mode": mode, "count": count, "duration": duration})

    @app.get("/api/status")
    def status() -> object:
        risk_history = db.query_recent("risk_scores", limit=50)
        recent_alerts = db.query_recent("drift_alerts", limit=20)

        current = risk_history[0] if risk_history else {
            "score": 0.0,
            "level": "NORMAL",
            "entropy_flag": 0,
        }

        chain_valid = True
        try:
            chain_valid = chain_logger.verify_chain()
        except ChainTamperError:
            chain_valid = False

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

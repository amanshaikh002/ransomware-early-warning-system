"""Unified orchestrator for the ransomware early-warning pipeline."""

from __future__ import annotations

import argparse
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from agent.decision_agent import DecisionAgent
from anomaly_detection.isolation_forest import IsolationForestDetector
from blockchain.evidence_logger import BlockchainEvidenceLogger
from dashboard.app import create_app
from database.db_manager import DatabaseManager
from drift.drift_detector import DriftDetector
from entropy.entropy_analyzer import EntropyAnalyzer
from features.feature_extractor import FeatureExtractor
from monitoring.file_watcher import FileWatcher, get_default_monitored_paths
from risk_engine.risk_scorer import RiskScorer
from testing.ransomware_simulator import run_bulk, run_normal, run_ransomware


logging.basicConfig(
	level=logging.INFO,
	format="%(asctime)s | %(levelname)-7s | %(message)s",
	datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


_suspicious_lock = threading.Lock()
_seen_process_names: set[str] = set()
_IGNORED_PNAMES = {"python.exe", "python3", "python", "unknown", ""}


def _ensure_file(path: Path) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	path.touch(exist_ok=True)


def _tail_jsonl(path: Path, stop_event: threading.Event, callback, from_end: bool = True) -> None:
	_ensure_file(path)
	with path.open("r", encoding="utf-8") as handle:
		if from_end:
			handle.seek(0, 2)
		while not stop_event.is_set():
			line = handle.readline()
			if not line:
				time.sleep(0.5)
				continue
			line = line.strip()
			if not line:
				continue
			try:
				callback(json.loads(line))
			except json.JSONDecodeError:
				logger.warning("Skipping malformed JSONL line from %s", path)


def _run_file_pipeline(
	watcher: FileWatcher,
	extractor: FeatureExtractor,
	entropy_analyzer: EntropyAnalyzer,
	database: DatabaseManager,
	stop_event: threading.Event,
) -> None:
	def _on_event(event: dict) -> None:
		extractor.add_event(event)
		database.insert_file_event(
			timestamp=str(event.get("timestamp", "")),
			event_type=str(event.get("event_type", "")),
			file_path=str(event.get("file_path", "")),
			file_size=int(event.get("file_size", -1)),
			process_name=str(event.get("process_name", "unknown")),
		)

		entropy_result = entropy_analyzer.handle_event(event)
		if entropy_result and entropy_result.get("entropy_flag"):
			database.insert_entropy_alert(
				timestamp=str(entropy_result.get("timestamp", "")),
				file_path=str(entropy_result.get("file_path", "")),
				entropy=float(entropy_result.get("entropy", 0.0)),
				threshold=float(entropy_result.get("threshold", 0.0)),
			)

		pname = str(event.get("process_name", ""))
		if pname and pname not in _IGNORED_PNAMES:
			with _suspicious_lock:
				_seen_process_names.add(pname)
				if len(_seen_process_names) > 50:
					_seen_process_names.clear()

	watcher.add_event_callback(_on_event)
	watcher.start()
	extractor.start_window_timer()

	try:
		while not stop_event.is_set():
			time.sleep(0.5)
	finally:
		extractor.stop_window_timer()
		watcher.stop()


def _run_drift_pipeline(
	detector: DriftDetector,
	feature_stream: Path,
	database: DatabaseManager,
	drift_stream: Path,
	stop_event: threading.Event,
) -> None:
	def _consume(vector: dict) -> None:
		result = detector.update(vector)
		if result.get("drift_detected"):
			database.insert_drift_alert(
				timestamp=str(result.get("timestamp", "")),
				severity=str(result.get("severity", "NONE")),
				top_feature=result.get("top_feature"),
				top_z_score=float(result.get("top_z_score", 0.0) or 0.0),
				write_rate=float(result.get("write_rate", 0.0)),
				rename_count=int(result.get("rename_count", 0)),
				detectors_fired=int(result.get("detectors_fired", 0)),
			)

		drift_record = {
			"timestamp": result.get("timestamp", ""),
			"severity": result.get("severity", "NONE"),
			"detectors_fired": result.get("detectors_fired", 0),
		}
		try:
			with drift_stream.open("a", encoding="utf-8") as fh:
				fh.write(json.dumps(drift_record, separators=(",", ":")) + "\n")
		except OSError as exc:
			logger.error("Failed to write drift record: %s", exc)

	_tail_jsonl(feature_stream, stop_event, _consume, from_end=True)


def _run_iforest_pipeline(
	detector: IsolationForestDetector,
	feature_stream: Path,
	iforest_stream: Path,
	stop_event: threading.Event,
) -> None:
	_ensure_file(feature_stream)
	_ensure_file(iforest_stream)
	samples: list[dict] = []
	trained = detector.model is not None
	with feature_stream.open("r", encoding="utf-8") as handle:
		handle.seek(0, 2)
		while not stop_event.is_set():
			line = handle.readline()
			if not line:
				time.sleep(0.5)
				continue
			try:
				vector = json.loads(line.strip())
			except json.JSONDecodeError:
				logger.warning("Skipping malformed feature vector in IF pipeline")
				continue
			if not trained:
				samples.append(vector)
				trained = detector.train_from_vectors(samples)
				if trained:
					logger.info("IsolationForest trained on %d samples", len(samples))
				continue
			result = detector.detect(vector)
			result["timestamp"] = vector.get("window_end", "")
			try:
				with iforest_stream.open("a", encoding="utf-8") as fh:
					fh.write(json.dumps(result, separators=(",", ":")) + "\n")
			except OSError as exc:
				logger.error("Failed to write iforest result: %s", exc)
			logger.info(
				"IsolationForest: anomaly=%s confidence=%.3f",
				result["anomaly"], result["confidence"],
			)


def _run_db_pruner(database: DatabaseManager, stop_event: threading.Event) -> None:
	"""Prune each table to at most 10 000 rows every 10 minutes."""
	tables = ("file_events", "drift_alerts", "risk_scores", "entropy_alerts")
	while not stop_event.is_set():
		for _ in range(600):
			if stop_event.is_set():
				return
			time.sleep(1)
		for table in tables:
			try:
				deleted = database.prune_table(table, max_records=10_000)
				if deleted:
					logger.info("Pruned %d rows from %s", deleted, table)
			except Exception as exc:
				logger.warning("Pruning failed for %s: %s", table, exc)


def _run_risk_db_sink(risk_stream: Path, database: DatabaseManager, stop_event: threading.Event) -> None:
	def _consume(record: dict) -> None:
		database.insert_risk_score(
			timestamp=str(record.get("timestamp", "")),
			score=float(record.get("score", 0.0)),
			level=str(record.get("level", "NORMAL")),
			entropy_flag=int(record.get("entropy_flag", 0)),
			triggered_response=int(record.get("triggered_response", 0)),
		)

	_tail_jsonl(risk_stream, stop_event, _consume, from_end=True)


def _run_dashboard(stop_event: threading.Event) -> None:
	app = create_app()
	dashboard_thread = threading.Thread(
		target=app.run,
		kwargs={
			"host": "127.0.0.1",
			"port": 5000,
			"debug": False,
			"use_reloader": False,
			"threaded": True,
		},
		daemon=True,
		name="DashboardFlaskThread",
	)
	dashboard_thread.start()
	while not stop_event.is_set():
		time.sleep(0.5)


def _run_simulator(mode: str, count: int, duration: int, start_delay: float) -> None:
	"""Run a one-shot simulator scenario for end-to-end alert demos."""
	if start_delay > 0:
		time.sleep(start_delay)

	logger.info("Starting simulator mode=%s", mode)
	if mode == "normal":
		run_normal(duration_seconds=duration)
	elif mode == "bulk":
		run_bulk(file_count=count)
	elif mode == "ransomware":
		run_ransomware(file_count=count)
	logger.info("Simulator mode=%s completed", mode)


def main() -> None:
	"""Start all monitoring modules as coordinated daemon threads."""
	parser = argparse.ArgumentParser(description="Ransomware early-warning orchestrator")
	parser.add_argument(
		"--simulate",
		choices=["none", "normal", "bulk", "ransomware"],
		default="none",
		help="Optionally run the ransomware simulator in-process after startup.",
	)
	parser.add_argument("--sim-count", type=int, default=15, help="File count for bulk/ransomware simulation.")
	parser.add_argument("--sim-duration", type=int, default=30, help="Duration seconds for normal simulation.")
	parser.add_argument(
		"--sim-delay",
		type=float,
		default=3.0,
		help="Seconds to wait before starting simulator (lets watchers initialize).",
	)
	args = parser.parse_args()

	project_root = Path(__file__).resolve().parent

	event_stream = project_root / "event_stream.jsonl"
	feature_stream = project_root / "feature_stream.jsonl"
	entropy_alerts = project_root / "entropy_alerts.jsonl"
	risk_stream = project_root / "risk_stream.jsonl"
	drift_stream = project_root / "drift_stream.jsonl"
	iforest_stream = project_root / "iforest_stream.jsonl"
	incidents_stream = project_root / "incidents.jsonl"
	reverification_report = project_root / "reverification_report.jsonl"

	# Truncate all live streams so the dashboard starts each session clean.
	# The blockchain ledger (evidence_chain.jsonl) is intentionally preserved
	# — it's the immutable forensic record across sessions.
	for path in [event_stream, feature_stream, entropy_alerts, risk_stream,
	             drift_stream, iforest_stream, incidents_stream,
	             reverification_report]:
		_ensure_file(path)
		try:
			path.write_text("", encoding="utf-8")
		except OSError as exc:
			logger.warning("Could not truncate %s: %s", path, exc)

	stop_event = threading.Event()
	database = DatabaseManager(str(project_root / "ransomware_monitor.db"))

	# Wipe the operational tables so the dashboard's "current" reflects
	# this session, not the previous one. Schema and indexes survive.
	for table in ("file_events", "drift_alerts", "risk_scores", "entropy_alerts"):
		try:
			database.prune_table(table, max_records=0)
		except Exception as exc:  # noqa: BLE001
			logger.warning("Could not reset table %s: %s", table, exc)

	# Seed a clean baseline so /api/status returns NORMAL/0 from the very
	# first poll, before any feature window has had a chance to close.
	now_iso = datetime.now(timezone.utc).isoformat()
	database.insert_risk_score(
		timestamp=now_iso,
		score=0.0,
		level="NORMAL",
		entropy_flag=0,
		triggered_response=0,
	)
	with incidents_stream.open("a", encoding="utf-8") as fh:
		fh.write(json.dumps({
			"timestamp": now_iso,
			"event": "MONITORING",
			"state": "MONITORING",
			"payload": {"reason": "session_start"},
		}, separators=(",", ":")) + "\n")

	monitored_paths = get_default_monitored_paths()
	sandbox_dir = str(Path.home() / "Documents" / "ransomware_test")
	Path(sandbox_dir).mkdir(parents=True, exist_ok=True)
	if sandbox_dir not in monitored_paths:
		monitored_paths.append(sandbox_dir)
	watcher = FileWatcher(monitored_paths, stream_file=str(event_stream))
	extractor = FeatureExtractor(window_seconds=5)
	extractor.stream_file = str(feature_stream)

	entropy_analyzer = EntropyAnalyzer(threshold=7.2)
	entropy_analyzer.alerts_file = str(entropy_alerts)
	entropy_analyzer.alerts_path = str(entropy_alerts)

	drift_detector = DriftDetector()
	iforest_detector = IsolationForestDetector()
	risk_scorer = RiskScorer(
		feature_stream_path=str(feature_stream),
		entropy_alerts_path=str(entropy_alerts),
		risk_stream_path=str(risk_stream),
		drift_stream_path=str(drift_stream),
		iforest_stream_path=str(iforest_stream),
		stop_event=stop_event,
	)
	# IMPORTANT: only the sandbox is given to the agent for locking.
	# Locking real user folders (Desktop / Documents / Downloads / Pictures)
	# with `icacls /deny Everyone:(W,D,DC) /T` makes them unusable from
	# File Explorer until manually unlocked. The watcher still observes
	# those folders for detection, but defensive responses are confined to
	# the sandbox so a false alarm can never lock a user out of their data.
	decision_agent = DecisionAgent(
		risk_stream_path=str(risk_stream),
		monitored_paths=[sandbox_dir],
		process_names_getter=lambda: set(_seen_process_names),
		stop_event=stop_event,
	)
	evidence_logger = BlockchainEvidenceLogger(
		risk_stream_path=str(risk_stream),
		stop_event=stop_event,
	)

	threads = [
		threading.Thread(
			target=_run_file_pipeline,
			args=(watcher, extractor, entropy_analyzer, database, stop_event),
			daemon=True,
			name="FileWatcherFeatureEntropyThread",
		),
		threading.Thread(
			target=_run_drift_pipeline,
			args=(drift_detector, feature_stream, database, drift_stream, stop_event),
			daemon=True,
			name="DriftDetectorThread",
		),
		threading.Thread(
			target=_run_iforest_pipeline,
			args=(iforest_detector, feature_stream, iforest_stream, stop_event),
			daemon=True,
			name="IsolationForestThread",
		),
		threading.Thread(
			target=_run_db_pruner,
			args=(database, stop_event),
			daemon=True,
			name="DbPrunerThread",
		),
		threading.Thread(
			target=risk_scorer.run,
			daemon=True,
			name="RiskScorerThread",
		),
		threading.Thread(
			target=decision_agent.run,
			daemon=True,
			name="DecisionAgentThread",
		),
		threading.Thread(
			target=evidence_logger.run,
			daemon=True,
			name="EvidenceLoggerThread",
		),
		threading.Thread(
			target=_run_risk_db_sink,
			args=(risk_stream, database, stop_event),
			daemon=True,
			name="RiskDbSinkThread",
		),
		threading.Thread(
			target=_run_dashboard,
			args=(stop_event,),
			daemon=True,
			name="DashboardThread",
		),
	]

	if args.simulate != "none":
		threads.append(
			threading.Thread(
				target=_run_simulator,
				args=(args.simulate, args.sim_count, args.sim_duration, args.sim_delay),
				daemon=True,
				name="RansomwareSimulatorThread",
			)
		)

	logger.info("Starting ransomware early-warning orchestrator")
	for thread in threads:
		thread.start()
		logger.info("Started %s", thread.name)

	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		logger.info("KeyboardInterrupt received, stopping threads...")
		stop_event.set()
	finally:
		watcher.stop()
		extractor.stop_window_timer()
		for thread in threads:
			thread.join(timeout=2)
		database.close()
		logger.info("Orchestrator stopped cleanly")


if __name__ == "__main__":
	main()

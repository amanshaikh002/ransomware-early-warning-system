"""Unified orchestrator for the ransomware early-warning pipeline."""

from __future__ import annotations

import argparse
import json
import logging
import threading
import time
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

	_tail_jsonl(feature_stream, stop_event, _consume, from_end=True)


def _run_iforest_pipeline(
	detector: IsolationForestDetector,
	feature_stream: Path,
	stop_event: threading.Event,
) -> None:
	_ensure_file(feature_stream)
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
				logger.warning("Skipping malformed feature vector line in IF pipeline")
				continue
			detector.detect(vector)


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

	for path in [event_stream, feature_stream, entropy_alerts, risk_stream]:
		_ensure_file(path)

	stop_event = threading.Event()
	database = DatabaseManager(str(project_root / "ransomware_monitor.db"))

	monitored_paths = get_default_monitored_paths()
	watcher = FileWatcher(monitored_paths, stream_file=str(event_stream))
	extractor = FeatureExtractor(window_seconds=10)
	extractor.stream_file = str(feature_stream)

	entropy_analyzer = EntropyAnalyzer(threshold=4.5)
	entropy_analyzer.alerts_file = str(entropy_alerts)
	entropy_analyzer.alerts_path = str(entropy_alerts)

	drift_detector = DriftDetector()
	iforest_detector = IsolationForestDetector()
	risk_scorer = RiskScorer(
		feature_stream_path=str(feature_stream),
		entropy_alerts_path=str(entropy_alerts),
		risk_stream_path=str(risk_stream),
		stop_event=stop_event,
	)
	decision_agent = DecisionAgent(
		risk_stream_path=str(risk_stream),
		sandbox_path=(monitored_paths[0] if monitored_paths else None),
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
			args=(drift_detector, feature_stream, database, stop_event),
			daemon=True,
			name="DriftDetectorThread",
		),
		threading.Thread(
			target=_run_iforest_pipeline,
			args=(iforest_detector, feature_stream, stop_event),
			daemon=True,
			name="IsolationForestThread",
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

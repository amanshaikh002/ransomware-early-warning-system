"""
============================================================================
Module 2 : Feature Extraction Module
Project  : Agentic AI-Based Ransomware Early-Warning System Using
           File Entropy and Behavioral Drift Analysis with
           Blockchain Evidence Logging
============================================================================

Purpose
-------
Convert raw file-system event streams (produced by Module 1 – FileWatcher)
into **behavioral feature vectors** using configurable sliding time windows.

The module supports two operational modes:

  1. **Simulation mode** (``--mode simulation``)
     Generates synthetic normal and ransomware-like events, feeds them
     through the extractor, and prints the resulting feature vectors.

  2. **Real-time mode** (``--mode realtime``)
     Starts the FileWatcher, receives live file-system events via
     ``add_event()``, and continuously computes sliding-window features.

Computed feature categories
---------------------------
1. File activity   – created / modified / deleted / renamed counts
2. Burst behaviour – total events, write-rate (events/sec)
3. File diversity  – unique extensions, unique directories touched
4. Process info    – unique process count, files per process
5. Statistical     – average / max / min file size

Libraries
---------
collections   – Counter, defaultdict for lightweight aggregation
datetime      – ISO-8601 timestamps & window arithmetic
statistics    – mean (with manual fallback for empty data)
os            – path splitting (extension, directory)
argparse      – CLI mode selection
json          – structured output

Author   : <your-name>
Created  : 2026-03-10
============================================================================
"""

import os
import sys
import json
import time
import logging
import argparse
import threading
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
#  Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ===========================================================================
#  FeatureExtractor
# ===========================================================================
class FeatureExtractor:
    """
    Sliding-window feature extractor for file-system event streams.

    Usage – feeding events one at a time
    -------------------------------------
    >>> extractor = FeatureExtractor(window_seconds=10)
    >>> extractor.add_event(event_dict)
    # When the window expires the extractor automatically computes
    # features, prints the vector, and resets for the next window.

    Usage – manual window control
    -----------------------------
    >>> extractor.process_window()   # force-compute current window
    >>> extractor.reset_window()     # discard buffer and start fresh

    Retrieving computed vectors
    ---------------------------
    >>> vectors = extractor.get_feature_vectors()
    """

    def __init__(self, window_seconds: int = 10):
        """
        Parameters
        ----------
        window_seconds : int
            Duration of each sliding window in seconds (default 10).
        """
        self._window_seconds = window_seconds

        # ---- window state ----
        self._window_start: datetime | None = None
        self._events: list[dict] = []

        # ---- persistent storage of all feature vectors ----
        self._feature_vectors: list[dict] = []

        # ---- thread-safety ----
        self._lock = threading.Lock()
        self._running: bool = False
        self._timer_thread: threading.Thread | None = None

        logger.info(
            "FeatureExtractor initialised — window size: %d s",
            self._window_seconds,
        )

    # =================================================================
    #  Public API
    # =================================================================

    def add_event(self, event: dict) -> dict | None:
        """
        Ingest a single event dictionary from the FileWatcher.

        Thread-safe: acquires the internal lock before modifying window state.

        Parameters
        ----------
        event : dict
            Structured event with keys: ``timestamp``, ``event_type``,
            ``file_path``, ``file_size``, ``process_id``, ``process_name``.

        Returns
        -------
        dict or None
            The computed feature vector if the window just closed,
            otherwise ``None``.
        """
        with self._lock:
            event_time = self._parse_timestamp(event["timestamp"])

            # Open the window on the very first event
            if self._window_start is None:
                self._window_start = event_time
                logger.info(
                    "⏱  Window opened at %s", self._window_start.isoformat()
                )

            # Buffer the event in the current window
            self._events.append(event)
            return None  # Timer thread handles window expiry

    # -----------------------------------------------------------------

    def process_window(self) -> dict | None:
        """
        Compute a feature vector from all events in the current window.

        If no events were buffered an empty zero-activity vector is emitted
        so that callers always receive a regular heartbeat output.

        Returns
        -------
        dict
            The feature vector (never ``None`` when a window is open).
        """
        with self._lock:
            return self._process_window_locked()

    def _process_window_locked(self) -> dict | None:
        """Internal: call only while holding self._lock."""
        if self._window_start is None:
            return None

        window_end = self._window_start + timedelta(
            seconds=self._window_seconds
        )

        if self._events:
            feature_vector = self._compute_features(self._window_start, window_end)
        else:
            # Emit a zero-activity vector — window was quiet
            feature_vector = {
                "window_start":              self._window_start.isoformat(),
                "window_end":                window_end.isoformat(),
                "files_created":             0,
                "files_modified":            0,
                "files_deleted":             0,
                "rename_count":              0,
                "total_file_events":         0,
                "write_rate":                0.0,
                "unique_file_types":         0,
                "directories_touched":       0,
                "unique_process_count":      0,
                "files_touched_per_process": 0.0,
                "average_file_size":         0.0,
                "max_file_size":             0,
                "min_file_size":             0,
            }

        self._emit(feature_vector)
        return feature_vector

    # -----------------------------------------------------------------

    def reset_window(self) -> None:
        """
        Discard buffered events and reset the window start marker.
        Thread-safe: call from outside the timer thread.
        """
        with self._lock:
            self._reset_window_locked()

    def _reset_window_locked(self) -> None:
        """Internal: call only while holding self._lock."""
        self._events.clear()
        self._window_start = None
        logger.info("🔄  Window reset — ready for new events.")

    # -----------------------------------------------------------------

    def get_feature_vectors(self) -> list[dict]:
        """Return all feature vectors computed so far (copies)."""
        with self._lock:
            return list(self._feature_vectors)

    def clear_feature_vectors(self) -> None:
        """Clear the stored feature vectors."""
        with self._lock:
            self._feature_vectors.clear()

    # =================================================================
    #  Time-driven window timer (background thread)
    # =================================================================

    def start_window_timer(self) -> None:
        """
        Start a background thread that automatically closes each window
        after ``window_seconds`` regardless of file-system activity.

        This ensures feature vectors are emitted on a fixed schedule
        even during quiet periods with no file events.
        """
        if self._running:
            return
        self._running = True
        # Initialise the window start to now so the first tick is on time
        with self._lock:
            if self._window_start is None:
                self._window_start = datetime.now(timezone.utc)
                logger.info(
                    "⏱  Window opened at %s", self._window_start.isoformat()
                )
        self._timer_thread = threading.Thread(
            target=self._timer_loop,
            name="FeatureExtractorTimer",
            daemon=True,
        )
        self._timer_thread.start()
        logger.info("⏲  Time-driven window timer started (%d s).", self._window_seconds)

    def stop_window_timer(self) -> None:
        """Signal the timer thread to stop and wait for it to exit."""
        self._running = False
        if self._timer_thread and self._timer_thread.is_alive():
            self._timer_thread.join(timeout=5)
        logger.info("⏹  Window timer stopped.")

    def _timer_loop(self) -> None:
        """
        Background loop: wakes every second and checks whether the current
        sliding window has expired.  If so, it processes and resets the
        window, then opens a fresh one anchored to the current time.
        """
        while self._running:
            time.sleep(1)
            with self._lock:
                if not self._running:
                    break
                if self._window_start is None:
                    continue
                now = datetime.now(timezone.utc)
                window_end = self._window_start + timedelta(
                    seconds=self._window_seconds
                )
                if now >= window_end:
                    # ---- Time's up: emit feature vector ----
                    self._process_window_locked()
                    # Reset and open new window anchored to wall-clock time
                    self._events.clear()
                    self._window_start = now
                    logger.info(
                        "⏱  New window opened at %s",
                        self._window_start.isoformat(),
                    )

    # =================================================================
    #  Feature computation (private)
    # =================================================================

    def _compute_features(
        self, window_start: datetime, window_end: datetime
    ) -> dict:
        """
        Aggregate buffered events into a single feature vector.

        Parameters
        ----------
        window_start, window_end : datetime
            Boundaries of the aggregation window.

        Returns
        -------
        dict   The feature vector.
        """
        events = self._events

        # ---- 1. File Activity Features ------------------------------------
        type_counts    = Counter(e["event_type"] for e in events)
        files_created  = type_counts.get("created", 0)
        files_modified = type_counts.get("modified", 0)
        files_deleted  = type_counts.get("deleted", 0)
        rename_count   = type_counts.get("renamed", 0)

        # ---- 2. Burst Behaviour Features ----------------------------------
        total_file_events = len(events)
        window_duration   = (window_end - window_start).total_seconds()
        write_rate = round(
            total_file_events / window_duration
            if window_duration > 0 else 0.0,
            4,
        )

        # ---- 3. File Diversity Features -----------------------------------
        extensions  = set()
        directories = set()
        for e in events:
            fp = e.get("file_path", "")
            _, ext = os.path.splitext(fp)
            if ext:
                extensions.add(ext.lower())
            directories.add(os.path.dirname(fp))

        unique_file_types   = len(extensions)
        directories_touched = len(directories)

        # ---- 4. Process Features ------------------------------------------
        processes: set[str] = set()
        files_per_process: dict[str, set[str]] = defaultdict(set)
        for e in events:
            pname = e.get("process_name", "unknown")
            processes.add(pname)
            files_per_process[pname].add(e.get("file_path", ""))

        unique_process_count = len(processes)
        files_touched_per_process = round(
            sum(len(v) for v in files_per_process.values())
            / unique_process_count
            if unique_process_count > 0
            else 0.0,
            2,
        )

        # ---- 5. Statistical Features (file size) --------------------------
        sizes = [
            e["file_size"]
            for e in events
            if isinstance(e.get("file_size"), (int, float))
            and e["file_size"] >= 0
        ]
        if sizes:
            average_file_size = round(statistics.mean(sizes), 2)
            max_file_size     = max(sizes)
            min_file_size     = min(sizes)
        else:
            average_file_size = 0.0
            max_file_size     = 0
            min_file_size     = 0

        # ---- Assemble feature vector --------------------------------------
        feature_vector = {
            # Window metadata
            "window_start":              window_start.isoformat(),
            "window_end":                window_end.isoformat(),
            # File activity
            "files_created":             files_created,
            "files_modified":            files_modified,
            "files_deleted":             files_deleted,
            "rename_count":              rename_count,
            # Burst behaviour
            "total_file_events":         total_file_events,
            "write_rate":                write_rate,
            # File diversity
            "unique_file_types":         unique_file_types,
            "directories_touched":       directories_touched,
            # Process
            "unique_process_count":      unique_process_count,
            "files_touched_per_process": files_touched_per_process,
            # Statistical
            "average_file_size":         average_file_size,
            "max_file_size":             max_file_size,
            "min_file_size":             min_file_size,
        }

        return feature_vector

    # =================================================================
    #  Helpers (private)
    # =================================================================

    @staticmethod
    def _parse_timestamp(ts: str) -> datetime:
        """Parse an ISO-8601 string into a timezone-aware datetime."""
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _emit(self, feature_vector: dict) -> None:
        """Print the feature vector to console and store it internally."""
        print("\n" + "─" * 60)
        print("📊 FEATURE VECTOR")
        print("─" * 60)
        print(json.dumps(feature_vector, indent=2))
        print("─" * 60 + "\n")
        self._feature_vectors.append(feature_vector)


# ===========================================================================
#  Simulation Mode — synthetic event generator
# ===========================================================================

def _run_simulation(extractor: FeatureExtractor) -> None:
    """
    Generate two batches of synthetic events and feed them through
    the extractor to demonstrate feature computation.

    Batch 1 – Normal user activity
        A few file creates and modifications across different apps.

    Batch 2 – Suspicious ransomware-like burst
        Rapid modify → rename → create-encrypted → delete pattern
        from a single unknown process.
    """
    print("\n" + "=" * 60)
    print("  MODULE 2 — FEATURE EXTRACTOR  (simulation mode)")
    print("=" * 60)

    now = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    #  Batch 1: Normal user activity  (window 1)
    # ------------------------------------------------------------------
    normal_events = [
        {
            "timestamp": (now + timedelta(seconds=0)).isoformat(),
            "event_type": "created",
            "file_path": r"C:\Users\Test\Documents\report.docx",
            "file_size": 15200,
            "process_id": 1234,
            "process_name": "winword.exe",
        },
        {
            "timestamp": (now + timedelta(seconds=1)).isoformat(),
            "event_type": "modified",
            "file_path": r"C:\Users\Test\Documents\report.docx",
            "file_size": 15800,
            "process_id": 1234,
            "process_name": "winword.exe",
        },
        {
            "timestamp": (now + timedelta(seconds=3)).isoformat(),
            "event_type": "created",
            "file_path": r"C:\Users\Test\Downloads\photo.jpg",
            "file_size": 2048000,
            "process_id": 5678,
            "process_name": "chrome.exe",
        },
        {
            "timestamp": (now + timedelta(seconds=5)).isoformat(),
            "event_type": "modified",
            "file_path": r"C:\Users\Test\Desktop\notes.txt",
            "file_size": 340,
            "process_id": 9012,
            "process_name": "notepad.exe",
        },
    ]

    print("\n▶  Feeding Window 1 events (normal activity) …\n")
    for evt in normal_events:
        extractor.add_event(evt)

    # ------------------------------------------------------------------
    #  Batch 2: Suspicious ransomware-like burst  (window 2)
    #  Timestamps jump beyond the window boundary to trigger extraction.
    # ------------------------------------------------------------------
    burst_base = now + timedelta(seconds=12)   # past 10-s window

    suspicious_events = [
        {
            "timestamp": (burst_base + timedelta(milliseconds=0)).isoformat(),
            "event_type": "modified",
            "file_path": r"C:\Users\Test\Documents\thesis.pdf",
            "file_size": 340000,
            "process_id": 9999,
            "process_name": "suspicious.exe",
        },
        {
            "timestamp": (burst_base + timedelta(milliseconds=50)).isoformat(),
            "event_type": "renamed",
            "file_path": r"C:\Users\Test\Documents\thesis.pdf",
            "file_size": 340000,
            "process_id": 9999,
            "process_name": "suspicious.exe",
        },
        {
            "timestamp": (burst_base + timedelta(milliseconds=80)).isoformat(),
            "event_type": "created",
            "file_path": r"C:\Users\Test\Documents\thesis.pdf.locked",
            "file_size": 340256,
            "process_id": 9999,
            "process_name": "suspicious.exe",
        },
        {
            "timestamp": (burst_base + timedelta(milliseconds=120)).isoformat(),
            "event_type": "deleted",
            "file_path": r"C:\Users\Test\Documents\thesis.pdf",
            "file_size": -1,
            "process_id": 9999,
            "process_name": "suspicious.exe",
        },
        {
            "timestamp": (burst_base + timedelta(milliseconds=200)).isoformat(),
            "event_type": "modified",
            "file_path": r"C:\Users\Test\Pictures\vacation.png",
            "file_size": 5120000,
            "process_id": 9999,
            "process_name": "suspicious.exe",
        },
        {
            "timestamp": (burst_base + timedelta(milliseconds=250)).isoformat(),
            "event_type": "renamed",
            "file_path": r"C:\Users\Test\Pictures\vacation.png",
            "file_size": 5120000,
            "process_id": 9999,
            "process_name": "suspicious.exe",
        },
        {
            "timestamp": (burst_base + timedelta(milliseconds=300)).isoformat(),
            "event_type": "created",
            "file_path": r"C:\Users\Test\Pictures\vacation.png.locked",
            "file_size": 5120512,
            "process_id": 9999,
            "process_name": "suspicious.exe",
        },
        {
            "timestamp": (burst_base + timedelta(milliseconds=350)).isoformat(),
            "event_type": "deleted",
            "file_path": r"C:\Users\Test\Pictures\vacation.png",
            "file_size": -1,
            "process_id": 9999,
            "process_name": "suspicious.exe",
        },
    ]

    print("▶  Feeding Window 2 events (suspicious burst) …\n")
    for evt in suspicious_events:
        extractor.add_event(evt)

    # Flush the remaining buffered events to produce Window 2's vector
    print("▶  Flushing remaining events …\n")
    fv = extractor.process_window()
    extractor.reset_window()

    # ------------------------------------------------------------------
    #  Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("  ALL COMPUTED FEATURE VECTORS")
    print("=" * 60)
    for i, fv in enumerate(extractor.get_feature_vectors(), 1):
        print(f"\n--- Vector {i} ---")
        print(json.dumps(fv, indent=2))

    print("\n✅  Simulation complete.\n")


# ===========================================================================
#  Real-Time Mode — integration with FileWatcher
# ===========================================================================

def _run_realtime(extractor: FeatureExtractor) -> None:
    """
    Start the FileWatcher from Module 1 and pipe every event into the
    FeatureExtractor *and* the EntropyAnalyzer.

    For every ``created`` or ``modified`` event the entropy of the file
    is calculated immediately.  If the entropy crosses the threshold a
    HIGH ENTROPY DETECTED alert is printed to the console.
    """
    # Resolve the project root (features/ sits one level below it)
    project_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # ---- Import FileWatcher (Module 1) ----
    try:
        from monitoring.file_watcher import FileWatcher, get_default_monitored_paths
    except ImportError as exc:
        logger.error(
            "Could not import FileWatcher. Make sure Module 1 "
            "(monitoring/file_watcher.py) is in the project root.\n%s",
            exc,
        )
        sys.exit(1)

    # ---- Import EntropyAnalyzer (Module 3) ----
    entropy_analyzer = None
    try:
        from entropy.entropy_analyzer import EntropyAnalyzer
        entropy_analyzer = EntropyAnalyzer(threshold=7.5)
        logger.info("🔬  EntropyAnalyzer loaded — threshold: 7.5 bits/byte")
    except ImportError:
        logger.warning(
            "EntropyAnalyzer not found. Entropy analysis will be skipped."
        )

    # Build the list of directories to watch
    monitored_paths = get_default_monitored_paths()
    if not monitored_paths:
        logger.error("No valid directories to monitor. Exiting.")
        sys.exit(1)

    # Create the watcher and wire events into the extractor
    watcher = FileWatcher(
        watch_directories=monitored_paths,
        recursive=True,
    )

    # Override the internal event handler callback so every event is
    # also fed into the FeatureExtractor and the EntropyAnalyzer.
    original_callback = watcher._handler._event_callback

    def _combined_callback(event_dict: dict) -> None:
        """Forward events to the watcher buffer, the extractor, and entropy."""
        if original_callback:
            original_callback(event_dict)

        # ---- Feature extraction ----
        extractor.add_event(event_dict)

        # ---- Entropy analysis (created / modified only) ----
        if entropy_analyzer and event_dict.get("event_type") in ("created", "modified"):
            file_path = event_dict.get("file_path", "")
            if file_path and os.path.isfile(file_path):
                entropy_result = entropy_analyzer.analyze_file(file_path)
                # Always print the entropy analysis result
                print()
                print("\033[96m" + "─" * 60 + "\033[0m")
                print("\033[96m" + "🔬 ENTROPY ANALYSIS" + "\033[0m")
                print("\033[96m" + "─" * 60 + "\033[0m")
                print(json.dumps(entropy_result, indent=2))
                # Print high-entropy warning if flagged
                if entropy_result.get("entropy_flag"):
                    print()
                    print("\033[91m" + "=" * 60 + "\033[0m")
                    print("\033[91m" + "  ⚠️  HIGH ENTROPY DETECTED" + "\033[0m")
                    print("\033[91m" + f"  Possible ransomware encryption detected!" + "\033[0m")
                    print("\033[91m" + f"  File    : {os.path.basename(file_path)}" + "\033[0m")
                    print("\033[91m" + f"  Entropy : {entropy_result.get('entropy')} bits/byte" + "\033[0m")
                    print("\033[91m" + "=" * 60 + "\033[0m")
                print()

    watcher._handler._event_callback = _combined_callback

    # Start monitoring + time-driven window timer
    watcher.start()
    extractor.start_window_timer()

    print("\n" + "=" * 60)
    print("  MODULE 2 — FEATURE EXTRACTOR  (real-time mode)")
    print("-" * 60)
    print("  Monitoring directories:")
    for d in monitored_paths:
        print(f"    • {d}")
    print("-" * 60)
    print(f"  Window size : {extractor._window_seconds} s  (time-driven)")
    print("  Press Ctrl+C to stop")
    print("=" * 60 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n⏹  Interrupt received. Shutting down …")
        extractor.stop_window_timer()
        fv = extractor.process_window()
        if fv:
            print("📊 Final partial window flushed.")
    finally:
        watcher.stop()

    # Print summary of all vectors collected in this session
    vectors = extractor.get_feature_vectors()
    if vectors:
        print("\n" + "=" * 60)
        print(f"  SESSION SUMMARY — {len(vectors)} feature vector(s)")
        print("=" * 60)
        for i, v in enumerate(vectors, 1):
            print(f"\n--- Vector {i} ---")
            print(json.dumps(v, indent=2))
    print("\n✅  Session ended.\n")


# ===========================================================================
#  CLI entry-point
# ===========================================================================

def main() -> None:
    """
    Parse command-line arguments and launch the selected mode.

    Usage
    -----
    Simulation : ``python feature_extractor.py --mode simulation``
    Real-time  : ``python feature_extractor.py --mode realtime``
    """
    parser = argparse.ArgumentParser(
        description=(
            "Module 2 – Feature Extraction for the Ransomware "
            "Early-Warning System.  Converts raw file-system events "
            "into behavioral feature vectors using sliding time windows."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["simulation", "realtime"],
        default="simulation",
        help="Operating mode: 'simulation' generates synthetic events; "
             "'realtime' connects to the FileWatcher (default: simulation).",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=10,
        help="Sliding-window duration in seconds (default: 10).",
    )

    args = parser.parse_args()

    # Create the extractor with the requested window size
    extractor = FeatureExtractor(window_seconds=args.window)

    if args.mode == "simulation":
        _run_simulation(extractor)
    else:
        _run_realtime(extractor)


if __name__ == "__main__":
    main()

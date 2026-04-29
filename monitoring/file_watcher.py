"""
============================================================================
Module 1 : File System Monitoring Module
Project  : Agentic AI-Based Ransomware Early-Warning System Using
           File Entropy and Behavioral Drift Analysis with
           Blockchain Evidence Logging
============================================================================

Purpose
-------
Monitor **multiple** important Windows user directories in real time and
capture granular file-system events (create, modify, delete, rename).
Ransomware typically targets user-data folders such as Desktop, Documents,
Downloads, and Pictures.  This module watches all of them simultaneously.

For every event the module collects structured metadata that downstream
modules (feature extraction, entropy analysis, drift detection) can consume.

Libraries
---------
watchdog  – cross-platform file-system event notification
psutil    – process-level metadata (PID, process name)
datetime  – ISO-8601 timestamps
os / json – path construction and structured output
pathlib   – robust path parsing for event filtering

Author   : <your-name>
Created  : 2026-03-09
============================================================================
"""

import os
import sys
import time
import json
import logging
import threading
from pathlib import PurePath
from datetime import datetime, timezone

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil

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
#  Event Filtering — suppress noise from system / build / temp files
# ===========================================================================

#: Directory names whose events should be silently ignored.
#: Any path component matching one of these (case-insensitive) triggers
#: the filter.  Add entries here to extend coverage.
IGNORED_DIRECTORIES: set[str] = {
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    "node_modules",
    "AppData",
    "ProgramData",
    "Windows",
    "$Recycle.Bin",
}

#: File extensions (lowercase, with leading dot) to ignore.
IGNORED_EXTENSIONS: set[str] = {
    ".lock",
    ".tmp",
    ".log",
    ".cache",
    ".pyo",
    ".pyc",
}

#: Substring patterns — if any of these appear anywhere in the
#: **filename** (not the full path), the event is filtered out.
IGNORED_FILENAME_PATTERNS: list[str] = [
    "~$",       # Microsoft Office temp files
    ".temp",    # generic temp suffix
    ".swp",     # Vim swap files
]

#: Filenames for internal JSONL streams that must be ignored to prevent
#: recursive self-logging when the watcher and downstream modules share
#: the same directory tree.
IGNORE_FILES: set[str] = {
    "event_stream.jsonl",
    "feature_stream.jsonl",
    "entropy_alerts.jsonl",
}


def should_ignore_event(file_path: str) -> bool:
    """
    Determine whether a file-system event should be silently discarded.

    The check is intentionally fast — it only inspects path components
    and the filename string without touching the filesystem.

    Parameters
    ----------
    file_path : str
        Absolute or relative path reported by watchdog.

    Returns
    -------
    bool
        ``True`` if the event should be ignored.
    """
    path = PurePath(file_path)

    # ---- 1. Check each directory component ----
    for part in path.parts:
        if part in IGNORED_DIRECTORIES:
            logger.debug("Ignored event (directory): %s", file_path)
            return True

    # ---- 2. Check file extension ----
    if path.suffix.lower() in IGNORED_EXTENSIONS:
        logger.debug("Ignored event (extension): %s", file_path)
        return True

    # ---- 3. Check filename substring patterns ----
    name = path.name
    for pattern in IGNORED_FILENAME_PATTERNS:
        if pattern in name:
            logger.debug("Ignored event (pattern '%s'): %s", pattern, file_path)
            return True

    return False


# ===========================================================================
#  Custom Event Handler
# ===========================================================================
class _EventHandler(FileSystemEventHandler):
    """
    Internal handler that translates raw watchdog events into structured
    dictionaries.  Each dictionary is printed to the console **and**
    stored in an internal buffer so that other modules can retrieve the
    events programmatically.
    """

    def __init__(self, event_callback=None):
        """
        Parameters
        ----------
        event_callback : callable, optional
            A function that will be called with the event dictionary every
            time a file-system event is captured.  Useful for piping events
            into a queue or a database without modifying this class.
        """
        super().__init__()
        self._event_callback = event_callback

    # ----- helpers --------------------------------------------------------

    @staticmethod
    def _get_file_size(path: str) -> int:
        """Return file size in bytes, or -1 if the file is inaccessible."""
        try:
            return os.path.getsize(path)
        except OSError:
            return -1

    @staticmethod
    def _get_process_info() -> tuple:
        """
        Return (pid, process_name) of the *current* Python process.

        Note
        ----
        watchdog delivers events asynchronously; reliably attributing
        each event to the *external* process that caused the I/O change
        is non-trivial on most OSes.  For research purposes we log the
        monitoring process itself.  A production system could integrate
        with OS audit logs (e.g., ETW on Windows, fanotify on Linux) for
        accurate process attribution.
        """
        try:
            proc = psutil.Process(os.getpid())
            return proc.pid, proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return os.getpid(), "unknown"

    # ----- core event builder ---------------------------------------------

    def _build_event(self, event, event_type: str) -> dict:
        """
        Construct the canonical event dictionary.

        Parameters
        ----------
        event      : watchdog event object
        event_type : one of "created", "modified", "deleted", "renamed"

        Returns
        -------
        dict   Structured event metadata.
        """
        # Determine the relevant file path
        file_path = event.src_path

        # For rename / move events, include both old and new paths
        dest_path = getattr(event, "dest_path", None)

        pid, pname = self._get_process_info()
        file_size = self._get_file_size(dest_path or file_path)

        event_dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "file_path": os.path.abspath(file_path),
            "file_size": file_size,
            "process_id": pid,
            "process_name": pname,
        }

        # Include destination path for rename events
        if dest_path:
            event_dict["dest_path"] = os.path.abspath(dest_path)

        return event_dict

    def _handle(self, event, event_type: str) -> dict:
        """Process the event: log it, invoke the callback, and return it."""
        # Skip directory-level events – we only care about files
        if event.is_directory:
            return None

        # ---- Ignore internal stream files (prevent recursive logging) ----
        src_path = getattr(event, "src_path", "") or ""
        dest_path = getattr(event, "dest_path", "") or ""
        for name in IGNORE_FILES:
            if name in src_path or (dest_path and name in dest_path):
                return None

        # ---- Apply noise filter ----
        if should_ignore_event(event.src_path):
            return None

        event_dict = self._build_event(event, event_type)

        # ---- Console output (pretty-printed JSON) ----
        logger.info(
            "FILE EVENT ▸ %s\n%s",
            event_type.upper(),
            json.dumps(event_dict, indent=2),
        )

        # ---- Optional callback for downstream modules ----
        if self._event_callback:
            self._event_callback(event_dict)

        return event_dict

    # ----- watchdog overrides ---------------------------------------------

    def on_created(self, event):
        """Triggered when a file is created in the monitored directory."""
        return self._handle(event, "created")

    def on_modified(self, event):
        """Triggered when a file is modified in the monitored directory."""
        return self._handle(event, "modified")

    def on_deleted(self, event):
        """Triggered when a file is deleted from the monitored directory."""
        return self._handle(event, "deleted")

    def on_moved(self, event):
        """Triggered when a file is renamed/moved in the monitored directory."""
        return self._handle(event, "renamed")


# ===========================================================================
    #  FileWatcher – public API
# ===========================================================================
class FileWatcher:
    """
    High-level wrapper around watchdog's Observer that can monitor
    **one or more** directories simultaneously.

    Usage — single directory
    ------------------------
    >>> watcher = FileWatcher(["./test_folder"])
    >>> watcher.start()          # non-blocking
    >>> watcher.stop()

    Usage — multiple directories (ransomware-target paths)
    ------------------------------------------------------
    >>> paths = get_default_monitored_paths()
    >>> watcher = FileWatcher(paths)
    >>> watcher.run()            # blocks until Ctrl+C

    Retrieving captured events:
    >>> events = watcher.get_events()
    """

    def __init__(
        self,
        watch_directories: list[str],
        recursive: bool = True,
        stream_file: str | None = None,
    ):
        """
        Parameters
        ----------
        watch_directories : list[str]
            One or more directory paths to monitor.
        recursive : bool, optional
            Whether to monitor subdirectories as well (default True).
        """
        # Resolve every path to its absolute form
        self._watch_dirs: list[str] = [
            os.path.abspath(d) for d in watch_directories
        ]
        self._recursive = recursive

        # Thread-safe state
        self._lock = threading.Lock()
        self._events: list[dict] = []          # in-memory event buffer
        self._callbacks: list[callable] = []   # subscriber callbacks

        # Optional JSONL stream file for cross-process consumers
        self._stream_file: str | None = stream_file
        if self._stream_file:
            try:
                # Start a fresh stream each time the watcher is launched
                open(self._stream_file, "w", encoding="utf-8").close()
                logger.info("📝  Event stream initialised at: %s", self._stream_file)
            except OSError as exc:
                logger.warning("Could not initialise event stream file %s: %s", self._stream_file, exc)
                self._stream_file = None

        self._handler = _EventHandler(
            event_callback=self._handle_event,
        )
        self._observer = Observer()

    # ----- internal -------------------------------------------------------

    def _handle_event(self, event_dict: dict | None) -> None:
        """
        Central event sink called by the internal handler.

        Responsibilities:
        - Append event to in-memory buffer
        - Fan out to registered callbacks (subscribers)
        - Append to JSONL stream file (if configured)
        """
        if not event_dict:
            return

        # Snapshot callbacks under lock so subscribers can mutate
        # their own state without blocking the watcher thread.
        with self._lock:
            self._events.append(event_dict)
            callbacks = list(self._callbacks)
            stream_file = self._stream_file

        # ---- Fan-out to in-process subscribers ----
        for cb in callbacks:
            try:
                cb(event_dict)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Error in event callback %r: %s", cb, exc)

        # ---- Append to JSONL stream for out-of-process consumers ----
        if stream_file:
            try:
                with open(stream_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event_dict) + "\n")
            except OSError as exc:
                logger.error("Failed to write event to %s: %s", stream_file, exc)

    # ----- public API -----------------------------------------------------

    def start(self) -> None:
        """
        Schedule all watched directories on the observer and start
        monitoring in a background thread (non-blocking).
        """
        for watch_dir in self._watch_dirs:
            # Create the directory if it doesn't exist yet
            if not os.path.isdir(watch_dir):
                os.makedirs(watch_dir, exist_ok=True)
                logger.info("Created watch directory: %s", watch_dir)

            # Register each directory with the same handler
            self._observer.schedule(
                self._handler,
                watch_dir,
                recursive=self._recursive,
            )
            logger.info(
                "🔍  Scheduled monitoring: %s (recursive=%s)",
                watch_dir,
                self._recursive,
            )

        self._observer.start()
        logger.info(
            "✅  FileWatcher started — watching %d director%s.",
            len(self._watch_dirs),
            "y" if len(self._watch_dirs) == 1 else "ies",
        )

    def stop(self) -> None:
        """
        Gracefully stop the observer thread.
        """
        self._observer.stop()
        self._observer.join()
        logger.info("🛑  FileWatcher stopped.")

    def add_event_callback(self, callback) -> None:
        """
        Register a callback to receive every filesystem event dictionary.

        The callback should accept a single ``event: dict`` argument.
        """
        with self._lock:
            self._callbacks.append(callback)

    def remove_event_callback(self, callback) -> None:
        """Unregister a previously registered event callback."""
        with self._lock:
            self._callbacks = [cb for cb in self._callbacks if cb is not callback]

    def run(self) -> None:
        """
        Convenience method: start monitoring and block until the user
        presses Ctrl+C.
        """
        self.start()

        # ---- Print a clear startup banner ----
        print("\n" + "=" * 60)
        print("  FILE SYSTEM MONITORING MODULE — ACTIVE")
        print("-" * 60)
        print("  Monitoring started on:")
        for d in self._watch_dirs:
            print(f"    • {d}")
        print("-" * 60)
        print("  Press Ctrl+C to stop")
        print("=" * 60 + "\n")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n⏹  Interrupt received. Shutting down …")
        finally:
            self.stop()

    def get_events(self) -> list[dict]:
        """
        Return all captured events so far.

        Returns
        -------
        list[dict]
            A list of event dictionaries captured since the watcher started.
        """
        with self._lock:
            return list(self._events)

    def clear_events(self) -> None:
        """Clear the internal event buffer."""
        with self._lock:
            self._events.clear()


# ===========================================================================
#  Default monitored paths — common ransomware targets
# ===========================================================================

#: Dedicated sandbox directory used by the ransomware simulator.
#: All monitored activity is confined to this path so internal project
#: files (including JSONL streams) are not observed.

WATCH_DIRECTORY: str = os.path.join(os.path.expanduser("~"), "Documents", "ransomware_test")



def get_default_monitored_paths() -> list[str]:
    """
    Return the default directory to monitor.

    For this project we restrict monitoring to the ransomware simulator
    sandbox directory so that project files (including the event and
    feature streams) are never observed.

    Returns
    -------
    list[str]
        A single-item list containing :data:`WATCH_DIRECTORY`.
    """
    return [WATCH_DIRECTORY]


# ===========================================================================
#  CLI entry-point
# ===========================================================================
if __name__ == "__main__":
    # If a CLI argument is given, monitor that single directory;
    # otherwise default to the important Windows user folders.
    if len(sys.argv) > 1:
        monitored_paths = [sys.argv[1]]
    else:
        monitored_paths = get_default_monitored_paths()

    if not monitored_paths:
        logger.error("No valid directories to monitor. Exiting.")
        sys.exit(1)

    # In standalone CLI mode we also enable the JSONL event stream so that
    # other agents (FeatureExtractor, EntropyAnalyzer) can subscribe via
    # ``event_stream.jsonl`` without a direct in-process callback.
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    event_stream_path = os.path.join(project_root, "event_stream.jsonl")

    watcher = FileWatcher(monitored_paths, stream_file=event_stream_path)
    watcher.run()

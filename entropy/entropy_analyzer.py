"""
============================================================================
Module 3 : Entropy Analysis Module
Project  : Agentic AI-Based Ransomware Early-Warning System Using
           File Entropy and Behavioral Drift Analysis with
           Blockchain Evidence Logging
============================================================================

Purpose
-------
Detect encryption-like behaviour in files by computing **Shannon entropy**.

Ransomware encrypts user files, which causes their byte distributions to
become nearly uniform — pushing entropy close to the theoretical maximum
of 8.0 bits per byte.  This module reads file contents, calculates
entropy, and flags files whose entropy exceeds a configurable threshold.

Shannon Entropy Formula
-----------------------
    H(X) = − Σ  p(x) · log₂ p(x)

where p(x) is the probability of each byte value (0–255).

* Plain text files   → low entropy  (~3.0 – 5.0)
* Compressed files   → high entropy (~7.0 – 7.8)
* Encrypted files    → very high    (~7.9 – 8.0)

Libraries
---------
os          – file existence and size checks
math        – log2 for entropy calculation
collections – Counter for byte-frequency counting
json        – structured output

Author   : <your-name>
Created  : 2026-03-10
============================================================================
"""

import os
import math
import json
import time
import logging
import argparse
from collections import Counter
from datetime import datetime, timezone

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
#  EntropyAnalyzer
# ===========================================================================
class EntropyAnalyzer:
    """
    Compute Shannon entropy for files and flag potential encryption.

    Usage
    -----
    >>> analyzer = EntropyAnalyzer(threshold=7.5)
    >>> result = analyzer.analyze_file("document.docx")
    >>> print(result)
    {'file_path': 'document.docx', 'entropy': 4.12, 'entropy_flag': False, ...}

    Parameters
    ----------
    threshold : float
        Entropy value above which a file is flagged as potentially
        encrypted (default 7.5).
    chunk_size : int
        Number of bytes to read per I/O operation when processing
        large files (default 1 MB).
    """

    # Default entropy threshold — files above this are flagged.
    # 7.2 targets genuinely AES/ChaCha20-encrypted content (7.9-8.0 bits/byte)
    # while avoiding false positives from JPEG/MP3/zip files (7.0-7.8).
    DEFAULT_THRESHOLD: float = 7.2

    # Default read chunk size (1 MB) for safe large-file handling
    DEFAULT_CHUNK_SIZE: int = 1_048_576  # 1 MB

    # File extensions that are *naturally* high-entropy (compressed media,
    # archives, modern Office) — entropy alone cannot distinguish them
    # from ciphertext. Skip them unless they also carry a ransomware
    # marker extension (see SUSPICIOUS_SUFFIXES).
    NATURALLY_HIGH_ENTROPY_EXTENSIONS: set[str] = {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".bmp",
        ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4a", ".flac",
        ".zip", ".gz", ".7z", ".rar", ".tar", ".bz2", ".xz", ".lz4",
        ".iso", ".dmg",
        ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
        ".pdf",
    }

    # Suffixes ransomware commonly appends after encryption. A file with
    # any of these is ALWAYS analyzed regardless of the underlying
    # extension — `.png.locked` should be flagged even though `.png`
    # alone would be skipped.
    SUSPICIOUS_SUFFIXES: set[str] = {
        ".locked", ".crypto", ".crypted", ".enc", ".encrypted",
        ".aes", ".cipher", ".cryp", ".pay", ".ransom",
    }

    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        """
        Parameters
        ----------
        threshold : float
            Entropy ceiling; files with H > threshold are flagged.
        chunk_size : int
            Bytes to read per I/O pass.
        """
        self._threshold = threshold
        self._chunk_size = chunk_size

        # Internal log of all analysis results
        self._results: list[dict] = []

        # Optional alerts stream file; when set, high-entropy alerts
        # (and notable errors) are appended as JSONL records so that
        # other modules can consume them asynchronously.
        self.alerts_file: str | None = None

        logger.info(
            "EntropyAnalyzer initialised — threshold: %.2f, "
            "chunk_size: %d bytes",
            self._threshold,
            self._chunk_size,
        )

    # =================================================================
    #  Public API
    # =================================================================

    def compute_entropy(self, file_path: str) -> float:
        """
        Calculate Shannon entropy of a file's byte stream.

        The file is read in chunks of ``self._chunk_size`` to handle
        large files without excessive memory usage.

        Parameters
        ----------
        file_path : str
            Path to the file to analyse.

        Returns
        -------
        float
            Shannon entropy in bits (0.0 – 8.0).

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        PermissionError
            If the file cannot be read.
        """
        file_path = os.path.abspath(file_path)

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # ---- Step 1: Count byte frequencies (0–255) ----
        byte_counts: Counter = Counter()
        total_bytes: int = 0

        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(self._chunk_size)
                if not chunk:
                    break
                byte_counts.update(chunk)
                total_bytes += len(chunk)

        # Empty file → zero entropy
        if total_bytes == 0:
            return 0.0

        # ---- Step 2: Compute probability and Shannon entropy ----
        entropy: float = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    # -----------------------------------------------------------------

    def analyze_file(self, file_path: str) -> dict:
        """
        Analyse a single file: compute entropy and flag if suspicious.

        Parameters
        ----------
        file_path : str
            Path to the file.

        Returns
        -------
        dict
            Structured result with keys:
            ``file_path``, ``file_size``, ``entropy``,
            ``entropy_flag``, ``threshold``, ``timestamp``.
            On error the dict includes an ``error`` key instead.
        """
        file_path = os.path.abspath(file_path)
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            # If the original path no longer exists (common in fast
            # ransomware simulations where files are rapidly renamed to
            # ``.locked``), transparently fall back to analysing the
            # corresponding ``.locked`` file when present.
            if not os.path.isfile(file_path):
                locked_candidate = file_path + ".locked"
                if os.path.isfile(locked_candidate):
                    file_path = locked_candidate

            # Skip naturally-high-entropy file types unless they carry a
            # ransomware marker suffix. Real PNG/MP3/ZIP files routinely
            # exceed any reasonable entropy threshold, so analyzing them
            # produces constant false positives. .png.locked etc. still
            # fall through to full analysis because the suspicious suffix
            # check below takes priority.
            lower_path = file_path.lower()
            has_suspicious_suffix = any(
                lower_path.endswith(suf) for suf in self.SUSPICIOUS_SUFFIXES
            )
            base_ext = os.path.splitext(lower_path)[1]
            if (
                not has_suspicious_suffix
                and base_ext in self.NATURALLY_HIGH_ENTROPY_EXTENSIONS
            ):
                logger.debug(
                    "Skipping entropy analysis for naturally high-entropy file: %s",
                    file_path,
                )
                result = {
                    "file_path": file_path,
                    "entropy": None,
                    "entropy_flag": False,
                    "threshold": self._threshold,
                    "timestamp": timestamp,
                    "skipped_reason": "naturally_high_entropy_extension",
                }
                self._results.append(result)
                return result

            entropy = self.compute_entropy(file_path)
            file_size = os.path.getsize(file_path)
            flagged = entropy > self._threshold

            result = {
                "file_path": file_path,
                "file_size": file_size,
                "entropy": entropy,
                "entropy_flag": flagged,
                "threshold": self._threshold,
                "timestamp": timestamp,
            }

        except FileNotFoundError:
            logger.warning("File not found: %s", file_path)
            result = {
                "file_path": file_path,
                "entropy": None,
                "entropy_flag": False,
                "error": "file_not_found",
                "timestamp": timestamp,
            }

        except PermissionError:
            logger.warning("Permission denied: %s", file_path)
            result = {
                "file_path": file_path,
                "entropy": None,
                "entropy_flag": False,
                "error": "permission_denied",
                "timestamp": timestamp,
            }

        except OSError as exc:
            logger.warning("OS error reading %s: %s", file_path, exc)
            result = {
                "file_path": file_path,
                "entropy": None,
                "entropy_flag": False,
                "error": str(exc),
                "timestamp": timestamp,
            }

        # Store and return the result
        self._results.append(result)
        return result

    # -----------------------------------------------------------------

    def analyze_event(self, event: dict) -> dict | None:
        """
        Analyse a file referenced by a FileWatcher event dictionary.

        Only ``modified`` and ``created`` events are analysed because
        those are the operations ransomware performs when encrypting.

        Parameters
        ----------
        event : dict
            A structured event from Module 1 (FileWatcher).

        Returns
        -------
        dict or None
            The entropy analysis result, or ``None`` if the event type
            is not relevant (e.g., ``deleted``).
        """
        event_type = event.get("event_type", "")
        if event_type not in ("modified", "created"):
            return None

        file_path = event.get("file_path", "")
        if not file_path:
            return None

        return self.analyze_file(file_path)

    # -----------------------------------------------------------------

    def handle_event(self, event: dict) -> dict | None:
        """
        Entry point for FileWatcher-style event dictionaries.

        Reacts only to ``modified`` and ``renamed`` events. For
        renames the destination path (``dest_path``) is preferred as
        this typically carries the encrypted ``.locked`` filename.

        When an entropy computation is performed the module optionally
        writes a compact alert record to ``entropy_alerts.jsonl``.
        """
        event_type = event.get("event_type", "")
        if event_type not in ("modified", "renamed"):
            return None

        if event_type == "renamed":
            file_path = event.get("dest_path") or event.get("file_path", "")
        else:
            file_path = event.get("file_path", "")

        if not file_path:
            return None

        result = self.analyze_file(file_path)

        alert_record = {
            "timestamp": result.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "file_path": result.get("file_path", file_path),
            "entropy": result.get("entropy"),
            "alert": "HIGH_ENTROPY" if result.get("entropy_flag") else "NORMAL",
        }
        if result.get("error"):
            alert_record["error"] = result["error"]

        if self.alerts_file:
            try:
                with open(self.alerts_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(alert_record) + "\n")
            except OSError as exc:
                logger.error("Failed to write entropy alert to %s: %s", self.alerts_file, exc)

        # Optional console output so that alerts are visible in realtime.
        # To avoid excessive noise, we print a banner only for high-entropy
        # files and keep normal-entropy events silent.
        if result.get("entropy_flag") and result.get("entropy") is not None:
            print()
            print("─" * 60)
            label = "ENCRYPTED" if str(result["file_path"]).lower().endswith(".locked") else "FILE"
            print(f"  {label}: {os.path.basename(result['file_path'])}")
            print(f"  Path      : {result['file_path']}")
            print(f"  Entropy   : {result['entropy']} bits/byte")
            print(f"  Threshold : {self._threshold} bits/byte")
            print("─" * 60)
            print("\033[91m" + "  ⚠ HIGH ENTROPY DETECTED — possible encryption" + "\033[0m")
            print("─" * 60)

        return result

    # -----------------------------------------------------------------

    def get_results(self) -> list[dict]:
        """Return all analysis results collected so far (copies)."""
        return list(self._results)

    def clear_results(self) -> None:
        """Clear the stored results."""
        self._results.clear()


# ===========================================================================
#  Real-Time Monitoring (event-stream subscriber)
# ===========================================================================

# Folder names under the user home directory to monitor (same targets as
# Module 1 so results are comparable — but watchdog is imported here
# independently, keeping this module fully self-contained).
_MONITOR_FOLDERS: list[str] = ["Desktop", "Documents", "Downloads", "Pictures"]


def _get_monitored_paths() -> list[str]:
    """Return existing paths under the current user's home directory."""
    home = os.path.expanduser("~")
    return [
        os.path.join(home, folder)
        for folder in _MONITOR_FOLDERS
        if os.path.isdir(os.path.join(home, folder))
    ]


class _EntropyEventHandler:
    """
    Watchdog-compatible event handler that automatically runs entropy
    analysis on every file-system change event.

    Improvements over v1
    --------------------
    - Handles ``moved`` (renamed) events — analyses ``dest_path``.
    - Prioritises ``.locked`` files for immediate analysis.
    - Adds a 0.15 s stabilization delay so ransomware can finish writing.
    - Retries up to 3 times (0.2 s apart) if the file is momentarily absent.
    """

    #: Seconds to wait after a file event before reading the file.
    #: Allows the writing process to flush and close the file handle.
    STABILIZATION_DELAY: float = 0.15

    #: Number of retry attempts when a file is not found after an event.
    MAX_RETRIES: int = 3

    #: Seconds to wait between retry attempts.
    RETRY_DELAY: float = 0.2

    def __init__(self, analyzer: "EntropyAnalyzer"):
        self._analyzer = analyzer

    # ------------------------------------------------------------------
    #  watchdog event dispatch
    # ------------------------------------------------------------------

    def dispatch(self, event) -> None:
        """Route watchdog events to the correct handler."""
        if event.is_directory:
            return

        event_type = event.event_type      # 'created', 'modified', 'moved'

        if event_type == "moved":
            # For rename/move events analyse the DESTINATION (the .locked file)
            dest = getattr(event, "dest_path", None)
            if dest:
                self._analyse(dest, "renamed")
            return

        if event_type in ("created", "modified"):
            src = event.src_path
            # Prioritise .locked files — they are the encrypted payload
            if src.lower().endswith(".locked"):
                self._analyse(src, event_type, priority=True)
            else:
                self._analyse(src, event_type)

    # ------------------------------------------------------------------
    #  Core analysis with retry + stabilization
    # ------------------------------------------------------------------

    def _analyse(self, file_path: str, event_type: str, priority: bool = False) -> None:
        """
        Compute entropy for *file_path* and print the result.

        Parameters
        ----------
        file_path : str
            Absolute path to the file to analyse.
        event_type : str
            Human-readable label used in console output.
        priority : bool
            When True (e.g. .locked files) the stabilization delay is
            slightly longer to ensure the write is fully flushed.
        """
        # ---- Step 1: Stabilization delay ----
        # Give the writing process time to finish closing the file.
        delay = self.STABILIZATION_DELAY * (2.0 if priority else 1.0)
        time.sleep(delay)

        # ---- Step 2: Retry loop ----
        # Rapid rename/delete means the file may not exist immediately.
        resolved_path = file_path
        found = False
        for attempt in range(1, self.MAX_RETRIES + 1):
            if os.path.isfile(resolved_path):
                found = True
                break
            if attempt < self.MAX_RETRIES:
                time.sleep(self.RETRY_DELAY)

        if not found:
            logger.debug(
                "Skipping %s — file not found after %d retries.",
                os.path.basename(resolved_path),
                self.MAX_RETRIES,
            )
            return

        # ---- Step 3: Run entropy analysis ----
        print()
        print("─" * 60)
        label = "ENCRYPTED" if resolved_path.lower().endswith(".locked") else event_type.upper()
        print(f"  FILE {label}: {os.path.basename(resolved_path)}")
        print(f"  Path: {resolved_path}")
        print("─" * 60)

        result = self._analyzer.analyze_file(resolved_path)

        print("\n\U0001f52c ENTROPY RESULT")
        print(json.dumps(result, indent=2))

        if result.get("entropy_flag"):
            print()
            print("\033[91m" + "=" * 60 + "\033[0m")
            print("\033[91m  ⚠️  HIGH ENTROPY DETECTED\033[0m")
            print("\033[91m  Possible ransomware encryption activity!\033[0m")
            print(f"\033[91m  File    : {os.path.basename(resolved_path)}\033[0m")
            print(f"\033[91m  Entropy : {result.get('entropy')} bits/byte\033[0m")
            print("\033[91m" + "=" * 60 + "\033[0m")
        elif result.get("error"):
            logger.debug("Could not analyse %s: %s", os.path.basename(resolved_path), result["error"])
        else:
            print(f"\n\u2705  Normal entropy ({result.get('entropy')} bits/byte)")
        print()


def _run_realtime_entropy(analyzer: "EntropyAnalyzer") -> None:
    """
    Subscribe to the central FileWatcher event stream and run entropy
    analysis on every relevant file event.

    Expected runtime topology:

        Terminal 1: python monitoring/file_watcher.py
        Terminal 3: python entropy/entropy_analyzer.py --mode realtime

    FileWatcher appends events to ``event_stream.jsonl`` and this
    module tails that file, writing alerts to ``entropy_alerts.jsonl``.
    """
    # Resolve project root (entropy/ sits one level below it)
    project_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )

    event_stream_path = os.path.join(project_root, "event_stream.jsonl")
    alerts_path = os.path.join(project_root, "entropy_alerts.jsonl")

    # Ensure the event stream exists so open() does not fail even if
    # the watcher has not started yet.
    try:
        open(event_stream_path, "a", encoding="utf-8").close()
    except OSError as exc:
        logger.error("Could not access event stream file %s: %s", event_stream_path, exc)
        import sys
        sys.exit(1)

    # Truncate / initialise the alerts file for the new session
    try:
        open(alerts_path, "w", encoding="utf-8").close()
        logger.info("🧾  Entropy alerts stream initialised at: %s", alerts_path)
    except OSError as exc:
        logger.warning("Could not initialise entropy alerts file: %s", exc)

    analyzer.alerts_file = alerts_path

    print("\n" + "=" * 60)
    print("  ENTROPY MONITOR STARTED (event-stream mode)")
    print("-" * 60)
    print("  Event source   : event_stream.jsonl")
    print(f"  Alerts output  : {os.path.basename(alerts_path)}")
    print(f"  Entropy thresh.: {analyzer._threshold} bits/byte")
    print("  Press Ctrl+C to stop")
    print("=" * 60 + "\n")

    buffer = ""
    try:
        with open(event_stream_path, "r", encoding="utf-8") as f:
            # Tail new events only
            f.seek(0, 2)
            while True:
                chunk = f.readline()
                if not chunk:
                    time.sleep(1)
                    continue

                buffer += chunk
                if not buffer.endswith("\n"):
                    continue

                line = buffer.strip()
                buffer = ""
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    logger.error("Failed to parse event line: %s", line)
                    continue

                analyzer.handle_event(event)
    except KeyboardInterrupt:
        print("\n⏹  Interrupt received. Stopping entropy monitor …")
    finally:
        logger.info("🛑  Entropy monitor stopped.")


# ===========================================================================
#  CLI entry-point
# ===========================================================================
if __name__ == "__main__":
    import sys

    parser = argparse.ArgumentParser(
        description=(
            "Module 3 – Entropy Analyzer.\n"
            "Runs either as a standalone real-time entropy monitor or as "
            "a one-shot demo / single-file analyser."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["realtime", "demo"],
        default=None,
        help=(
            "'realtime' – watch Desktop/Documents/Downloads/Pictures and "
            "compute entropy on every file change (default when no file is given). "
            "'demo'     – run the built-in test with synthetic files."
        ),
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=EntropyAnalyzer.DEFAULT_THRESHOLD,
        help=f"Entropy flag threshold in bits/byte (default: {EntropyAnalyzer.DEFAULT_THRESHOLD}).",
    )
    parser.add_argument(
        "file",
        nargs="?",
        default=None,
        help="Optional: path to a specific file to analyse (overrides --mode).",
    )

    args = parser.parse_args()
    analyzer = EntropyAnalyzer(threshold=args.threshold)

    # ---- Priority 1: analyse a specific file ----
    if args.file:
        print(f"\n▶  Analysing file: {args.file}\n")
        result = analyzer.analyze_file(args.file)
        print("📊 Entropy Result")
        print(json.dumps(result, indent=2))
        if result.get("entropy_flag"):
            print("\n⚠️  HIGH ENTROPY — possible encryption detected!")
        else:
            print("\n✅  Entropy within normal range.")
        sys.exit(0)

    # ---- Priority 2: realtime mode ----
    if args.mode == "realtime" or args.mode is None:
        _run_realtime_entropy(analyzer)
        sys.exit(0)

    # ---- Priority 3: demo mode ----
    import tempfile

    print("\n" + "=" * 60)
    print("  MODULE 3 — ENTROPY ANALYZER  (demo mode)")
    print("=" * 60 + "\n")

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w", encoding="utf-8") as tmp:
        tmp.write("Hello world! " * 200)
        plain_path = tmp.name

    with tempfile.NamedTemporaryFile(suffix=".locked", delete=False) as tmp:
        tmp.write(os.urandom(4096))
        encrypted_path = tmp.name

    with tempfile.NamedTemporaryFile(suffix=".empty", delete=False) as tmp:
        empty_path = tmp.name

    demo_files = [
        ("Plain text (low entropy)",           plain_path),
        ("Simulated encrypted (high entropy)",  encrypted_path),
        ("Empty file",                          empty_path),
    ]

    for label, path in demo_files:
        print(f"── {label} ──")
        result = analyzer.analyze_file(path)
        print("📊 Entropy Result")
        print(json.dumps(result, indent=2))
        print("⚠️  HIGH ENTROPY — possible encryption detected!" if result.get("entropy_flag") else "✅  Entropy within normal range.")
        print()

    for _, path in demo_files:
        try:
            os.remove(path)
        except OSError:
            pass

    print("=" * 60)
    print("  ALL RESULTS")
    print("=" * 60)
    for i, r in enumerate(analyzer.get_results(), 1):
        print(f"\n--- Result {i} ---")
        print(json.dumps(r, indent=2))

    print("\n✅  Demo complete.\n")


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
import logging
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

    # Default entropy threshold — files above this are flagged
    DEFAULT_THRESHOLD: float = 7.5

    # Default read chunk size (1 MB) for safe large-file handling
    DEFAULT_CHUNK_SIZE: int = 1_048_576  # 1 MB

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

    def get_results(self) -> list[dict]:
        """Return all analysis results collected so far (copies)."""
        return list(self._results)

    def clear_results(self) -> None:
        """Clear the stored results."""
        self._results.clear()


# ===========================================================================
#  CLI entry-point — testing mode
# ===========================================================================
if __name__ == "__main__":
    import sys
    import tempfile

    print("\n" + "=" * 60)
    print("  MODULE 3 — ENTROPY ANALYZER  (test mode)")
    print("=" * 60 + "\n")

    analyzer = EntropyAnalyzer(threshold=7.5)

    # ------------------------------------------------------------------
    #  If the user passes a file path as argument, analyse that file
    # ------------------------------------------------------------------
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"▶  Analysing user-supplied file: {target}\n")
        result = analyzer.analyze_file(target)
        print("📊 Entropy Result")
        print(json.dumps(result, indent=2))
        sys.exit(0)

    # ------------------------------------------------------------------
    #  Otherwise run built-in demo with synthetic files
    # ------------------------------------------------------------------
    print("▶  No file path provided — running built-in demo.\n")

    # ---- Demo file 1: Plain text (low entropy) ----
    with tempfile.NamedTemporaryFile(
        suffix=".txt", delete=False, mode="w", encoding="utf-8"
    ) as tmp:
        tmp.write("Hello world! " * 200)
        plain_path = tmp.name

    # ---- Demo file 2: Simulated encrypted data (high entropy) ----
    with tempfile.NamedTemporaryFile(
        suffix=".locked", delete=False
    ) as tmp:
        # os.urandom produces near-maximum entropy bytes
        tmp.write(os.urandom(4096))
        encrypted_path = tmp.name

    # ---- Demo file 3: Empty file ----
    with tempfile.NamedTemporaryFile(
        suffix=".empty", delete=False
    ) as tmp:
        empty_path = tmp.name

    demo_files = [
        ("Plain text (low entropy)",      plain_path),
        ("Simulated encrypted (high entropy)", encrypted_path),
        ("Empty file",                     empty_path),
    ]

    for label, path in demo_files:
        print(f"── {label} ──")
        result = analyzer.analyze_file(path)
        print("📊 Entropy Result")
        print(json.dumps(result, indent=2))

        if result.get("entropy_flag"):
            print("⚠️  HIGH ENTROPY — possible encryption detected!")
        else:
            print("✅  Entropy within normal range.")
        print()

    # Clean up temp files
    for _, path in demo_files:
        try:
            os.remove(path)
        except OSError:
            pass

    # ---- Summary ----
    print("=" * 60)
    print("  ALL RESULTS")
    print("=" * 60)
    for i, r in enumerate(analyzer.get_results(), 1):
        print(f"\n--- Result {i} ---")
        print(json.dumps(r, indent=2))

    print("\n✅  Demo complete.\n")

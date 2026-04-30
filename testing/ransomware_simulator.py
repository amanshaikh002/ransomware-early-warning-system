"""
============================================================================
Testing Module : Ransomware Behaviour Simulator
Project        : Agentic AI-Based Ransomware Early-Warning System Using
                 File Entropy and Behavioral Drift Analysis with
                 Blockchain Evidence Logging
============================================================================

Purpose
-------
Generate **controlled file-system activity** inside a monitored directory
so that the full detection pipeline can be exercised end-to-end:

    Simulator  →  FileWatcher  →  FeatureExtractor  →  EntropyAnalyzer

Three operational modes are supported:

    --mode normal      Slow, low-volume activity (baseline behaviour)
    --mode bulk        High-volume creates and edits (no renames)
    --mode ransomware  Simulated encryption: base64-encode → rename
                       to .locked → delete original



Libraries
---------
os, time, random, string, base64, shutil, argparse, json, logging

Author   : <your-name>
Created  : 2026-03-10
============================================================================
"""

import os
import sys
import time
import json
import random
import string
import shutil
import logging
import argparse
import threading
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

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

#: Sandbox directory — all simulated activity stays here.
#: Must match the FileWatcher's monitored path (see monitoring/file_watcher.py:493).
SANDBOX_DIR: str = os.path.join(
    os.path.expanduser("~"), "Documents", "ransomware_test"
)

#: File extensions used to create realistic test files.
SAMPLE_EXTENSIONS: list[str] = [
    ".txt", ".docx", ".pdf", ".xlsx", ".jpg", ".png", ".csv",
]


# ===========================================================================
#  Helpers
# ===========================================================================

def _ensure_sandbox() -> str:
    """Create the sandbox directory if it does not exist and return its path."""
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    logger.info("📁  Sandbox directory: %s", SANDBOX_DIR)
    return SANDBOX_DIR


def _random_filename(ext: str | None = None) -> str:
    """Generate a random filename like ``doc_a7f3b2.txt``."""
    slug = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    if ext is None:
        ext = random.choice(SAMPLE_EXTENSIONS)
    return f"doc_{slug}{ext}"


def _random_content(min_bytes: int = 200, max_bytes: int = 5000) -> str:
    """Generate random readable text content."""
    length = random.randint(min_bytes, max_bytes)
    words = [
        "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 10)))
        for _ in range(length // 6)
    ]
    return " ".join(words) + "\n"


def _create_file(directory: str, filename: str | None = None) -> str:
    """Create a file with random content and return its path."""
    if filename is None:
        filename = _random_filename()
    filepath = os.path.join(directory, filename)
    content = _random_content()
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(content)
    logger.info("✏️  Created: %s  (%d bytes)", filename, len(content))
    return filepath


def _modify_file(filepath: str) -> None:
    """Append random content to an existing file."""
    extra = _random_content(50, 500)
    with open(filepath, "a", encoding="utf-8") as fh:
        fh.write(extra)
    logger.info("📝  Modified: %s  (+%d bytes)", os.path.basename(filepath), len(extra))


def _encrypt_file(filepath: str) -> str:
    """
    Simulate ransomware encryption:
    1. Read original content
    2. Base64-encode it (mimics encryption — raises entropy)
    3. Overwrite with encoded content
    4. Rename to .locked extension
    5. Delete the original (the renamed file remains)

    Returns the path of the .locked file.
    """
    # Step 1 - Determine original file size
    original_size = os.path.getsize(filepath)

    # Step 2 - Generate cryptographically random bytes (simulates AES-256 output)
    # os.urandom produces ~7.99 bits/byte entropy, matching real ransomware output.
    encrypted = os.urandom(max(original_size, 256))

    # Step 3 - Overwrite original file with simulated ciphertext
    with open(filepath, "wb") as fh:
        fh.write(encrypted)

    # Step 4 — Rename extension to .locked
    locked_path = filepath + ".locked"
    last_error: OSError | None = None
    for attempt in range(5):
        try:
            os.rename(filepath, locked_path)
            last_error = None
            break
        except OSError as exc:
            last_error = exc
            if getattr(exc, "winerror", None) == 32 and attempt < 4:
                time.sleep(0.25 * (attempt + 1))
                continue
            last_error = exc
            break

    if last_error is not None:
        # On Windows, OneDrive/AV can briefly hold the file open.
        # Fall back to writing the locked copy directly so the demo keeps running.
        with open(locked_path, "wb") as fh:
            fh.write(encrypted)
        try:
            os.remove(filepath)
        except OSError as exc:
            if getattr(exc, "winerror", None) not in {32, 5}:
                raise
        logger.warning(
            "🔁  Rename blocked, wrote fallback locked copy: %s",
            os.path.basename(locked_path),
        )

    logger.info(
        "🔒  Encrypted: %s → %s  (entropy ↑)",
        os.path.basename(filepath),
        os.path.basename(locked_path),
    )
    return locked_path


# ===========================================================================
#  Simulation modes
# ===========================================================================

def run_normal(duration_seconds: int = 30, stop_event: threading.Event | None = None) -> None:
    """
    **Normal mode** — slow, low-volume user-like activity.

    Creates a handful of files with 2–3 second pauses in between,
    then modifies a few of them.  Represents baseline behaviour.
    """
    sandbox = _ensure_sandbox()

    print("\n" + "=" * 60)
    print("  SIMULATOR — NORMAL MODE")
    print(f"  Duration  : ~{duration_seconds} s")
    print(f"  Directory : {sandbox}")
    print("=" * 60 + "\n")

    created_files: list[str] = []
    end_time = time.time() + duration_seconds

    while time.time() < end_time:
        if stop_event is not None and stop_event.is_set():
            logger.info("⏹  Normal mode interrupted by stop request.")
            break
        # Randomly decide: create or modify
        if not created_files or random.random() < 0.6:
            fp = _create_file(sandbox)
            created_files.append(fp)
        else:
            fp = random.choice(created_files)
            _modify_file(fp)

        delay = random.uniform(2.0, 3.5)
        if stop_event is not None:
            if stop_event.wait(timeout=delay):
                logger.info("⏹  Normal mode interrupted by stop request.")
                break
        else:
            time.sleep(delay)

    print(f"\n✅  Normal mode complete — {len(created_files)} files created.\n")


def run_bulk(file_count: int = 30, stop_event: threading.Event | None = None) -> None:
    """
    **Bulk mode** — rapid file creation and modification.

    Creates many files quickly, then modifies a random subset.
    Does NOT rename extensions (non-malicious bulk activity).
    """
    sandbox = _ensure_sandbox()

    print("\n" + "=" * 60)
    print("  SIMULATOR — BULK MODE")
    print(f"  Files     : {file_count}")
    print(f"  Directory : {sandbox}")
    print("=" * 60 + "\n")

    # Phase 1 — Rapid creation
    created_files: list[str] = []
    print("▶  Phase 1: Creating files …\n")
    for i in range(file_count):
        if stop_event is not None and stop_event.is_set():
            logger.info("⏹  Bulk mode interrupted by stop request.")
            return
        fp = _create_file(sandbox)
        created_files.append(fp)
        time.sleep(random.uniform(0.05, 0.15))

    # Phase 2 — Modify a random subset
    modify_count = min(file_count // 2, len(created_files))
    targets = random.sample(created_files, modify_count)
    print(f"\n▶  Phase 2: Modifying {modify_count} files …\n")
    for fp in targets:
        if stop_event is not None and stop_event.is_set():
            logger.info("⏹  Bulk mode interrupted by stop request.")
            return
        _modify_file(fp)
        time.sleep(random.uniform(0.05, 0.15))

    print(f"\n✅  Bulk mode complete — {file_count} created, "
          f"{modify_count} modified.\n")


def run_ransomware(file_count: int = 15, stop_event: threading.Event | None = None) -> None:
    """
    **Ransomware mode** — simulates encryption behaviour.

    1. Creates target files (the "victim" data).
    2. Iterates through each file and "encrypts" it:
       - reads content → base64-encodes → overwrites → renames to .locked
    3. Uses very short inter-operation delays (0.1–0.3 s).

    This pattern triggers:
      • High write-rate in FeatureExtractor
      • High rename_count
      • Entropy spike in EntropyAnalyzer
    """
    sandbox = _ensure_sandbox()

    print("\n" + "=" * 60)
    print("  SIMULATOR — RANSOMWARE MODE  ⚠️")
    print(f"  Victim files : {file_count}")
    print(f"  Directory    : {sandbox}")
    print("  ⚠️  All activity is sandboxed — no real files are harmed.")
    print("=" * 60 + "\n")

    # Phase 1 — Create victim files
    print("▶  Phase 1: Creating victim files …\n")
    victim_files: list[str] = []
    for _ in range(file_count):
        if stop_event is not None and stop_event.is_set():
            logger.info("⏹  Ransomware mode interrupted during Phase 1.")
            break
        fp = _create_file(sandbox)
        victim_files.append(fp)
        time.sleep(random.uniform(0.1, 0.2))

    time.sleep(1)

    # Phase 2 — Encrypt each victim file
    print("\n▶  Phase 2: Encrypting files (simulated) …\n")
    locked_files: list[str] = []
    for fp in victim_files:
        if stop_event is not None and stop_event.is_set():
            logger.info("⏹  Ransomware mode interrupted during Phase 2.")
            break
        if os.path.isfile(fp):
            locked = _encrypt_file(fp)
            locked_files.append(locked)
            time.sleep(random.uniform(0.1, 0.3))

    # Summary
    print("\n" + "-" * 60)
    print("  RANSOMWARE SIMULATION SUMMARY")
    print("-" * 60)
    print(f"  Files created   : {len(victim_files)}")
    print(f"  Files encrypted : {len(locked_files)}")
    print(f"  Directory       : {sandbox}")
    print("-" * 60)
    print("\n✅  Ransomware simulation complete.\n")


# ===========================================================================
#  Cleanup utility
# ===========================================================================

def cleanup_sandbox() -> None:
    """
    Remove the sandbox directory.

    If the DecisionAgent ran `icacls /deny Everyone:(W,D,DC) /T` during a
    RESPONDING transition and was killed before unlocking, the directory
    is unreadable to shutil. We try a normal rmtree first; on failure,
    remove the deny ACEs via icacls and retry once.
    """
    if not os.path.isdir(SANDBOX_DIR):
        logger.info("Sandbox does not exist — nothing to clean.")
        return

    try:
        shutil.rmtree(SANDBOX_DIR)
        logger.info("🧹  Sandbox cleaned: %s", SANDBOX_DIR)
        return
    except PermissionError as exc:
        logger.warning("rmtree blocked (%s); attempting to unlock sandbox", exc)

    import platform
    import subprocess
    if platform.system() == "Windows":
        try:
            subprocess.run(
                ["icacls", SANDBOX_DIR, "/remove:d", "Everyone", "/T", "/C"],
                capture_output=True, text=True, timeout=20,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as sub_exc:
            logger.error("icacls unlock failed: %s", sub_exc)

    try:
        shutil.rmtree(SANDBOX_DIR)
        logger.info("🧹  Sandbox cleaned after unlock: %s", SANDBOX_DIR)
    except OSError as exc:
        logger.error(
            "Sandbox cleanup still failed after unlock attempt: %s. "
            "You may need to remove it manually with: "
            "icacls \"%s\" /remove:d Everyone /T  &&  rmdir /s /q \"%s\"",
            exc, SANDBOX_DIR, SANDBOX_DIR,
        )
        raise


# ===========================================================================
#  CLI entry-point
# ===========================================================================

def main() -> None:
    """
    Parse arguments and run the selected simulation mode.

    Usage
    -----
    ::

        python ransomware_simulator.py --mode normal
        python ransomware_simulator.py --mode bulk
        python ransomware_simulator.py --mode ransomware
        python ransomware_simulator.py --cleanup
    """
    parser = argparse.ArgumentParser(
        description=(
            "Ransomware Behaviour Simulator — generates controlled "
            "file-system activity inside C:\\Users\\aarya\\OneDrive\\Desktop\\College stuff\\VIT\\TY\\S6\\CSAB\\CP\\ransomware_test "
            "for end-to-end testing of the detection pipeline."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "bulk", "ransomware"],
        default="normal",
        help="Simulation mode (default: normal).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=15,
        help="Number of files to generate (bulk/ransomware modes, default: 15).",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Duration in seconds (normal mode, default: 30).",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove the sandbox directory and exit.",
    )

    args = parser.parse_args()

    # Handle cleanup
    if args.cleanup:
        cleanup_sandbox()
        return

    # Run selected mode
    if args.mode == "normal":
        run_normal(duration_seconds=args.duration)
    elif args.mode == "bulk":
        run_bulk(file_count=args.count)
    elif args.mode == "ransomware":
        run_ransomware(file_count=args.count)


if __name__ == "__main__":
    main()

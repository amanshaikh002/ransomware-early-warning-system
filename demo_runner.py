import subprocess
import sys
import time
from typing import List


def main() -> None:
    """
    Launch all ransomware early-warning system modules concurrently for
    demonstration purposes.

    Modules started:
      - monitoring/file_watcher.py
      - features/feature_extractor.py --mode realtime --window 10
      - entropy/entropy_analyzer.py       (default realtime mode)
      - drift/drift_detector.py --mode realtime

    All subprocesses run in the foreground with their stdout/stderr
    attached so logs are visible in a single terminal. Press Ctrl+C to
    terminate all modules gracefully.
    """
    python_exe = sys.executable or "python"

    commands = [
        ([python_exe, "monitoring/file_watcher.py"], "FileWatcher"),
        (
            [
                python_exe,
                "features/feature_extractor.py",
                "--mode",
                "realtime",
                "--window",
                "10",
            ],
            "FeatureExtractor",
        ),
        ([python_exe, "entropy/entropy_analyzer.py"], "EntropyAnalyzer"),
        (
            [
                python_exe,
                "drift/drift_detector.py",
                "--mode",
                "realtime",
            ],
            "DriftDetector",
        ),
    ]

    processes: List[subprocess.Popen] = []

    try:
        # Start all modules as independent subprocesses
        for cmd, name in commands:
            proc = subprocess.Popen(cmd)
            processes.append(proc)

        # Print demonstration banner after successful launch
        print("\n" + "=" * 48)
        print("Agentic AI Ransomware Early-Warning System")
        print("Live Demonstration Mode")
        print("=" * 23 + "\n")
        print("Modules running:")
        print("[\u2714] FileWatcher")
        print("[\u2714] FeatureExtractor")
        print("[\u2714] EntropyAnalyzer")
        print("[\u2714] DriftDetector")
        print("\nPress Ctrl+C to stop the system\n")

        # Keep the runner alive until interrupted
        while True:
            # Optionally, we could monitor child exit codes here, but
            # for the demo we simply block and let subprocess logs
            # stream to this terminal.
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping modules...")
        for proc in processes:
            if proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    # On Windows some processes may have already exited
                    # or refuse termination; ignore and continue.
                    pass

        # Give processes a short grace period to exit
        deadline = time.time() + 5.0
        for proc in processes:
            if proc.poll() is None:
                timeout = max(0.0, deadline - time.time())
                if timeout <= 0:
                    break
                try:
                    proc.wait(timeout=timeout)
                except Exception:
                    pass

        print("System stopped successfully.")


if __name__ == "__main__":
    main()


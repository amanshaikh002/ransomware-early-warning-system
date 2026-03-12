"""
============================================================================
Module 4 : Behavioral Drift Detection
Project  : Agentic AI-Based Ransomware Early-Warning System Using
           File Entropy and Behavioral Drift Analysis with
           Blockchain Evidence Logging
============================================================================

Purpose
-------
Detect abnormal deviations in filesystem behavioral feature vectors
produced by Module 2 (FeatureExtractor).  Three complementary
detection algorithms are applied in parallel:

1. **Z-Score** — statistical z-score computed against a rolling history of
   per-feature values.  Flags sudden spikes (|z| > z_threshold).

2. **ADWIN** (ADaptive WINdowing, via the ``river`` library) — streaming
   drift detector that automatically adjusts its window size and signals
   when a distributional change is detected.

3. **Page-Hinkley** — cumulative-sum test designed to detect *gradual*
   upward drift in a monitored signal.

Each detected drift is assigned a **severity** level:

    1 detector  →  LOW
    2 detectors →  MEDIUM
    3 detectors →  HIGH

Libraries
---------
statistics   – mean / stdev for Z-Score
collections  – deque for bounded feature history
river.drift  – ADWIN streaming detector
datetime     – ISO-8601 timestamps
json         – structured output

Author   : <your-name>
Created  : 2026-03-12
============================================================================
"""

import os
import time
import json
import math
import logging
import argparse
import statistics
from collections import deque, defaultdict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
#  Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ===========================================================================
#  Page-Hinkley Test  (pure Python, no external library needed)
# ===========================================================================
class _PageHinkley:
    """
    Cumulative-sum (CUSUM) drift detector for gradual upward trends.

    Drift is signalled when the cumulative deviation of observations
    above their running mean exceeds a configurable threshold.

    Parameters
    ----------
    threshold : float
        Cumulative deviation required to declare drift (default 50).
    delta : float
        Minimum acceptable magnitude of change to track (default 0.005).
    """

    def __init__(self, threshold: float = 50.0, delta: float = 0.005):
        self._threshold = threshold
        self._delta = delta
        self._n: int = 0
        self._sum: float = 0.0          # cumulative sum x_i
        self._min_sum: float = float("inf")  # running minimum of cumulative sum
        self.drift_detected: bool = False

    def update(self, value: float) -> None:
        """Feed the next observation and update drift state."""
        self._n += 1
        self._sum += value - self._delta

        if self._sum < self._min_sum:
            self._min_sum = self._sum

        # Page-Hinkley statistic: cumulative deviation above minimum
        ph_stat = self._sum - self._min_sum
        self.drift_detected = ph_stat > self._threshold

    def reset(self) -> None:
        """Reset detector state (call after drift is handled)."""
        self.__init__(self._threshold, self._delta)


# ===========================================================================
#  DriftDetector
# ===========================================================================

#: Features from the feature vector that indicate ransomware-like behaviour.
MONITORED_FEATURES: list[str] = [
    # Strong ransomware indicators (given extra attention in Z-score analysis)
    "write_rate",
    "files_modified",
    "rename_count",
    # Supporting context features
    "files_touched_per_process",
    "directories_touched",
]

#: Minimum number of baseline windows required before Z-score detection starts.
#: A small value improves responsiveness during short demos while still
#: establishing a basic notion of "normal" behaviour.
MIN_BASELINE_WINDOWS: int = 3

#: Default Z-score threshold for anomaly detection. Lowering this from 3.0 to
#: 2.0 makes the detector more sensitive to sudden bursts in write_rate,
#: files_modified, and rename_count that are characteristic of ransomware.
Z_THRESHOLD: float = 2.0

#: Map severity label based on how many detectors fired.
_SEVERITY_MAP: dict[int, str] = {0: "NONE", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}


class DriftDetector:
    """
    Real-time behavioral drift detector for filesystem feature vectors.

    Combines three detection algorithms:
    - Z-Score (sudden statistical anomaly)
    - ADWIN   (streaming distribution change, via ``river``)
    - Page-Hinkley (gradual cumulative upward drift)

    Usage
    -----
    >>> detector = DriftDetector()
    >>> result = detector.update(feature_vector)
    >>> if result["drift_detected"]:
    ...     print("DRIFT!", result["severity"])

    Parameters
    ----------
    z_threshold : float
        Z-score magnitude above which a feature observation is flagged
        (default 3.0).
    history_size : int
        Maximum number of past observations to retain per feature for
        Z-score computation (default 30).
    ph_threshold : float
        Page-Hinkley cumulative threshold before drift is declared
        (default 50).
    min_history : int
        Minimum observations required before Z-score fires (default 5).
    """

    def __init__(
        self,
        z_threshold: float = Z_THRESHOLD,
        history_size: int = 30,
        ph_threshold: float = 50.0,
        min_history: int = MIN_BASELINE_WINDOWS,
    ):
        self._z_threshold = z_threshold
        self._history_size = history_size
        self._min_history = min_history

        # ---- Per-feature rolling history (for Z-Score) ----
        self._history: dict[str, deque] = {
            feat: deque(maxlen=history_size) for feat in MONITORED_FEATURES
        }

        # ---- ADWIN detectors (one per monitored feature) ----
        try:
            from river.drift import ADWIN
            self._adwin: dict[str, object] = {
                feat: ADWIN() for feat in MONITORED_FEATURES
            }
            self._adwin_available = True
        except ImportError:
            logger.warning(
                "river library not found — ADWIN detection disabled.  "
                "Install it: pip install river"
            )
            self._adwin = {}
            self._adwin_available = False

        # ---- Page-Hinkley detectors (one per monitored feature) ----
        self._ph: dict[str, _PageHinkley] = {
            feat: _PageHinkley(threshold=ph_threshold) for feat in MONITORED_FEATURES
        }

        # ---- Result history ----
        self._drift_results: list[dict] = []
        self._window_count: int = 0

        logger.info(
            "DriftDetector initialised — z_threshold: %.1f, "
            "history_size: %d, ADWIN: %s",
            self._z_threshold,
            self._history_size,
            "enabled" if self._adwin_available else "disabled",
        )

    # =================================================================
    #  Public API
    # =================================================================

    def update(self, feature_vector: dict) -> dict:
        """
        Ingest a new feature vector and run all three drift detectors.

        Parameters
        ----------
        feature_vector : dict
            A feature vector from ``FeatureExtractor`` containing at
            least the keys in ``MONITORED_FEATURES``.

        Returns
        -------
        dict
            A structured drift result (see :meth:`_build_result`).
        """
        self._window_count += 1
        timestamp = datetime.now(timezone.utc).isoformat()

        per_feature: dict[str, dict] = {}
        overall_z_flag    = False
        overall_adwin_flag = False
        overall_ph_flag    = False

        for feat in MONITORED_FEATURES:
            value = float(feature_vector.get(feat, 0.0))

            # ---- Z-Score ----
            zscore, z_flag = self._zscore(feat, value)

            # ---- ADWIN ----
            adwin_flag = self._update_adwin(feat, value)

            # ---- Page-Hinkley ----
            ph_flag = self._update_ph(feat, value)

            # ---- Append to history AFTER computing scores ----
            self._history[feat].append(value)

            per_feature[feat] = {
                "value":   value,
                "z_score": zscore,
                "z_flag":  z_flag,
                "adwin":   adwin_flag,
                "ph":      ph_flag,
            }

            if z_flag:    overall_z_flag    = True
            if adwin_flag: overall_adwin_flag = True
            if ph_flag:   overall_ph_flag    = True

        # ---- Severity ----
        detectors_fired = sum([overall_z_flag, overall_adwin_flag, overall_ph_flag])
        severity = _SEVERITY_MAP.get(detectors_fired, "HIGH")
        drift_detected = detectors_fired >= 1

        result = self._build_result(
            timestamp, per_feature,
            overall_z_flag, overall_adwin_flag, overall_ph_flag,
            detectors_fired, severity, drift_detected,
            feature_vector,
        )

        self._drift_results.append(result)
        self._emit(result)
        return result

    def get_results(self) -> list[dict]:
        """Return all drift results collected so far."""
        return list(self._drift_results)

    def clear_results(self) -> None:
        """Clear stored drift results."""
        self._drift_results.clear()

    # =================================================================
    #  Detection algorithms (private)
    # =================================================================

    def _zscore(self, feat: str, value: float) -> tuple[float | None, bool]:
        """
        Compute Z-score for *value* against the feature's rolling history.

        Returns ``(None, False)`` if there is insufficient history.
        """
        hist = list(self._history[feat])
        # Start detecting after a small baseline window history so that
        # ransomware-like bursts are caught early in short demos.
        if len(hist) < MIN_BASELINE_WINDOWS:
            return None, False

        try:
            mu  = statistics.mean(hist)
            sig = statistics.stdev(hist)
        except statistics.StatisticsError:
            return None, False

        if sig == 0:
            # No variance — any non-zero deviation is anomalous
            zscore = float("inf") if value != mu else 0.0
        else:
            zscore = (value - mu) / sig

        z_rounded = round(zscore, 4) if math.isfinite(zscore) else zscore
        flagged = abs(zscore) > self._z_threshold
        return z_rounded, flagged

    def _update_adwin(self, feat: str, value: float) -> bool:
        """Feed *value* into the ADWIN detector for *feat*.  Returns drift flag."""
        if not self._adwin_available:
            return False
        detector = self._adwin[feat]
        detector.update(value)
        return bool(detector.drift_detected)

    def _update_ph(self, feat: str, value: float) -> bool:
        """Feed *value* into the Page-Hinkley detector.  Returns drift flag."""
        self._ph[feat].update(value)
        return self._ph[feat].drift_detected

    # =================================================================
    #  Output helpers (private)
    # =================================================================

    def _build_result(
        self,
        timestamp: str,
        per_feature: dict,
        z_flag: bool,
        adwin_flag: bool,
        ph_flag: bool,
        detectors_fired: int,
        severity: str,
        drift_detected: bool,
        raw_vector: dict,
    ) -> dict:
        """Assemble the structured drift result dictionary."""
        # Find the most anomalous feature (highest |z| among features with
        # a valid Z-score). This improves attribution so demonstrations
        # clearly highlight which behavioural dimension went "off the rails".
        z_scores: dict[str, float] = {
            feat: info["z_score"]
            for feat, info in per_feature.items()
            if info["z_score"] is not None
        }
        if z_scores:
            top_feature = max(z_scores, key=lambda k: abs(z_scores[k]))
            top_z = z_scores[top_feature]
        else:
            top_feature = None
            top_z = 0.0

        return {
            "timestamp":        timestamp,
            "window":           self._window_count,
            "drift_detected":   drift_detected,
            "severity":         severity,
            "detectors_fired":  detectors_fired,
            # Summary flags
            "z_score_alert":    z_flag,
            "adwin_alert":      adwin_flag,
            "page_hinkley_alert": ph_flag,
            # Most anomalous feature (quick reference)
            "top_feature":      top_feature,
            "top_z_score":      round(top_z, 4) if math.isfinite(top_z) else str(top_z),
            # Per-feature breakdown
            "features": per_feature,
            # Key raw values for dashboards / blockchain logging
            "write_rate":           raw_vector.get("write_rate", 0.0),
            "files_modified":       raw_vector.get("files_modified", 0),
            "rename_count":         raw_vector.get("rename_count", 0),
        }

    def _emit(self, result: dict) -> None:
        """Print the drift result to the console."""
        is_drift = result["drift_detected"]
        severity  = result["severity"]

        print()
        if is_drift:
            colour  = "\033[91m" if severity == "HIGH" else \
                      "\033[93m" if severity == "MEDIUM" else "\033[33m"
            reset   = "\033[0m"
            print(colour + "=" * 48 + reset)
            print(colour + f"🚨 BEHAVIORAL DRIFT DETECTED [{severity}]" + reset)
            print(colour + "=" * 48 + reset)
        else:
            print("─" * 62)
            print("  ✅  No behavioral drift detected — activity normal.")
            print("─" * 62)

        # Compact summary (omit full per-feature breakdown to reduce noise)
        summary = {k: v for k, v in result.items() if k != "features"}
        print(json.dumps(summary, indent=2))

        if is_drift:
            print()
            print(f"Top anomalous feature : {result['top_feature']}")
            print(f"Z-Score               : {result['top_z_score']}")
            print(f"Z-Score alert         : {result['z_score_alert']}")
            print(f"ADWIN alert           : {result['adwin_alert']}")
            print(f"Page-Hinkley alert    : {result['page_hinkley_alert']}")
            reset = "\033[0m"
            colour = "\033[91m" if severity == "HIGH" else "\033[93m"
            print(colour + "=" * 48 + reset)
        print()


# ===========================================================================
#  Real-Time Monitoring (standalone mode)
# ===========================================================================

def _run_realtime_drift(detector: DriftDetector, stream_path: str) -> None:
    """Continuously tail the feature stream and detect drift in real-time."""
    if not os.path.exists(stream_path):
        # Create empty file so tailing doesn't crash if Module 2 hasn't started
        open(stream_path, "a", encoding="utf-8").close()

    print("\n" + "=" * 62)
    print("  MODULE 4 — DRIFT DETECTOR  (real-time mode)")
    print("-" * 62)
    print(f"  Listening for feature vectors on:")
    print(f"    • {stream_path}")
    print("  Press Ctrl+C to stop")
    print("=" * 62 + "\n")

    try:
        with open(stream_path, "r", encoding="utf-8") as f:
            # Go directly to the end of the file — we only care about *new*
            # real-time activity, not historic simulation data.
            f.seek(0, 2)
            buffer = ""
            while True:
                chunk = f.readline()
                if not chunk:
                    time.sleep(1)
                    continue

                buffer += chunk
                # If we haven't seen a newline, the write is incomplete (mid-flush).
                # Wait for the rest of the line to appear.
                if not buffer.endswith("\n"):
                    continue

                line = buffer.strip()
                buffer = ""  # Reset buffer for the next line
                
                if not line:
                    continue

                try:
                    feature_vector = json.loads(line)
                    detector.update(feature_vector)
                except json.JSONDecodeError:
                    logger.error("Failed to parse vector: %s", line)
    except KeyboardInterrupt:
        print("\n⏹  Interrupt received. Stopping drift detector …")
    finally:
        logger.info("🛑  Drift detector stopped.")


# ===========================================================================
#  Standalone CLI
# ===========================================================================
def _run_demo() -> None:
    """Run built-in offline test for verification."""
    print("\n" + "=" * 62)
    print("  MODULE 4 — BEHAVIORAL DRIFT DETECTOR  (demo mode)")
    print("=" * 62 + "\n")

    detector = DriftDetector(z_threshold=Z_THRESHOLD, min_history=MIN_BASELINE_WINDOWS)

    # ---- Phase 1: Normal baseline activity (quiet windows) ----
    print("▶  Phase 1: feeding normal baseline windows …\n")
    NORMAL_VECTOR = {
        "write_rate":               0.3,
        "files_modified":           2,
        "rename_count":             0,
        "files_touched_per_process": 2.0,
        "directories_touched":      1,
    }
    for i in range(8):
        detector.update(NORMAL_VECTOR)

    # ---- Phase 2: Ransomware-like burst ----
    print("\n▶  Phase 2: ransomware-like burst …\n")
    BURST_VECTOR = {
        "write_rate":               12.5,
        "files_modified":           90,
        "rename_count":             30,
        "files_touched_per_process": 30.0,
        "directories_touched":      1,
    }
    for i in range(3):
        detector.update(BURST_VECTOR)

    # ---- Summary ----
    print("\n" + "=" * 62)
    print("  SESSION SUMMARY")
    print("=" * 62)
    results = detector.get_results()
    drifts = [r for r in results if r["drift_detected"]]
    print(f"  Total windows   : {len(results)}")
    print(f"  Drift detections: {len(drifts)}")
    if drifts:
        print(f"  Max severity    : {max(r['severity'] for r in drifts)}")
    print("\n✅  Demo complete.\n")


if __name__ == "__main__":
    import sys

    parser = argparse.ArgumentParser(
        description="Module 4 – Behavioral Drift Detector."
    )
    parser.add_argument(
        "--mode",
        choices=["realtime", "demo"],
        default="realtime",
        help="Run mode (default: realtime).",
    )
    args = parser.parse_args()

    if args.mode == "realtime":
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        stream_path = os.path.join(project_root, "feature_stream.jsonl")
        detector = DriftDetector(z_threshold=Z_THRESHOLD, min_history=MIN_BASELINE_WINDOWS)
        _run_realtime_drift(detector, stream_path)
    else:
        _run_demo()

"""Isolation Forest based anomaly detector for feature vectors."""

from __future__ import annotations

import argparse
import json
import logging
import math
import time
from pathlib import Path
import threading

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class IsolationForestDetector:
    """Train or apply an IsolationForest model on behavior vectors."""

    FEATURE_ORDER = [
        "write_rate",
        "files_modified",
        "rename_count",
        "files_touched_per_process",
        "directories_touched",
    ]

    def __init__(
        self,
        model_path: str | None = None,
        min_samples: int = 50,
        contamination: float = 0.05,
    ) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self.model_path = Path(model_path) if model_path else project_root / "isolation_forest.pkl"
        self.min_samples = min_samples
        self.contamination = contamination
        self.model: IsolationForest | None = None
        self._warned_missing_model = False
        self._load_model_if_exists()

    def _load_model_if_exists(self) -> None:
        if self.model_path.exists():
            self.model = joblib.load(self.model_path)
            logger.info("Loaded IsolationForest model from %s", self.model_path)

    def _extract_vector(self, data: dict) -> list[float]:
        return [float(data.get(name, 0.0)) for name in self.FEATURE_ORDER]

    def train_from_vectors(self, vectors: list[dict]) -> bool:
        if len(vectors) < self.min_samples:
            logger.info("Collected %d/%d samples for training", len(vectors), self.min_samples)
            return False

        matrix = np.array([self._extract_vector(v) for v in vectors], dtype=float)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
        )
        self.model.fit(matrix)
        joblib.dump(self.model, self.model_path)
        logger.info("IsolationForest training complete; model saved to %s", self.model_path)
        return True

    def detect(self, vector: dict) -> dict:
        if self.model is None:
            if not self._warned_missing_model:
                logger.warning("IsolationForest model not found. Detection skipped until training completes.")
                self._warned_missing_model = True
            return {"anomaly": False, "anomaly_score": 0.0, "confidence": 0.0}

        sample = np.array([self._extract_vector(vector)], dtype=float)
        raw_score = float(self.model.decision_function(sample)[0])
        anomaly = int(self.model.predict(sample)[0]) == -1
        confidence = 1.0 / (1.0 + math.exp(raw_score * 5.0))
        confidence = max(0.0, min(1.0, confidence))
        return {
            "anomaly": anomaly,
            "anomaly_score": raw_score,
            "confidence": confidence,
        }

    @staticmethod
    def _ensure_file(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)

    def run_train(self, feature_stream_path: str | None = None, stop_event: threading.Event | None = None) -> None:
        stop_event = stop_event or threading.Event()
        project_root = Path(__file__).resolve().parent.parent
        stream_path = Path(feature_stream_path) if feature_stream_path else project_root / "feature_stream.jsonl"
        self._ensure_file(stream_path)

        samples: list[dict] = []
        idle_samples = 0
        with stream_path.open("r", encoding="utf-8") as handle:
            handle.seek(0)
            while not stop_event.is_set():
                line = handle.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    vector = json.loads(line.strip())
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed feature vector line during training.")
                    continue

                if all(abs(value) < 1e-9 for value in self._extract_vector(vector)):
                    idle_samples += 1
                    if idle_samples % 10 == 0:
                        logger.info("Collected %d idle vectors (quiet windows)", idle_samples)

                samples.append(vector)

                if self.train_from_vectors(samples):
                    if idle_samples:
                        logger.info("Training used %d vectors including %d idle windows", len(samples), idle_samples)
                    return

    def run_detect(self, feature_stream_path: str | None = None, stop_event: threading.Event | None = None) -> None:
        stop_event = stop_event or threading.Event()
        project_root = Path(__file__).resolve().parent.parent
        stream_path = Path(feature_stream_path) if feature_stream_path else project_root / "feature_stream.jsonl"
        self._ensure_file(stream_path)

        with stream_path.open("r", encoding="utf-8") as handle:
            handle.seek(0, 2)
            while not stop_event.is_set():
                line = handle.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    vector = json.loads(line.strip())
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed feature vector line in detection.")
                    continue
                result = self.detect(vector)
                logger.info("IsolationForest result: %s", result)

    def run_demo(self) -> None:
        normal = []
        for _ in range(max(self.min_samples, 60)):
            normal.append(
                {
                    "write_rate": np.random.normal(1.0, 0.3),
                    "files_modified": np.random.normal(2.0, 1.0),
                    "rename_count": np.random.normal(0.5, 0.5),
                    "files_touched_per_process": np.random.normal(2.0, 0.6),
                    "directories_touched": np.random.normal(1.0, 0.2),
                }
            )
        self.train_from_vectors(normal)

        attacks = [
            {
                "write_rate": 18,
                "files_modified": 70,
                "rename_count": 25,
                "files_touched_per_process": 40,
                "directories_touched": 9,
            },
            {
                "write_rate": 22,
                "files_modified": 120,
                "rename_count": 35,
                "files_touched_per_process": 50,
                "directories_touched": 14,
            },
        ]

        for vector in attacks:
            print(json.dumps({"input": vector, "result": self.detect(vector)}, indent=2))


def main() -> None:
    """CLI entry point for train/detect/demo."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="Isolation Forest anomaly detector")
    parser.add_argument("--mode", choices=["train", "detect", "demo"], default="detect")
    parser.add_argument("--min-samples", type=int, default=50)
    args = parser.parse_args()

    detector = IsolationForestDetector(min_samples=args.min_samples)

    if args.mode == "demo":
        detector.run_demo()
    elif args.mode == "train":
        try:
            detector.run_train()
        except KeyboardInterrupt:
            pass
    else:
        try:
            detector.run_detect()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

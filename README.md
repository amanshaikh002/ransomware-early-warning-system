# Agentic AI-Based Ransomware Early-Warning System Using File Entropy and Behavioral Drift Analysis with Blockchain Evidence Logging

## Overview

Ransomware attacks encrypt user files rapidly and cause severe data loss before traditional security systems respond. Most detection tools rely on known malware signatures and detect attacks only after significant damage has occurred.

This project proposes an **Agentic AI-based ransomware early-warning system** that detects suspicious file activity in real time by analyzing:

* File system behavior
* File entropy changes
* Behavioral drift from normal activity
* Process-level access patterns

The system continuously monitors file events, extracts behavioral features, and applies anomaly detection techniques to identify ransomware-like patterns early.

To ensure forensic integrity, the system also stores security evidence in a **tamper-resistant blockchain ledger**.

---

## Key Features

* Real-time file system monitoring
* Behavioral feature extraction using sliding time windows
* Detection of abnormal file modification bursts
* Entropy-based detection of encrypted files
* AI-based anomaly detection
* Agentic decision engine for automated response
* Blockchain-based forensic evidence logging
* Visualization dashboard for monitoring alerts

---

## System Architecture

```
Windows File System
        ↓
File Monitoring Module
        ↓
Feature Extraction Module
        ↓
Entropy Analysis Module
        ↓
Behavioral Drift Detection
        ↓
Machine Learning Anomaly Detection
        ↓
Risk Scoring Engine
        ↓
Agentic Decision System
        ↓
Blockchain Evidence Logging
        ↓
Monitoring Dashboard
```

---

## Modules Implemented

### Module 1: File Monitoring

Continuously monitors important user directories such as:

* Desktop
* Documents
* Downloads
* Pictures

Captured events include:

* File creation
* File modification
* File deletion
* File rename/move

Each event is recorded with metadata such as:

* timestamp
* file path
* file size
* process information

Example event:

```json
{
  "timestamp": "2026-03-09T19:43:39.385844+00:00",
  "event_type": "modified",
  "file_path": "C:\\Users\\Lenovo\\Downloads\\file.docx",
  "file_size": 18721,
  "process_id": 1452,
  "process_name": "python.exe"
}
```

---

### Module 2: Feature Extraction

This module converts raw file events into **behavioral feature vectors** using sliding time windows.

Example features extracted:

* files_created
* files_modified
* files_deleted
* rename_count
* write_rate
* unique_file_types
* directories_touched
* unique_process_count
* average_file_size

Example feature vector:

```json
{
  "window_start": "2026-03-09T20:06:51.651903+00:00",
  "window_end": "2026-03-09T20:07:11.651903+00:00",
  "files_created": 2,
  "files_modified": 1,
  "rename_count": 0,
  "write_rate": 0.6
}
```

These features represent the **behavior of the system during a time window** and will later be used for anomaly detection.

---

### Module 3: Entropy Analysis

This module calculates the Shannon entropy of file contents during modification or creation events to detect potential encryption.

* Reads files in safe chunks
* Calculates byte frequency probabilities
* Flags files crossing a configurable high-entropy threshold (e.g., > 7.5 bits/byte)

Example output:

```json
{
  "file_path": "C:\\Users\\Lenovo\\Downloads\\file.docx.locked",
  "file_size": 18721,
  "entropy": 7.95,
  "entropy_flag": true,
  "threshold": 7.5
}
```

---

### Testing Simulator

A safe, sandboxed testing module built into the system to generate simulated file system activity (normal, bulk, and ransomware-like) directly inside monitored directories (`~/Documents/ransomware_test/`). This guarantees the entire event pipeline (FileWatcher → FeatureExtractor → EntropyAnalyzer) can be thoroughly evaluated end-to-end without risking actual system data.

---

## Algorithms Used

The project integrates multiple cybersecurity and machine learning techniques:

* Shannon Entropy Analysis
* Sliding Window Feature Aggregation
* Z-Score Statistical Anomaly Detection
* ADWIN / Page-Hinkley Drift Detection
* Isolation Forest Anomaly Detection
* Weighted Risk Scoring
* Finite State Machine Agent
* SHA-256 Hashing
* Merkle Tree Hashing
* Blockchain Smart Contracts

---

## Technology Stack

Backend

* Python

Monitoring

* watchdog
* psutil

Data Processing

* NumPy
* pandas

Machine Learning

* scikit-learn
* river

Blockchain

* Ethereum / Ganache
* Solidity

Database

* SQLite / PostgreSQL

Visualization

* React / HTML
* Chart.js / Plotly

---

## Project Structure

```
ransomware-early-warning-system

monitoring/
    file_watcher.py

features/
    feature_extractor.py

entropy/
    entropy_analyzer.py

testing/
    ransomware_simulator.py

blockchain/
database/
dashboard/
utils/

requirements.txt
main.py
README.md
```

---

## How It Works

1. The system monitors file system activity in real time.
2. File events are streamed into the feature extraction module.
3. Events are aggregated within sliding time windows.
4. Behavioral features are generated for each window.
5. The anomaly detection engine analyzes these features.
6. Suspicious behavior triggers alerts and response actions.
7. Evidence is securely stored on blockchain.

---

## Example Detection Scenario

Normal user activity:

```
files_modified = 3
rename_count = 0
write_rate = 0.2/sec
```

Ransomware attack:

```
files_modified = 120
rename_count = 110
write_rate = 12/sec
```

The system detects this abnormal behavior and raises an early warning.

---

## Current Progress

Completed:

* File Monitoring Module
* Feature Extraction Module
* Entropy Analysis Engine
* Testing Simulator

Upcoming modules:

* Behavioral Drift Detection
* Isolation Forest Anomaly Detection
* Risk Scoring Engine
* Agentic Decision System
* Blockchain Evidence Logging
* Security Dashboard

---

## Future Enhancements

* Federated learning across multiple endpoints
* Graph-based process behavior modeling
* Automated ransomware rollback
* Integration with cloud SIEM platforms
* Reinforcement learning for response optimization

---

## License

This project is developed for academic and research purposes.

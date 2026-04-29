# Agentic AI-Based Ransomware Early-Warning System

> **Real-time detection of ransomware-like file activity using Shannon Entropy, Behavioral Drift, Isolation Forest anomaly detection, and a Finite State Machine agent — with tamper-resistant blockchain evidence logging and a live web dashboard.**

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [System Architecture](#system-architecture)
4. [Modules](#modules)
5. [Algorithms & Techniques](#algorithms--techniques)
6. [Technology Stack](#technology-stack)
7. [Performance Results](#performance-results)
8. [Installation](#installation)
9. [How to Run](#how-to-run)
10. [Project Structure](#project-structure)
11. [API Reference](#api-reference)
12. [Detection Scenario Example](#detection-scenario-example)
13. [Future Enhancements](#future-enhancements)
14. [License](#license)

---

## Overview

Ransomware attacks encrypt user files at high speed, causing severe data loss before traditional signature-based security systems can respond. This project implements an **Agentic AI-Based Ransomware Early-Warning System** that detects suspicious file system activity in real time — _before_ encryption is complete.

The system operates as a multi-threaded pipeline of specialized modules:

- **File system events** are captured the moment they occur.
- **Behavioral features** are extracted over sliding time windows.
- **Entropy analysis** flags files whose byte-randomness crosses encryption thresholds.
- **Drift detection** identifies sudden statistical deviations from the established baseline.
- **Isolation Forest** flags anomalous feature vectors that differ from learned normal behavior.
- A **weighted risk scorer** fuses all signals into a single score (0–100).
- A **Finite State Machine agent** transitions through `MONITORING → ALERT → RESPONDING` and applies defensive actions (process termination, folder locking via `icacls`).
- Every security decision is appended to a **SHA-256 / Merkle-chained blockchain ledger** for forensic integrity.
- A **Flask web dashboard** provides real-time visibility into every layer of the pipeline.

---

## Key Features

| Feature | Details |
|---|---|
| **Real-time file monitoring** | Watches Desktop, Documents, Downloads, Pictures, and a sandbox directory |
| **Sliding-window feature extraction** | Aggregates 9+ behavioral features every 5 seconds |
| **Shannon entropy analysis** | Detects files with entropy > 7.2 bits/byte (consistent with AES-encrypted content) |
| **Behavioral drift detection** | ADWIN + Page-Hinkley + Z-score across multiple features |
| **Isolation Forest anomaly detection** | Pre-trained model + online learning from baseline windows |
| **Fused risk scoring** | Weighted combination of all detector signals; levels: NORMAL / SUSPICIOUS / HIGH\_RISK / CRITICAL |
| **Agentic FSM response** | Automatic process kill + `icacls` folder locking on HIGH\_RISK/CRITICAL |
| **VSS snapshots** | Volume Shadow Copy triggered on ALERT to preserve file state |
| **Blockchain evidence log** | Append-only SHA-256 / Merkle-chained `.jsonl` ledger; tamper-detectable |
| **Re-verification auditor** | Post-attack coverage report: which `.locked` files were caught, which were missed |
| **Live web dashboard** | Flask + Vanilla JS dashboard with charts, live simulation controls, and a decoy injector |
| **Sandboxed simulator** | Safe ransomware, bulk, and normal activity simulation inside `~/Documents/ransomware_test/` |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Windows File System                          │
│        (Desktop / Documents / Downloads / Pictures / sandbox)       │
└────────────────────────────┬────────────────────────────────────────┘
                             │  filesystem events (watchdog)
                             ▼
                   ┌─────────────────┐
                   │  File Watcher   │──── event_stream.jsonl
                   └────────┬────────┘
                            │
              ┌─────────────┼──────────────┐
              ▼             ▼              ▼
   ┌──────────────┐ ┌────────────┐ ┌──────────────┐
   │  Feature     │ │  Entropy   │ │  Database    │
   │  Extractor   │ │  Analyzer  │ │  Manager     │
   │ (5 s window) │ │ (≥7.2 b/B) │ │  (SQLite)    │
   └──────┬───────┘ └─────┬──────┘ └──────────────┘
          │               │
          │  feature_stream.jsonl
          │               │  entropy_alerts.jsonl
          ▼               ▼
   ┌─────────────────────────────────┐
   │          Risk Scorer            │──── risk_stream.jsonl
   │  (Entropy + Drift + IF + rate)  │
   └──────────────┬──────────────────┘
                  │
        ┌─────────┼──────────┐
        ▼         ▼          ▼
┌────────────┐ ┌──────┐ ┌──────────────────────┐
│   Drift    │ │  IF  │ │   Decision Agent     │
│  Detector  │ │  Det.│ │   (FSM)              │
└────────────┘ └──────┘ │  MONITORING→ALERT    │
                        │  →RESPONDING         │
                        └──────────┬───────────┘
                                   │
                         ┌─────────┴──────────┐
                         ▼                    ▼
                ┌──────────────┐    ┌─────────────────┐
                │  Blockchain  │    │   Web Dashboard  │
                │  Evidence    │    │  (Flask :5000)   │
                │  Logger      │    └─────────────────┘
                └──────────────┘
```

---

## Modules

### Module 1 — File Monitoring (`monitoring/file_watcher.py`)

Uses `watchdog` to monitor file system events across key user directories and the sandboxed test folder. Every event is:
- Enriched with process metadata (`psutil`)
- Appended to `event_stream.jsonl`
- Passed synchronously into the Feature Extractor and Entropy Analyzer

**Captured events:** `created`, `modified`, `deleted`, `renamed`

**Metadata per event:** timestamp, file path, file size, process PID, process name

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

### Module 2 — Feature Extraction (`features/feature_extractor.py`)

Aggregates raw events into **behavioral feature vectors** over a configurable sliding time window (default: 5 s). Features include:

| Feature | Description |
|---|---|
| `files_created` | New file creation count |
| `files_modified` | Modification count |
| `files_deleted` | Deletion count |
| `rename_count` | Rename / move count |
| `write_rate` | Writes per second |
| `unique_file_types` | Distinct extensions touched |
| `directories_touched` | Unique parent directories |
| `unique_process_count` | Distinct process names |
| `average_file_size` | Mean file size in bytes |

Vectors are streamed to `feature_stream.jsonl` for consumption by Drift Detector, Isolation Forest, and Risk Scorer.

---

### Module 3 — Entropy Analysis (`entropy/entropy_analyzer.py`)

Calculates Shannon entropy of file contents on every `created` or `modified` event:

```
H = -Σ p_i * log₂(p_i)
```

Files with `H > 7.2 bits/byte` (configurable) are flagged — consistent with AES/ChaCha20 encrypted ciphertext. Results are saved to `entropy_alerts.jsonl` and the SQLite database.

```json
{
  "file_path": "C:\\Users\\Lenovo\\Downloads\\file.docx.locked",
  "file_size": 18721,
  "entropy": 7.95,
  "entropy_flag": true,
  "threshold": 7.2
}
```

---

### Module 4 — Behavioral Drift Detection (`drift/drift_detector.py`)

Detects statistical deviations from the baseline using three concurrent algorithms:

| Algorithm | Sensitivity |
|---|---|
| **ADWIN** (Adaptive Windowing) | Concept drift in write-rate |
| **Page-Hinkley** | Monotonic shifts in feature means |
| **Z-Score** | Per-feature outlier detection |

Drift is classified into severity levels: `NONE`, `LOW`, `MEDIUM`, `HIGH`. Only MEDIUM+ contributes to the risk score to reduce false positives.

---

### Module 5 — Isolation Forest Anomaly Detection (`anomaly_detection/isolation_forest.py`)

- Loads a **pre-trained model** (`isolation_forest.pkl`) trained on benign baseline vectors.
- Continues online training from the first windows of each session.
- Flags feature vectors as anomalous with a confidence score.
- Results are appended to `iforest_stream.jsonl`.

---

### Module 6 — Risk Scoring Engine (`risk_engine/risk_scorer.py`)

Fuses all detector outputs into a unified **risk score (0–100)**:

| Signal | Max Contribution |
|---|---|
| Entropy flag | 25 pts |
| Write rate | 20 pts |
| Rename count | 20 pts |
| Drift severity | 20 pts |
| Isolation Forest | 15 pts |

**Risk Levels:**

| Score Range | Level |
|---|---|
| 0–29 | `NORMAL` |
| 30–49 | `SUSPICIOUS` |
| 50–74 | `HIGH_RISK` |
| 75–100 | `CRITICAL` |

---

### Module 7 — Agentic Decision System (`agent/decision_agent.py`)

A **Finite State Machine** that autonomously responds to escalating risk:

```
MONITORING ──(score ≥ 50)──► ALERT ──(score ≥ 75)──► RESPONDING
     ▲                          │                         │
     └─────(3 quiet windows)────┘◄────(attack ends)───────┘
```

**RESPONDING actions:**
- Identify suspicious process names from monitored events
- Terminate malicious processes (`psutil.Process.terminate()`)
- Apply `icacls /deny Everyone:(W,D,DC) /T` to the sandbox directory
- Trigger VSS Volume Shadow Copy snapshot (requires admin)
- Log the incident to `incidents.jsonl`

> **Safety:** Defensive locking is restricted to the sandbox `~/Documents/ransomware_test/`. Real user folders are _monitored_ but never locked, preventing a false alarm from causing data loss.

---

### Module 8 — Blockchain Evidence Logger (`blockchain/evidence_logger.py`)

Every risk score event is appended to an **append-only blockchain ledger** (`evidence_chain.jsonl`):

- Each block contains: `index`, `timestamp`, `payload`, `previous_hash`, `hash`
- Hash = `SHA-256(index + timestamp + payload + previous_hash)`
- The full chain can be verified at any time — a single tampered block breaks the Merkle chain

```python
# Verify chain integrity
from blockchain.evidence_logger import BlockchainEvidenceLogger
log = BlockchainEvidenceLogger()
print(log.verify_chain())   # True / raises ChainTamperError
```

---

### Module 9 — Re-Verification Auditor (`verification/reverifier.py`)

Post-attack audit that cross-references every `.locked` file in the sandbox against all detector streams:

- **Caught:** flagged by Entropy OR Drift OR Isolation Forest
- **Missed:** not flagged by any detector (honest blind-spot reporting)
- **Coverage %:** `(caught / total) * 100`

Exposed via `/api/reverification` and the dashboard's "Re-Verify" button.

---

### Module 10 — Web Dashboard (`dashboard/app.py` + `dashboard/index.html`)

A single-page Flask + Vanilla JS application served at `http://127.0.0.1:5000`:

| Panel | Content |
|---|---|
| **Status Banner** | Agent state (MONITORING / ALERT / RESPONDING), current risk score, chain validity |
| **Risk Score Chart** | Live time-series of risk scores with level color bands |
| **Detector Activity** | Real-time entropy flag count, drift severity, IF anomaly status |
| **Live Simulation** | Trigger normal / bulk / ransomware simulation from the browser |
| **Decoy Injector** | Inject a low-entropy `.locked` file to test blind-spot detection |
| **Re-Verification** | Run and display the full coverage audit report |
| **Blockchain Log** | Most recent evidence blocks with hash preview |
| **Session Reset** | Truncate all live JSONL streams and wipe DB operational tables |

---

### Testing Simulator (`testing/ransomware_simulator.py`)

A fully sandboxed simulator that creates activity inside `~/Documents/ransomware_test/`:

| Mode | Behavior |
|---|---|
| `normal` | Slow, low-volume file creation/modification — the _negative_ dataset |
| `bulk` | High write volume, no renames — tests false-positive resistance |
| `ransomware` | Base64-encodes files, renames to `.locked`, deletes originals — the _positive_ dataset |

---

## Algorithms & Techniques

- **Shannon Entropy** — encrypted-file identification
- **Sliding Window Feature Aggregation** — temporal behavioral profiling
- **Z-Score Statistical Anomaly Detection** — per-feature outlier scoring
- **ADWIN (Adaptive Windowing)** — concept drift in streaming data
- **Page-Hinkley Test** — monotonic shift detection
- **Isolation Forest** — unsupervised anomaly detection on feature vectors
- **Weighted Fusion Risk Scoring** — multi-signal evidence aggregation
- **Finite State Machine** — autonomous, state-aware response agent
- **SHA-256 Hashing** — block content integrity
- **Merkle-Chain Linking** — tamper-evident forensic ledger

---

## Technology Stack

| Category | Libraries / Tools |
|---|---|
| **Language** | Python 3.13+ |
| **File Monitoring** | `watchdog >= 3.0`, `psutil >= 5.9` |
| **Data Processing** | `numpy >= 1.26`, `pandas >= 2.0` |
| **Machine Learning** | `scikit-learn >= 1.4`, `river >= 0.21`, `joblib >= 1.3` |
| **Web Framework** | `Flask >= 3.0` |
| **Database** | SQLite (via `sqlite3` stdlib) |
| **Frontend** | Vanilla JS + Chart.js (bundled in `index.html`) |
| **Blockchain** | Custom SHA-256 / Merkle-chain implementation |

---

## Performance Results

Results from a canonical `--mode ransomware --count 50` simulation (~25-second burst, measured against a 60-second idle baseline):

### Detection Performance (per 5-second window)

| Metric | Entropy | Drift | Isolation Forest | Fused Risk Score |
|---|---|---|---|---|
| True Positives | 4 | 3 | 1 | 4 |
| False Negatives | 0 | 1 | 3 | 0 |
| False Positives | 0 | 0 | 0 | 0 |
| True Negatives | 12 | 12 | 12 | 12 |
| **Recall** | **1.00** | 0.75 | 0.25 | **1.00** |
| **Precision** | **1.00** | **1.00** | **1.00** | **1.00** |
| **F1 Score** | **1.00** | 0.86 | 0.40 | **1.00** |
| **FPR** | **0.00** | **0.00** | **0.00** | **0.00** |

### Latency

| Metric | Typical Value |
|---|---|
| File event dispatch latency | < 50 ms |
| Feature window size | 5 s |
| Time-to-detect (TTD) | 5 – 10 s |
| Time to ALERT state | 5 – 10 s |
| Time to RESPONDING | 10 – 15 s |
| `icacls` lock applied | < 200 ms after RESPONDING |
| Recovery (return to MONITORING) | ~40 s after attack ends |

### Coverage & Damage Prevention (50-file ransomware run)

| Metric | Value |
|---|---|
| Total `.locked` files | 50 |
| Caught by at least one detector | 50 |
| Coverage | **100 %** |
| Files encrypted before lock | 25 – 40 |
| Files encrypted after lock | **0** |
| Damage prevented | **20 – 50 %** |

> After injecting a low-entropy decoy, coverage drops to ~98 % — demonstrating that the re-verifier honestly reports the system's own blind spots.

### System Overhead

| Metric | Typical Value |
|---|---|
| Event throughput | 10 – 30 events/sec |
| Memory footprint | 60 – 150 MB |
| CPU usage | 5 – 15 % (1 core) |
| SQLite DB size | < 5 MB (10k-row auto-pruning) |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-org>/ransomware-early-warning-system.git
cd ransomware-early-warning-system

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt
```

> **Windows note:** The `icacls` folder-locking feature and VSS snapshots require running the terminal **as Administrator**. The system runs in monitoring-only mode without admin rights.

---

## How to Run

All commands should be run from the project root.

### Full Pipeline (recommended)

Starts all modules — file watcher, feature extractor, entropy analyzer, drift detector, isolation forest, risk scorer, decision agent, blockchain logger, database, and dashboard — as coordinated daemon threads:

```bash
python main.py
```

Then open **http://127.0.0.1:5000** in your browser.

### Full Pipeline + Built-in Simulation

```bash
# Normal activity (no alerts expected)
python main.py --simulate normal --sim-duration 60

# Bulk writes (false-positive resistance test)
python main.py --simulate bulk --sim-count 30

# Ransomware attack (positive scenario)
python main.py --simulate ransomware --sim-count 50

# Control start delay before simulator fires (default: 3 s)
python main.py --simulate ransomware --sim-count 50 --sim-delay 5
```

### Run Individual Modules

```bash
# File watcher only
python monitoring/file_watcher.py

# Feature extractor (real-time, 10-second window)
python features/feature_extractor.py --mode realtime --window 10

# Entropy analyzer on a specific file
python entropy/entropy_analyzer.py path/to/suspicious_file.pdf

# Entropy analyzer built-in demo
python entropy/entropy_analyzer.py
```

### Simulator (standalone)

```bash
# Normal user activity (60 s)
python testing/ransomware_simulator.py --mode normal --duration 60

# Bulk file operations
python testing/ransomware_simulator.py --mode bulk --count 30

# Ransomware simulation (encrypts + renames + deletes)
python testing/ransomware_simulator.py --mode ransomware --count 50

# Clean up sandbox
python testing/ransomware_simulator.py --cleanup
```

### Verify Blockchain Integrity

```bash
python -m blockchain.evidence_logger --verify
```

---

## Project Structure

```
ransomware-early-warning-system/
│
├── main.py                        # Unified orchestrator — starts all daemon threads
├── requirements.txt
├── README.md
│
├── monitoring/
│   └── file_watcher.py            # watchdog-based filesystem event capture
│
├── features/
│   └── feature_extractor.py       # Sliding-window behavioral feature vectors
│
├── entropy/
│   └── entropy_analyzer.py        # Shannon entropy encryption detection
│
├── drift/
│   └── drift_detector.py          # ADWIN + Page-Hinkley + Z-score drift detection
│
├── anomaly_detection/
│   └── isolation_forest.py        # Isolation Forest anomaly detection
│
├── risk_engine/
│   └── risk_scorer.py             # Weighted multi-signal fusion → risk score
│
├── agent/
│   └── decision_agent.py          # FSM agent: MONITORING → ALERT → RESPONDING
│
├── blockchain/
│   └── evidence_logger.py         # SHA-256 / Merkle-chain forensic ledger
│
├── verification/
│   └── reverifier.py              # Post-attack coverage auditor
│
├── database/
│   └── db_manager.py              # SQLite persistence layer
│
├── dashboard/
│   ├── app.py                     # Flask REST API + static file server
│   └── index.html                 # Single-page monitoring dashboard
│
├── testing/
│   └── ransomware_simulator.py    # Sandboxed attack simulator
│
├── isolation_forest.pkl           # Pre-trained Isolation Forest model
├── ransomware_monitor.db          # SQLite operational database
│
└── *.jsonl                        # Live streaming data files
    ├── event_stream.jsonl
    ├── feature_stream.jsonl
    ├── entropy_alerts.jsonl
    ├── drift_stream.jsonl
    ├── iforest_stream.jsonl
    ├── risk_stream.jsonl
    ├── incidents.jsonl
    ├── evidence_chain.jsonl       # ← Blockchain ledger (preserved across sessions)
    └── reverification_report.jsonl
```

---

## API Reference

The Flask dashboard exposes a REST API on `http://127.0.0.1:5000`:

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Serve the monitoring dashboard |
| `/api/status` | GET | Current risk score, agent state, chain validity |
| `/api/events` | GET | Recent file events from SQLite |
| `/api/entropy` | GET | Recent entropy alerts |
| `/api/drift` | GET | Recent drift alert records |
| `/api/risk` | GET | Risk score time series |
| `/api/incidents` | GET | Agent FSM state transitions |
| `/api/blockchain` | GET | Recent blockchain blocks |
| `/api/reverification` | GET | Coverage audit report |
| `/api/simulate` | POST | Trigger a simulation (`mode`, `count`, `duration`) |
| `/api/inject_decoy` | POST | Inject a low-entropy `.locked` decoy file |
| `/api/reset` | POST | Truncate live streams and wipe DB operational tables |

---

## Detection Scenario Example

**Normal user activity (benign window):**

```
files_modified  = 3
rename_count    = 0
write_rate      = 0.2 /sec
entropy_flag    = false
risk_score      = 4       → NORMAL
```

**Active ransomware attack:**

```
files_modified  = 120
rename_count    = 110
write_rate      = 12 /sec
entropy_flag    = true (H ≈ 7.99 bits/byte)
drift_severity  = HIGH
if_anomaly      = true
risk_score      = 90      → CRITICAL
agent_state     → RESPONDING
```

The agent detects the attack within one feature window (5–10 s), locks the sandbox, and appends the incident to the blockchain ledger.

---

## Future Enhancements

- **Federated learning** — share anomaly models across endpoints without centralizing data
- **Graph-based process behavior modeling** — model file access as a process-file interaction graph
- **Automated ransomware rollback** — restore files from VSS snapshots via the dashboard
- **Cloud SIEM integration** — forward incidents to Splunk / Elastic SIEM via webhooks
- **Reinforcement learning agent** — learn optimal response thresholds through simulated environments
- **Smart contract extension** — deploy evidence logging to a public blockchain (e.g., Ethereum Sepolia)

---

## License

This project is developed for academic and research purposes at VIT University (Sem 6 — Cyber Security and Blockchain Technology).

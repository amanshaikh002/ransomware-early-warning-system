# Agentic AI-Based Ransomware Early-Warning System

**Implementation, architecture, algorithms, and mathematical foundations.**

> A real-time, end-to-end ransomware detection and response system built around
> file-system event monitoring, statistical drift analysis, machine-learning
> anomaly detection, weighted risk scoring, an agentic finite-state response
> machine, tamper-evident blockchain evidence, persistent storage, a live
> web dashboard, and post-attack forensic re-verification.

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [System Architecture](#2-system-architecture)
3. [Data Flow & Stream Schemas](#3-data-flow--stream-schemas)
4. [Module 1 — File Watcher](#4-module-1--file-watcher)
5. [Module 2 — Feature Extractor](#5-module-2--feature-extractor)
6. [Module 3 — Entropy Analyzer](#6-module-3--entropy-analyzer)
7. [Module 4 — Behavioral Drift Detector](#7-module-4--behavioral-drift-detector)
8. [Module 5 — Isolation Forest Anomaly Detector](#8-module-5--isolation-forest-anomaly-detector)
9. [Module 6 — Risk Scoring Engine](#9-module-6--risk-scoring-engine)
10. [Module 7 — Decision Agent (FSM)](#10-module-7--decision-agent-fsm)
11. [Module 8 — Blockchain Evidence Logger](#11-module-8--blockchain-evidence-logger)
12. [Module 9 — Database Persistence](#12-module-9--database-persistence)
13. [Module 10 — Re-verification Audit](#13-module-10--re-verification-audit)
14. [Module 11 — Web Dashboard](#14-module-11--web-dashboard)
15. [Orchestration & Runtime](#15-orchestration--runtime)
16. [Safety Constraints](#16-safety-constraints)
17. [Configuration Reference](#17-configuration-reference)
18. [Mathematical Foundations Appendix](#18-mathematical-foundations-appendix)
19. [Glossary](#19-glossary)

---

## 1. Abstract

Ransomware encrypts user data faster than signature-based antivirus can react.
This project detects an attack while it is still in progress by fusing four
parallel detectors over a streaming feature pipeline:

1. **Shannon entropy** of file content (catches ciphertext randomness).
2. **Statistical drift** in filesystem behavior (Z-score, ADWIN, Page-Hinkley).
3. **Unsupervised ML anomaly detection** (Isolation Forest).
4. **Weighted fusion** into a single 0–100 risk score.

Sustained high-risk windows drive a finite-state machine through
`MONITORING → ALERT → RESPONDING → RECOVERING → MONITORING`, with real OS-level
defensive actions (Volume Shadow Copy snapshot, NTFS deny-write ACL on the
sandbox, suspicious-process suspension). Every confirmed alert is appended to a
SHA-256 hash-chained ledger that detects tampering. A Flask-based web dashboard
visualizes the live state and exposes operational controls.

A **post-attack re-verification audit** walks the sandbox after the burst and
explains, per file, which detectors caught it and which missed it — turning the
system from a black box into an explainable forensic instrument.

---

## 2. System Architecture

The pipeline is decomposed into 11 modules linked by append-only JSONL streams.
Each module can run standalone (each has a CLI entry point) or together as
daemon threads inside a single orchestrator process (`main.py`).

```
                             FILESYSTEM
                                 │
                                 ▼
         ┌───────────────────────────────────────────────┐
         │   Module 1   FileWatcher (watchdog + psutil)  │
         │   • create / modify / delete / rename events  │
         │   • IGNORE_FILES self-loop guard              │
         └───────────────────────────────────────────────┘
                                 │ event_stream.jsonl
                                 ▼
         ┌───────────────────────────────────────────────┐
         │   Module 2   FeatureExtractor (5 s windows)   │
         │   • Counter, defaultdict, sliding window      │
         │   • Time-driven daemon emits a vector even    │
         │     during quiet windows (heartbeat)          │
         └───────────────────────────────────────────────┘
                                 │ feature_stream.jsonl
        ┌────────────────────────┼─────────────────────────┐
        ▼                        ▼                         ▼
 ┌──────────────┐        ┌────────────────┐       ┌────────────────────┐
 │  Module 3    │        │   Module 4     │       │    Module 5        │
 │  Entropy     │        │   Drift        │       │    Isolation Forest│
 │  Analyzer    │        │   Detector     │       │    (sklearn)       │
 │              │        │  Z+ADWIN+PH    │       │  online training   │
 └──────────────┘        └────────────────┘       └────────────────────┘
        │                        │                         │
 entropy_alerts.jsonl   drift_stream.jsonl        iforest_stream.jsonl
        │                        │                         │
        └─────────────┬──────────┴─────────────────────────┘
                      ▼
         ┌────────────────────────────────────────────────┐
         │ Module 6  RiskScorer  (weighted fusion 0–100)  │
         └────────────────────────────────────────────────┘
                      │  risk_stream.jsonl
   ┌───────────┬──────┴────────────┬──────────────────┬────────────┐
   ▼           ▼                   ▼                  ▼            ▼
┌─────────┐ ┌──────────────┐ ┌────────────┐  ┌──────────────┐ ┌─────────┐
│ Mod 7   │ │ Mod 8        │ │ Mod 9 DB   │  │ Mod 11       │ │ Mod 10  │
│Decision │ │ Blockchain   │ │ Persist.   │  │ Dashboard    │ │ Re-     │
│Agent    │ │ Evidence     │ │ (SQLite)   │  │ (Flask + JS) │ │ verifier│
│ FSM     │ │ Logger SHA-256│ │            │  │ /api/status  │ │ on      │
│ icacls/ │ │ chain        │ │            │  │ port 5000    │ │ demand  │
│ VSS/    │ │              │ │            │  │              │ │         │
│ suspend │ │              │ │            │  │              │ │         │
└─────────┘ └──────────────┘ └────────────┘  └──────────────┘ └─────────┘
   │            │
   ▼            ▼
incidents.jsonl evidence_chain.jsonl  (tamper-evident, preserved across sessions)
```

### Why JSONL streams?

Streams between modules give:
- **Process isolation** — any module can run as its own process without code changes.
- **Replay-ability** — saved JSONL files can be re-fed into any downstream module for offline debugging.
- **Decoupling** — adding or replacing a detector requires no changes to upstream code.

When run via `main.py`, all modules share one Python process for convenience but communicate through the same JSONL contract.

---

## 3. Data Flow & Stream Schemas

| Stream | Producer | Consumer(s) | Schema (key fields) |
|---|---|---|---|
| `event_stream.jsonl` | FileWatcher | FeatureExtractor (callback), Entropy (callback) | `timestamp`, `event_type`, `file_path`, `file_size`, `process_id`, `process_name`, `dest_path?` |
| `feature_stream.jsonl` | FeatureExtractor | DriftDetector, IsolationForest, RiskScorer | window_start/end + 13 numeric features |
| `entropy_alerts.jsonl` | EntropyAnalyzer | RiskScorer, Reverifier | `file_path`, `entropy`, `alert ∈ {HIGH_ENTROPY, NORMAL}` |
| `drift_stream.jsonl` | DriftDetector | RiskScorer, Reverifier | `severity ∈ {NONE, LOW, MEDIUM, HIGH}`, `detectors_fired` |
| `iforest_stream.jsonl` | IsolationForest | RiskScorer, Reverifier | `anomaly`, `confidence`, `anomaly_score` |
| `risk_stream.jsonl` | RiskScorer | DecisionAgent, BlockchainLogger, DB sink, Dashboard | `score`, `level`, `entropy_flag`, sub-components |
| `incidents.jsonl` | DecisionAgent | Dashboard (`/api/status` reads last line for agent state) | `event`, `state`, `payload` |
| `reverification_report.jsonl` | Reverifier | Dashboard `/api/reverification` | full audit object |
| `evidence_chain.jsonl` | BlockchainLogger | Dashboard chain-valid indicator | hash-chained alert blocks |

Files marked **preserved across sessions**: `evidence_chain.jsonl`, `isolation_forest.pkl`. Everything else is truncated at orchestrator startup.

---

## 4. Module 1 — File Watcher

**File:** `monitoring/file_watcher.py`

### Purpose

Capture every create / modify / delete / rename event on the user's real
`Desktop`, `Documents`, `Downloads`, `Pictures` folders, plus the dedicated
sandbox directory.

### Architecture

Wrapper around the cross-platform [`watchdog`](https://pypi.org/project/watchdog/)
library. A single `_EventHandler` instance is scheduled against every monitored
directory with `recursive=True`. Events are normalized into a structured Python
dict and dispatched to two destinations simultaneously:

1. **In-process callbacks** registered via `watcher.add_event_callback(fn)`.
2. **Append-only JSONL stream** at `event_stream.jsonl`.

### Algorithm (pseudo-code)

```
on FileSystemEvent e:
    if e.is_directory:                   return
    if any IGNORE_FILE in e.src_path:    return        # self-loop guard
    if should_ignore_event(e.src_path):  return        # noise filter
    target_path = e.dest_path or e.src_path
    pname, pid = _get_process_info(target_path)        # currently O(1)
    file_size  = os.path.getsize(target_path) or -1
    event = { timestamp, event_type, file_path, file_size,
              process_id, process_name, dest_path? }
    for cb in callbacks: cb(event)
    append json(event) + '\n' to event_stream.jsonl
```

### Filtering

| Filter | Members |
|---|---|
| `IGNORED_DIRECTORIES` | `.git`, `__pycache__`, `venv`, `.venv`, `node_modules`, `AppData`, `ProgramData`, `Windows`, `$Recycle.Bin` |
| `IGNORED_EXTENSIONS` | `.lock`, `.tmp`, `.log`, `.cache`, `.pyo`, `.pyc` |
| `IGNORED_FILENAME_PATTERNS` | `~$` (Office temp), `.temp`, `.swp` |
| `IGNORE_FILES` (self-loop guard) | `event_stream.jsonl`, `feature_stream.jsonl`, `entropy_alerts.jsonl`, `risk_stream.jsonl`, `drift_stream.jsonl`, `iforest_stream.jsonl`, `incidents.jsonl`, `evidence_chain.jsonl`, `ransomware_monitor.db`, `ransomware_monitor.db-journal` |

### Process Attribution

Returns `("unknown", -1)` immediately. The previous implementation used
`psutil.process_iter(["pid","name","open_files"])` per event, which on Windows
takes ≥ 100 ms per event because most processes raise `AccessDenied` for
`open_files()` without admin. Under bursty load this overflowed watchdog's
`ReadDirectoryChangesW` buffer and dropped ~95% of events.

Accurate per-event attribution requires OS audit logs (ETW on Windows, fanotify
on Linux, auditd) which are out of scope here.

### Output schema

```json
{
  "timestamp":    "2026-04-29T11:25:21.573620+00:00",
  "event_type":   "renamed",
  "file_path":    "C:\\Users\\Lenovo\\Documents\\ransomware_test\\doc_xyz.jpg",
  "file_size":    4838,
  "process_id":   -1,
  "process_name": "unknown",
  "dest_path":    "C:\\Users\\Lenovo\\Documents\\ransomware_test\\doc_xyz.jpg.locked"
}
```

---

## 5. Module 2 — Feature Extractor

**File:** `features/feature_extractor.py`

### Purpose

Convert raw, high-frequency file events into normalized statistical feature
vectors over fixed time windows.

### Architecture

Time-driven sliding-window aggregator. A background daemon thread closes a
**5-second** window on every tick:

```
every 1 second:
    if now ≥ window_start + window_seconds:
        compute features over buffered events
        emit feature vector  (callbacks + stream file)
        clear buffer; window_start = now
```

Empty windows still emit a zero-activity vector — downstream detectors get a
heartbeat regardless of activity.

### Features computed per window

| Category | Feature | Symbol |
|---|---|---|
| Activity | files_created, files_modified, files_deleted, rename_count | $c, m, d, r$ |
| Burst | total_file_events, write_rate | $T = c+m+d+r$, $R$ |
| Diversity | unique_file_types, directories_touched | $\|E\|, \|D\|$ |
| Process | unique_process_count, files_touched_per_process | $\|P\|, \bar f$ |
| Statistical | average_file_size, max_file_size, min_file_size | $\bar s, s_{max}, s_{min}$ |

### Mathematical formulas

$$
R = \frac{T}{w} \quad \text{(write rate; }w\text{ = window seconds)}
$$

$$
\bar s = \frac{1}{n} \sum_{i=1}^{n} s_i \quad \text{(mean file size)}
$$

$$
\sigma_s^2 = \frac{1}{n} \sum_{i=1}^{n} (s_i - \bar s)^2 \quad \text{(variance)}
$$

$$
\bar f = \frac{1}{|P|} \sum_{p \in P} |\{f : \text{process}(f) = p\}|
$$

$$
H_{\text{ext}} = -\sum_{e \in E} p(e) \log_2 p(e), \quad p(e) = \frac{\text{count}(e)}{n}
$$

### Output schema

```json
{
  "window_start": "2026-04-29T10:39:00.000+00:00",
  "window_end":   "2026-04-29T10:39:05.000+00:00",
  "files_created": 28, "files_modified": 199, "files_deleted": 0,
  "rename_count": 90, "total_file_events": 317, "write_rate": 28.9,
  "unique_file_types": 7, "directories_touched": 1,
  "unique_process_count": 1, "files_touched_per_process": 45.0,
  "average_file_size": 3759.97, "max_file_size": 6230, "min_file_size": 0
}
```

---

## 6. Module 3 — Entropy Analyzer

**File:** `entropy/entropy_analyzer.py`

### Purpose

Detect ciphertext-quality randomness in file contents. Encrypted files have
near-uniform byte distributions, pushing Shannon entropy close to its
theoretical maximum of 8 bits/byte.

### Shannon entropy

For a file with byte counts $c_x$ where $x \in \{0..255\}$ and total $N = \sum c_x$:

$$
H(X) = - \sum_{x=0}^{255} p(x) \log_2 p(x), \quad p(x) = \frac{c_x}{N}
$$

| Content type | Typical $H$ |
|---|---|
| English text | 3.0 – 5.0 |
| Office docs (uncompressed XML) | 5.0 – 6.5 |
| JPEG / MP3 / ZIP / DOCX (compressed) | 7.0 – 7.8 |
| AES / ChaCha20 ciphertext | 7.9 – 8.0 |

### Algorithm

```
analyze_file(path):
    if path has SUSPICIOUS_SUFFIX (.locked, .crypto, ...): proceed
    elif extension in NATURALLY_HIGH_ENTROPY_EXTENSIONS:    skip with reason
    read in 1 MB chunks; update Counter[byte] += 1
    H = sum( p · log2(p) for p in count/N if p > 0 ) * -1
    return { entropy: H, entropy_flag: H > 7.2 }
```

### Threshold and whitelist

- `DEFAULT_THRESHOLD = 7.2` bits/byte. Catches genuine ciphertext
  (~7.99) without false-flagging compressed media (~7.0–7.8).
- `NATURALLY_HIGH_ENTROPY_EXTENSIONS` = `{ .png, .jpg, .jpeg, .gif, .webp,
  .heic, .bmp, .mp3, .mp4, .mov, .avi, .mkv, .webm, .m4a, .flac, .zip, .gz,
  .7z, .rar, .tar, .bz2, .xz, .lz4, .iso, .dmg, .docx, .xlsx, .pptx, .odt,
  .ods, .odp, .pdf }`.
- `SUSPICIOUS_SUFFIXES` = `{ .locked, .crypto, .crypted, .enc, .encrypted,
  .aes, .cipher, .cryp, .pay, .ransom }`.
- A file with a suspicious suffix is **always** analyzed, even if its base
  extension is on the whitelist — so `.png.locked` is examined while plain
  `.png` is skipped.

### Output

Each handled event appends a record to `entropy_alerts.jsonl`:

```json
{ "timestamp": "...", "file_path": "...", "entropy": 7.9586,
  "alert": "HIGH_ENTROPY" }
```

---

## 7. Module 4 — Behavioral Drift Detector

**File:** `drift/drift_detector.py`

### Purpose

Flag windows whose feature vector deviates from recent baseline behavior. Three
algorithms run in parallel — the more that agree, the higher the severity.

### Monitored features

```python
MONITORED_FEATURES = [
    "write_rate", "files_modified", "rename_count",
    "files_touched_per_process", "directories_touched",
]
```

### (a) Z-Score — sudden statistical spike

Maintain a rolling history $\mathcal{H}$ of the last 30 values per feature.

$$
\mu = \frac{1}{|\mathcal{H}|} \sum_{x \in \mathcal{H}} x
\qquad
\sigma = \sqrt{\frac{1}{|\mathcal{H}|-1} \sum_{x \in \mathcal{H}} (x - \mu)^2}
$$

$$
z = \frac{x_{\text{current}} - \mu}{\sigma}
$$

Fire if $|z| > 3.0$. Requires $|\mathcal{H}| \ge 10$ before activating;
stdev of fewer points has too much variance to be statistically meaningful.

### (b) ADWIN — Adaptive Windowing

From `river.drift.ADWIN`. Maintains an internal history of observations and
splits it into two contiguous sub-windows $W_0, W_1$ of sizes $n_0, n_1$ with
empirical means $\mu_0, \mu_1$. Drift declared when:

$$
| \mu_0 - \mu_1 | > \varepsilon, \qquad
\varepsilon = \sqrt{ \frac{1}{n_0} + \frac{1}{n_1} } \cdot \sqrt{2 \ln \frac{2}{\delta}}
$$

with confidence parameter $\delta$ (default 0.002). On detection, the older
sub-window is dropped — the algorithm self-adapts to non-stationary data.

### (c) Page-Hinkley — gradual cumulative drift

Tracks the cumulative deviation above the running minimum:

$$
S_n = \sum_{i=1}^{n} (x_i - \delta), \qquad
m_n = \min_{1 \le k \le n} S_k
$$

$$
PH_n = S_n - m_n
$$

Drift declared when $PH_n > \lambda$ (threshold $\lambda = 50.0$,
$\delta = 0.005$). Catches "low and slow" attacks that don't trip
Z-score's spike detector.

### Severity ladder

| Detectors fired | Severity |
|:---:|---|
| 0 | NONE |
| 1 | LOW |
| 2 | MEDIUM |
| 3 | HIGH |

### Idle-window suppression

When **all** monitored features are exactly zero, all detector flags are forced
off regardless of internal state. Page-Hinkley CUSUM accumulates noise on long
zero-streams and would otherwise produce spurious LOW alerts during idle
periods.

### Output

```json
{ "timestamp": "...", "window": 92, "drift_detected": true,
  "severity": "MEDIUM", "detectors_fired": 2,
  "z_score_alert": false, "adwin_alert": true, "page_hinkley_alert": true,
  "top_feature": "rename_count", "top_z_score": 4.2,
  "write_rate": 28.9, "files_modified": 199, "rename_count": 90 }
```

---

## 8. Module 5 — Isolation Forest Anomaly Detector

**File:** `anomaly_detection/isolation_forest.py`

### Purpose

Unsupervised ML detection of feature-vector anomalies that the rule-based
detectors miss — specifically, **unusual combinations** of features that no
single feature flags individually.

### How Isolation Forest works

The algorithm builds an ensemble of $T$ random binary trees over a sample of
the data. To "isolate" a point, the tree picks a random feature and a random
split value; the point's path length to a leaf is short for outliers
(quickly isolated) and long for inliers (deep in the tree).

For a point $x$ across $T$ trees with average path length $E[h(x)]$:

$$
s(x, n) = 2^{-\frac{E[h(x)]}{c(n)}}
$$

where $c(n) = 2 H(n-1) - \frac{2(n-1)}{n}$ is the average path length of an
unsuccessful BST search, and $H(i) = \ln(i) + \gamma$ is the harmonic number.

Score interpretation:
- $s \approx 1$ → strong anomaly
- $s \approx 0.5$ → ambiguous
- $s \ll 0.5$ → strong inlier

### Implementation

```python
IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
```

- **Online training**: collects the first 50 feature vectors from
  `feature_stream.jsonl`, fits the model, persists it to
  `isolation_forest.pkl`.
- **Inference** post-training: for each new vector, returns
  $\{anomaly, anomaly\_score, confidence\}$ where:

$$
\text{confidence} = \mathrm{clip}\left( \frac{1}{1 + e^{5 \cdot \text{raw}}}, 0, 1 \right)
$$

(sigmoid of the raw `decision_function` output, mapped so higher = more
anomalous).

- **Feature vector** for inference (5 features):
```
[ write_rate, files_modified, rename_count,
  files_touched_per_process, directories_touched ]
```

### Output

```json
{ "anomaly": true, "anomaly_score": -0.12, "confidence": 0.65,
  "timestamp": "..." }
```

---

## 9. Module 6 — Risk Scoring Engine

**File:** `risk_engine/risk_scorer.py`

### Purpose

Fuse all detector signals into a single 0–100 risk score that drives the agent.

### Architecture

Tails four streams in parallel:
- `feature_stream.jsonl` (drives the cadence — one score per window)
- `entropy_alerts.jsonl` (state update)
- `drift_stream.jsonl` (state update)
- `iforest_stream.jsonl` (state update)

Per loop iteration: drain **all** pending lines from each state-update stream
(critical — the previous one-line-per-iteration approach lagged 30 seconds
behind during bursts), then read one feature vector and compute a score.

### Score formula

$$
\text{score} =
\underbrace{25 \cdot \mathbb{1}_{\text{entropy}}}_{\text{cipher detected}} +
\underbrace{20 \cdot \min\!\left(\frac{R}{20}, 1\right)}_{\text{write burst}} +
\underbrace{20 \cdot \min\!\left(\frac{r}{30}, 1\right)}_{\text{rename burst}} +
\underbrace{20 \cdot d}_{\text{drift}} +
\underbrace{15 \cdot c_{\text{IF}}}_{\text{ML anomaly}}
$$

where:
- $\mathbb{1}_{\text{entropy}} \in \{0, 1\}$: at least one HIGH_ENTROPY alert in last 60 s
- $R$ = write rate (events/sec), $r$ = rename count this window
- $d \in \{0.0, 0.3, 0.6, 1.0\}$ for drift severity NONE/LOW/MEDIUM/HIGH
- $c_{\text{IF}} \in [0, 1]$: smoothed IsolationForest confidence

Maximum value = 100 by construction.

### Level mapping

| score | level |
|:---:|---|
| `< 30` | NORMAL |
| `30 – 59` | SUSPICIOUS |
| `60 – 79` | HIGH_RISK |
| `≥ 80` | CRITICAL |

### Entropy flag TTL

A single high-entropy file shouldn't pin the score forever. The flag decays:

$$
\mathbb{1}_{\text{entropy}} = \begin{cases}
1 & \text{if last entropy alert within last 60 s} \\
0 & \text{otherwise}
\end{cases}
$$

### IF confidence smoothing

To avoid flicker:

$$
c_{\text{IF}}^{(t+1)} = \begin{cases}
\text{confidence}_t & \text{if anomaly}_t \\
\max\!\left(0, c_{\text{IF}}^{(t)} - 0.1\right) & \text{otherwise}
\end{cases}
$$

Each computed score is appended to `risk_stream.jsonl` and inserted into the
SQLite `risk_scores` table by the `RiskDbSinkThread`.

---

## 10. Module 7 — Decision Agent (FSM)

**File:** `agent/decision_agent.py`

### Purpose

Drive automated defensive response based on **sustained** risk signals. A
finite-state machine prevents knee-jerk reactions to a single spike.

### State diagram

```
            first HIGH_RISK / CRITICAL
   MONITORING ──────────────────────────────► ALERT
       ▲                                       │
       │   3 below-30 windows                  │ 2 consecutive HIGH wins
       │   (decay path)                        │
       │                                       ▼
       │                                  RESPONDING
       │                                       │
       │   5 quiet windows                     │ 3 below-30 wins
       │                                       ▼
   MONITORING  ◄────────────────────────  RECOVERING
                                               │
                                               │ risk rises again
                                               ▼
                                           ALERT
```

### Side effects per transition

| Transition | Action |
|---|---|
| `MONITORING → ALERT` | Log warning banner + `_take_vss_snapshot()` (Volume Shadow Copy of `C:\` for rollback capability) |
| `ALERT → RESPONDING` | `_lock_sandbox()` (icacls deny on sandbox) + `_suspend_suspicious_processes()` (psutil.suspend all tracked names) |
| `RESPONDING → RECOVERING` | `_unlock_sandbox()` + `_resume_suspended_processes()` |
| `RECOVERING → MONITORING` | Log only; FSM resets counters |
| `ALERT → MONITORING` (decay) | Log only; FSM resets counters |

### Lock/unlock implementation (Windows)

```bash
# Lock
icacls <sandbox> /deny "Everyone:(W,D,DC)" /T

# Unlock
icacls <sandbox> /remove:d Everyone /T
```

`/T` applies recursively. The deny ACE blocks Write, Delete, and
DeleteSubdirectoriesAndFiles for the `Everyone` group, including the
ransomware process attempting to encrypt new files.

### Linux fallback

Walks the directory and clears write bits via `chmod`:

```python
m = target.stat().st_mode
target.chmod(m & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
```

### VSS snapshot

```bash
wmic shadowcopy call create Volume='C:\\'
```

Creates a system-level shadow copy of the `C:` drive. If files were destroyed
before the agent reacted, they can be recovered from this snapshot. Failure is
logged but does not block the FSM transition.

### Process suspension

```python
import psutil
for proc in psutil.process_iter(["pid", "name"]):
    if proc.info["name"] in suspicious_names:
        proc.suspend()
        suspended_pids.append(proc.info["pid"])
```

`suspicious_names` comes from a callback (`process_names_getter`) that returns
the set of non-Python process names the watcher has recently seen modify files.
On Windows without admin, this set is usually empty (events report
`process_name = "unknown"`); the agent logs a warning rather than killing the
wrong process.

### Persistence

Every state transition is appended to `incidents.jsonl`:

```json
{ "timestamp": "...", "event": "RESPONDING", "state": "RESPONDING",
  "payload": { "score": 78.0, "level": "HIGH_RISK", ... } }
```

The dashboard's `/api/status` endpoint reads the **last line** to render the
current agent state badge.

---

## 11. Module 8 — Blockchain Evidence Logger

**File:** `blockchain/evidence_logger.py`

### Purpose

Tamper-evident, append-only forensic ledger of every confirmed alert. Any
retroactive edit to a past block invalidates the chain.

### Block schema

```json
{
  "index":        N,
  "timestamp":    "...",
  "alert_type":   "RISK_SCORE",
  "severity":     "HIGH_RISK",
  "payload":      { ...risk_record... },
  "payload_hash": "sha256(payload, sort_keys)",
  "prev_hash":    "sha256 of previous block",
  "block_hash":   "sha256(everything above)"
}
```

### Hashing

- Payload hash:
$$
H_p = \mathrm{SHA256}\bigl(\mathrm{JSON}_{\text{sorted}}(\text{payload})\bigr)
$$

- Block hash:
$$
H_b = \mathrm{SHA256}\bigl(\mathrm{JSON}_{\text{sorted}}(\text{block} \setminus \{block\_hash\})\bigr)
$$

- Chain link:
$$
\text{block}_n.\text{prev\_hash} = \text{block}_{n-1}.\text{block\_hash}
$$

Tampering with any field of any block changes its `block_hash`, breaking the
`prev_hash` reference of every subsequent block — the entire suffix becomes
detectably invalid.

### Tip cache (O(1) appends)

```python
def __init__(self):
    self._last_hash = "0" * 64
    self._next_index = 0
    self._load_chain_tip()       # read only the LAST line of the file

def add_alert(self, ...):
    block = { "index": self._next_index, "prev_hash": self._last_hash, ... }
    block["block_hash"] = sha256(...)
    append_line(block)
    self._last_hash = block["block_hash"]
    self._next_index += 1
```

The previous implementation re-read the entire chain on every append — O(n)
per write — which became progressively slow as the ledger grew.

### Verification

```python
def verify_chain():
    expected_prev = "0" * 64
    for block in blocks_in_order:
        assert block.prev_hash == expected_prev
        assert block.payload_hash == sha256(payload)
        assert block.block_hash == sha256(block - {block_hash})
        expected_prev = block.block_hash
    return True
```

The dashboard calls this at most every 30 s (cached) and renders a green
"Chain Valid" indicator if true, red "Chain Invalid" otherwise.

---

## 12. Module 9 — Database Persistence

**File:** `database/db_manager.py`

### Purpose

Persistent storage for the dashboard's history queries.

### Schema

```sql
CREATE TABLE file_events(
    id INTEGER PRIMARY KEY,
    timestamp TEXT, event_type TEXT,
    file_path TEXT, file_size INTEGER, process_name TEXT
);

CREATE TABLE drift_alerts(
    id INTEGER PRIMARY KEY,
    timestamp TEXT, severity TEXT,
    top_feature TEXT, top_z_score REAL,
    write_rate REAL, rename_count INTEGER,
    detectors_fired INTEGER
);

CREATE TABLE risk_scores(
    id INTEGER PRIMARY KEY,
    timestamp TEXT, score REAL, level TEXT,
    entropy_flag INTEGER, triggered_response INTEGER
);

CREATE TABLE entropy_alerts(
    id INTEGER PRIMARY KEY,
    timestamp TEXT, file_path TEXT,
    entropy REAL, threshold REAL
);
```

### Concurrency

Single SQLite connection (`check_same_thread=False`) guarded by a single
`threading.Lock`. All writes serialize through the lock; reads also acquire it.

### Pruning

```python
def prune_table(table, max_records=10_000):
    DELETE FROM {table}
    WHERE id NOT IN (SELECT id FROM {table} ORDER BY id DESC LIMIT ?)
```

A `DbPrunerThread` runs every 10 minutes and trims each table to the last
10 000 rows. Calling `prune_table(.., 0)` clears a table entirely — used by
the orchestrator's session-reset path and the `/api/reset_session` endpoint.

---

## 13. Module 10 — Re-verification Audit

**File:** `verification/reverifier.py`

### Purpose

After an attack ends, walk the sandbox and identify which `.locked` files the
detection pipeline caught vs. missed, with **per-detector reasons** for any
miss.

### Algorithm

```
audit():
    locked = list every *.locked file in sandbox
    entropy_records = read entropy_alerts.jsonl
    drift_records   = read drift_stream.jsonl
    iforest_records = read iforest_stream.jsonl
    for each f in locked:
        f_mtime = mtime of f
        # ENTROPY: per-file path lookup
        ent = lookup f.path in entropy_records
        entropy_caught = ent.alert == "HIGH_ENTROPY"
        # DRIFT: temporal correlation, MEDIUM/HIGH only
        drift_caught = exists d in drift_records with
                       d.severity in {MEDIUM,HIGH}
                       and |d.timestamp - f_mtime| ≤ 15s
        # IF: temporal correlation
        iforest_caught = exists r in iforest_records with
                         r.anomaly == True
                         and |r.timestamp - f_mtime| ≤ 15s
        if any caught: add to caught[]
        else:           add to missed[] with reasons
    return { total, caught, missed, coverage_pct, ... }
```

### Why only MEDIUM/HIGH drift counts

LOW drift fires routinely from Page-Hinkley CUSUM noise on near-idle
baselines. Counting LOW alerts as "catching" a file would mark every locked
file as caught regardless — including decoy files we explicitly created to
demonstrate misses. MEDIUM/HIGH require ≥ 2 detectors to agree, which
corresponds to a real burst.

### Per-detector miss reasons

| Condition | Reason text |
|---|---|
| No entropy record for path | "entropy: no alert recorded — file may have been renamed/deleted before the analyzer could read it" |
| Entropy `skipped_reason` set | "entropy: skipped (naturally_high_entropy_extension) — extension is on the whitelist" |
| Entropy error | "entropy: read error (\<error\>)" |
| Entropy below threshold | "entropy: 3.4 bits/byte was below threshold 7.2 — file content was not random enough to flag" |
| Drift fired but not near file | "drift: detectors fired Nx this session but none within ±15s of this file" |
| No drift this session | "drift: no detector fired during this session — activity volume may have been below the burst threshold" |
| IF fired but not near file | "iforest: flagged N anomalies this session but none within ±15s of this file" |
| IF model untrained | "iforest: no anomaly flagged — model may still be in training phase (needs 50 samples)" |

### Output

```json
{
  "timestamp": "...",
  "total_locked_files": 36,
  "caught_count": 35, "missed_count": 1, "coverage_percent": 97.2,
  "detector_summary": { "entropy_alerts_high": 154,
                        "drift_alerts_fired": 4,
                        "iforest_anomalies": 1 },
  "missed_files": [
    { "file_path": "...decoy_xxx.txt.locked", "size": 5580,
      "caught_by": { "entropy": false, "drift": false, "iforest": false },
      "reasons": [ "entropy: 3.39 bits/byte ...",
                   "drift: detectors fired 4x this session ...",
                   "iforest: ..." ] }
  ]
}
```

The dashboard renders this as the **Re-verification Report** card.

---

## 14. Module 11 — Web Dashboard

**Files:** `dashboard/app.py` + `dashboard/index.html`

### Architecture

- **Backend**: Flask app, single-process, registered as a daemon thread inside `main.py` on port 5000.
- **Frontend**: Vanilla HTML + JS + Chart.js (CDN), no build step. One `index.html` served from `/`.

### REST API

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/` | – | `index.html` |
| GET | `/api/status` | – | full payload (current_risk_score, current_level, agent_state, recent_alerts, risk_history, chain_valid, simulator state, pipeline counters) |
| POST | `/api/simulate` | `{ mode, count, duration }` | `{ ok, mode }` |
| POST | `/api/stop_simulation` | – | `{ ok, stopped_mode }` (signals simulator's stop_event; auto-cleanup follows) |
| GET | `/api/reverification` | – | latest audit report |
| POST | `/api/reverify_now` | – | runs audit on demand |
| POST | `/api/inject_decoy_missed` | – | drops a low-entropy `.locked` file in sandbox so audit reports a missed detection |
| POST | `/api/reset_session` | – | clears DB tables + JSONL streams, preserves blockchain ledger and ML model |

### `/api/status` payload

```json
{
  "current_risk_score": 41.6,
  "current_level": "SUSPICIOUS",
  "agent_state": "RESPONDING",
  "last_entropy_flag": 1,
  "recent_alerts": [...drift alerts...],
  "risk_history": [...recent scores for chart...],
  "chain_valid": true,
  "simulator_running": false,
  "simulator_mode": "ransomware",
  "simulator_started_at": "...",
  "simulator_last_error": null,
  "simulator_last_defense": "🛡 Defense activated mid-attack — ...",
  "pipeline": { "file_events_total": 1108,
                "risk_scores_total": 17,
                "entropy_alerts_total": 546,
                "iforest_trained": true }
}
```

### Frontend cards

| Card | Content |
|---|---|
| Current Risk | Color-coded conic-gradient gauge (green/amber/orange/red), level badge, entropy flag |
| Agent and Integrity | State badge with state-specific color, blockchain Chain Valid indicator, risk-history line chart |
| Detection Pipeline | KPI 2×2 grid (file events, risk scores, entropy alerts, ML model status) |
| Live Simulation | Mode dropdown, count, duration, Start / Stop & Cleanup buttons, status row |
| Recent Drift Alerts | Table with color-coded severity pills and local-time timestamps |
| Re-verification Report | Total/caught/missed counts, coverage %, detector hits, missed-files table with reasons, Inject Decoy + Run Now buttons |

### Polling cadence

- `/api/status` every **5 s**.
- `/api/reverification` every **7 s**.

### UX details

- Pulse animation on counter changes (`.updated` class with `pulse-soft` keyframe)
- Card hover lift (translateY + deeper shadow)
- Severity pills color-coded LOW/MEDIUM/HIGH
- Agent state badge color-coded MONITORING/ALERT/RESPONDING/RECOVERING
- Local-time timestamps everywhere (was UTC)
- Confirm dialog on Reset Session
- Defense-success message replaces error-text when `PermissionError` came from sandbox path

---

## 15. Orchestration & Runtime

**File:** `main.py`

### Single-command launch

```bash
python main.py
# or with auto-simulation
python main.py --simulate ransomware --sim-count 50
```

### Threads spawned

| Thread | Purpose |
|---|---|
| FileWatcherFeatureEntropyThread | Modules 1 + 2 + 3 |
| DriftDetectorThread | Module 4 |
| IsolationForestThread | Module 5 (online training + detection) |
| RiskScorerThread | Module 6 |
| DecisionAgentThread | Module 7 |
| EvidenceLoggerThread | Module 8 |
| RiskDbSinkThread | Persists risk_stream → SQLite |
| DashboardThread | Flask on `127.0.0.1:5000` |
| DbPrunerThread | Trims DB tables every 10 min |
| RansomwareSimulatorThread | Optional, only if `--simulate` |

### Session reset at startup

The orchestrator truncates the following so each session starts clean:
- `event_stream.jsonl`, `feature_stream.jsonl`, `entropy_alerts.jsonl`
- `risk_stream.jsonl`, `drift_stream.jsonl`, `iforest_stream.jsonl`
- `incidents.jsonl`, `reverification_report.jsonl`
- All four operational SQLite tables

It then seeds the dashboard's first poll:
- A `risk_score(0, NORMAL)` row in SQLite.
- A `MONITORING` entry in `incidents.jsonl`.

**Preserved across sessions** (intentional — these are accumulated artifacts):
- `evidence_chain.jsonl` (blockchain ledger)
- `isolation_forest.pkl` (trained ML model)

### Standalone CLIs

Each module can run alone for testing:

```bash
python monitoring/file_watcher.py
python features/feature_extractor.py --mode realtime --window 5
python entropy/entropy_analyzer.py [path]
python drift/drift_detector.py --mode demo
python anomaly_detection/isolation_forest.py --mode demo
python risk_engine/risk_scorer.py --mode demo
python agent/decision_agent.py --mode demo
python blockchain/evidence_logger.py --demo
python verification/reverifier.py
python testing/ransomware_simulator.py --mode ransomware --count 50
python testing/ransomware_simulator.py --cleanup
```

---

## 16. Safety Constraints

The DecisionAgent's RESPONDING state takes real OS-level actions. Several
constraints prevent accidental damage:

1. **`monitored_paths` for the agent is restricted to the sandbox in
   `main.py`, not the real user folders.** Locking real Desktop / Documents
   / Downloads / Pictures with `icacls /deny Everyone:(W,D,DC) /T` would
   render them inaccessible from File Explorer until manually unlocked. The
   watcher still observes those folders for detection, but defensive locking
   only ever applies to `~/Documents/ransomware_test/`.

2. **VSS snapshot failure is non-fatal.** It's a best-effort recovery
   capability; if `wmic shadowcopy` is unavailable or returns non-zero, the
   FSM still proceeds.

3. **Process suspension is permission-gated.** `psutil.Process.suspend()`
   requires elevated privileges on Windows for processes outside the user's
   session. If `process_names_getter()` returns an empty set, the agent
   logs a warning and skips suspension rather than killing the wrong
   process.

4. **Inject Decoy auto-recovers from lingering deny ACEs.** If a previous
   session left the sandbox locked and the new session writes a decoy, the
   first write fails with PermissionError. The endpoint then runs
   `icacls /remove:d Everyone /T` and retries once.

5. **Defense-triggered PermissionError is reframed as success.** If the
   simulator's encryption write fails *because* the agent locked the sandbox
   mid-attack, that's exactly the system's intended behavior. The dashboard
   shows "🛡 Defense activated mid-attack" in green rather than a red
   "Last run error" message.

---

## 17. Configuration Reference

Every tunable constant in one table:

| File | Constant | Value | Effect |
|---|---|---|---|
| `monitoring/file_watcher.py` | `IGNORED_DIRECTORIES` | (10 names) | Skip these directory components |
| | `IGNORED_EXTENSIONS` | (6 extensions) | Skip these file types |
| | `IGNORE_FILES` | (10 filenames) | Skip the project's own JSONL/DB |
| `features/feature_extractor.py` | `window_seconds` | 5 | Feature window size |
| `entropy/entropy_analyzer.py` | `DEFAULT_THRESHOLD` | 7.2 | bits/byte for HIGH_ENTROPY flag |
| | `DEFAULT_CHUNK_SIZE` | 1 048 576 | 1 MB I/O chunk |
| | `NATURALLY_HIGH_ENTROPY_EXTENSIONS` | 32 entries | Skip-list |
| | `SUSPICIOUS_SUFFIXES` | 10 entries | Always-analyze override |
| `drift/drift_detector.py` | `Z_THRESHOLD` | 3.0 | Z-score firing |
| | `MIN_BASELINE_WINDOWS` | 10 | Warmup before Z-score active |
| | `HISTORY_SIZE` | 30 | Rolling history depth |
| | `PH_THRESHOLD` | 50.0 | Page-Hinkley λ |
| | `_PageHinkley.delta` | 0.005 | PH δ |
| `anomaly_detection/isolation_forest.py` | `min_samples` | 50 | Online-training threshold |
| | `contamination` | 0.05 | Expected outlier fraction |
| | `n_estimators` | 200 | Number of trees |
| `risk_engine/risk_scorer.py` | weight (entropy) | 25 | |
| | weight (write_rate) | 20 | saturates at R = 20 |
| | weight (rename_count) | 20 | saturates at r = 30 |
| | weight (drift) | 20 | × DRIFT_MAP value |
| | weight (iforest) | 15 | × confidence |
| | `_entropy_ttl_seconds` | 60 | Flag decay |
| | `DRIFT_MAP` | NONE 0, LOW 0.3, MED 0.6, HIGH 1.0 | |
| | level breakpoints | 30 / 60 / 80 | NORMAL / SUSPICIOUS / HIGH_RISK / CRITICAL |
| `agent/decision_agent.py` | ALERT trigger | first HIGH_RISK or CRITICAL | |
| | RESPONDING trigger | 2 consecutive HIGH wins | |
| | RECOVERING trigger | 3 wins below 30 | |
| | RECOVERING → MONITORING | 5 quiet wins | |
| | ALERT → MONITORING (decay) | 3 wins below 30 | |
| `verification/reverifier.py` | `TEMPORAL_WINDOW_SECONDS` | 15.0 | mtime ± window for drift/IF |
| | `DRIFT_CATCH_SEVERITIES` | {MEDIUM, HIGH} | |
| `database/db_manager.py` | DbPruner interval | 600 s | |
| | per-table retention | 10 000 | |

---

## 18. Mathematical Foundations Appendix

### 18.1 Shannon entropy

For a discrete random variable $X$ with values in alphabet $\mathcal{A}$ and
probability mass $p(x) = \Pr[X = x]$:

$$
H(X) = -\sum_{x \in \mathcal{A}} p(x) \log_2 p(x)
$$

For 8-bit bytes ($|\mathcal{A}| = 256$):

$$
0 \le H(X) \le \log_2 256 = 8 \text{ bits/byte}
$$

The maximum is attained iff $p(x) = 1/256$ for all $x$ (uniform distribution),
which is exactly what symmetric ciphers asymptotically produce.

### 18.2 Z-score

For a sample $\{x_1, \ldots, x_n\}$ with sample mean $\mu$ and sample standard
deviation $\sigma$:

$$
z_i = \frac{x_i - \mu}{\sigma}
$$

Under the assumption that $X \sim \mathcal{N}(\mu, \sigma^2)$ (approximately
true for many filesystem metrics on stationary baselines):

$$
\Pr[\,|z| > 3\,] \approx 0.0027
$$

So the false-positive rate at threshold 3 is ~0.27% per feature per window.

### 18.3 ADWIN test statistic

Given two adjacent sub-windows of an observed sequence with sizes $n_0, n_1$
and means $\mu_0, \mu_1$, ADWIN declares a distributional change with confidence
$1 - \delta$ when:

$$
| \mu_0 - \mu_1 | \;>\; \varepsilon_{\text{cut}}(n_0, n_1, \delta)
$$

with the Hoeffding-style bound:

$$
\varepsilon_{\text{cut}} = \sqrt{\frac{1}{2 m} \ln \frac{4}{\delta}},
\qquad m = \frac{1}{1/n_0 + 1/n_1}
$$

(or equivalently the form used in the reference paper; `river`'s
implementation follows Bifet & Gavaldà 2007).

### 18.4 Page-Hinkley CUSUM

Given a stream $x_1, x_2, \ldots$ with hypothesized clean mean $\mu_0$ and a
minimum detectable shift $\delta$ (allowable noise):

$$
S_n = \sum_{i=1}^{n} (x_i - \mu_0 - \delta)
$$

$$
m_n = \min_{1 \le k \le n} S_k
$$

$$
PH_n = S_n - m_n
$$

Drift declared when $PH_n > \lambda$ (chosen threshold). Sensitive to gradual
upward drift even when no individual sample exceeds the Z-score threshold.

### 18.5 Isolation Forest path-length anomaly score

Build $T$ random binary trees on subsamples of size $\psi$. For a query point $x$,
compute the average path length $E[h(x)]$ across trees. Define:

$$
c(\psi) = 2 H(\psi - 1) - \frac{2(\psi - 1)}{\psi},
\qquad H(i) = \ln(i) + \gamma_{\text{Euler}}
$$

The anomaly score:

$$
s(x) = 2^{-\frac{E[h(x)]}{c(\psi)}}
$$

Interpretation:
- $s(x) \to 1$ → strong anomaly (short isolation path)
- $s(x) \to 0.5$ → ambiguous
- $s(x) \to 0$ → strong inlier

### 18.6 SHA-256 hash chain integrity

Define $H : \{0,1\}^* \to \{0,1\}^{256}$ as SHA-256. For block sequence
$B_0, B_1, \ldots, B_n$ where each $B_i$ contains its own hash $h_i$ and a
reference $p_i$ to the previous hash:

$$
\text{valid} \iff \forall i \ge 1:\ p_i = h_{i-1}
\;\wedge\; h_i = H(B_i \setminus \{h_i\})
$$

Tampering with field $f$ in block $B_k$ changes $h_k$, which by the chain
property invalidates every block $B_j$ for $j \ge k$. The probability of
constructing a colliding tampered block under SHA-256 is $\le 2^{-128}$ per
attempt (negligible).

### 18.7 Logistic confidence smoothing

To map the IsolationForest raw `decision_function` output $r$ (centered near 0,
negative for anomalies) to a $[0,1]$ confidence:

$$
c = \sigma(5 r) = \frac{1}{1 + e^{-5r}}
$$

The factor 5 sharpens the slope. Higher $r$ ⇒ closer to 1 (anomaly), lower $r$
⇒ closer to 0 (normal).

---

## 19. Glossary

| Term | Meaning |
|---|---|
| ACL | Access Control List — Windows NTFS permission set on a file/dir |
| ADWIN | ADaptive WINdowing — streaming drift detection algorithm |
| CUSUM | CUmulative SUM — change-point detection technique (Page-Hinkley) |
| Drift | Statistical change in the distribution of a streamed feature |
| FSM | Finite-State Machine — finite states with transition rules |
| icacls | Windows command-line ACL editor |
| IF | Isolation Forest — unsupervised tree ensemble for anomaly detection |
| Merkle chain | Sequential hash chain where each block commits to the previous |
| PH | Page-Hinkley test — cumulative-sum change-point detector |
| Sandbox | Isolated directory `~/Documents/ransomware_test/` for safe testing |
| SHA-256 | Cryptographic hash function, 256-bit output |
| Shannon entropy | Information-theoretic measure of unpredictability |
| Sliding window | Moving fixed-duration interval over streamed data |
| TTL | Time-To-Live — duration after which state expires |
| VSS | Volume Shadow Copy Service — Windows snapshot mechanism |
| Z-score | Number of standard deviations from the mean |

---

**End of document.**

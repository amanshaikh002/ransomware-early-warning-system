# Results & Evaluation Parameters

**Quantitative evaluation of the Agentic AI-Based Ransomware Early-Warning System.**

This document defines the parameters used to evaluate the system, the
methodology to measure each, the formulas behind them, and a template for
recording observations from your own test runs.

---

## Table of Contents

1. [Evaluation Methodology](#1-evaluation-methodology)
2. [Test Scenarios](#2-test-scenarios)
3. [Detection Performance Parameters](#3-detection-performance-parameters)
4. [Latency Parameters](#4-latency-parameters)
5. [Coverage & Audit Parameters](#5-coverage--audit-parameters)
6. [Per-Detector Contribution](#6-per-detector-contribution)
7. [System Performance Parameters](#7-system-performance-parameters)
8. [Defense Effectiveness Parameters](#8-defense-effectiveness-parameters)
9. [Blockchain Integrity Parameters](#9-blockchain-integrity-parameters)
10. [Results Summary Template](#10-results-summary-template)
11. [Data Collection Helpers](#11-data-collection-helpers)

---

## 1. Evaluation Methodology

### Ground truth definition

Because we use a controlled simulator instead of live malware, ground truth is
unambiguous:

- **Positive instance** = a simulated ransomware encryption event (a `.locked`
  file produced by `run_ransomware()`) within the 5-second window in which it
  was created.
- **Negative instance** = any other 5-second window during the test (idle
  baseline, normal user activity, bulk file creation without renames).

### Confusion matrix

| | Predicted Positive (alert fired) | Predicted Negative (no alert) |
|---|---|---|
| **Actual Positive** (ransomware window) | TP | FN |
| **Actual Negative** (benign window) | FP | TN |

We measure at two granularities:

| Granularity | Definition |
|---|---|
| **Per-window** | One sample per 5-second feature window. Used for detection-rate, FPR, precision, recall. |
| **Per-file** | One sample per encrypted/decoy file. Used for coverage % (re-verification report). |

### Test phases

Every reported run has three phases:

1. **Baseline** (≥ 60 s of idle / normal activity) — establishes the false-positive rate.
2. **Attack** (a `ransomware` simulation) — establishes the true-positive rate.
3. **Recovery** (≥ 30 s after attack ends) — verifies the FSM returns to MONITORING.

---

## 2. Test Scenarios

### 2.1 — Baseline (idle)

```bash
python main.py
# wait 2 minutes, do nothing
```

Expected: agent stays in MONITORING, risk score ≤ 5, drift severity NONE on
every window, no entropy alerts.

### 2.2 — Normal user activity

```bash
python testing/ransomware_simulator.py --mode normal --duration 60
```

Slow, low-volume file creation/modification. Expected: no alerts; this is the
**negative** dataset.

### 2.3 — Bulk activity (negative-control burst)

```bash
python testing/ransomware_simulator.py --mode bulk --count 30
```

High write volume but no renames. Tests false-positive resistance — pure write
bursts (e.g., a backup tool) should NOT trigger HIGH_RISK by themselves.

### 2.4 — Ransomware attack

```bash
python testing/ransomware_simulator.py --mode ransomware --count 50
```

Or via the dashboard's **Live Simulation** card with `Mode = ransomware`,
`File Count = 50`. The canonical positive scenario.

### 2.5 — Decoy / blind-spot test

After the ransomware run, click **Inject Decoy** on the dashboard. Creates a
low-entropy `.locked` file. Tests whether the system honestly reports a missed
detection.

---

## 3. Detection Performance Parameters

### 3.1 Definitions and formulas

Let TP, FP, TN, FN be confusion-matrix counts measured at per-window
granularity.

| Parameter | Formula | What it tells you |
|---|---|---|
| **Accuracy** | $\dfrac{TP + TN}{TP + TN + FP + FN}$ | Overall correctness |
| **Precision** | $\dfrac{TP}{TP + FP}$ | Of the alerts I raised, how many were real? |
| **Recall** (sensitivity, TPR) | $\dfrac{TP}{TP + FN}$ | Of the actual attacks, how many did I catch? |
| **Specificity** (TNR) | $\dfrac{TN}{TN + FP}$ | Of the benign windows, how many did I correctly not alarm on? |
| **False Positive Rate** (FPR) | $\dfrac{FP}{FP + TN} = 1 - \text{specificity}$ | Wrong alarms per benign window |
| **F1 Score** | $\dfrac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ | Harmonic mean — single number balancing the two |
| **MCC** (Matthews) | $\dfrac{TP \cdot TN - FP \cdot FN}{\sqrt{(TP+FP)(TP+FN)(TN+FP)(TN+FN)}}$ | Class-imbalance-robust correlation, $[-1, 1]$ |

### 3.2 Per-detector confusion matrices

Same parameters computed independently for each layer:

| Detector | "Alert" defined as |
|---|---|
| Entropy | Any HIGH_ENTROPY record in the window |
| Drift | `severity ≥ MEDIUM` (LOW excluded — too noisy) |
| Isolation Forest | `anomaly == True` |
| Risk Score | `level ∈ {SUSPICIOUS, HIGH_RISK, CRITICAL}` (i.e. score ≥ 30) |
| Final Decision | Agent transitioned to ALERT or beyond |

### 3.3 Reference results (from a clean ransomware run)

Typical observed values for `--mode ransomware --count 50` (~25-second burst):

| Parameter | Entropy | Drift | IF | Risk≥30 |
|---|---:|---:|---:|---:|
| TP (windows) | 4 | 3 | 1 | 4 |
| FN | 0 | 1 | 3 | 0 |
| FP (during 60s baseline) | 0 | 0 | 0 | 0 |
| TN | 12 | 12 | 12 | 12 |
| **Recall** | 1.00 | 0.75 | 0.25 | 1.00 |
| **Precision** | 1.00 | 1.00 | 1.00 | 1.00 |
| **F1** | 1.00 | 0.86 | 0.40 | 1.00 |
| **FPR** | 0.00 | 0.00 | 0.00 | 0.00 |

Interpretation: entropy is the highest-recall single detector (every
ransomware window has at least one `.locked` file with ~7.99 entropy);
IsolationForest has the lowest recall because it needs a large baseline
sample and may not find every burst window anomalous; the **fused risk
score** achieves perfect precision and recall on the canonical scenario.

---

## 4. Latency Parameters

How fast does the system react?

| Parameter | Definition | Typical value |
|---|---|---|
| $t_{\text{event}}$ | Wall-clock between filesystem event and watcher dispatch | < 50 ms |
| $t_{\text{window}}$ | Feature window size | **5 s** (configurable) |
| $t_{\text{detect}}$ | Time from first malicious file write to first alert in `risk_stream.jsonl` with score ≥ 30 | 5 – 10 s |
| $t_{\text{ALERT}}$ | Time to FSM transition `MONITORING → ALERT` | 5 – 10 s |
| $t_{\text{RESPOND}}$ | Time to FSM transition `ALERT → RESPONDING` (lock activated) | 10 – 15 s |
| $t_{\text{lock}}$ | Time from RESPONDING transition to `icacls` deny ACE applied | < 200 ms |
| $t_{\text{recover}}$ | Time after attack stops before agent returns to MONITORING | ~ 40 s (3 below-30 + 5 quiet windows × 5 s) |

### Time-to-detect (TTD)

The headline metric for an early-warning system:

$$
TTD = t_{\text{first\_alert}} - t_{\text{first\_malicious\_write}}
$$

A bounded value: $t_{\text{window}} \le TTD \le 2 \cdot t_{\text{window}}$ in
the worst case (an attack starting at the very end of a window won't be
flagged until the next window closes).

### Files-encrypted-before-defense (FEBD)

How many files were encrypted before the icacls lock kicked in:

$$
FEBD = (\text{count of }.locked\text{ files at }t_{\text{lock}})
$$

Lower is better. With a 50-file simulation typical FEBD is ~25–40, meaning the
defense kicked in mid-attack and saved ~10–25 of the victim files.

---

## 5. Coverage & Audit Parameters

These come from the **re-verification report** (`/api/reverification`).

| Parameter | Formula |
|---|---|
| Total locked files | $N = \|\,\{f \in \text{sandbox} : f \text{ ends in } .locked\}\,\|$ |
| Caught files | $C = \|\,\{f : f \text{ flagged by entropy} \lor \text{drift} \lor \text{IF}\,\}\|$ |
| Missed files | $M = N - C$ |
| **Coverage %** | $\text{Coverage} = \dfrac{C}{N} \times 100$ |
| Per-detector coverage | $\text{Cov}_{\text{ent}} = \dfrac{|\{f : \text{entropy}_f\}|}{N}$, etc. |

A healthy result on the canonical ransomware scenario:

| Metric | Expected |
|---|---:|
| Total locked files | 50 |
| Caught | 50 |
| Missed | 0 |
| Coverage | 100 % |
| Entropy hits | ≥ 50 |
| Drift hits (MEDIUM/HIGH) | 2 – 5 |
| IF anomalies | 0 – 3 |

After clicking **Inject Decoy**:

| Metric | Expected |
|---|---:|
| Total locked files | 51 |
| Caught | 50 |
| Missed | 1 (the decoy) |
| Coverage | 98.0 % |
| Reasons given for the missed file | 3 (one per detector) |

The drop from 100% to 98% is the system honestly reporting a known blind spot —
not a failure mode.

---

## 6. Per-Detector Contribution

How much does each detector add to the final score? Compute the **average
contribution** across all attack windows:

$$
\bar c_i = \frac{1}{|W_{\text{attack}}|} \sum_{w \in W_{\text{attack}}} \text{score}_i(w)
$$

where $\text{score}_i(w)$ is the term contributed by detector $i$ in window $w$:

| Detector | Term |
|---|---|
| Entropy | $25 \cdot \mathbb{1}_{\text{entropy}}$ |
| Write rate | $20 \cdot \min(R/20, 1)$ |
| Rename count | $20 \cdot \min(r/30, 1)$ |
| Drift | $20 \cdot d$ |
| IsolationForest | $15 \cdot c_{\text{IF}}$ |

Typical contributions during a ransomware burst:

| Detector | $\bar c_i$ during attack | Comments |
|---|---:|---|
| Entropy | 25.0 | Saturates immediately on first `.locked` |
| Rename count | ~20.0 | Saturates above 30 renames per window |
| Write rate | ~10–18 | Depends on burst speed |
| Drift | ~6.0 (LOW) → ~12 (MED) → 20 (HIGH) | Climbs as detectors agree |
| IsolationForest | 0–10 | Trained or in warmup |
| **Sum** | **60–95** | Drives ≥ HIGH_RISK |

---

## 7. System Performance Parameters

| Parameter | How to measure | Typical |
|---|---|---|
| Event throughput | Lines/sec written to `event_stream.jsonl` during a 50-file burst | 10–30 events/sec |
| Feature emission rate | 1 line per `t_{\text{window}}` to `feature_stream.jsonl` | 0.2 vectors/sec (5 s window) |
| Memory footprint (orchestrator) | Task Manager, peak working set | 60 – 150 MB |
| CPU usage (orchestrator, 1 core) | Task Manager during attack | 5 – 15 % |
| Disk usage growth (1 hr idle) | `dir /a` on JSONL files after 1 hour | < 1 MB |
| Disk usage growth (50-file attack) | After one ransomware run | ~ 100 KB JSONL + sandbox files |
| SQLite size | After 1 hr active use | < 5 MB (10k-row pruning enforced) |

### Throughput formulas

$$
\text{Event throughput} = \frac{|\text{lines in event\_stream.jsonl}|}{t_{\text{end}} - t_{\text{start}}}
$$

$$
\text{Risk score latency} = t_{\text{score\_written}} - t_{\text{feature\_written}}
$$

(typically < 1 s).

---

## 8. Defense Effectiveness Parameters

Quantifying the FSM's response.

| Parameter | Definition |
|---|---|
| **Time to lock** $T_L$ | $t_{\text{RESPONDING transition}} - t_{\text{first\_malicious\_write}}$ |
| **Files encrypted before lock** | Count of `.locked` files at $T_L$ |
| **Files encrypted after lock** | Count of `.locked` files appearing after $T_L$ (should be 0 if lock works) |
| **Damage prevented %** | $\dfrac{\text{intended\_count} - \text{actual\_locked}}{\text{intended\_count}} \times 100$ |
| **VSS snapshot success rate** | Whether VSS snapshot succeeded on each ALERT transition |
| **Recovery success** | Whether agent transitioned back to MONITORING within 60 s of attack end |

Typical for a 50-file ransomware run:

| Parameter | Observed |
|---|---:|
| Time to lock $T_L$ | 10 – 15 s |
| Files encrypted before lock | 25 – 40 |
| Files encrypted after lock | 0 |
| Damage prevented | 20 – 50 % |
| VSS snapshot success | yes (when run as admin) / logs warning otherwise |
| Recovery success | yes |

---

## 9. Blockchain Integrity Parameters

| Parameter | Definition | Typical |
|---|---|---|
| Block append latency | Time from alert to block written | < 5 ms |
| Chain length | Total blocks at end of run | grows monotonically |
| Verification time | `verify_chain()` runtime | < 50 ms per 1000 blocks |
| Tamper detection | After deliberately editing one block, does `verify_chain()` raise `ChainTamperError`? | yes |
| Integrity over time | `chain_valid` flag in `/api/status` consistently true | 100 % |

### Demonstrating tamper detection

```bash
# 1. Run a ransomware sim to populate the ledger
python main.py --simulate ransomware --sim-count 20

# 2. Confirm valid
python -m blockchain.evidence_logger --verify
# → Chain valid: True

# 3. Edit one block in evidence_chain.jsonl (e.g. flip 'severity')
# 4. Re-verify
python -m blockchain.evidence_logger --verify
# → "Block hash mismatch at block index N" (ChainTamperError)
```

---

## 10. Results Summary Template

Fill in this table for your own runs and include in the project report.

### 10.1 Setup

| Field | Value |
|---|---|
| Date / time | ____________________ |
| Machine | _______ (CPU, RAM, OS) |
| Python version | 3.13.x |
| Detectors active | Entropy / Drift / IF / Risk |
| Simulation params | mode = ransomware, count = ____, duration = ____ |

### 10.2 Detection performance (per-window, 5 s windows)

| Metric | Value |
|---|---:|
| TP | _____ |
| FP | _____ |
| TN | _____ |
| FN | _____ |
| Accuracy | _____ |
| Precision | _____ |
| Recall (TPR) | _____ |
| Specificity (TNR) | _____ |
| F1 Score | _____ |
| FPR | _____ |
| MCC | _____ |

### 10.3 Latency

| Metric | Value (s) |
|---|---:|
| Time-to-detect (TTD) | _____ |
| Time to ALERT | _____ |
| Time to RESPONDING | _____ |
| Time to lock | _____ |
| Recovery time | _____ |

### 10.4 Coverage & damage

| Metric | Value |
|---|---:|
| Total `.locked` files | _____ |
| Caught | _____ |
| Missed | _____ |
| Coverage % | _____ |
| Files encrypted before lock | _____ |
| Damage prevented % | _____ |

### 10.5 Per-detector contribution

| Detector | Avg contribution to score |
|---|---:|
| Entropy (max 25) | _____ |
| Write rate (max 20) | _____ |
| Rename count (max 20) | _____ |
| Drift (max 20) | _____ |
| IsolationForest (max 15) | _____ |

### 10.6 System performance

| Metric | Value |
|---|---|
| Event throughput | _____ events/sec |
| Memory footprint | _____ MB |
| CPU usage | _____ % |
| SQLite size | _____ MB |

### 10.7 Blockchain integrity

| Metric | Value |
|---|---|
| Final block count | _____ |
| Chain valid | yes / no |
| Tamper test detected? | yes / no |

---

## 11. Data Collection Helpers

Run these AFTER a test session ends (or after **Reset Session** between
scenarios) to collect numbers for the template above.

### 11.1 Detection counts via SQLite

```python
import sqlite3
conn = sqlite3.connect("ransomware_monitor.db")
print("file_events:", conn.execute("SELECT COUNT(*) FROM file_events").fetchone()[0])
print("risk_scores:", conn.execute("SELECT COUNT(*) FROM risk_scores").fetchone()[0])
print("drift_alerts:", conn.execute("SELECT COUNT(*) FROM drift_alerts").fetchone()[0])
print("entropy_alerts:", conn.execute("SELECT COUNT(*) FROM entropy_alerts").fetchone()[0])

# Score distribution
for level, count in conn.execute(
    "SELECT level, COUNT(*) FROM risk_scores GROUP BY level"
):
    print(f"  {level:12s}: {count}")
```

### 11.2 Coverage % via the re-verifier

```python
from verification.reverifier import Reverifier
report = Reverifier().audit()
print(f"Total: {report['total_locked_files']}")
print(f"Caught: {report['caught_count']}  Missed: {report['missed_count']}")
print(f"Coverage: {report['coverage_percent']}%")
print(f"Detector hits: {report['detector_summary']}")
```

### 11.3 Time-to-detect via JSONL diffing

```python
import json
from datetime import datetime

# First malicious write event timestamp
with open("event_stream.jsonl") as f:
    for line in f:
        e = json.loads(line)
        if "ransomware_test" in e["file_path"] and e["event_type"] == "renamed":
            t_attack_start = datetime.fromisoformat(e["timestamp"])
            break

# First risk-stream entry with level >= SUSPICIOUS
with open("risk_stream.jsonl") as f:
    for line in f:
        r = json.loads(line)
        if r["level"] != "NORMAL":
            t_first_alert = datetime.fromisoformat(r["timestamp"])
            break

print(f"TTD = {(t_first_alert - t_attack_start).total_seconds():.1f} s")
```

### 11.4 Files encrypted before lock

```python
import json, os
from datetime import datetime
from pathlib import Path

# Time the agent transitioned to RESPONDING
with open("incidents.jsonl") as f:
    t_lock = None
    for line in f:
        i = json.loads(line)
        if i["state"] == "RESPONDING":
            t_lock = datetime.fromisoformat(i["timestamp"])
            break

if t_lock:
    sandbox = Path.home() / "Documents" / "ransomware_test"
    locked_files = list(sandbox.glob("*.locked"))
    before = sum(1 for f in locked_files
                 if datetime.fromtimestamp(f.stat().st_mtime, tz=t_lock.tzinfo) <= t_lock)
    after  = len(locked_files) - before
    print(f"Locked before agent activated: {before}")
    print(f"Locked after agent activated : {after}  (should be 0 if lock worked)")
```

### 11.5 Blockchain validity + count

```python
from blockchain.evidence_logger import BlockchainEvidenceLogger
log = BlockchainEvidenceLogger()
print(f"Chain valid: {log.verify_chain()}")
print(f"Block count: {log._next_index}")
```

### 11.6 Memory / CPU snapshot (Windows)

```powershell
Get-Process python | Where-Object { $_.MainWindowTitle -like "*main*" } |
  Select-Object Id, @{n="CPU(s)";e={$_.CPU}},
                @{n="Memory(MB)";e={[math]::Round($_.WorkingSet64/1MB,1)}}
```

---

## Reporting tip

In the project report, recommended structure for the Results section:

1. **Brief experimental setup** (one paragraph; copy from §10.1).
2. **Confusion matrix table** for the fused risk-score detector (most
   important number).
3. **Per-detector recall comparison** — bar chart or table from §10.5.
   Shows that detector ensembling materially helps.
4. **Latency** — TTD and time-to-respond from §10.3. Demonstrates the
   "early warning" claim.
5. **Coverage with and without the decoy** — from §10.4. Shows the
   re-verification audit can identify the system's own blind spots,
   which is a feature, not a bug.
6. **Defense effectiveness** — files saved by the icacls lock (§10.4).
   Quantifies the agentic AI's actual contribution to harm reduction.
7. **Blockchain integrity** — confirm chain validity, demonstrate
   tamper detection by editing a block.

Each result above is reproducible by running:

```bash
python main.py --simulate ransomware --sim-count 50
# wait ~60 s for full FSM cycle
# then run the helpers in §11
```

---

**End of document.**

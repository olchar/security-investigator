---
name: scope-drift-detection-device
description: 'Use this skill when asked to detect scope drift, behavioral expansion, or process baseline deviation on devices or endpoints. Triggers on keywords like "device drift", "device process drift", "endpoint drift", "process baseline", "device behavioral change", or when investigating whether a device has gradually expanded its process execution beyond an established baseline. This skill builds a configurable-window behavioral baseline using DeviceProcessEvents, compares baseline with recent activity, computes a weighted Drift Score across 5 dimensions (Volume, Processes, Accounts, Process Chains, Signing Companies), and correlates with SecurityAlert, DeviceInfo (for uptime corroboration via MDE sensor health), and command-line pattern analysis. Supports fleet-wide and single-device modes.'
---

# Device Scope Drift Detection — Instructions

## Purpose

This skill detects **scope drift** — the gradual, often imperceptible expansion of process execution behavior beyond an established baseline — in **endpoints and devices**. Unlike sudden compromise (which triggers alerts), scope drift is a slow-burn pattern that evades threshold-based detections.

**Entity Type:** Device

| Identifier | Primary Table(s) | Use Case |
|------------|-------------------|----------|
| DeviceName (hostname) | `DeviceProcessEvents` | Endpoints, servers, workstations — fleet-wide or single-device process baseline analysis |

**What this skill detects:**
- Volume spikes in process execution relative to historical baseline
- New processes or process chains not seen in the baseline period
- New service accounts or user contexts executing processes
- Unsigned or unusually-signed binaries executing on endpoints
- Reconnaissance, lateral movement, persistence, and exfiltration command patterns
- Security alerts involving the drifting devices

**Two operating modes:**

| Mode | When to Use | Scope |
|------|-------------|-------|
| **Fleet-wide** | "Check all devices for process drift", "device drift across the fleet" | Computes per-device drift scores, ranks all devices, flags those > 150% |
| **Single-device** | "Investigate process drift on DEVICE-01", specific hostname provided | Deep dive on one device with full process inventory and command-line analysis |

**Related skills:**
- [SPN Scope Drift](../spn/SKILL.md) — for service principals
- [User Scope Drift](../user/SKILL.md) — for user accounts (UPNs)

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
3. **[Quick Start](#quick-start-tldr)** - 10-step investigation pattern
4. **[Drift Score Formula](#drift-score-formula)** - Weighted composite scoring (5 dimensions)
5. **[Execution Workflow](#execution-workflow)** - Complete 4-phase process
6. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns (Queries 14-22)
7. **[Report Template](#report-template)** - Output format specification
8. **[Known Pitfalls](#known-pitfalls)** - Edge cases and false positives
9. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY device scope drift analysis:**

1. **ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)
2. **ALWAYS ask the user for output mode** if not specified: inline chat summary or markdown file report (or both)
3. **ALWAYS determine mode** — fleet-wide or single-device
4. **ALWAYS determine time windows** — baseline period and recent period (configurable, defaults: 6-day baseline, 1-day recent within 7-day lookback)
5. **ALWAYS build baseline FIRST** before comparing recent activity
6. **ALWAYS apply the low-volume denominator floor** to prevent false-positive drift scores on sparse baselines
7. **ALWAYS correlate across all required data sources** (DeviceProcessEvents, SecurityAlert, DeviceInfo)
8. **ALWAYS run independent queries in parallel** for performance
9. **NEVER report a drift flag without corroborating evidence** from at least one secondary data source

### Data Sources

| Data Source | Role | Purpose |
|-------------|------|---------|
| `DeviceProcessEvents` | ✅ Primary | Device process execution baseline |
| `SecurityAlert` | ✅ Corroboration | Corroborating alert evidence |
| `SecurityIncident` | ✅ Corroboration | Real alert status/classification |
| `DeviceInfo` | ✅ Corroboration | Device uptime/power-on pattern via MDE sensor health (primary — covers all MDE-onboarded devices) |
| `Heartbeat` | ⚡ Fallback | Device uptime for non-MDE devices with Log Analytics agent (AMA/MMA) only |

---

## ⛔ MANDATORY: Sentinel Workspace Selection

**This skill requires a Sentinel workspace to execute queries. Follow these rules STRICTLY:**

### When invoked from incident-investigation skill:
- Inherit the workspace selection from the parent investigation context
- If no workspace was selected in parent context: **STOP and ask user to select**

### When invoked standalone (direct user request):
1. **ALWAYS call `list_sentinel_workspaces` MCP tool FIRST**
2. **If 1 workspace exists:** Auto-select, display to user, proceed
3. **If multiple workspaces exist:**
   - Display all workspaces with Name and ID
   - ASK: "Which Sentinel workspace should I use for this investigation?"
   - **⛔ STOP AND WAIT** for user response
   - **⛔ DO NOT proceed until user explicitly selects**
4. **If a query fails on the selected workspace:**
   - **⛔ DO NOT automatically try another workspace**
   - STOP and report the error, display available workspaces, ASK user to select

**🔴 PROHIBITED ACTIONS:**
- ❌ Selecting a workspace without user consent when multiple exist
- ❌ Switching to another workspace after a failure without asking
- ❌ Proceeding with investigation if workspace selection is ambiguous

---

## Output Modes

This skill supports two output modes. **ASK the user which they prefer** if not explicitly specified. Both may be selected.

### Mode 1: Inline Chat Summary (Default)
- Render the full drift analysis directly in the chat response
- Includes ASCII tables, drift dimension bars, and security assessment
- Best for quick review and interactive follow-up questions

### Mode 2: Markdown File Report
- Save a comprehensive report to `reports/scope-drift/device/Scope_Drift_Report_<entity>_<timestamp>.md`
- All ASCII visualizations render correctly inside markdown code fences (` ``` `)
- Includes all data from inline mode plus additional detail sections
- Use `create_file` tool — NEVER use terminal commands for file output
- **Filename patterns:**
  - **Fleet-wide:** `Scope_Drift_Report_fleet_devices_YYYYMMDD_HHMMSS.md`
  - **Single-device:** `Scope_Drift_Report_<device_name>_YYYYMMDD_HHMMSS.md` (lowercase, sanitized)

### Markdown Rendering Notes
- ✅ ASCII tables, box-drawing characters, and bar charts render perfectly in markdown code blocks
- ✅ Unicode block characters (`█` full block, `─` box-drawing horizontal) display correctly in monospaced fonts
- ✅ Emoji indicators (🔴🟢🟡⚠️✅) render natively in GitHub-flavored markdown
- ✅ Standard markdown tables (`| col |`) render as formatted tables
- **Tip:** Wrap all ASCII art in triple-backtick code fences for consistent rendering

---

## Quick Start (TL;DR)

When a user requests device scope drift detection:

1. **Select Workspace** → `list_sentinel_workspaces`, auto-select or ask
2. **Determine Mode** → Fleet-wide or single-device? Determine time windows.
3. **Determine Output Mode** → Ask if not specified: inline, markdown file, or both
4. **Run Phase 1** → Query 14 (daily summary) + Query 15 (per-device breakdown)
5. **Apply Fleet Scaling** → Compute drift scores, rank devices, apply tiered depth limits (see [Fleet Scaling](#fleet-scaling-large-environments))
6. **Run Phase 2** → Query 16 (first-seen processes) + Query 17 (rare process chains) — scoped to **Tier 1 + Tier 2 devices only**
7. **Run Phase 3** → Query 18 (SecurityAlert + SecurityIncident) + Query 19 (unsigned/unusual) + Query 20 (notable command-line patterns) — scoped to **Tier 1 devices only**
8. **Run Phase 4 (corroboration)** → Query 21 (DeviceInfo uptime) + Query 22 (per-session volume) for flagged/intermittent devices in **Tier 1**
9. **Compute Final Assessment** → Combine drift scores with corroborating evidence
10. **Output Results** → Render in selected mode(s) with tiered depth

### Baseline and Recent Windows

Device process drift supports **configurable time windows** unlike sign-in drift (which uses fixed 90d/7d). The user may specify:

| User Request | Baseline Window | Recent Window |
|-------------|-----------------|---------------|
| "24 hours over the last 7 days" | Days 1–6 | Day 7 (last 24h) |
| "last 48 hours vs previous week" | Days 3–9 | Days 1–2 |
| "process drift last 30 days" | Days 8–30 | Days 1–7 |
| No time specified | Last 6 days | Last 24 hours |

**Note:** `DeviceProcessEvents` in Sentinel Data Lake has 90-day retention, but in Advanced Hunting only 30 days. For lookbacks > 30 days, use Sentinel Data Lake (`query_lake` with `TimeGenerated`).

---

## Fleet Scaling (Large Environments)

**Problem:** In small environments (< 50 devices), every device gets a full deep dive. In environments with hundreds or thousands of devices, running Queries 16–22 for every flagged device is prohibitively expensive (query timeouts, massive result sets, unreadable reports).

**Solution:** After Phase 1 computes drift scores for all devices, apply tiered depth based on fleet size and drift severity.

### Fleet Size Detection

After Query 15, count distinct devices in the result set:

| Fleet Size | Tier | Deep Dive Limit | Behavior |
|-----------|------|-----------------|----------|
| **≤ 50 devices** | Small | All flagged | Full deep dive for every device > 150%. No limiting needed. |
| **51–200 devices** | Medium | Top 10 | Full deep dive for top 10 by DriftScore. Summary row for remaining flagged devices. |
| **201–1000 devices** | Large | Top 10 | Full deep dive for top 10. Tier 2 summary (next 20) with first-seen processes only. Remaining flagged devices listed in ranking table with scores but no deep dive. |
| **> 1000 devices** | Very Large | Top 10 | Same as Large, plus: filter Query 15 to `BL_TotalEvents > 10` to exclude near-silent devices from scoring. |

### Tiered Depth Model

After computing drift scores and ranking all devices, assign tiers:

| Tier | Devices | Queries Run | Report Depth |
|------|---------|-------------|--------------|
| **Tier 1** (Full) | Top N by DriftScore (N = deep dive limit from table above) | All: Q16, Q17, Q18, Q19, Q20, Q21, Q22 | Full deep dive: ASCII chart, dimension table, first-seen processes, process chains, command-line patterns, alerts, DeviceInfo uptime |
| **Tier 2** (Summary) | Next 20 flagged devices (or remaining if < 20) | Q16 only (first-seen processes) | One-line summary per device: score, top 3 new processes, flag status |
| **Tier 3** (Score only) | All remaining flagged devices | None beyond Phase 1 | Row in ranking table: device name, drift score, dimension ratios, flag emoji |
| **Stable** | Devices ≤ 150% | None beyond Phase 1 | Omitted from deep dives. Included in fleet summary statistics only. |

### KQL Scoping for Large Fleets

When running Phase 2–4 queries for large fleets, scope them to the relevant device tier using a `let` block:

```kql
// Scope Phase 2–3 queries to Tier 1 devices only
let tier1Devices = dynamic(["device-a", "device-b", "device-c"]);
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where DeviceName in~ (tier1Devices)
// ... rest of query
```

### User Override

If the user explicitly asks for "all devices" or "full report", honor the request but warn:

> ⚠️ Fleet has <N> devices with <X> flagged above 150%. Running full deep dives for all flagged devices may be slow and produce a very long report. Proceed? (Default: top 10 deep dives + summary for others)

### Report Disclosure

When tiered depth is applied, **always disclose** in the report header:

```
**Fleet Size:** <N> devices (Large fleet — tiered analysis applied)
**Deep Dives:** Top <X> by DriftScore (Tier 1: full analysis)
**Summaries:** <Y> additional flagged devices (Tier 2: first-seen processes only)
**Score Only:** <Z> additional flagged devices (Tier 3: ranking table only)
**Stable:** <W> devices ≤ 150% (omitted from deep dives)
```

---

## Drift Score Formula

The Drift Score is a weighted composite of behavioral dimensions, normalized so that **100 = identical to baseline**.

### Device Formula (5 Dimensions)

$$
\text{DriftScore}_{Device} = 0.30V + 0.25P + 0.15A + 0.20C + 0.10S
$$

| Dimension | Weight | Metric | Why |
|-----------|--------|--------|-----|
| **Volume** | 30% | Daily avg process events (recent / baseline) | Sudden activity surges indicate new software, lateral movement, or compromise |
| **Processes** | 25% | Distinct process filenames executed | New processes = new software deployment, malware, or living-off-the-land tools |
| **Accounts** | 15% | Distinct account identities executing processes | New accounts = lateral movement, privilege escalation, or unauthorized access |
| **Process Chains** | 20% | Distinct parent→child process relationships | New chains = novel execution patterns, potentially malicious process trees |
| **Signing Companies** | 10% | Distinct file signing entities | New unsigned or unusually-signed binaries = potential malware or unauthorized tools |

### Interpretation Scale

| Score | Meaning | Action |
|-------|---------|--------|
| **< 80** | Contracting scope | ✅ Normal — entity is doing less than usual |
| **80–120** | Stable / normal variance | ✅ No action required |
| **120–150** | Moderate deviation | 🟡 Monitor — check for legitimate reasons |
| **> 150** | Significant drift | 🔴 FLAG — investigate with corroborating evidence |
| **> 250** | Extreme drift | 🔴 CRITICAL — immediate investigation required |

### Low-Volume Denominator Floor

**CRITICAL:** For devices with sparse baselines (< 10 daily process events), the volume ratio is artificially inflated. Apply a floor:

```
IF BL_DailyAvg < 10:
    AdjustedVolumeRatio = RC_DailyAvg / max(BL_DailyAvg, 10) * 100
    Flag the score with: "⚠️ Low-volume baseline — ratio may be inflated"
```

---

## Execution Workflow

### Phase 1: Behavioral Baseline vs. Recent Comparison

**Default windows:** Baseline = days 1-6 ago, Recent = last 24h (within 7-day lookback). Configurable by user.

This is the primary query that computes per-device behavioral profiles and drift metrics.

| Data Source | Query | Notes |
|-------------|-------|-------|
| `DeviceProcessEvents` | Query 14 | Fleet-wide daily summary |
| `DeviceProcessEvents` | Query 15 | Per-device daily breakdown with drift score computation |

**Fleet-wide produces ONE drift score per device.** Devices are ranked by DriftScore; those exceeding 150% are assigned to tiers based on fleet size (see [Fleet Scaling](#fleet-scaling-large-environments)). Tier 1 devices get full deep dives; Tier 2 get summary analysis; Tier 3 appear in the ranking table only.

### Phase 2: Process Drift Pattern Analysis

- **First-seen processes (Query 16):** Processes appearing only in the recent window with no baseline history. These are the strongest drift signal — new software, tools, or malware.
- **Rare process chains (Query 17):** Parent→child execution relationships seen only in the recent window. New chains may indicate novel attack patterns, lateral movement tools, or changed automation.

### Phase 3: Corroborating Signal Collection (Run in Parallel)

- **SecurityAlert + SecurityIncident (Query 18):** Alerts referencing any of the analyzed devices, joined with SecurityIncident for real status. **Never read SecurityAlert.Status directly** — it's always "New".
- **Unsigned/unusual processes (Query 19):** Processes with signing companies not seen in the baseline, or unsigned binaries. Legitimate software deployments will show known signing companies; malware or tools may be unsigned or signed by unusual entities.
- **Notable command-line patterns (Query 20):** Search for reconnaissance commands (`whoami`, `net user`, `ipconfig`, `nltest`, `systeminfo`), lateral movement (`psexec`, `wmic`), persistence mechanisms (`schtasks`, `reg add`), and exfiltration indicators (`curl`, `wget`, `certutil`).
- **Account landscape analysis:** Review which accounts executed processes — flag any new service accounts, admin accounts, or unexpected user contexts in the recent window.

### Phase 4: Uptime Corroboration (For Flagged/Intermittent Devices)

- **DeviceInfo uptime pattern (Query 21):** For any device with a drift score near or above the 150% threshold, or any device known/suspected to be intermittently powered on, query the `DeviceInfo` table to determine actual uptime days via MDE sensor health state. This is the primary corroboration source and covers all MDE-onboarded devices. For non-MDE devices with only Log Analytics agent (AMA/MMA), fall back to the `Heartbeat` table using the same query pattern (substitute `DeviceInfo` → `Heartbeat`, `DeviceName` → `Computer`, `SensorHealthState` → `OSType`).
- **Per-session process volume (Query 22):** Query `DeviceProcessEvents` per-day to show per-session event concentration. This context is critical for interpreting volume-based drift — a device that was online only 5 days out of 90 will have a diluted baseline daily average, making any recent power-on session appear as a massive volume spike.
- **Run Queries 21+22 for flagged devices and include the uptime context in the deep dive section.**

### Phase 5: Score Computation & Report Generation

1. Compute DriftScore per device using the 5-dimension formula
2. Apply the low-volume denominator floor
3. Flag any device exceeding 150% threshold
4. Handle special cases:
   - **Newly onboarded devices** (no baseline = DriftScore 999) should be flagged as "New Device" rather than drift
   - **Data Lake ingestion boundaries** may cause zero recent-window activity — verify before reporting contraction
5. For devices with elevated Volume ratio (>200%) or near-threshold DriftScore (>130%): Run Queries 21+22 (DeviceInfo uptime + per-session volume) to determine if the volume spike is explained by intermittent power-on usage. If the device was only online for a small fraction of the baseline window, note as **mitigating factor**.
6. Generate risk assessment with emoji-coded findings
7. Render output in the user's selected mode

---

## Sample KQL Queries

### Query 14: Device Process Events — Daily Summary (Fleet-Wide)

```kql
// Daily summary of process events across all devices
// Configurable: adjust 'lookback' for total analysis window
let lookback = 7d;
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| summarize
    TotalEvents = count(),
    DistinctDevices = dcount(DeviceName),
    DistinctProcesses = dcount(FileName),
    DistinctAccounts = dcount(AccountName),
    DistinctChains = dcount(strcat(InitiatingProcessFileName, "→", FileName)),
    DistinctCompanies = dcount(ProcessVersionInfoCompanyName)
    by Day = bin(TimeGenerated, 1d)
| order by Day asc
```

**Purpose:** Provides the fleet-wide daily trend to identify volume anomalies and determine optimal baseline/recent window split. Use this to verify data availability before running the per-device breakdown.

### Query 15: Per-Device Daily Breakdown & Drift Score Computation

```kql
// Per-device per-day behavioral profile with drift score computation
// Configurable time windows:
//   baselineDays = number of days in baseline period
//   recentDays = number of days in recent period
//   lookback = baselineDays + recentDays
let lookback = 7d;
let recentDays = 1;  // Last N days as "recent" window
let baselineDays = 6; // Remaining days as "baseline"
let recentStart = ago(1d * recentDays);
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| extend IsRecent = TimeGenerated >= recentStart
| summarize
    TotalEvents = count(),
    DistinctProcesses = dcount(FileName),
    DistinctAccounts = dcount(AccountName),
    DistinctChains = dcount(strcat(InitiatingProcessFileName, "→", FileName)),
    DistinctCompanies = dcount(ProcessVersionInfoCompanyName)
    by DeviceName, IsRecent
| extend Period = iff(IsRecent, "Recent", "Baseline")
| order by DeviceName, Period asc
```

**Post-Processing:** After retrieving results, compute per-device drift scores:

1. For each device, extract Baseline and Recent rows
2. Compute daily averages: `BL_DailyAvg = BL_TotalEvents / baselineDays`, `RC_DailyAvg = RC_TotalEvents / recentDays`
3. Compute dimension ratios: `VolumeRatio = RC_DailyAvg / max(BL_DailyAvg, 10) * 100`
4. Apply the Device formula: `DriftScore = 0.30×Volume + 0.25×Processes + 0.15×Accounts + 0.20×Chains + 0.10×Companies`
5. Handle edge cases:
   - Device in baseline only (no recent data): Check if data ingestion boundary or genuine silence
   - Device in recent only (no baseline): Set DriftScore = 999, flag as "New Device — no baseline"
   - Apply denominator floor (`max(BL_value, 10)`) for low-volume devices

**Single-Device Mode:** Add `| where DeviceName =~ '<DEVICE_NAME>'` as the second filter to scope to one device.

### Query 16: First-Seen Processes (New in Recent Window)

```kql
// Processes appearing only in the recent window — not seen in baseline
// This is the strongest drift signal for devices
let lookback = 7d;
let recentDays = 1;
let recentStart = ago(1d * recentDays);
let baselineProcesses = DeviceProcessEvents
| where TimeGenerated between (ago(lookback) .. recentStart)
| distinct FileName;
DeviceProcessEvents
| where TimeGenerated >= recentStart
| distinct DeviceName, FileName, ProcessVersionInfoCompanyName
| join kind=leftanti baselineProcesses on FileName
| summarize
    NewProcessCount = dcount(FileName),
    NewProcesses = make_set(FileName, 50),
    Companies = make_set(ProcessVersionInfoCompanyName, 50)
    by DeviceName
| where NewProcessCount > 0
| order by NewProcessCount desc
```

**Interpretation:**
- New processes from recognized vendors (Microsoft, Google, etc.) → likely software updates or deployments
- **Version-stamped update binaries** (`AM_Delta_Patch_*.exe`, `MicrosoftEdge_X64_*.exe`, `odt*.tmp.exe`) → expected noise, always appear as "new" (see pitfall: Version-Stamped Process Name False Positives)
- New unsigned processes or processes from unknown companies → investigate immediately
- Large number of new processes on a single device → may indicate software deployment, but also possible malware dropper

**Single-Device Mode:** Add `| where DeviceName =~ '<DEVICE_NAME>'` to both the baseline and recent subqueries. Then expand to show full process details including `ProcessCommandLine` and `FolderPath`.

**Fleet-Wide vs. Per-Device First-Seen Behavior:** This query identifies processes that are globally novel — not seen on *any* device during the baseline. If a process ran on DeviceA during baseline but appears on DeviceB for the first time in the recent window, it will NOT be flagged because the baseline `distinct FileName` covers all devices. This design choice reduces noise (known-good processes aren't re-flagged per device) but may miss per-device novelty. For per-device first-seen analysis, scope the baseline `distinct` by `DeviceName` — note this is significantly more expensive on large fleets.

### Query 17: Rare Process Chains (Parent→Child Relationships)

```kql
// Process chains (parent→child) seen only in recent window
let lookback = 7d;
let recentDays = 1;
let recentStart = ago(1d * recentDays);
let baselineChains = DeviceProcessEvents
| where TimeGenerated between (ago(lookback) .. recentStart)
| extend Chain = strcat(InitiatingProcessFileName, "→", FileName)
| distinct Chain;
DeviceProcessEvents
| where TimeGenerated >= recentStart
| extend Chain = strcat(InitiatingProcessFileName, "→", FileName)
| join kind=leftanti baselineChains on Chain
| summarize
    Occurrences = count(),
    Devices = make_set(DeviceName, 20),
    DeviceCount = dcount(DeviceName),
    Accounts = make_set(AccountName, 10),
    SampleCommandLine = take_any(ProcessCommandLine)
    by Chain
| order by Occurrences desc
| take 30
```

**Interpretation:**
- Common chains like `explorer.exe→notepad.exe` appearing as "new" → baseline window too short or intermittent usage
- **Update chains** like `wuauclt.exe→AM_Delta_Patch_*.exe` or `microsoftedgeupdate.exe→MicrosoftEdge_X64_*.exe` → expected noise from automatic updates, always appear as "new" due to version-stamped child process names
- Suspicious chains like `cmd.exe→powershell.exe→certutil.exe` → investigate for LOLBin abuse
- Chains appearing on a single device vs. fleet-wide → single device may indicate targeted activity

### Query 18: Device SecurityAlert + SecurityIncident Correlation

```kql
// Security alerts referencing analyzed devices, joined with SecurityIncident for real status
// IMPORTANT: SecurityAlert.Status is immutable (always "New") — MUST join SecurityIncident
// Substitute <DEVICE_NAMES> with comma-separated device names from Query 15
let lookback = 7d;
let relevantAlerts = SecurityAlert
| where TimeGenerated > ago(lookback)
| where Entities has_any (<DEVICE_NAMES>) or CompromisedEntity has_any (<DEVICE_NAMES>)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProductName, ProductComponentName,
    Tactics, Techniques, CompromisedEntity, TimeGenerated;
SecurityIncident
| where CreatedTime > ago(lookback)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| project IncidentNumber, Title, Severity, Status, Classification,
    AlertName, AlertSeverity, ProductName, Tactics, Techniques,
    CompromisedEntity, AlertTime = TimeGenerated1
| order by AlertTime desc
```

**Interpreting Incident Status in Drift Context:**
| Incident Status | Classification | Impact on Drift Assessment |
|-----------------|----------------|----------------------------|
| Closed | TruePositive | 🔴 Confirmed threat — significantly increases drift risk |
| Closed | FalsePositive | 🟢 False alarm — discount from drift risk, note as noise |
| Closed | BenignPositive | 🟡 Expected behavior — note but don't escalate |
| Active/New | Any | 🟠 Unresolved — flag for attention, may indicate ongoing threat |

**Product Name Mapping (Legacy → Current Branding):**

| SecurityAlert.ProductName (raw) | Report Display Name |
|--------------------------------|---------------------|
| Microsoft Defender Advanced Threat Protection | **Microsoft Defender for Endpoint** |
| Microsoft Cloud App Security | **Microsoft Defender for Cloud Apps** |
| Microsoft Data Loss Prevention | **Microsoft Purview Data Loss Prevention** |
| Azure Sentinel | **Microsoft Sentinel** |
| Microsoft 365 Defender | **Microsoft Defender XDR** |
| Office 365 Advanced Threat Protection | **Microsoft Defender for Office 365** |
| Azure Advanced Threat Protection | **Microsoft Defender for Identity** |

**Report Rendering:** Group by incident, show severity/status/classification. Translate `ProductName` to current branding. Link back to device drift scores — a device with both high drift score AND correlated security alerts is highest priority for investigation.

### Query 19: Unsigned/Unusual Signing Companies in Recent Window

```kql
// Signing companies appearing only in the recent window
// Unsigned or unusually-signed binaries may indicate unauthorized software or malware
let lookback = 7d;
let recentDays = 1;
let recentStart = ago(1d * recentDays);
let baselineCompanies = DeviceProcessEvents
| where TimeGenerated between (ago(lookback) .. recentStart)
| where isnotempty(ProcessVersionInfoCompanyName)
| distinct ProcessVersionInfoCompanyName;
DeviceProcessEvents
| where TimeGenerated >= recentStart
| summarize
    EventCount = count(),
    Devices = make_set(DeviceName, 20),
    Processes = make_set(FileName, 20)
    by ProcessVersionInfoCompanyName
| join kind=leftanti baselineCompanies on ProcessVersionInfoCompanyName
| where isnotempty(ProcessVersionInfoCompanyName)
| order by EventCount desc
```

**For unsigned processes (empty company field):**
```kql
// Find unsigned processes in the recent window
// NOTE: Linux devices will dominate results — Linux binaries lack ProcessVersionInfoCompanyName by design.
// Consider filtering to Windows devices: | where DeviceName !has "linux"
let lookback = 7d;
let recentDays = 1;
let recentStart = ago(1d * recentDays);
DeviceProcessEvents
| where TimeGenerated >= recentStart
| where isempty(ProcessVersionInfoCompanyName)
| summarize
    EventCount = count(),
    Devices = make_set(DeviceName, 20),
    SampleCommandLine = take_any(ProcessCommandLine)
    by FileName, FolderPath
| order by EventCount desc
| take 20
```

### Query 20: Notable Command-Line Pattern Detection

```kql
// Search for reconnaissance, lateral movement, persistence, and exfiltration command patterns
// Run against the recent window to identify suspicious activity
let lookback = 7d;
let recentDays = 1;
let recentStart = ago(1d * recentDays);
DeviceProcessEvents
| where TimeGenerated >= recentStart
| where ProcessCommandLine has_any (
    // Reconnaissance
    "whoami", "net user", "net group", "net localgroup", "nltest", "systeminfo",
    "ipconfig /all", "nslookup", "query user", "qwinsta",
    // Lateral movement
    "psexec", "wmic", "invoke-command", "enter-pssession", "new-pssession",
    // Persistence
    "schtasks /create", "reg add", "sc create", "New-Service",
    // Credential access
    "mimikatz", "sekurlsa", "lsass", "procdump", "comsvcs.dll",
    // Exfiltration / download
    "certutil -urlcache", "bitsadmin /transfer", "curl ", "wget ",
    "Invoke-WebRequest", "downloadstring", "downloadfile"
    )
| project TimeGenerated, DeviceName, AccountName, FileName,
    InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated desc
| take 50
```

**Interpretation:**
- Commands executed by expected service accounts (e.g., MDI sensor running `ipconfig /flushdns`) → benign
- Linux health checks (`curl` to MCR, `wget` for MOTD) executed by root → expected operational noise
- Reconnaissance commands from user accounts or unexpected contexts → investigate
- Multiple categories of suspicious commands on the same device → high confidence indicator of compromise

### Query 21: DeviceInfo Uptime Pattern (Device Corroboration)

```kql
// Corroboration query: Determine actual device uptime days from DeviceInfo table (MDE sensor)
// DeviceInfo records entity snapshots ~hourly for MDE-onboarded devices
// Run for the full analysis window (baseline + recent) to see power-on cadence
// Substitute <DEVICE_NAME> with the target device hostname
let totalDays = 97; // Intentionally wider than the drift analysis window (default 7d) to capture the device's long-term power-on cadence across 90+ days
DeviceInfo
| where TimeGenerated > ago(1d * totalDays)
| where DeviceName has "<DEVICE_NAME>"
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    RecordCount = count(),
    SensorHealth = take_any(SensorHealthState),
    OnboardingStatus = take_any(OnboardingStatus)
    by Day = bin(TimeGenerated, 1d)
| order by Day asc
```

**Heartbeat fallback** (for non-MDE devices with Log Analytics agent only):
```kql
// Fallback: Use Heartbeat table when DeviceInfo returns 0 results (device not MDE-onboarded)
let totalDays = 97;
Heartbeat
| where TimeGenerated > ago(1d * totalDays)
| where Computer has "<DEVICE_NAME>"
| summarize 
    FirstHeartbeat = min(TimeGenerated),
    LastHeartbeat = max(TimeGenerated),
    HeartbeatCount = count()
    by Day = bin(TimeGenerated, 1d)
| order by Day asc
```

**Interpretation:**
- **Gaps between days = device was powered off (or MDE sensor was inactive).** Count the rows to determine total days online vs. the full analysis window.
- **SensorHealthState** values: `Active` (sensor reporting normally), `Inactive` (sensor not communicating), `Misconfigured` (partial telemetry). Use to assess data quality.
- **Intermittent devices** (online <30% of baseline window) will produce artificially diluted baseline daily averages. A single power-on session will appear as a large volume spike. This is a **mathematical artifact**, not genuine drift.
- **Consistent daily presence** confirms the baseline daily average is representative — volume spikes are more meaningful.
- **Use case:** When a device shows elevated Volume ratio (>200%) but low Process/Account/Chain diversity ratios, check DeviceInfo first. If the device was only online 5 days out of 90, the 312% volume ratio is expected.
- **Example:** A device with 4,243 baseline events spread across only 4 power-on sessions (~40 hrs total) has a "true" daily average of ~1,060 events/session-day, not the diluted ~47 events/calendar-day. A recent session producing 1,031 events is exactly normal.
- **Why DeviceInfo over Heartbeat:** DeviceInfo is generated by the MDE sensor (~hourly entity snapshots) and covers all Defender-onboarded devices. Heartbeat requires a Log Analytics agent (AMA/MMA) which many MDE-only devices don't have. In testing, DeviceInfo showed 28 days of coverage where Heartbeat showed only 3 days for the same device.

### Query 22: Per-Session Process Volume (Device Corroboration)

```kql
// Corroboration query: Show event volume and diversity per power-on session
// Confirms events are concentrated in short bursts, not spread evenly
// Substitute <DEVICE_NAME> with the target device hostname
let totalDays = 97; // Intentionally wider than the drift analysis window (default 7d) to capture per-session behavior across the device's full power-on history
DeviceProcessEvents
| where TimeGenerated > ago(1d * totalDays)
| where DeviceName has "<DEVICE_NAME>"
| summarize 
    Events = count(),
    UniqueProcesses = dcount(FileName),
    UniqueAccounts = dcount(AccountName),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated)
    by Day = bin(TimeGenerated, 1d)
| extend SessionDuration = LastEvent - FirstEvent
| order by Day asc
```

**Interpretation:**
- **Per-session event volumes** should be compared across sessions. If each power-on session produces roughly similar event counts (600–1,500), the behavior is consistent regardless of how infrequently the device is used.
- **SessionDuration** shows how long the device was active per day. Cross-reference with DeviceInfo FirstSeen/LastSeen for validation.
- **Process diversity per session** (UniqueProcesses) should be similar across sessions. If the most recent session shows 90+ unique processes and baseline sessions also show 70–90+, the diversity is normal — the same software runs each time the device boots.
- **Use in report:** Include a power-on session table in the Flagged Device Deep Dive to contextualize why the volume ratio is elevated. Note: "Volume-driven score inflation due to intermittent usage pattern — per-session behavior is consistent with baseline sessions."

---

## Report Template

### Inline Chat Report Structure (Fleet-Wide)

The inline report MUST include these sections in order:

1. **Header** — Workspace, analysis period (baseline/recent windows), drift threshold, device count, total events
2. **Fleet Daily Trend Table** — Day-by-day event counts, distinct processes, accounts, chains, companies
3. **Per-Device Drift Score Ranking** — All devices sorted by DriftScore descending, with per-dimension ratios and flag status
4. **Flagged Device Deep Dive** (for each **Tier 1** device > 150% or DriftScore=999) — Baseline vs. recent comparison, dimension bar chart, new processes, process chains, account context. For new devices (999): identify as "newly onboarded" and list all processes observed. **For devices with elevated volume ratio:** include DeviceInfo uptime pattern (Query 21) and per-session volume table (Query 22) showing power-on cadence and per-session event consistency. Flag intermittent devices with: "⚠️ Intermittent device — online N of M baseline days. Volume ratio reflects power-on burst, not behavioral expansion."
5. **Tier 2 Device Summaries** (if fleet scaling applied) — One-line summary per Tier 2 device: drift score, top 3 first-seen processes, flag status. No full deep dive.
6. **First-Seen Process Summary** — Processes appearing only in recent window, grouped by device (Tier 1 + Tier 2 devices)
7. **Correlated Security Alerts** — SecurityAlert+SecurityIncident correlation for all analyzed devices
8. **Uptime Context** (if applicable) — For flagged or near-threshold devices, include DeviceInfo-derived power-on session table showing each session's duration, event count, and process diversity. This section contextualizes volume-driven drift scores.
9. **Account Landscape** — Summary of which accounts executed processes, flagging any unexpected contexts
10. **Notable Command-Line Patterns** — Reconnaissance/lateral movement/persistence command matches
11. **Security Assessment** — Emoji-coded findings table with evidence citations
12. **Verdict Box** — Overall fleet risk level, per-device verdicts, recommendations

### Inline Chat Report Structure (Single-Device)

Same as fleet-wide sections 1, 3-11, but for one device only. Add:
- Full process inventory (baseline vs recent)
- Complete command-line analysis for suspicious processes
- Process chain tree visualization

### Markdown File Report Structure

When outputting to markdown file, include everything from the inline format PLUS:

**Filename patterns:**
- **Fleet-wide:** `reports/scope-drift/device/Scope_Drift_Report_fleet_devices_YYYYMMDD_HHMMSS.md`
- **Single-device:** `reports/scope-drift/device/Scope_Drift_Report_<device_name>_YYYYMMDD_HHMMSS.md`

```markdown
# Device Process Scope Drift Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Workspace:** <workspace_name>
**Baseline Period:** <start> → <end> (<N> days)
**Recent Period:** <start> → <end> (<N> days)
**Drift Threshold:** 150%
**Data Sources:** DeviceProcessEvents, SecurityAlert, SecurityIncident, DeviceInfo
**Mode:** Fleet-Wide | Single-Device (<device_name>)
**Devices Analyzed:** <count>
**Total Events:** <count>

---

## Executive Summary

<1-3 sentence summary: how many devices analyzed, how many flagged, overall risk level>

---

## Fleet Daily Trend

<ASCII table: Day | Events | Devices | Processes | Accounts | Chains | Companies>
<!-- Wrap in code fence for consistent rendering -->

---

## Per-Device Drift Score Ranking

<Table with all devices, per-dimension ratios, DriftScore, flag status>
<Devices with DriftScore=999 flagged as "New Device">

---

## Flagged Device Deep Dive

### <Device Name> — Drift Score <score>

**ASCII Drift Dimension Chart (REQUIRED):**

Render a box-drawn chart inside a code fence. **Inner width: 58 chars** (every line between `│` markers = exactly 58 visual characters). No emoji inside boxes — use text labels.

**Alignment:** Name (9 chars padded) + weight (5) + gap (2) + bars (20 `█─`) + gap (2) + pct (6, right-aligned: `XXX.X%` or ` XX.X%`) + gap (2) + direction (10 total: `^`/`v`/`=` + 9 trailing spaces). Status labels (centered): `STABLE`, `STABLE (Low-Volume)`, `NEAR THRESHOLD`, `ABOVE THRESHOLD`, `CRITICAL`. Direction: `^` (up), `v` (down), `=` (stable).

**Bar characters:** Use `█` (U+2588 full block) for filled portions and `─` (U+2500 box-drawing horizontal) for the unfilled track.

**Uptime-adjusted Volume:** When the Volume dimension has been adjusted for intermittent uptime (see Pitfalls → Intermittent-Use Device Volume Inflation), display the **effective (adjusted) percentage** in the chart and move the raw value into the description column. This keeps the percentage column fixed-width and avoids breaking bar alignment. Example: `XXX.X%  ^  (raw: YYY.Y%)`.

```
┌──────────────────────────────────────────────────────────┐
│                 DEVICE DRIFT SCORE: XX.X                 │
│                          STABLE                          │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Volume   (30%)  ██████──────────────  XXX.X%  ^         │
│  Processes(25%)  ███─────────────────   XX.X%  v         │
│  Accounts (15%)  ██████──────────────  XXX.X%  =         │
│  Chains   (20%)  ██──────────────────   XX.X%  v         │
│  Companies(10%)  ██████──────────────  XXX.X%  =         │
│                                                          │
│  ────────────────────────── 100% baseline ──┤            │
│                  150% drift threshold ▲                  │
└──────────────────────────────────────────────────────────┘
```

**Bar fill:** 20 chars wide. Filled = round(ratio/100 × 20), capped at 20. Title and status: center within 58 chars. Use `█` for filled, `─` for unfilled.

**Then** render the standard markdown dimension table:

| Dimension | Weight | Baseline | Recent | Ratio | Weighted | Status |
|-----------|--------|----------|--------|-------|----------|--------|

<Baseline vs recent comparison table>
<New processes list with signing companies>
<New process chains>
<Account context>

#### Uptime Context (if intermittent device)

<If Volume ratio >200% or device known to be intermittent, include DeviceInfo-derived power-on session table>

| Session | Power On | Power Off | Duration | Events | Processes |
|---------|----------|-----------|----------|--------|-----------|
| 1 | <date/time> | <date/time> | ~N hrs | <count> | <count> |
| ... | ... | ... | ... | ... | ... |

⚠️ Intermittent device — online N of M baseline days. Volume ratio reflects power-on burst, not behavioral expansion. Per-session behavior is consistent with baseline sessions.

---

## First-Seen Processes

<Processes appearing only in recent window, by device>

---

## Correlated Security Alerts

<SecurityAlert + SecurityIncident correlation>
<Group by incident, show severity/status/classification>

---

## Notable Command-Line Patterns

<Reconnaissance/lateral movement/persistence/exfiltration matches>
<Context: which account, which device, benign vs suspicious>

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| 🔴/🟢/🟡 **Factor** | Evidence-based finding |

---

## Verdict

**ASCII Verdict Box (REQUIRED):**

Render a box-drawn verdict summary inside a code fence. **Inner width: 66 chars.** No emoji inside boxes. Pad every line to exactly 66 chars between `│` markers.

For fleet-wide reports:
```
┌──────────────────────────────────────────────────────────────────┐
│  OVERALL FLEET RISK: <LEVEL> -- <One-line summary>               │
│  Flagged Devices: X of Y  (Threshold: 150%)                      │
│  Root Cause: <Brief root cause explanation>                      │
└──────────────────────────────────────────────────────────────────┘
```

For single-device reports:
```
┌──────────────────────────────────────────────────────────────────┐
│  OVERALL RISK: <LEVEL> -- <One-line summary>                     │
│  Drift Score: XX.X  (Interpretation)                             │
│  Root Cause: <Brief root cause explanation>                      │
└──────────────────────────────────────────────────────────────────┘
```

**Then** render the full verdict with:
- Per-device verdicts (for fleet-wide)
- Root Cause Analysis paragraph
- Key Findings (numbered list)
- Recommendations (emoji-prefixed list)

---

## Appendix: Query Details

Render a single markdown table summarizing all queries executed. **Do NOT include full KQL text** — the canonical queries are already documented in this SKILL.md file. The appendix serves as an audit trail only.

| Query | Table(s) | Records Scanned | Results | Execution |
|-------|----------|----------------:|--------:|----------:|
| Q15 — Device Process Baseline vs. Recent | DeviceProcessEvents | X,XXX | N rows | X.XXs |
| ... | ... | ... | ... | ... |

*Query definitions: see the Sample KQL Queries section in this SKILL.md file.*
```

---

## Known Pitfalls

### SecurityAlert.Status Is Immutable — Always Join SecurityIncident
**Problem:** The `Status` field on `SecurityAlert` is set to `"New"` at creation time and **never changes**. It does NOT reflect whether the alert has been investigated, closed, or classified.
**Solution:** MUST join with `SecurityIncident` to get real `Status` (New/Active/Closed) and `Classification` (TruePositive/FalsePositive/BenignPositive). See Query 18 which implements this join.

### Low-Volume Statistical Inflation
**Problem:** Entities with very low baseline activity will show extreme volume ratios even with minor changes.
**Solution:** Apply the denominator floor (minimum 10 events/day for volume ratio calculation). Always flag low-volume baselines in the report.

### Seasonal/Cyclical Baselines
**Problem:** Some devices have weekly patterns (lower on weekends) or monthly cycles (patch Tuesday).
**Solution:** Note if the recent window falls on an atypical portion of the cycle. The baseline smooths most cyclical patterns, but edge cases exist.

### Newly Onboarded Devices (DriftScore = 999)
**Problem:** Devices that appear only in the recent window (no baseline data) will have all dimension ratios default to 999, producing an extreme drift score. This does NOT indicate malicious drift — it indicates a newly discovered or recently onboarded device.
**Solution:** Flag these devices as "🔵 New Device — No Baseline" rather than "🔴 Critical Drift". Review the process inventory to confirm the device is running expected management software (MDM agents, AV, etc.). Recommend monitoring for an additional baseline period before assessing drift.

### Data Lake Ingestion Boundary
**Problem:** DeviceProcessEvents in Sentinel Data Lake may have an ingestion lag or retention boundary that causes the most recent hours of data to be absent. This can make devices appear to have zero recent-window activity when data simply hasn't been ingested yet.
**Solution:** In the fleet daily trend (Query 14), verify that the most recent day has comparable event counts to previous days. If the last day shows significantly fewer events across ALL devices, note: "⚠️ Data Lake ingestion boundary detected — recent window may be incomplete." Adjust the recent window start time if needed.

### Advanced Hunting Fallback
**Problem:** `DeviceProcessEvents` may fail in Advanced Hunting (`RunAdvancedHuntingQuery`) due to query complexity, timeout, or API limitations. This table is available in both Advanced Hunting and Sentinel Data Lake.
**Solution:** Default to **Sentinel Data Lake** (`query_lake` with `TimeGenerated`) for device process drift queries. Advanced Hunting uses `Timestamp` instead of `TimeGenerated` and has a 30-day retention limit. If Data Lake also fails, check if the table is connected via the Defender XDR connector.

### System/Service Accounts Dominating Volume
**Problem:** The majority of process events on servers come from system accounts (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `root`). These accounts are expected and will dominate volume, process, and chain dimensions.
**Solution:** When analyzing drift, distinguish between system-level processes (expected) and user-driven processes (more significant for drift). In the account landscape, flag any human user accounts (`non-system`) executing unusual processes. System accounts executing new processes are still worth noting but at lower priority.

### Short Baseline Windows and False Positives
**Problem:** Unlike SPN/user drift which uses a 90-day baseline, device process drift often uses shorter windows (e.g., 6 days baseline, 1 day recent). Short baselines miss infrequent but legitimate processes (weekly maintenance scripts, monthly update cycles, etc.).
**Solution:** Note the baseline length in the report. If many "first-seen" processes are common system utilities (Task Scheduler, Windows Update, antivirus scans), acknowledge that a longer baseline would likely include them. Recommend extending to 14-30 days for production use.

### DeviceProcessEvents Volume Limits
**Problem:** `DeviceProcessEvents` can generate massive volumes — tens of thousands of events per device per day on busy servers. KQL queries with `dcount()` and `make_set()` can be expensive.
**Solution:** Always apply `TimeGenerated` filter as the FIRST filter. Use `take` or `summarize` to limit intermediate results. For fleet-wide analysis across many devices, consider processing in batches if total events exceed 500K.

### Intermittent-Use Device Volume Inflation
**Problem:** Devices that are only powered on occasionally (e.g., once per month for maintenance, lab servers, training VMs) will have their baseline daily average diluted across the full analysis window — even though telemetry only exists for a handful of days. When one of these devices powers on during the recent window, the volume ratio can spike to 300%+ even though per-session behavior is identical to baseline sessions. This creates near-threshold or above-threshold DriftScores driven entirely by the volume dimension, with no meaningful behavioral change.
**Solution:** For any device with Volume ratio >200% but Process/Account/Chain/Company ratios below 100%, run **Query 21 (DeviceInfo uptime)** to determine actual days online. If the device was online for <30% of the baseline window (i.e., fewer than ~27 out of 90 days), flag as "⚠️ Intermittent device — volume-driven score inflation" and include a per-session comparison (Query 22). Consider reporting both the raw DriftScore and an "adjusted" assessment that contextualizes the volume dimension against actual uptime days rather than calendar days. The **diversity dimensions** (Processes, Accounts, Chains, Companies) are not affected by intermittent usage and remain reliable drift indicators.

**Chart formatting for adjusted Volume:** In the ASCII drift chart, display only the **effective (adjusted) percentage** in the percentage column, and append the raw value in the description text after the bar. This avoids variable-width bracket content that breaks bar alignment. Example:
```
Volume   [ 85.1%] ████████────── ↓ Adjusted from 288.3% raw (intermittent uptime)
Process  [ 79.5%] ████████────── ↓ Contracting (97/122 unique)
```

### Version-Stamped Process Name False Positives
**Problem:** Automatic software updates produce binaries with version numbers embedded in the filename (e.g., `AM_Delta_Patch_1.443.XXX.0.exe`, `MicrosoftEdge_X64_134.0.XXXX.XX_*.exe`, `odt*.tmp.exe`). These appear as "first-seen" in Query 16 and "new chains" in Query 17 regardless of baseline length, because each update generates a unique filename.
**Solution:** When interpreting first-seen processes, check `ProcessVersionInfoCompanyName` — if the signing company is well-known (Microsoft Corporation, Google LLC, etc.), these are expected update artifacts. In the report, group these under "📦 Expected Update Artifacts" rather than flagging as suspicious drift. For automated scoring, consider excluding filenames matching patterns like `AM_Delta_Patch_*`, `MicrosoftEdge_X64_*`, and `*.tmp.exe` from the drift score calculation, or weighting them lower.

### Linux Processes Dominate Unsigned Query
**Problem:** Linux binaries do not populate `ProcessVersionInfoCompanyName` (a Windows PE metadata field). Query 19b (unsigned processes) will be flooded with legitimate Linux utilities (`gawk`, `bash`, `grep`, `sed`, `curl`, `apt-get`, etc.) on any fleet containing Linux devices.
**Solution:** When running Query 19b on a mixed fleet, filter to Windows devices only (`| where DeviceName !has "linux"`) or annotate Linux results separately. For Linux devices, focus on unusual binary paths (e.g., processes running from `/tmp/`, `/dev/shm/`, or user home directories) rather than signing status.

---

## Error Handling

### Common Issues

| Issue | Solution |
|-------|----------|
| `DeviceProcessEvents` table not found | Table may not be connected via Defender XDR connector. Check with `search_tables`. Verify Defender for Endpoint is onboarded. |
| `DeviceProcessEvents` query timeout | Reduce lookback window or add intermediate `summarize`. Split fleet-wide into batches by device if >20 devices. |
| Advanced Hunting fails for DeviceProcessEvents | Default to Sentinel Data Lake (`query_lake`). Adapt `Timestamp` → `TimeGenerated`. See Advanced Hunting Fallback pitfall. |
| Device appears only in recent window | New device onboarding — set DriftScore=999, flag as "New Device", not malicious drift. |
| All devices show zero recent events | Data Lake ingestion boundary — verify with fleet daily trend (Query 14). Adjust recent window if needed. |
| Query timeout | Reduce the lookback window, or add `\| take 100` to intermediate results. |

### Validation Checklist

Before presenting results, verify:

- [ ] All applicable data sources were queried (even if some returned 0 results)
- [ ] Low-volume denominator floor was applied to any device with BL_DailyAvg < 10
- [ ] Corroborating evidence was checked for every flagged device
- [ ] Empty results are explicitly reported with ✅ (not silently omitted)
- [ ] The report includes the drift score formula and threshold for transparency
- [ ] SecurityAlert was joined with SecurityIncident for real Status/Classification (never read SecurityAlert.Status directly)
- [ ] Incident classifications (TP/FP/BP) were factored into risk assessment — FalsePositive alerts discounted, TruePositive alerts escalated
- [ ] Fleet daily trend was verified for data completeness (no ingestion boundary issues)
- [ ] Newly onboarded devices (baseline-only = no recent, or recent-only = no baseline) were correctly identified
- [ ] DriftScore=999 entities were flagged as "New Device" not "Critical Drift"
- [ ] System/service account processes were distinguished from user-driven processes
- [ ] First-seen processes were checked for legitimate software deployment vs suspicious binaries
- [ ] Version-stamped update binaries (AM_Delta_Patch_*, MicrosoftEdge_X64_*, odt*.tmp.exe) were classified as expected noise
- [ ] Unsigned/unusually-signed binaries were identified (Linux devices flagged separately from Windows)
- [ ] Notable command-line patterns were searched (reconnaissance, lateral movement, persistence, exfiltration)
- [ ] SecurityAlert correlation was performed for all analyzed devices
- [ ] Baseline window length was noted and its limitations acknowledged
- [ ] For devices with Volume ratio >200% or DriftScore >130%: DeviceInfo uptime (Query 21) was checked to identify intermittent-use devices
- [ ] Intermittent-use devices were annotated with uptime context and per-session comparison (Query 22)
- [ ] Volume-driven drift scores on intermittent devices were contextualized as mathematical artifacts (not behavioral expansion)

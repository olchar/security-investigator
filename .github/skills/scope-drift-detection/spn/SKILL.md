---
name: scope-drift-detection-spn
description: 'Use this skill when asked to detect scope drift, behavioral expansion, or gradual privilege/access creep in service principals or automation accounts. Triggers on keywords like "scope drift", "service principal drift", "SPN behavioral change", "automation account drift", "baseline deviation", "access expansion", or when investigating whether a service principal has gradually expanded beyond its intended purpose. This skill builds a 90-day behavioral baseline per SPN, compares it with 7-day recent activity, computes a weighted Drift Score across 5 dimensions, and correlates with SecurityAlert, AuditLogs, and DeviceNetworkEvents for corroborating evidence.'
---

# Service Principal Scope Drift Detection — Instructions

## Purpose

> **Credit:** The scope drift detection concept for service principals was inspired by [Iftekhar Hussain](https://techcommunity.microsoft.com/users/iftekhar%20hussain/20243)'s article *[The Agentic SOC Era: How Sentinel MCP Enables Autonomous Security Reasoning](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/the-agentic-soc-era-how-sentinel-mcp-enables-autonomous-security-reasoning/4491003)* (Feb 2026), which demonstrated multi-source correlation across AADServicePrincipalSignInLogs, AuditLogs, DeviceNetworkEvents, and SecurityAlert to build 90-day behavioral baselines and surface drift via weighted scoring.

This skill detects **scope drift** — the gradual, often imperceptible expansion of access or behavior beyond an established baseline — in **Entra ID service principals**. Unlike sudden compromise (which triggers alerts), scope drift is a slow-burn pattern that evades threshold-based detections.

**Entity Type:** Service Principal

| Identifier | Primary Table(s) | Use Case |
|------------|-------------------|----------|
| ServicePrincipalName / ServicePrincipalId | `AADServicePrincipalSignInLogs` | App registrations, automation accounts, managed identities |

**What this skill detects:**
- Volume spikes in sign-in activity relative to historical baseline
- New target resources (APIs, services) not previously accessed
- New source IP addresses or geographic locations
- Increased failure rates indicating probing or misconfiguration
- Credential/permission changes correlated with behavioral shifts
- Security alerts involving the drifting entities

**Related skills:**
- [User Scope Drift](../user/SKILL.md) — for user accounts (UPNs)
- [Device Scope Drift](../device/SKILL.md) — for endpoints/devices

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
3. **[Quick Start](#quick-start-tldr)** - 6-step investigation pattern
4. **[Drift Score Formula](#drift-score-formula)** - Weighted composite scoring (5 dimensions)
5. **[Execution Workflow](#execution-workflow)** - Complete 4-phase process
6. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns (Queries 1-5)
7. **[Report Template](#report-template)** - Output format specification
8. **[Known Pitfalls](#known-pitfalls)** - Edge cases and false positives
9. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY SPN scope drift analysis:**

1. **ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)
2. **ALWAYS ask the user for output mode** if not specified: inline chat summary or markdown file report (or both)
3. **ALWAYS build baseline FIRST** before comparing recent activity
4. **ALWAYS apply the low-volume denominator floor** to prevent false-positive drift scores on sparse baselines
5. **ALWAYS correlate across all required data sources** (AADServicePrincipalSignInLogs, AuditLogs, SecurityAlert, DeviceNetworkEvents)
6. **ALWAYS run independent queries in parallel** for performance
7. **NEVER report a drift flag without corroborating evidence** from at least one secondary data source

### Data Sources

| Data Source | Role | Purpose |
|-------------|------|---------|
| `AADServicePrincipalSignInLogs` | ✅ Primary | SPN sign-in behavioral baseline |
| `AuditLogs` | ✅ Corroboration | Permission/credential/role changes |
| `SecurityAlert` | ✅ Corroboration | Corroborating alert evidence |
| `SecurityIncident` | ✅ Corroboration | Real alert status/classification |
| `DeviceNetworkEvents` | ✅ Corroboration | Network activity correlation |

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
- Includes ASCII tables, Pareto chart, drift dimension bars, and security assessment
- Best for quick review and interactive follow-up questions

### Mode 2: Markdown File Report
- Save a comprehensive report to `reports/scope-drift/spn/Scope_Drift_Report_<entity>_<timestamp>.md`
- All ASCII visualizations render correctly inside markdown code fences (` ``` `)
- Includes all data from inline mode plus additional detail sections
- Use `create_file` tool — NEVER use terminal commands for file output
- **Filename patterns:**
  - **Single SPN:** `Scope_Drift_Report_<spn_short_name>_YYYYMMDD_HHMMSS.md` (use display name, sanitized: lowercase, spaces/special chars replaced with hyphens)
  - **All SPNs:** `Scope_Drift_Report_all_spns_YYYYMMDD_HHMMSS.md` (tenant-wide scan of all service principals)

### Markdown Rendering Notes
- ✅ ASCII tables, box-drawing characters, and bar charts render perfectly in markdown code blocks
- ✅ Unicode block characters (`█` full block, `─` box-drawing horizontal) display correctly in monospaced fonts
- ✅ Emoji indicators (🔴🟢🟡⚠️✅) render natively in GitHub-flavored markdown
- ✅ Standard markdown tables (`| col |`) render as formatted tables
- **Tip:** Wrap all ASCII art in triple-backtick code fences for consistent rendering

---

## Quick Start (TL;DR)

When a user requests SPN scope drift detection:

1. **Select Workspace** → `list_sentinel_workspaces`, auto-select or ask
2. **Determine Output Mode** → Ask if not specified: inline, markdown file, or both
3. **Run Phase 1** → Query 1 (AADServicePrincipalSignInLogs baseline vs recent)
4. **Apply Entity Scaling** → Compute drift scores, rank SPNs, apply tiered depth limits (see [Entity Scaling](#entity-scaling-large-environments))
5. **Run Phases 2-3** → Queries 2-5 (AuditLogs + SecurityAlert + DeviceNetworkEvents) — scoped per tier
6. **Compute Final Assessment** → Combine drift scores with corroborating evidence
7. **Output Results** → Render in selected mode(s) with tiered depth

---

## Entity Scaling (Large Environments)

**Problem:** In small tenants, running Queries 2–5 for every SPN is fine. In enterprise environments with hundreds or thousands of service principals, running deep-dive queries for every flagged entity is prohibitively expensive and produces unreadable reports.

**Solution:** After Phase 1 computes drift scores for all SPNs, apply tiered depth based on entity count and drift severity.

### Entity Count Detection

After Query 1, count distinct SPNs in the result set:

| Entity Count | Tier | Deep Dive Limit | Behavior |
|-------------|------|-----------------|----------|
| **≤ 30 SPNs** | Small | All flagged | Full deep dive for every SPN > 150%. No limiting needed. |
| **31–100 SPNs** | Medium | Top 10 | Full deep dive for top 10 by DriftScore. Summary row for remaining flagged SPNs. |
| **101–500 SPNs** | Large | Top 10 | Full deep dive for top 10. Tier 2 summary (next 15) with new resources/IPs only. Remaining flagged SPNs listed in ranking table with scores but no deep dive. |
| **> 500 SPNs** | Very Large | Top 10 | Same as Large, plus: filter Phase 1 results to `BL_TotalSignIns > 10` to exclude near-silent SPNs from scoring. |

### Tiered Depth Model

After computing drift scores and ranking all SPNs, assign tiers:

| Tier | Entities | Queries Run | Report Depth |
|------|----------|-------------|--------------|
| **Tier 1** (Full) | Top N by DriftScore | All: Q2, Q3, Q4, Q5 | Full deep dive: ASCII chart, dimension table, new resources/IPs/locations, AuditLog changes, alerts, network activity |
| **Tier 2** (Summary) | Next 15 flagged SPNs (or remaining if < 15) | Q4 only (SecurityAlert correlation) | One-line summary per SPN: score, top 3 new resources, new IPs, flag status |
| **Tier 3** (Score only) | All remaining flagged SPNs | None beyond Phase 1 | Row in ranking table: SPN name, drift score, dimension ratios, flag emoji |
| **Stable** | SPNs ≤ 150% | None beyond Phase 1 | Omitted from deep dives. Included in summary statistics only. |

### User Override

If the user explicitly asks for "all SPNs detailed" or "full report", honor the request but warn:

> ⚠️ Tenant has <N> service principals with <X> flagged above 150%. Running full deep dives for all flagged SPNs may be slow and produce a very long report. Proceed? (Default: top 10 deep dives + summary for others)

### Report Disclosure

When tiered depth is applied, **always disclose** in the report header:

```
**Entity Count:** <N> service principals (Large tenant — tiered analysis applied)
**Deep Dives:** Top <X> by DriftScore (Tier 1: full analysis)
**Summaries:** <Y> additional flagged SPNs (Tier 2: alert correlation only)
**Score Only:** <Z> additional flagged SPNs (Tier 3: ranking table only)
**Stable:** <W> SPNs ≤ 150% (omitted from deep dives)
```

---

## Drift Score Formula

The Drift Score is a weighted composite of behavioral dimensions, normalized so that **100 = identical to baseline**.

### Service Principal Formula (5 Dimensions)

$$
\text{DriftScore}_{SPN} = 0.30V + 0.25R + 0.20IP + 0.15L + 0.10F
$$

| Dimension | Weight | Metric | Why |
|-----------|--------|--------|-----|
| **Volume** | 30% | Daily avg sign-ins (recent / baseline) | Sudden activity surges indicate misuse or compromise |
| **Resources** | 25% | Distinct target resources accessed | New resource targets = lateral expansion |
| **IPs** | 20% | Distinct source IP addresses | New IPs = infrastructure changes, credential theft |
| **Locations** | 15% | Distinct geographic locations | New geos = impossible travel or proxy rotation |
| **Failure Rate** | 10% | Failure rate delta (recent − baseline) | Rising failures = probing or brute-force |

### Interpretation Scale

| Score | Meaning | Action |
|-------|---------|--------|
| **< 80** | Contracting scope | ✅ Normal — entity is doing less than usual |
| **80–120** | Stable / normal variance | ✅ No action required |
| **120–150** | Moderate deviation | 🟡 Monitor — check for legitimate reasons |
| **> 150** | Significant drift | 🔴 FLAG — investigate with corroborating evidence |
| **> 250** | Extreme drift | 🔴 CRITICAL — immediate investigation required |

### Low-Volume Denominator Floor

**CRITICAL:** For entities with sparse baselines (< 10 daily sign-ins), the volume ratio is artificially inflated. Apply a floor:

```
IF BL_DailyAvg < 10:
    AdjustedVolumeRatio = RC_DailyAvg / max(BL_DailyAvg, 10) * 100
    Flag the score with: "⚠️ Low-volume baseline — ratio may be inflated"
```

This prevents an entity averaging 1 sign-in/day from triggering at 6 sign-ins/day (600% ratio but trivial absolute volume).

---

## Execution Workflow

### Phase 1: Behavioral Baseline vs. Recent Comparison

**Baseline window:** 90 days (days 8–97 ago)
**Recent window:** 7 days (last 7 days)

This is the primary query that computes per-SPN behavioral profiles and drift metrics.

| Data Source | Query | Notes |
|-------------|-------|-------|
| `AADServicePrincipalSignInLogs` | Query 1 | Single query, 5 dimensions |

### Phase 2: Permission & Configuration Change Audit

**Data source:** `AuditLogs`
**Correlation:** Same 97-day window, filtered to SPNs from Phase 1

**Operations to Look For:**
- `Add/Remove service principal credentials`
- `Update application – Certificates and secrets management`
- `Consent to application`
- `Add delegated permission grant`
- `Add app role assignment to service principal`
- `Add application`
- `Add service principal`
- Any operation containing: "permission", "role", "consent", "oauth", "credential", "certificate", "secret"

### Phase 3: Corroborating Signal Collection (Run in Parallel)

- **SecurityAlert + SecurityIncident (Query 4):** Check for alerts referencing SPN IDs or names, joined with SecurityIncident for real status/classification. **Never read SecurityAlert.Status directly** — it's always "New".
- **DeviceNetworkEvents (Query 5):** Check for anomalous network activity from service accounts.

### Phase 4: Score Computation & Report Generation

1. Compute DriftScore per SPN using the 5-dimension formula
2. Apply the low-volume denominator floor
3. Flag any entity exceeding 150% threshold
4. For flagged entities: assess corroborating evidence (permission changes, alerts, network anomalies)
5. Generate risk assessment with emoji-coded findings
6. Render output in the user's selected mode

---

## Sample KQL Queries

### Query 1: Baseline vs. Recent Behavioral Comparison

```kql
// Build 90-day baseline (days 8-97 ago) vs recent 7 days per service principal
let baselineStart = ago(97d);
let baselineEnd = ago(7d);
let recentStart = ago(7d);
// Baseline period: per-SPN behavioral profile
let baseline = AADServicePrincipalSignInLogs
| where TimeGenerated between (baselineStart .. baselineEnd)
| summarize
    BL_TotalSignIns = count(),
    BL_Days = dcount(bin(TimeGenerated, 1d)),
    BL_DistinctResources = dcount(ResourceDisplayName),
    BL_DistinctIPs = dcount(IPAddress),
    BL_DistinctLocations = dcount(Location),
    BL_FailRate = round(1.0 * countif(ResultType != "0" and ResultType != 0) / count() * 100, 2),
    BL_Resources = make_set(ResourceDisplayName, 50),
    BL_IPs = make_set(IPAddress, 50),
    BL_Locations = make_set(Location, 50)
    by ServicePrincipalName, ServicePrincipalId;
// Recent period: last 7 days
let recent = AADServicePrincipalSignInLogs
| where TimeGenerated >= recentStart
| summarize
    RC_TotalSignIns = count(),
    RC_Days = dcount(bin(TimeGenerated, 1d)),
    RC_DistinctResources = dcount(ResourceDisplayName),
    RC_DistinctIPs = dcount(IPAddress),
    RC_DistinctLocations = dcount(Location),
    RC_FailRate = round(1.0 * countif(ResultType != "0" and ResultType != 0) / count() * 100, 2),
    RC_Resources = make_set(ResourceDisplayName, 50),
    RC_IPs = make_set(IPAddress, 50),
    RC_Locations = make_set(Location, 50)
    by ServicePrincipalName, ServicePrincipalId;
// Join and compute drift metrics
baseline
| join kind=inner recent on ServicePrincipalId
| extend
    BL_DailyAvg = round(1.0 * BL_TotalSignIns / BL_Days, 1),
    RC_DailyAvg = round(1.0 * RC_TotalSignIns / RC_Days, 1)
| extend
    VolumeRatio = iff(BL_DailyAvg > 0, round(RC_DailyAvg / BL_DailyAvg * 100, 1), 999.0),
    ResourceRatio = iff(BL_DistinctResources > 0, round(1.0 * RC_DistinctResources / BL_DistinctResources * 100, 1), 999.0),
    IPRatio = iff(BL_DistinctIPs > 0, round(1.0 * RC_DistinctIPs / BL_DistinctIPs * 100, 1), 999.0),
    LocationRatio = iff(BL_DistinctLocations > 0, round(1.0 * RC_DistinctLocations / BL_DistinctLocations * 100, 1), 999.0),
    FailRateDelta = RC_FailRate - BL_FailRate,
    NewResources = set_difference(RC_Resources, BL_Resources),
    NewIPs = set_difference(RC_IPs, BL_IPs),
    NewLocations = set_difference(RC_Locations, BL_Locations)
| extend
    NewResourceCount = array_length(NewResources),
    NewIPCount = array_length(NewIPs),
    NewLocationCount = array_length(NewLocations)
| extend
    // Composite Drift Score (weighted)
    DriftScore = round(
        (VolumeRatio * 0.30) +
        (ResourceRatio * 0.25) +
        (IPRatio * 0.20) +
        (LocationRatio * 0.15) +
        (iff(FailRateDelta > 0, 100.0 + FailRateDelta * 10, 100.0) * 0.10)
    , 1)
| project ServicePrincipalName, ServicePrincipalId,
    BL_Days, BL_TotalSignIns, BL_DailyAvg, BL_DistinctResources, BL_DistinctIPs, BL_DistinctLocations, BL_FailRate,
    RC_Days, RC_TotalSignIns, RC_DailyAvg, RC_DistinctResources, RC_DistinctIPs, RC_DistinctLocations, RC_FailRate,
    VolumeRatio, ResourceRatio, IPRatio, LocationRatio, FailRateDelta, DriftScore,
    NewResourceCount, NewIPCount, NewLocationCount,
    NewResources, NewIPs, NewLocations,
    BL_Resources, RC_Resources
| order by DriftScore desc
```

### Query 2: AuditLog Permission & Credential Changes

```kql
// Permission/credential/role changes for service principals
// Substitute <SPN_IDS> with comma-separated SPN IDs from Query 1
// Substitute <SPN_NAMES> with SPN display names from Query 1
AuditLogs
| where TimeGenerated > ago(97d)
| where OperationName has_any ("service principal", "application", "credential", "certificate",
    "secret", "permission", "role", "consent", "oauth")
| where tostring(TargetResources) has_any (<SPN_IDS>)
    or tostring(InitiatedBy) has_any (<SPN_IDS>)
| extend InBaseline = TimeGenerated < ago(7d)
| summarize
    BaselineOps = countif(InBaseline),
    RecentOps = countif(not(InBaseline)),
    Operations = make_set(OperationName, 20),
    RecentOperations = make_set_if(OperationName, not(InBaseline), 20)
    by bin(TimeGenerated, 7d), OperationName
| order by TimeGenerated desc
| take 50
```

### Query 3: Detailed Recent AuditLog Changes

```kql
// Detailed drill-down for the recent 7-day window
// Substitute <SPN_IDS> with SPN IDs from Query 1
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("service principal", "application", "credential", "certificate",
    "secret", "permission", "role", "consent", "oauth", "update")
| where tostring(TargetResources) has_any (<SPN_IDS>)
| project TimeGenerated, OperationName, Result,
    InitiatedBy = tostring(parse_json(tostring(InitiatedBy)).app.displayName),
    TargetName = tostring(parse_json(tostring(parse_json(tostring(TargetResources))[0])).displayName),
    TargetId = tostring(parse_json(tostring(parse_json(tostring(TargetResources))[0])).id),
    ModifiedProperties = tostring(parse_json(tostring(parse_json(tostring(TargetResources))[0])).modifiedProperties)
| order by TimeGenerated desc
```

### Query 4: SecurityAlert + SecurityIncident Correlation

```kql
// Security alerts referencing any of the service principals, joined with SecurityIncident for real status
// IMPORTANT: SecurityAlert.Status is immutable (always "New") — MUST join SecurityIncident for real Status/Classification
// Substitute <SPN_IDS> and <SPN_NAMES> with values from Query 1
let relevantAlerts = SecurityAlert
| where TimeGenerated > ago(97d)
| where Entities has_any (<SPN_IDS>) or Entities has_any (<SPN_NAMES>)
    or CompromisedEntity has_any (<SPN_NAMES>)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProductName, ProductComponentName, Tactics, TimeGenerated;
SecurityIncident
| where CreatedTime > ago(97d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| extend Period = iff(TimeGenerated1 < ago(7d), "Baseline", "Recent")
| summarize
    BaselineAlerts = countif(Period == "Baseline"),
    RecentAlerts = countif(Period == "Recent"),
    TotalAlerts = count(),
    Severities = make_set(AlertSeverity, 5),
    IncidentStatuses = make_set(Status, 5),
    Classifications = make_set(Classification, 5),
    BaselineIncidents = dcountif(IncidentNumber, Period == "Baseline"),
    RecentIncidents = dcountif(IncidentNumber, Period == "Recent")
    by ProductName
| order by TotalAlerts desc
```

**Interpreting Incident Status in Drift Context:**
| Incident Status | Classification | Impact on Drift Assessment |
|-----------------|----------------|----------------------------|
| Closed | TruePositive | 🔴 Confirmed threat — significantly increases drift risk |
| Closed | FalsePositive | 🟢 False alarm — discount from drift risk, note as noise |
| Closed | BenignPositive | 🟡 Expected behavior — note but don't escalate |
| Active/New | Any | 🟠 Unresolved — flag for attention, may indicate ongoing threat |

**Product Name Mapping (Legacy → Current Branding):**

The `ProductName` field in `SecurityAlert` contains the detection product. When rendering reports, translate to current Microsoft branding:

| SecurityAlert.ProductName (raw) | Report Display Name |
|--------------------------------|---------------------|
| Microsoft Defender Advanced Threat Protection | **Microsoft Defender for Endpoint** |
| Microsoft Cloud App Security | **Microsoft Defender for Cloud Apps** |
| Microsoft Data Loss Prevention | **Microsoft Purview Data Loss Prevention** |
| Azure Sentinel | **Microsoft Sentinel** |
| Microsoft 365 Defender | **Microsoft Defender XDR** |
| Office 365 Advanced Threat Protection | **Microsoft Defender for Office 365** |
| Azure Advanced Threat Protection | **Microsoft Defender for Identity** |

**Note:** `ProviderName` (e.g., `ASI Scheduled Alerts`, `MDATP`, `MCAS`) is the internal provider identifier. `ProductName` (e.g., `Azure Sentinel`, `Microsoft Defender Advanced Threat Protection`) is the user-facing product name. Always use `ProductName` for grouping and display; `ProviderName` is unreliable for product identification (e.g., all alerts show as `Microsoft XDR` at the incident level).

**Report Rendering:** Group alerts by product using the current branded name. Show **Baseline Alerts vs Recent Alerts** and **Baseline Incidents vs Recent Incidents** columns per product row, plus Severity and Classification. Include a **Total** row. Add a brief 1-2 sentence summary comparing alert volume between periods. Do NOT list individual alert names — keep the table concise at the product level.

### Query 5: DeviceNetworkEvents Correlation

```kql
// Network activity from service accounts targeting SPN-associated resources
// Focus on system/service accounts and connections to Microsoft service endpoints
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessAccountName has_any ("service", "system")
    or RemoteUrl has_any ("graph.microsoft.com", "management.azure.com",
        "vault.azure.net", "storage.azure.net")
| summarize
    ConnectionCount = count(),
    DistinctDevices = dcount(DeviceName),
    Devices = make_set(DeviceName, 10),
    DistinctRemoteIPs = dcount(RemoteIP),
    RemoteUrls = make_set(RemoteUrl, 10),
    Ports = make_set(RemotePort, 10)
    by InitiatingProcessFileName, InitiatingProcessAccountName
| where ConnectionCount > 0
| order by ConnectionCount desc
| take 20
```

---

## Report Template

### Inline Chat Report Structure

The inline report MUST include these sections in order:

1. **Header** — Workspace, analysis period, drift threshold, data sources
2. **Ranked Drift Score Table** — All SPNs sorted by DriftScore descending, with per-dimension ratios
3. **Flagged Entity Deep Dive** (for each **Tier 1** SPN > 150%) — Baseline vs. recent comparison, dimension bar chart, new IPs/resources, corroborating evidence
4. **Tier 2 Entity Summaries** (if entity scaling applied) — One-line summary per Tier 2 SPN: score, top 3 new resources, new IPs, alert count
5. **Correlated Signal Summary** — Findings from all 4 data sources in a single table
5. **Behavioral Baseline Chart** — ASCII bar chart showing all SPNs' daily avg vs. baseline
6. **Security Assessment** — Emoji-coded findings table with evidence citations
7. **Verdict Box** — Overall risk level, root cause analysis, recommendations

### Markdown File Report Structure

When outputting to markdown file, include everything from the inline format PLUS:

**Filename patterns:**
- **Single SPN:** `reports/scope-drift/spn/Scope_Drift_Report_<spn_short_name>_YYYYMMDD_HHMMSS.md`
- **All SPNs:** `reports/scope-drift/spn/Scope_Drift_Report_all_spns_YYYYMMDD_HHMMSS.md`

```markdown
# Service Principal Scope Drift Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Workspace:** <workspace_name>
**Baseline Period:** <start> → <end> (90 days)
**Recent Period:** <start> → <end> (7 days)
**Drift Threshold:** 150%
**Data Sources:** AADServicePrincipalSignInLogs, AuditLogs, DeviceNetworkEvents, SecurityAlert

---

## Executive Summary

<1-3 sentence summary: how many SPNs analyzed, how many flagged, overall risk level>

---

## Drift Score Ranking

<ASCII table with all SPNs, per-dimension ratios, flag status>
<!-- Wrap in code fence for consistent rendering -->

---

## Flagged Entities

### <SPN Name> — Drift Score <score>

**ASCII Drift Dimension Chart (REQUIRED):**

Render a box-drawn chart inside a code fence. **Inner width: 58 chars** (every line between `│` markers = exactly 58 visual characters). No emoji inside boxes — use text labels.

**Alignment:** Name (9 chars padded) + weight (5) + gap (2) + bars (20 `█─`) + gap (2) + pct (6, right-aligned: `XXX.X%` or ` XX.X%`) + gap (2) + direction (10 total: `^`/`v`/`=` + 9 trailing spaces, or FailRate: delta like `v-X.XX` + 4 trailing spaces). Status labels (centered): `STABLE`, `STABLE (Low-Volume)`, `NEAR THRESHOLD`, `ABOVE THRESHOLD`, `CRITICAL`. Direction: `^` (up), `v` (down), `=` (stable).

**Bar characters:** Use `█` (U+2588 full block) for filled portions and `─` (U+2500 box-drawing horizontal) for the unfilled track.

```
┌──────────────────────────────────────────────────────────┐
│                   SPN DRIFT SCORE: XX.X                  │
│                          STABLE                          │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Volume   (30%)  ██████──────────────  XXX.X%  ^         │
│  Resources(25%)  ███─────────────────   XX.X%  v         │
│  IPs      (20%)  ██████──────────────  XXX.X%  =         │
│  Locations(15%)  ██──────────────────   XX.X%  v         │
│  FailRate (10%)  ██████──────────────  XXX.X%  v-X.XX    │
│                                                          │
│  ────────────────────────── 100% baseline ──┤            │
│                  150% drift threshold ▲                  │
└──────────────────────────────────────────────────────────┘
```

**Bar fill:** 20 chars wide. Filled = round(ratio/100 × 20), capped at 20. Title and status: center within 58 chars (include adjusted score if applicable, e.g., "SPN DRIFT SCORE: 107.5 (adj 80.5)"). Use `█` for filled, `─` for unfilled.

**Then** render the standard markdown dimension table:

| Dimension | Weight | Baseline (90d) | Recent (7d) | Ratio | Weighted | Status |
|-----------|--------|----------------|-------------|-------|----------|--------|

<New resources, new IPs, new locations enumeration>
<Corroborating evidence from AuditLogs, SecurityAlert, DeviceNetworkEvents>

---

## Pareto Analysis

<ASCII Pareto chart of drift dimensions or categories>
<80/20 analysis text>

---

## Correlated Signals

| Data Source | Finding | Incident Status |
|-------------|---------|-----------------|
| AADServicePrincipalSignInLogs | ... | N/A |
| AuditLogs | ... | N/A |
| DeviceNetworkEvents | ... | N/A |
| SecurityAlert / SecurityIncident | <Group by ProductName, translate to current branding> | <Status: New/Active/Closed, Classification: TP/FP/BP> |

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| 🔴/🟢/🟡 **Factor** | Evidence-based finding |

---

## Verdict

**ASCII Verdict Box (REQUIRED):**

Render a box-drawn verdict summary inside a code fence. **Inner width: 66 chars.** No emoji inside boxes. Pad every line to exactly 66 chars between `│` markers.

```
┌──────────────────────────────────────────────────────────────────┐
│  OVERALL RISK: <LEVEL> -- <One-line summary>                     │
│  Flagged SPNs: X of Y  (Threshold: 150%)                         │
│  Root Cause: <Brief root cause explanation>                      │
└──────────────────────────────────────────────────────────────────┘
```

**Then** render the full verdict with:
- Root Cause Analysis paragraph
- Key Findings (numbered list)
- Recommendations (emoji-prefixed list)

---

## Appendix: Query Details

Render a single markdown table summarizing all queries executed. **Do NOT include full KQL text** — the canonical queries are already documented in this SKILL.md file. The appendix serves as an audit trail only.

| Query | Table(s) | Records Scanned | Results | Execution |
|-------|----------|----------------:|--------:|----------:|
| Q1 — SPN Baseline vs. Recent | AADServicePrincipalSignInLogs | X,XXX | N rows | X.XXs |
| ... | ... | ... | ... | ... |

*Query definitions: see the Sample KQL Queries section in this SKILL.md file.*
```

---

## Known Pitfalls

### SecurityAlert.Status Is Immutable — Always Join SecurityIncident
**Problem:** The `Status` field on `SecurityAlert` is set to `"New"` at creation time and **never changes**. It does NOT reflect whether the alert has been investigated, closed, or classified. Reading `SecurityAlert.Status` as current investigation status will always show "New" regardless of actual state.
**Solution:** MUST join with `SecurityIncident` to get real `Status` (New/Active/Closed) and `Classification` (TruePositive/FalsePositive/BenignPositive). See Query 4 which implements this join. When assessing drift risk from alerts, differentiate: Closed-FalsePositive alerts are noise (discount), Closed-TruePositive alerts are confirmed threats (escalate), Active/New incidents need attention (flag).

### Low-Volume Statistical Inflation
**Problem:** Entities with very low baseline activity (e.g., 1 sign-in/day) will show extreme volume ratios even with minor changes.
**Solution:** Apply the denominator floor (minimum 10 sign-ins/day for volume ratio calculation). Always flag low-volume baselines in the report.

### Seasonal/Cyclical Baselines
**Problem:** Some entities have weekly patterns (lower on weekends) or monthly cycles (month-end batch jobs).
**Solution:** Note if the 7-day recent window falls on an atypical portion of the cycle. The 90-day baseline smooths most cyclical patterns, but edge cases exist.

### IPv6 Fabric Address Churn
**Problem:** Microsoft first-party SPNs (MCAS, Defender, etc.) rotate through `fd00:` internal fabric IPv6 addresses automatically. This inflates the IP ratio without representing actual infrastructure changes.
**Solution:** When all new IPs share the same `fd00:` prefix, note this as "Microsoft internal fabric rotation" and downgrade the IP dimension's contribution to the drift score assessment. Do NOT flag IPv6 churn from Microsoft fabric addresses as suspicious.

### Credential Rotation False Positives
**Problem:** Automated certificate/secret rotation creates regular `Add/Remove service principal credentials` audit entries.
**Solution:** Check if credential operations follow a regular cadence (weekly/monthly). If rotation is periodic and consistent with baseline, classify as operational — not drift.

### SPNs Without Baseline Data
**Problem:** Newly provisioned SPNs have no baseline to compare against.
**Solution:** These are excluded from the `join kind=inner` and will not appear in results. If the user asks about a specific SPN with no baseline, report: "No baseline data available — SPN was provisioned within the recent window or has no sign-in history in the 90-day baseline period."

---

## Error Handling

### Common Issues

| Issue | Solution |
|-------|----------|
| `AADServicePrincipalSignInLogs` table not found | This table may not exist in all workspaces. Check if it's available with `search_tables`. Try Advanced Hunting as fallback. |
| Zero entities in results | Verify the workspace has sign-in data for the entity type. Check if logging is enabled. |
| Query timeout | Reduce the baseline window from 90 to 60 days, or add `\| take 100` to intermediate results. |
| AuditLogs `has_any` not matching | Ensure IDs are quoted strings in the `dynamic()` array. Use `tostring()` on dynamic fields. |
| Very large number of SPNs | Add `\| where BL_TotalSignIns > 10` to filter out extremely low-activity SPNs that add noise. |

### Validation Checklist

Before presenting results, verify:

- [ ] All applicable data sources were queried (even if some returned 0 results)
- [ ] Low-volume denominator floor was applied to any entity with BL_DailyAvg < 10
- [ ] Corroborating evidence was checked for every flagged entity
- [ ] Empty results are explicitly reported with ✅ (not silently omitted)
- [ ] The report includes the drift score formula and threshold for transparency
- [ ] SecurityAlert was joined with SecurityIncident for real Status/Classification (never read SecurityAlert.Status directly)
- [ ] Incident classifications (TP/FP/BP) were factored into risk assessment — FalsePositive alerts discounted, TruePositive alerts escalated
- [ ] IPv6 `fd00:` addresses were identified as Microsoft fabric (not adversary infrastructure)
- [ ] Credential rotation cadence was assessed for AuditLog findings

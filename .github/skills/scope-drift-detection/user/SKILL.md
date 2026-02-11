---
name: scope-drift-detection-user
description: 'Use this skill when asked to detect scope drift, behavioral expansion, or gradual privilege/access creep in user accounts. Triggers on keywords like "user drift", "user behavioral change", "user scope drift", "user baseline deviation", "user access expansion", or when investigating whether a user account has gradually expanded beyond its established behavioral baseline. This skill builds a 90-day behavioral baseline for both interactive and non-interactive sign-ins, compares with 7-day recent activity, computes weighted Drift Scores (7 dimensions for interactive, 6 for non-interactive), and correlates with SecurityAlert, AuditLogs, Identity Protection, custom anomaly tables, CloudAppEvents (cloud app activity drift), and EmailEvents (email pattern drift).'
---

# User Account Scope Drift Detection — Instructions

## Purpose

This skill detects **scope drift** — the gradual, often imperceptible expansion of access or behavior beyond an established baseline — in **Entra ID user accounts**. Unlike sudden compromise (which triggers alerts), scope drift is a slow-burn pattern that evades threshold-based detections.

**Entity Type:** User Account

| Identifier | Primary Table(s) | Use Case |
|------------|-------------------|----------|
| UserPrincipalName (UPN) | `SigninLogs` + `AADNonInteractiveUserSignInLogs` | Human users, admin accounts, shared mailboxes |

**What this skill detects:**
- Volume spikes in sign-in activity relative to historical baseline
- New applications accessed (potential unauthorized access or shadow IT)
- New target resources (APIs, services) not previously accessed
- New device/OS/browser combinations
- New source IP addresses or geographic locations
- Increased failure rates indicating probing or misconfiguration
- Account configuration changes correlated with behavioral shifts
- Security alerts involving the user
- Identity Protection risk events
- Pre-computed sign-in anomalies (custom table)
- Cloud app activity drift — new action types, admin operations, impersonation, external user activity (CloudAppEvents)
- Email pattern drift — volume/direction changes, new sender domains, threat email trends (EmailEvents)

**Related skills:**
- [SPN Scope Drift](../spn/SKILL.md) — for service principals
- [Device Scope Drift](../device/SKILL.md) — for endpoints/devices

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
3. **[Quick Start](#quick-start-tldr)** - 7-step investigation pattern
4. **[Drift Score Formula](#drift-score-formula)** - Weighted composite scoring (Interactive: 7 dimensions, Non-Interactive: 6 dimensions)
5. **[Execution Workflow](#execution-workflow)** - Complete 4-phase process
6. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns (Queries 6-13)
7. **[Report Template](#report-template)** - Output format specification
8. **[Known Pitfalls](#known-pitfalls)** - Edge cases and false positives
9. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY user scope drift analysis:**

1. **ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)
2. **ALWAYS ask the user for output mode** if not specified: inline chat summary or markdown file report (or both)
3. **ALWAYS build baseline FIRST** before comparing recent activity
4. **ALWAYS compute BOTH interactive AND non-interactive drift scores** — user accounts produce two drift scores
5. **ALWAYS apply the low-volume denominator floor** to prevent false-positive drift scores on sparse baselines
6. **ALWAYS correlate across all required data sources** (SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, SecurityAlert, Anomaly table, Identity Protection, CloudAppEvents, EmailEvents)
7. **ALWAYS run independent queries in parallel** for performance
8. **NEVER report a drift flag without corroborating evidence** from at least one secondary data source

### Data Sources

| Data Source | Role | Purpose |
|-------------|------|---------|
| `SigninLogs` | ✅ Primary | User interactive sign-in baseline |
| `AADNonInteractiveUserSignInLogs` | ✅ Primary | User non-interactive (token refresh) baseline |
| `AuditLogs` | ✅ Corroboration | Password/MFA/role/group changes |
| `SecurityAlert` | ✅ Corroboration | Corroborating alert evidence |
| `SecurityIncident` | ✅ Corroboration | Real alert status/classification |
| `Signinlogs_Anomalies_KQL_CL` | ✅ Corroboration | Pre-computed anomaly detection (custom table) |
| `SigninLogs` (risk fields) | ✅ Corroboration | Identity Protection risk events |
| `CloudAppEvents` | ✅ Corroboration | Cloud app activity drift — action types, admin operations, apps, IPs, impersonation |
| `EmailEvents` | ✅ Corroboration | Email pattern drift — volume/direction, sender domains, threat emails |

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
- Save a comprehensive report to `reports/scope-drift/user/Scope_Drift_Report_<username>_<timestamp>.md`
- All ASCII visualizations render correctly inside markdown code fences (` ``` `)
- Includes all data from inline mode plus additional detail sections
- Use `create_file` tool — NEVER use terminal commands for file output
- **Filename pattern:** `Scope_Drift_Report_<username>_YYYYMMDD_HHMMSS.md` (extract username from UPN, e.g., `jdoe` from `jdoe@contoso.com`)

### Markdown Rendering Notes
- ✅ ASCII tables, box-drawing characters, and bar charts render perfectly in markdown code blocks
- ✅ Unicode block characters (`█` full block, `─` box-drawing horizontal) display correctly in monospaced fonts
- ✅ Emoji indicators (🔴🟢🟡⚠️✅) render natively in GitHub-flavored markdown
- ✅ Standard markdown tables (`| col |`) render as formatted tables
- **Tip:** Wrap all ASCII art in triple-backtick code fences for consistent rendering

---

## Quick Start (TL;DR)

When a user requests user scope drift detection:

1. **Select Workspace** → `list_sentinel_workspaces`, auto-select or ask
2. **Determine Output Mode** → Ask if not specified: inline, markdown file, or both
3. **Run Phase 1** → Query 6 (SigninLogs interactive) + Query 7 (AADNonInteractiveUserSignInLogs)
4. **Apply Entity Scaling (multi-user only)** → If analyzing multiple users, compute drift scores, rank, apply tiered depth limits (see [Entity Scaling](#entity-scaling-multi-user-analysis))
5. **Run Phases 2-3** → Queries 8-13 (AuditLogs + SecurityAlert + Anomaly table + Identity Protection + CloudAppEvents + EmailEvents) — scoped per tier if multi-user
6. **Compute Drift Scores** → Apply 7-dimension interactive formula + 6-dimension non-interactive formula, flag if >150%, assess with corroborating evidence
7. **Output Results** → Render in selected mode(s)

---

## Entity Scaling (Multi-User Analysis)

**Problem:** This skill is typically used for single-user investigations, but users may request tenant-wide or group-based analysis ("drift for all users", "drift for finance department"). Running Queries 8–13 for every user in a large tenant is prohibitively expensive and produces unreadable reports.

**Solution:** For multi-user analysis, after Phase 1 computes drift scores for all target users, apply tiered depth based on user count and drift severity.

**Single-user mode:** When investigating one specific user (the common case), skip this section entirely — always run all queries at full depth.

### User Count Detection

After Queries 6+7, count distinct users in the result set:

| User Count | Tier | Deep Dive Limit | Behavior |
|-----------|------|-----------------|----------|
| **1 user** | Single | Full | All queries at full depth. This section does not apply. |
| **2–30 users** | Small | All flagged | Full deep dive for every user > 150%. No limiting needed. |
| **31–100 users** | Medium | Top 10 | Full deep dive for top 10 by max(Interactive, Non-Interactive) DriftScore. Summary row for remaining flagged users. |
| **101–500 users** | Large | Top 10 | Full deep dive for top 10. Tier 2 summary (next 15) with Identity Protection + alerts only. Remaining flagged users listed in ranking table. |
| **> 500 users** | Very Large | Top 10 | Same as Large, plus: filter Phase 1 results to `BL_TotalSignIns > 10` to exclude near-silent accounts from scoring. |

### Tiered Depth Model (Multi-User)

| Tier | Users | Queries Run | Report Depth |
|------|-------|-------------|--------------|
| **Tier 1** (Full) | Top N by DriftScore | All: Q8–Q13 | Full deep dive: both ASCII charts, dimension tables, AuditLog changes, alerts, anomalies, Identity Protection, CloudAppEvents, EmailEvents |
| **Tier 2** (Summary) | Next 15 flagged users (or remaining if < 15) | Q10 + Q11 only (Identity Protection + SecurityAlert) | One-line summary: both scores, risk state, alert count, flag status |
| **Tier 3** (Score only) | All remaining flagged users | None beyond Phase 1 | Row in ranking table: UPN, interactive score, non-interactive score, flag emoji |
| **Stable** | Users ≤ 150% | None beyond Phase 1 | Omitted from deep dives. Included in summary statistics only. |

### User Override

If the user explicitly asks for "all users detailed" or "full report", honor the request but warn:

> ⚠️ Analysis covers <N> users with <X> flagged above 150%. Running full deep dives for all flagged users may be slow and produce a very long report. Proceed? (Default: top 10 deep dives + summary for others)

### Report Disclosure (Multi-User)

When tiered depth is applied, **always disclose** in the report header:

```
**User Count:** <N> users (Large cohort — tiered analysis applied)
**Deep Dives:** Top <X> by DriftScore (Tier 1: full analysis)
**Summaries:** <Y> additional flagged users (Tier 2: risk + alerts only)
**Score Only:** <Z> additional flagged users (Tier 3: ranking table only)
**Stable:** <W> users ≤ 150% (omitted from deep dives)
```

---

## Drift Score Formula

The Drift Score is a weighted composite of behavioral dimensions, normalized so that **100 = identical to baseline**.

**User accounts produce TWO drift scores** (interactive + non-interactive). Both must be computed and reported.

### User Account Formula — Interactive (7 Dimensions)

$$
\text{DriftScore}_{Interactive} = 0.25V + 0.20A + 0.10R + 0.15IP + 0.10L + 0.10D + 0.10F
$$

| Dimension | Weight | Metric | Why |
|-----------|--------|--------|-----|
| **Volume** | 25% | Daily avg interactive sign-ins | Reduced weight vs SPN — user volume is naturally more variable |
| **Applications** | 20% | Distinct apps accessed | New apps = potential unauthorized access or shadow IT |
| **Resources** | 10% | Distinct target resources accessed | Reduced weight — apps are a better user-level signal |
| **IPs** | 15% | Distinct source IP addresses | New IPs = different network, VPN, or credential theft |
| **Locations** | 10% | Distinct geographic locations | New geos = travel or impossible travel |
| **Devices** | 10% | Distinct device types (OS + browser) | New devices = potential unauthorized device |
| **Failure Rate** | 10% | Failure rate delta | Rising failures = password spray target or lockout |

### User Account Formula — Non-Interactive (6 Dimensions)

$$
\text{DriftScore}_{NonInteractive} = 0.30V + 0.20A + 0.15R + 0.15IP + 0.10L + 0.10F
$$

| Dimension | Weight | Metric | Why |
|-----------|--------|--------|-----|
| **Volume** | 30% | Daily avg non-interactive sign-ins | Higher weight — non-interactive volume is more predictable |
| **Applications** | 20% | Distinct apps with token refreshes | New apps = potential token theft or rogue app consent |
| **Resources** | 15% | Distinct resources targeted | New resources = lateral expansion via token reuse |
| **IPs** | 15% | Distinct source IPs | New IPs = session hijack or AiTM proxy |
| **Locations** | 10% | Distinct geographic locations | Geographic shifts in token usage |
| **Failure Rate** | 10% | Failure rate delta | Rising failures = expired/revoked token churn |

**Note:** Devices dimension is excluded from non-interactive because token refreshes don't generate reliable device telemetry.

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

**User-specific note:** Non-interactive sign-ins often have very high volume (thousands/day) from background token refreshes. The floor is less likely to trigger for non-interactive, but always check interactive separately.

### Failure Rate Dimension — Delta-to-Ratio Conversion

**CRITICAL:** The FailRate dimension is a **percentage-point delta**, not a multiplicative ratio like the other dimensions. Convert it to the same 0–200+ scale using this formula:

```
FailRateDelta = RecentFailRate - BaselineFailRate  (percentage points)
FailRateRatio = 100 + (FailRateDelta × 10)         (scaled: each +1pp = +10 on the ratio scale)
```

| Baseline FailRate | Recent FailRate | Delta | Ratio | Interpretation |
|-------------------|-----------------|-------|-------|----------------|
| 5.00% | 5.00% | 0.00 | 100.0 | No change |
| 5.00% | 8.00% | +3.00 | 130.0 | Moderate increase |
| 5.00% | 12.00% | +7.00 | 170.0 | 🔴 Above threshold |
| 5.00% | 2.00% | -3.00 | 70.0 | Improving (contracting) |
| 0.00% | 0.00% | 0.00 | 100.0 | No change (both clean) |
| 0.00% | 5.00% | +5.00 | 150.0 | 🟡 At threshold — new failures appearing |

**Edge case:** Baseline = 0% avoids division-by-zero because delta is additive, not multiplicative. The scaling factor (×10) means each percentage point of failure rate increase maps to 10 points on the drift scale. This keeps FailRate on the same magnitude as the other dimensions.

**In the ASCII chart:** Show the ratio as the bar fill percentage and append the raw delta as direction indicator: `^+X.XX` (increasing) or `v-X.XX` (decreasing).

---

## Execution Workflow

### Phase 1: Behavioral Baseline vs. Recent Comparison

**Baseline window:** 90 days (days 8–97 ago)
**Recent window:** 7 days (last 7 days)

This is the primary query that computes per-user behavioral profiles and drift metrics.

| Data Source | Query | Notes |
|-------------|-------|-------|
| `SigninLogs` | Query 6 | Interactive, 7 dimensions (adds Apps, Devices) |
| `AADNonInteractiveUserSignInLogs` | Query 7 | Non-interactive, 6 dimensions (adds Apps, no Devices) |

**User accounts produce TWO drift scores** (interactive + non-interactive). Both must be computed and reported.

### Phase 2: Account Configuration Change Audit

**Data source:** `AuditLogs`
**Correlation:** Same 97-day window, filtered to the user from Phase 1

**Operations to Look For:**
- `Reset user password`
- `Change user password`
- `Update user`
- `Add member to group`
- `Add member to role`
- `Register security info`
- `Delete security info`
- `Update StsRefreshTokenValidFrom`
- Any operation containing: "password", "MFA", "role", "group", "conditional", "auth"

### Phase 3: Corroborating Signal Collection (Run in Parallel)

- **SecurityAlert + SecurityIncident (Query 11):** Check for alerts referencing user UPN, joined with SecurityIncident for real status/classification. **Never read SecurityAlert.Status directly** — it's always "New".
- **Signinlogs_Anomalies_KQL_CL (Query 9):** Pre-computed anomaly detection (new IPs, new device combos, geographic novelty). Custom table — may not exist in all workspaces.
- **Identity Protection risk fields (Query 10):** `RiskLevelDuringSignIn`, `RiskState`, `RiskEventTypes_V2` from `SigninLogs`.
- **CloudAppEvents (Query 12):** Cloud app activity drift — baseline vs. recent comparison of action types, applications, IPs, countries, admin/external/impersonated operations. Requires user's `AccountObjectId` (Entra Object ID) — resolve from UPN via Graph API before querying. May not exist if XDR connector is not streaming to Data Lake.
- **EmailEvents (Query 13):** Email pattern drift — baseline vs. recent comparison of volume, send/receive ratio, email direction, sender domains, threat email prevalence. Uses UPN for both sender and recipient matching. May not exist if XDR connector is not streaming to Data Lake.

### Phase 4: Score Computation & Report Generation

1. Compute DriftScore for BOTH interactive and non-interactive using entity-specific formulas
2. Apply the low-volume denominator floor
3. Flag if either score exceeds 150% threshold
4. For flagged users: assess corroborating evidence (account changes, alerts, anomaly table, Identity Protection, cloud app activity drift, email pattern drift)
5. Generate risk assessment with emoji-coded findings
6. Render output in the user's selected mode

---

## Sample KQL Queries

### Query 6: User Interactive Sign-In Baseline vs. Recent

```kql
// Build 90-day baseline vs 7-day recent for user interactive sign-ins
// Substitute <UPN> with user's UPN
let baselineStart = ago(97d);
let baselineEnd = ago(7d);
SigninLogs
| where UserPrincipalName =~ '<UPN>'
| where TimeGenerated >= baselineStart
| extend Period = iff(TimeGenerated < baselineEnd, "Baseline", "Recent")
| summarize
    TotalSignIns = count(),
    Days = dcount(bin(TimeGenerated, 1d)),
    DistinctApps = dcount(AppDisplayName),
    DistinctResources = dcount(ResourceDisplayName),
    DistinctIPs = dcount(IPAddress),
    DistinctLocations = dcount(Location),
    DistinctDevices = dcount(strcat(tostring(parse_json(DeviceDetail).operatingSystem), "|", tostring(parse_json(DeviceDetail).browser))),
    FailRate = round(1.0 * countif(ResultType != "0" and ResultType != 0) / count() * 100, 2),
    Apps = make_set(AppDisplayName, 50),
    Resources = make_set(ResourceDisplayName, 50),
    IPs = make_set(IPAddress, 50),
    Locations = make_set(Location, 50),
    Devices = make_set(strcat(tostring(parse_json(DeviceDetail).operatingSystem), "|", tostring(parse_json(DeviceDetail).browser)), 50)
    by Period
| order by Period asc
```

**Post-processing:** Compare Baseline vs Recent rows. Compute ratios per dimension. Calculate `set_difference()` equivalents in the assessment to identify new apps, IPs, locations, and devices appearing only in the Recent period.

### Query 7: User Non-Interactive Sign-In Baseline vs. Recent

```kql
// Build 90-day baseline vs 7-day recent for user non-interactive sign-ins
// Substitute <UPN> with user's UPN
let baselineStart = ago(97d);
let baselineEnd = ago(7d);
AADNonInteractiveUserSignInLogs
| where UserPrincipalName =~ '<UPN>'
| where TimeGenerated >= baselineStart
| extend Period = iff(TimeGenerated < baselineEnd, "Baseline", "Recent")
| summarize
    TotalSignIns = count(),
    Days = dcount(bin(TimeGenerated, 1d)),
    DistinctApps = dcount(AppDisplayName),
    DistinctResources = dcount(ResourceDisplayName),
    DistinctIPs = dcount(IPAddress),
    DistinctLocations = dcount(Location),
    FailRate = round(1.0 * countif(ResultType != "0" and ResultType != 0) / count() * 100, 2),
    Apps = make_set(AppDisplayName, 50),
    Resources = make_set(ResourceDisplayName, 50),
    IPs = make_set(IPAddress, 50),
    Locations = make_set(Location, 50)
    by Period
| order by Period asc
```

**Note:** Devices dimension is excluded from non-interactive queries — token refreshes don't generate reliable device telemetry.

**KQL Pattern Note:** Uses single-pass `extend Period = iff(...)` pattern instead of separate baseline/recent subqueries joined with `join kind=inner on 1==1`. The cross-join pattern is NOT supported in KQL — always use the Period flag approach for user queries.

### Query 8: User AuditLog Configuration Changes

```kql
// User account configuration changes (password, MFA, roles, groups)
// Substitute <UPN> with user's UPN
AuditLogs
| where TimeGenerated > ago(97d)
| where OperationName has_any ("password", "MFA", "role", "group", "conditional", "auth",
    "user", "member", "security info")
| where tostring(TargetResources) has '<UPN>'
    or tostring(InitiatedBy) has '<UPN>'
    or Identity =~ '<UPN>'
| extend InBaseline = TimeGenerated < ago(7d)
| summarize
    BaselineOps = countif(InBaseline),
    RecentOps = countif(not(InBaseline)),
    Operations = make_set(OperationName, 30)
    by OperationName
| order by RecentOps desc
```

### Query 9: SigninLogs Anomaly Table (Custom)

> **🔴 CRITICAL — CASE-SENSITIVE TABLE NAME:** The table is `Signinlogs_Anomalies_KQL_CL` (lowercase 'l' in "logs"). Do NOT use `SigninLogs_Anomalies_KQL_CL` — that will fail with `SemanticError: Failed to resolve table`. KQL custom `_CL` tables are case-sensitive. Copy the name exactly as written below.

```kql
// Pre-computed anomalies from Signinlogs_Anomalies_KQL_CL
// Substitute <UPN> with user's UPN
// ⚠️ CASE-SENSITIVE: Table name is "Signinlogs" (lowercase 'l'), NOT "SigninLogs"
// Note: This table may not exist in all workspaces — handle gracefully
Signinlogs_Anomalies_KQL_CL
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ '<UPN>'
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10 or CountryNovelty or CityNovelty or StateNovelty, "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| where Severity in ("High", "Medium", "Low")
| project DetectedDateTime, AnomalyType, Value, Severity, Country, City,
    ArtifactHits, CountryNovelty, CityNovelty, OS, BrowserFamily
| order by DetectedDateTime desc
| take 20
```

### Query 10: Identity Protection Risk Events

```kql
// Identity Protection risk signals from SigninLogs
// Substitute <UPN> with user's UPN
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ '<UPN>'
| where RiskLevelDuringSignIn != "none" and RiskLevelDuringSignIn != ""
| project TimeGenerated, RiskLevelDuringSignIn, RiskState, RiskEventTypes_V2,
    IPAddress, Location, AppDisplayName,
    DeviceOS = tostring(parse_json(DeviceDetail).operatingSystem),
    Browser = tostring(parse_json(DeviceDetail).browser),
    ConditionalAccessStatus
| order by TimeGenerated desc
| take 20
```

**Note:** Identity Protection events supplement the drift analysis. Any `atRisk` or `confirmedCompromised` risk states in the recent window should be flagged prominently, regardless of drift score.

### Query 11: User SecurityAlert + SecurityIncident Correlation

```kql
// Security alerts and incidents referencing the user
// IMPORTANT: SecurityAlert.Status is immutable (always "New") — MUST join SecurityIncident for real Status/Classification
// Substitute <UPN> with user's UPN
let relevantAlerts = SecurityAlert
| where TimeGenerated > ago(97d)
| where Entities has '<UPN>' or CompromisedEntity has '<UPN>'
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProductName, ProductComponentName, Tactics, Techniques, TimeGenerated;
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

**Report Rendering:** Same rules as SPN — show Baseline vs Recent alert/incident counts per product, with a Total row and brief summary. Do NOT list individual alert names.

### Query 12: CloudAppEvents — Cloud App Activity Drift

```kql
// Cloud app activity drift — baseline vs recent comparison
// Tracks action type diversity, application usage, IP/geo distribution,
// admin operations, external user activity, and impersonation
// Substitute <ACCOUNT_OBJECT_ID> with user's Entra Object ID (resolve from UPN via Graph API)
// NOTE: This table requires XDR connector streaming to Data Lake
let baselineStart = ago(97d);
let baselineEnd = ago(7d);
CloudAppEvents
| where TimeGenerated >= baselineStart
| where AccountObjectId == '<ACCOUNT_OBJECT_ID>'
| extend Period = iff(TimeGenerated < baselineEnd, "Baseline", "Recent")
| summarize
    TotalEvents = count(),
    Days = dcount(bin(TimeGenerated, 1d)),
    DistinctActions = dcount(ActionType),
    DistinctApps = dcount(Application),
    DistinctObjects = dcount(ObjectName),
    DistinctIPs = dcount(IPAddress),
    DistinctCountries = dcount(CountryCode),
    AdminOps = countif(IsAdminOperation),
    ExternalUserOps = countif(IsExternalUser),
    ImpersonatedOps = countif(IsImpersonated),
    Actions = make_set(ActionType, 100),
    Apps = make_set(Application, 50),
    IPs = make_set(IPAddress, 50),
    Countries = make_set(CountryCode, 20)
    by Period
| order by Period asc
```

**How to resolve AccountObjectId from UPN:**
Use Microsoft Graph API: `GET /v1.0/users/<UPN>?$select=id` → use the `id` field as `<ACCOUNT_OBJECT_ID>`.

**Drift Interpretation for CloudAppEvents (Corroboration — not scored):**

CloudAppEvents provides qualitative corroboration, not a scored drift dimension. Focus on these signals:

| Signal | Baseline → Recent Change | Risk Implication |
|--------|--------------------------|------------------|
| DistinctActions ↑↑ | New action types appearing | Expanded permissions or new tooling usage |
| AdminOps ↑↑ | New admin-level operations | Privilege escalation or new admin role assignment |
| ExternalUserOps > 0 (new) | External user activity appearing | Potential guest account abuse or B2B compromise |
| ImpersonatedOps > 0 (new) | Impersonation activity appearing | Delegated access abuse or admin impersonation |
| New applications | Apps in Recent not in Baseline | Shadow IT, rogue app consent, or lateral movement |
| New countries | Countries in Recent not in Baseline | Geographic anomaly — correlate with SigninLogs locations |
| DistinctIPs ↑↑ | Significant new IPs | VPN rotation, proxy usage, or credential sharing |

**Corroboration with other drift signals:**
- New admin operations in CloudAppEvents + role assignment in AuditLogs = strong privilege escalation signal
- New applications in CloudAppEvents + new apps in SigninLogs = confirmed shadow IT adoption
- New countries in CloudAppEvents + geographic anomalies in anomaly table = travel or compromise

### Query 13: EmailEvents — Email Pattern Drift

```kql
// Email pattern drift — baseline vs recent comparison
// Tracks volume, send/receive ratio, direction distribution,
// sender diversity, domain diversity, and threat email prevalence
// Substitute <UPN> with user's UPN (matches both sender and recipient)
// NOTE: This table requires XDR connector streaming to Data Lake
let baselineStart = ago(97d);
let baselineEnd = ago(7d);
EmailEvents
| where TimeGenerated >= baselineStart
| where RecipientEmailAddress =~ '<UPN>' or SenderMailFromAddress =~ '<UPN>'
| extend Period = iff(TimeGenerated < baselineEnd, "Baseline", "Recent")
| summarize
    TotalEmails = count(),
    Days = dcount(bin(TimeGenerated, 1d)),
    SentCount = countif(SenderMailFromAddress =~ '<UPN>'),
    ReceivedCount = countif(RecipientEmailAddress =~ '<UPN>'),
    InboundCount = countif(EmailDirection == "Inbound"),
    OutboundCount = countif(EmailDirection == "Outbound"),
    IntraOrgCount = countif(EmailDirection == "Intra-org"),
    DistinctSenders = dcount(SenderMailFromAddress),
    DistinctRecipients = dcountif(RecipientEmailAddress, SenderMailFromAddress =~ '<UPN>'),
    DistinctSenderDomains = dcount(SenderMailFromDomain),
    ThreatEmails = countif(ThreatTypes != ""),
    DistinctSubjects = dcount(Subject),
    SenderDomains = make_set(SenderMailFromDomain, 50),
    DeliveryActions = make_set(DeliveryAction, 10)
    by Period
| order by Period asc
```

**Drift Interpretation for EmailEvents (Corroboration — not scored):**

EmailEvents provides qualitative corroboration, not a scored drift dimension. Focus on these signals:

| Signal | Baseline → Recent Change | Risk Implication |
|--------|--------------------------|------------------|
| SentCount ↑↑↑ | Sudden spike in outbound email | Potential spam/phishing campaign from compromised account |
| SentCount drops to 0 | User stopped sending email | Account takeover with mail forwarding rule (check OfficeActivity) |
| ThreatEmails ↑ | Increase in threat-flagged inbound | Targeted phishing campaign against user |
| New SenderDomains (inbound) | Domains in Recent not in Baseline | New communication partners or phishing domains |
| IntraOrgCount → 0 (was > 0) | Lost intra-org email patterns | User isolated or moved to different tenant |
| DeliveryAction changes | More "Junked" or "Blocked" in Recent | Email security policies catching more threats |
| DistinctSubjects ↓↓ (with volume ↑) | Many emails with few subjects | Automated/bulk email — potential spam or notification storm |
| OutboundCount ↑ + new recipients | Sudden outbound expansion | Data exfiltration or mass-mailing from compromised mailbox |

**Corroboration with other drift signals:**
- Outbound email spike + new forwarding rule in OfficeActivity/AuditLogs = email exfiltration (T1114.003)
- ThreatEmails ↑ + Identity Protection risk events + new IPs in SigninLogs = active phishing campaign with partial success
- SentCount → 0 + non-interactive IP drift = account takeover with inbox rule redirect

---

## Report Template

### Inline Chat Report Structure

The inline report MUST include these sections in order:

1. **Header** — Workspace, analysis period, drift threshold, data sources
2. **Interactive Drift Score** — 7-dimension breakdown with ratios
3. **Non-Interactive Drift Score** — 6-dimension breakdown with ratios
4. **Flagged Dimension Deep Dive** (for any dimension > 150%) — Baseline vs. recent comparison, new IPs/apps/devices, dimension bar chart
5. **Correlated Signal Summary** — AuditLogs, SecurityAlert/Incident, and anomaly table findings in a single table
6. **Identity Protection Summary** — Risk events, risk states, risk levels
7. **Cloud App Activity Drift** — CloudAppEvents baseline vs. recent: action types, apps, admin ops, impersonation, new countries/IPs
8. **Email Pattern Drift** — EmailEvents baseline vs. recent: volume, direction, sender domains, threat emails
9. **Security Assessment** — Emoji-coded findings table with evidence citations
10. **Verdict Box** — Overall risk level, root cause analysis, recommendations

### Markdown File Report Structure

When outputting to markdown file, include everything from the inline format PLUS:

**Filename pattern:** `reports/scope-drift/user/Scope_Drift_Report_<username>_YYYYMMDD_HHMMSS.md`

```markdown
# User Account Scope Drift Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Workspace:** <workspace_name>
**User:** <UPN>
**Baseline Period:** <start> → <end> (90 days)
**Recent Period:** <start> → <end> (7 days)
**Drift Threshold:** 150%
**Data Sources:** SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, SecurityAlert, Signinlogs_Anomalies_KQL_CL, Identity Protection, CloudAppEvents, EmailEvents

---

## Executive Summary

<1-3 sentence summary: interactive drift score, non-interactive drift score, overall risk level>

---

## Interactive Sign-In Drift

**Drift Score: XX.X%** — <status emoji> <Contracting/Stable/Expanding>

<LaTeX formula block>

**ASCII Drift Dimension Chart (REQUIRED):**

Render a box-drawn chart inside a code fence. **Inner width: 58 chars** (every line between `│` markers = exactly 58 visual characters). No emoji inside boxes — use text labels.

**Alignment:** Name (9 chars padded) + weight (5) + gap (2) + bars (20 `█─`) + gap (2) + pct (6, right-aligned: `XXX.X%` or ` XX.X%`) + gap (2) + direction (10 total: `^`/`v`/`=` + 9 trailing spaces, or FailRate: delta like `v-X.XX` + 4 trailing spaces). Status labels (centered): `STABLE`, `STABLE (Low-Volume)`, `NEAR THRESHOLD`, `ABOVE THRESHOLD`, `CRITICAL`. Direction: `^` (up), `v` (down), `=` (stable).

**Bar characters:** Use `█` (U+2588 full block) for filled portions and `─` (U+2500 box-drawing horizontal) for the unfilled track.

```
┌──────────────────────────────────────────────────────────┐
│               INTERACTIVE DRIFT SCORE: XX.X              │
│                          STABLE                          │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Volume   (25%)  ██████──────────────  XXX.X%  ^         │
│  Apps     (20%)  ███─────────────────   XX.X%  v         │
│  Resources(10%)  ██████──────────────  XXX.X%  =         │
│  IPs      (15%)  █───────────────────   XX.X%  v         │
│  Locations(10%)  ███─────────────────   XX.X%  =         │
│  Devices  (10%)  ██──────────────────   XX.X%  v         │
│  FailRate (10%)  ██████──────────────  XXX.X%  v-X.XX    │
│                                                          │
│  ────────────────────────── 100% baseline ──┤            │
│                  150% drift threshold ▲                  │
└──────────────────────────────────────────────────────────┘
```

**Bar fill:** 20 chars wide. Filled = round(ratio/100 × 20), capped at 20. Title and status: center within 58 chars. Use `█` for filled, `─` for unfilled.

**Then** render the standard markdown dimension table:

| Dimension | Weight | Baseline (90d) | Recent (7d) | Ratio | Weighted | Status |
|-----------|--------|----------------|-------------|-------|----------|--------|

<New apps, IPs, locations, devices appearing only in recent period>

---

## Non-Interactive Sign-In Drift

**Drift Score: XX.X%** — <status emoji> <Contracting/Stable/Expanding>

<LaTeX formula block>

**ASCII Drift Dimension Chart (REQUIRED):**

Same box-drawn format as Interactive. **Inner width: 58 chars.** 6 dimensions (no Devices):

```
┌──────────────────────────────────────────────────────────┐
│             NON-INTERACTIVE DRIFT SCORE: XX.X            │
│                          STABLE                          │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Volume   (30%)  ███████─────────────  XXX.X%  ^         │
│  Apps     (20%)  ████────────────────   XX.X%  v         │
│  Resources(15%)  █████───────────────  XXX.X%  =         │
│  IPs      (15%)  ██──────────────────   XX.X%  v         │
│  Locations(10%)  ███─────────────────   XX.X%  =         │
│  FailRate (10%)  ███████████─────────  XXX.X%  ^+X.XX    │
│                                                          │
│  ────────────────────────── 100% baseline ──┤            │
│                  150% drift threshold ▲                  │
└──────────────────────────────────────────────────────────┘
```

**Then** render the standard markdown dimension table:

| Dimension | Weight | Baseline (90d) | Recent (7d) | Ratio | Weighted | Status |
|-----------|--------|----------------|-------------|-------|----------|--------|

<New apps, IPs, locations appearing only in recent period>

---

## Account Configuration Changes

<AuditLogs findings: password changes, MFA changes, role assignments, group memberships>

---

## Pre-Computed Anomalies

<Signinlogs_Anomalies_KQL_CL findings or gap note if table unavailable>

---

## Identity Protection

<Risk events, risk states, risk levels from SigninLogs>

---

## Cloud App Activity Drift

<CloudAppEvents baseline vs. recent comparison — action types, apps, IPs, countries, admin/external/impersonated operations>
<New actions, new apps, new countries appearing only in recent period>
<Corroboration notes — cross-reference with AuditLogs, SigninLogs>
<If table unavailable: "⚠️ CloudAppEvents table not available in this workspace — XDR connector may not be streaming to Data Lake.">

---

## Email Pattern Drift

<EmailEvents baseline vs. recent comparison — volume, sent/received, direction, sender domains, threat emails>
<Notable changes — outbound spikes, new sender domains, threat email trends>
<Corroboration notes — cross-reference with OfficeActivity for forwarding rules, Identity Protection for phishing>
<If table unavailable: "⚠️ EmailEvents table not available in this workspace — XDR connector may not be streaming to Data Lake.">

---

## Correlated Security Alerts

| Data Source | Finding | Incident Status |
|-------------|---------|-----------------|
| SigninLogs | ... | N/A |
| AADNonInteractiveUserSignInLogs | ... | N/A |
| AuditLogs | ... | N/A |
| Signinlogs_Anomalies_KQL_CL | ... | N/A |
| CloudAppEvents | ... | N/A |
| EmailEvents | ... | N/A |
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
│  Interactive Score:     XX.X  (< 80 = Contracting)               │
│  Non-Interactive Score: XX.X  (< 80 = Contracting)               │
│  Root Cause: <Brief root cause explanation>                      │
└──────────────────────────────────────────────────────────────────┘
```

**Then** render the full verdict with:
- Root Cause Analysis paragraph
- Key Findings (numbered list)
- Recommendations (emoji-prefixed list)

---

## Appendix: Query Details

Render a single markdown table summarizing all queries executed. **Do NOT include full KQL text** — the canonical queries are already documented in this SKILL.md file (Queries 6–13). The appendix serves as an audit trail only.

| Query | Table(s) | Records Scanned | Results | Execution |
|-------|----------|----------------:|--------:|----------:|
| Q6 — Interactive Baseline vs. Recent | SigninLogs | X,XXX | N rows | X.XXs |
| Q7 — Non-Interactive Baseline vs. Recent | AADNonInteractiveUserSignInLogs | XX,XXX | N rows | X.XXs |
| ... | ... | ... | ... | ... |

*Query definitions: see Queries 6–13 in this SKILL.md file.*
```

---

## Known Pitfalls

### SecurityAlert.Status Is Immutable — Always Join SecurityIncident
**Problem:** The `Status` field on `SecurityAlert` is set to `"New"` at creation time and **never changes**. It does NOT reflect whether the alert has been investigated, closed, or classified.
**Solution:** MUST join with `SecurityIncident` to get real `Status` (New/Active/Closed) and `Classification` (TruePositive/FalsePositive/BenignPositive). See Query 11 which implements this join.

### Low-Volume Statistical Inflation
**Problem:** Entities with very low baseline activity (e.g., 1 sign-in/day) will show extreme volume ratios even with minor changes.
**Solution:** Apply the denominator floor (minimum 10 sign-ins/day for volume ratio calculation). Always flag low-volume baselines in the report.

### Seasonal/Cyclical Baselines
**Problem:** Some entities have weekly patterns (lower on weekends) or monthly cycles (month-end batch jobs).
**Solution:** Note if the 7-day recent window falls on an atypical portion of the cycle. The 90-day baseline smooths most cyclical patterns, but edge cases exist.

### 90-Day IP/App Contraction
**Problem:** The 90-day baseline captures ISP address rotations, travel IPs, and occasional app usage that won't naturally recur in a 7-day window. This makes user accounts appear to be "contracting" (score < 80) when they are actually stable.
**Solution:** For user accounts showing contraction, check if the absolute numbers are reasonable. If the user had 30 IPs over 90 days but only 2 in 7 days, this is expected — note it as "natural IP diversity compression" rather than genuine scope reduction.

### Non-Interactive Volume Inflation
**Problem:** Non-interactive sign-ins (token refreshes, background app activity) can number in the thousands per day. A brief outage or token cache flush can cause dramatic volume swings.
**Solution:** Weight non-interactive drift scores lower in the overall assessment unless corroborated by new apps or IPs. Volume-only drift in non-interactive is rarely meaningful without other signals.

### Cross-Join KQL Error
**Problem:** `join kind=inner on 1==1` (cross-join) is NOT supported in KQL Sentinel Data Lake. The SPN query uses separate subqueries joined on `ServicePrincipalId`, but user queries target a single UPN and cannot use this pattern.
**Solution:** User queries MUST use the single-pass `extend Period = iff(TimeGenerated < baselineEnd, "Baseline", "Recent")` pattern with `summarize ... by Period`. See Queries 6 and 7.

### Identity Protection Risk States Lingering
**Problem:** Risk events (e.g., `unfamiliarFeatures`, `anonymizedIPAddress`) may show `RiskState == "atRisk"` for days/weeks after the triggering event if no admin action is taken.
**Solution:** Check `RiskState` carefully. `"atRisk"` doesn't mean ongoing compromise — it means the risk was never remediated or dismissed. Flag these for admin review but don't automatically escalate drift score.

### Device Telemetry Gaps
**Problem:** `DeviceDetail` in `SigninLogs` may be empty or `{}` for some sign-in types (SSO, mobile apps, headless clients).
**Solution:** If `DistinctDevices` is very low (0-1) despite many sign-ins, note the gap rather than treating low device count as meaningful.

### 🔴 Custom Anomaly Table — CASE-SENSITIVE NAME
**Problem:** `Signinlogs_Anomalies_KQL_CL` is a custom table that may not exist in all workspaces. **🔴 CRITICAL:** The table name uses **lowercase 'l'** in "logs" — `Signinlogs` NOT `SigninLogs`. KQL custom `_CL` table names are **case-sensitive**. LLMs tend to auto-correct this to match the standard `SigninLogs` table — this WILL cause a `SemanticError: Failed to resolve table` error. Always copy the exact table name from Query 9.
**Solution:** If the table returns a `SemanticError`, first verify you used the correct casing (`Signinlogs_Anomalies_KQL_CL`). If it still fails after verifying casing, then the table genuinely doesn't exist — skip Query 9 gracefully and note: "⚠️ Custom anomaly table not available in this workspace — skipping pre-computed anomaly check." Do not fail the entire analysis.

### CloudAppEvents Uses AccountObjectId, Not UPN
**Problem:** `CloudAppEvents` identifies users via `AccountObjectId` (Entra Object ID GUID), not `UserPrincipalName`. Querying by UPN will return 0 results.
**Solution:** Before executing Query 12, resolve the user's Entra Object ID from their UPN using Microsoft Graph API: `GET /v1.0/users/<UPN>?$select=id`. Use the returned `id` value as `<ACCOUNT_OBJECT_ID>` in the query. If Graph API is unavailable, fall back to `AccountDisplayName` with `has` operator (less precise — display names are not unique).

### CloudAppEvents/EmailEvents Table Availability
**Problem:** Both `CloudAppEvents` and `EmailEvents` are XDR-native tables that require the Defender XDR connector to stream data into the Sentinel Data Lake. They may not exist in all workspaces.
**Solution:** If either table is not found, skip the corresponding query gracefully and note: "⚠️ [Table] not available in this workspace — XDR connector may not be streaming to Data Lake." Do not fail the entire analysis. These are corroboration signals, not primary drift dimensions.

### CloudAppEvents Empty CountryCode and IPAddress
**Problem:** Some `CloudAppEvents` entries (particularly system-initiated or API-driven operations) have empty `CountryCode` and/or `IPAddress` fields. These inflate `DistinctCountries` and `DistinctIPs` counts with empty string entries.
**Solution:** The query uses `dcount()` which counts empty strings as a distinct value. When interpreting results, note that one "country" or "IP" may be an empty string representing internal/system events. In the drift interpretation, focus on named countries and non-empty IPs.

### EmailEvents ThreatTypes Empty String vs Null
**Problem:** `ThreatTypes` field in `EmailEvents` uses empty string `""` for clean emails, not null. Using `isnotempty()` would miss this distinction.
**Solution:** Query 13 uses `ThreatTypes != ""` which correctly filters for threat-flagged emails only. When `ThreatEmails` count is 0 in Recent but > 0 in Baseline, this is a positive signal (fewer threats reaching the user) rather than a drift concern.

### EmailEvents Dual-Direction Matching
**Problem:** Query 13 matches on both `RecipientEmailAddress` and `SenderMailFromAddress`, so a single email where the user is both sender and recipient (e.g., sending to self) could be double-counted.
**Solution:** This edge case is negligible in practice. The `SentCount` and `ReceivedCount` breakdowns use explicit directional filters, so the subtotals are accurate even if `TotalEmails` has minor inflation from self-sent emails.

---

## Error Handling

### Common Issues

| Issue | Solution |
|-------|----------|
| `SigninLogs` table not found | Rare but possible in workspaces without Entra ID P1/P2 logging enabled. Report as blocker. |
| `AADNonInteractiveUserSignInLogs` table not found | Check workspace configuration. Non-interactive logs require diagnostic settings. Skip non-interactive analysis and note the gap. |
| `Signinlogs_Anomalies_KQL_CL` table not found | **First check casing** — the table name is `Signinlogs` (lowercase 'l'), NOT `SigninLogs`. LLMs frequently auto-correct this. If casing is correct and it still fails, the custom table may not exist in this workspace. Skip Query 9 gracefully with a note; do not fail the analysis. |
| `CloudAppEvents` table not found | XDR connector may not be streaming to Data Lake. Skip Query 12 gracefully with note; do not fail the analysis. These are corroboration signals. |
| `EmailEvents` table not found | XDR connector may not be streaming to Data Lake. Skip Query 13 gracefully with note; do not fail the analysis. These are corroboration signals. |
| CloudAppEvents returns 0 results for valid user | Verify `AccountObjectId` — this field uses Entra Object ID (GUID), not UPN. Resolve via Graph API: `GET /v1.0/users/<UPN>?$select=id`. |
| Zero entities in results | Verify the workspace has sign-in data for the user. Check if logging is enabled. Verify UPN spelling. |
| Query timeout | Reduce the baseline window from 90 to 60 days, or add `\| take 100` to intermediate results. |
| AuditLogs `has_any` not matching | Ensure IDs are quoted strings in the `dynamic()` array. Use `tostring()` on dynamic fields. |
| `join kind=inner on 1==1` error | Cross-join not supported in KQL. Use single-pass `extend Period = iff(...)` pattern instead. See Queries 6-7. |
| Identity Protection fields empty | `RiskLevelDuringSignIn` may be "none" for all records if Identity Protection is not licensed. Note the gap; don't treat as "no risk." |

### Validation Checklist

Before presenting results, verify:

- [ ] All applicable data sources were queried (even if some returned 0 results)
- [ ] Low-volume denominator floor was applied to any entity with BL_DailyAvg < 10
- [ ] Corroborating evidence was checked for every flagged entity
- [ ] Empty results are explicitly reported with ✅ (not silently omitted)
- [ ] The report includes the drift score formula and threshold for transparency
- [ ] SecurityAlert was joined with SecurityIncident for real Status/Classification (never read SecurityAlert.Status directly)
- [ ] Incident classifications (TP/FP/BP) were factored into risk assessment — FalsePositive alerts discounted, TruePositive alerts escalated
- [ ] Both interactive AND non-interactive drift scores were computed
- [ ] IP/app contraction was contextualized (90-day diversity vs 7-day window)
- [ ] Identity Protection risk states were checked and reported
- [ ] Custom anomaly table was queried (or gap noted if unavailable)
- [ ] CloudAppEvents was queried for cloud app activity drift (or gap noted if table unavailable)
- [ ] EmailEvents was queried for email pattern drift (or gap noted if table unavailable)
- [ ] CloudAppEvents AccountObjectId was resolved from UPN via Graph API (not queried by UPN)
- [ ] Device telemetry gaps were noted if DeviceDetail was sparse

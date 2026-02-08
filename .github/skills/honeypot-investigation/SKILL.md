---
name: honeypot-investigation
description: Use this skill when asked to analyze, investigate, or report on honeypot server security. Triggers on keywords like "honeypot investigation", "analyze honeypot", "honeypot security", "honeypot report", or when a server name is mentioned with honeypot analysis context. This skill provides comprehensive security analysis including attack patterns, threat intelligence correlation, IP enrichment, vulnerability assessment, and executive report generation.
---

# Honeypot Investigation Agent - Instructions

## Purpose

This agent performs comprehensive security analysis on honeypot servers to assess attack patterns, threat intelligence, vulnerabilities, and defensive effectiveness. Honeypots are decoy systems designed to attract attackers and provide early warning of emerging threats.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Investigation Parameters](#investigation-parameters)** - Input requirements
3. **[Execution Workflow](#execution-workflow)** - Complete process with time tracking
4. **[KQL Query Library](#kql-query-library)** - Validated query patterns
5. **[Report Template](#report-template)** - Executive markdown structure
6. **[Error Handling](#error-handling)** - Troubleshooting guide
7. **[Visualization Options](#visualization-options)** - Heatmap and Geomap skills

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY honeypot investigation:**

1. **ALWAYS calculate date ranges correctly** (use current date from context)
2. **ALWAYS track and report time after each major step** (mandatory per main instructions)
3. **ALWAYS run independent queries in parallel** (drastically faster execution)
4. **ALWAYS save intermediate results to temp/** (enables debugging and auditing)
5. **ALWAYS use `create_file` for reports** (NEVER use PowerShell terminal commands)

**Date Range Rules (from main copilot-instructions):**
- **Real-time/recent searches:** Add +2 days to current date for end range
- **Example:** Current date = Dec 12, 2025; Last 48 hours = `datetime(2025-12-10)` to `datetime(2025-12-14)`

---

## Investigation Parameters

### Required Inputs

| Parameter | Description | Example |
|-----------|-------------|---------|
| **Honeypot Name** | Server/device name | `honeypot-server` |
| **Time Range** | Investigation period | `last 48 hours`, `last 7 days` |

### Automatic Derivations

- **Start Date**: Current date - time range
- **End Date**: Current date + 2 days (per date range rules)
- **Output File**: `reports/honeypot/Honeypot_Executive_Report_<hostname>_<timestamp>.md`
- **Temp Files**: `temp/honeypot_ips_<timestamp>.json`, `temp/honeypot_data_<timestamp>.json`

---

## Execution Workflow

### 🚨 MANDATORY: Time Tracking Pattern

**YOU MUST TRACK AND REPORT TIME AFTER EVERY MAJOR STEP:**

```
[MM:SS] ✓ Step description (XX seconds)
```

**Required Reporting Points:**
1. After Phase 1 (failed connection queries)
2. After Phase 2 (IP enrichment + threat intel)
3. After Phase 3 (incident filtering)
4. After Phase 4 (vulnerability scan)
5. After Phase 5 (report generation)
6. Final: Total elapsed time

---

### Phase 1: Query Failed Connections (PARALLEL)

**Execute ALL THREE queries in parallel using `mcp_sentinel-data_query_lake`:**

#### Query 1A: SecurityEvent (Windows Security Logs)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let honeypot = '<HONEYPOT_NAME>';
SecurityEvent
| where TimeGenerated between (start .. end)
| where Computer contains honeypot  // Use 'contains' for flexible hostname matching
| where EventID in (4625, 4771, 4776)  // Failed logon attempts
| where isnotempty(IpAddress) and IpAddress != "-"  // IpAddress is built-in field
| where IpAddress != "127.0.0.1"  // Exclude localhost (internal honeypot traffic)
| summarize 
    FailedAttempts=count(), 
    FirstSeen=min(TimeGenerated), 
    LastSeen=max(TimeGenerated),
    TargetAccounts=make_set(Account, 10)
    by IpAddress, EventID
| extend EventType = case(
    EventID == 4625, "Failed Logon",
    EventID == 4771, "Kerberos Pre-Auth Failed",
    EventID == 4776, "NTLM Auth Failed",
    "Unknown")
| order by FailedAttempts desc
| take 50
```

#### Query 1B: W3CIISLog (IIS Web Server Logs)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let honeypot = '<HONEYPOT_NAME>';
W3CIISLog
| where TimeGenerated between (start .. end)
| where Computer =~ honeypot
| where tolong(scStatus) >= 400  // HTTP errors (4xx/5xx) - scStatus is string type
| where cIP != "127.0.0.1" and cIP != "::1"  // Exclude localhost (internal honeypot traffic)
| summarize 
    RequestCount=count(), 
    FirstSeen=min(TimeGenerated), 
    LastSeen=max(TimeGenerated),
    TargetedURIs=make_set(csUriStem, 10),
    StatusCodes=make_set(tolong(scStatus), 5)  // Convert to long for proper aggregation
    by IpAddress = cIP
| order by RequestCount desc
| take 50
```

#### Query 1C: DeviceNetworkEvents (Defender Network Traffic - INBOUND ONLY)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let honeypot = '<HONEYPOT_NAME>';
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName =~ honeypot
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted", "ConnectionFound")  // Successful inbound TCP connections
| where LocalPort in (3389, 80, 443, 445, 22, 21, 23, 8080, 8443)  // Filter by attacked services (LocalPort = honeypot's listening port)
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1" and RemoteIP != "::ffff:127.0.0.1"  // Exclude localhost
| where RemoteIP !startswith "192.168." and RemoteIP !startswith "10." and RemoteIP !startswith "172.16."  // Exclude RFC1918 private IPs
| where RemoteIP !startswith "fe80:" and RemoteIP !startswith "fc00:" and RemoteIP !startswith "fd00:"  // Exclude IPv6 link-local and ULA
| where RemoteIP !startswith "::ffff:"  // Filter out IPv6-mapped IPv4 addresses (reduces duplicate noise)
| summarize 
    ConnectionCount=count(), 
    FirstSeen=min(TimeGenerated), 
    LastSeen=max(TimeGenerated),
    TargetedPorts=make_set(LocalPort, 10),  // LocalPort = attacked services on honeypot
    Actions=make_set(ActionType, 5)
    by RemoteIP  // RemoteIP = attacker source
| order by ConnectionCount desc
| take 50
```

**IMPORTANT:** This query shows **TCP connection establishment** (network layer), NOT successful authentication. Attackers who appear here may still fail at the authentication layer (SecurityEvent 4625). For honeypots, all inbound connections should be treated as reconnaissance/attack attempts.

**After Phase 1 completes:**
- Merge all three result sets
- **Rank IPs by attack volume** (prioritize SecurityEvent FailedAttempts, then W3CIISLog RequestCount, then DeviceNetworkEvents ConnectionCount)
- **Select top 10-15 IPs** for enrichment (focus on high-volume attackers, not one-off scanners)
- Extract unique IP addresses into array
- Save **prioritized IPs only** to `temp/honeypot_ips_<timestamp>.json` in format: `{"ips": ["1.2.3.4", "5.6.7.8", ...]}`
- Document total unique attacker count separately for report statistics
- Report elapsed time: `[MM:SS] ✓ Failed connection queries completed (XX seconds) - [total_count] unique IPs identified, top [enrichment_count] prioritized for enrichment`

---

### Phase 2: IP Enrichment & Threat Intelligence (PARALLEL)

**Execute IP enrichment script AND Sentinel threat intel query in parallel:**

#### 2A: Run IP Enrichment Script
```powershell
# Read prioritized IPs from JSON file (top 10-15 by attack volume)
# This reduces token consumption by ~80% while maintaining critical intelligence
$env:PYTHONPATH = "<WORKSPACE_ROOT>"
cd "<WORKSPACE_ROOT>"
.\.venv\Scripts\python.exe enrich_ips.py --file temp/honeypot_ips_<timestamp>.json
```

**Enrichment provides (for prioritized IPs only):**
- Geolocation (city, region, country)
- ISP/Organization (ASN, org name)
- VPN/Proxy/Tor detection (`is_vpn`, `is_proxy`, `is_tor`)
- Abuse reputation (`abuse_confidence_score`, `total_reports`)
- Shodan intelligence: open ports, CVEs, tags (e.g., `eol-os`, `self-signed`, `c2`), CPEs, hostnames
- Risk level assessment (HIGH/MEDIUM/LOW)

**Note:** Enrichment script provides aggregated statistics for all IPs - use these summary stats in report narrative instead of listing every IP

#### 2B: Query Sentinel Threat Intelligence
```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>", ...]);  // From Phase 1 prioritized list (top 10-15 IPs)
ThreatIntelIndicators
| extend IndicatorType = replace_string(replace_string(replace_string(tostring(split(ObservableKey, ":", 0)), "[", ""), "]", ""), "\"", "")
| where IndicatorType in ("ipv4-addr", "ipv6-addr", "network-traffic")
| extend NetworkSourceIP = toupper(ObservableValue)
| where NetworkSourceIP in (target_ips)
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend Description = tostring(parse_json(Data).description)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| extend TrafficLightProtocolLevel = tostring(parse_json(AdditionalFields).TLPLevel)
| extend ActivityGroupNames = extract(@"ActivityGroup:(\S+)", 1, tostring(parse_json(Data).labels))
| summarize arg_max(TimeGenerated, *) by NetworkSourceIP
| project 
    TimeGenerated,
    IPAddress = NetworkSourceIP,
    ThreatDescription = Description,
    ActivityGroupNames,
    Confidence,
    ValidUntil,
    TrafficLightProtocolLevel,
    IsActive
| order by Confidence desc, TimeGenerated desc
```

**After Phase 2 completes:**
- Merge IP enrichment JSON with Sentinel threat intel results
- Save combined data to `temp/honeypot_data_<timestamp>.json`
- Report elapsed time: `[MM:SS] ✓ IP enrichment completed (XX seconds)`

---

### Phase 3: Query Security Incidents (Sentinel KQL)

**Step 3A: Get Device ID from Sentinel**

```kql
let honeypot = '<HONEYPOT_NAME>';
DeviceInfo
| where TimeGenerated > ago(30d)
| where DeviceName =~ honeypot or DeviceName contains honeypot
| summarize arg_max(TimeGenerated, *)
| project DeviceId, DeviceName, OSPlatform, OSVersion, PublicIP
```

**Extract `DeviceId` (GUID) from result - returns single most recent device record.**

**Step 3B: Query Security Incidents**

```kql
let targetDevice = "<HONEYPOT_NAME>";
let targetDeviceId = "<DEVICE_ID>";  // REQUIRED: Get from DeviceInfo query (Step 3A)
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has targetDevice or Entities has targetDeviceId
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)  // Filter on CreatedTime for incidents created in range
| summarize arg_max(TimeGenerated, *) by ProviderIncidentId  // Get most recent state per ProviderIncidentId
| project ProviderIncidentId, Title, Severity, Status, Classification, CreatedTime, LastModifiedTime, Owner, AdditionalData, AlertIds, Labels
| where not(tostring(Labels) has "Redirected")  // Exclude merged incidents
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| extend ProviderIncidentUrl = tostring(AdditionalData.providerIncidentUrl)
| extend OwnerUPN = tostring(Owner.userPrincipalName)
| extend LastModifiedTime = todatetime(LastModifiedTime)
| summarize 
    Title = any(Title),
    Severity = any(Severity),
    Status = any(Status),
    Classification = any(Classification),
    CreatedTime = any(CreatedTime),
    LastModifiedTime = any(LastModifiedTime),
    OwnerUPN = any(OwnerUPN),
    ProviderIncidentUrl = any(ProviderIncidentUrl),
    AlertCount = count(),
    MitreTactics = make_set(Tactics)
    by ProviderIncidentId
| order by LastModifiedTime desc
| take 10
```

**IMPORTANT:** 
- This query joins SecurityIncident with SecurityAlert to provide full incident context
- **Deduplication**: The final `summarize` statement collapses multiple alerts per incident into a single row (groups by ProviderIncidentId)
- **Filter on `CreatedTime`** to find incidents created in the investigation period
- **Use `arg_max(TimeGenerated, *) by IncidentNumber`** to get the most recent update for each incident (includes status changes, comments, etc.)
- **Returns up to 10 unique incidents** (grouped by ProviderIncidentId to ensure one row per external incident ID)

- **⚠️ CHECK STATUS FIELD:** Only report incidents with Status="New" or "Active" as threats. Status="Closed" + Classification="BenignPositive" = expected honeypot activity (do not flag as threat)

**After Phase 3 completes:**
- Report elapsed time: `[MM:SS] ✓ Security incidents query completed (XX seconds)`

---

### Phase 4: Vulnerability Assessment

**⚠️ CRITICAL: TVM tables are snapshot tables — NO time filtering!**
- `DeviceTvmSoftwareVulnerabilities` has NO `Timestamp` or `TimeGenerated` column
- Do NOT add `where Timestamp between (...)` — it will fail with a schema error
- Do NOT use Sentinel Data Lake (`query_lake`) — TVM tables are only available via Advanced Hunting
- Use `RunAdvancedHuntingQuery` MCP tool only

#### Step 4A: Query Vulnerabilities via Advanced Hunting KQL
```kql
let deviceName = '<HONEYPOT_NAME>';
DeviceTvmSoftwareVulnerabilities
| where DeviceName startswith deviceName
| project
    CveId,
    VulnerabilitySeverityLevel,
    SoftwareVendor,
    SoftwareName,
    SoftwareVersion,
    RecommendedSecurityUpdate,
    RecommendedSecurityUpdateId
| summarize by CveId, VulnerabilitySeverityLevel, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| order by case(VulnerabilitySeverityLevel == "Critical", 1, VulnerabilitySeverityLevel == "High", 2, VulnerabilitySeverityLevel == "Medium", 3, 4) asc
| take 30
```

**Key columns returned:**
- `CveId` — CVE identifier (e.g., CVE-2025-15467)
- `VulnerabilitySeverityLevel` — String: Critical / High / Medium / Low
- `SoftwareVendor`, `SoftwareName`, `SoftwareVersion` — Affected software details
- `RecommendedSecurityUpdate` — Patch info (may be empty)

**🔴 PROHIBITED:**
- ❌ Adding `Timestamp` or `TimeGenerated` filters (column does not exist)
- ❌ Projecting `CvssScore` (column does not exist — use `VulnerabilitySeverityLevel` instead)
- ❌ Using Sentinel Data Lake MCP (`query_lake`) for TVM tables
- ❌ Using `GetDefenderMachineVulnerabilities` API (requires separate machine ID lookup, less reliable)

**After Phase 4 completes:**
- Report elapsed time: `[MM:SS] ✓ Vulnerability scan completed (XX seconds)`

---

### Phase 5: Generate Executive Report

**Use the Report Template (see section below) to create markdown report.**

**Critical Report Sections:**
1. **Executive Summary** - High-level findings (2-3 paragraphs)
2. **Attack Surface Analysis** - Failed connections by IP, service, pattern
3. **Threat Intelligence Correlation** - Known malicious IPs, APT groups, VPNs
4. **Security Incidents** - Incidents triggered by honeypot activity
5. **Attack Pattern Analysis** - Targeted services, credential attacks, web exploits
6. **Vulnerability Status** - Current CVEs and exploitation risk
7. **Key Detection Insights** - TTPs, MITRE ATT&CK mapping, novel indicators
8. **Honeypot Effectiveness** - Metrics and recommendations
9. **Conclusion** - Summary and next steps

**Report Generation:**
1. Populate template with data from Phases 1-4
2. Use `create_file` to save: `reports/honeypot/Honeypot_Executive_Report_<hostname>_<timestamp>.md`
3. Return absolute path to user

**After Phase 5 completes:**
- Report elapsed time: `[MM:SS] ✓ Report generated (XX seconds)`
- **Provide comprehensive timeline breakdown with total elapsed time**

---

## KQL Query Library

### Additional Useful Queries

#### Query: Top Targeted User Accounts (Credential Attacks)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let honeypot = '<HONEYPOT_NAME>';
SecurityEvent
| where TimeGenerated between (start .. end)
| where Computer =~ honeypot
| where EventID == 4625  // Failed logon
| summarize FailedAttempts = count() by Account
| order by FailedAttempts desc
| take 20
```

#### Query: Web Exploitation Patterns (SQL Injection, XSS, Path Traversal)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let honeypot = '<HONEYPOT_NAME>';
W3CIISLog
| where TimeGenerated between (start .. end)
| where Computer =~ honeypot
| where csUriStem has_any ("'", "union", "select", "script", "../", "..\\", "cmd.exe", "powershell")
| summarize 
    AttemptCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    UniqueIPs = dcount(cIP)
    by ExploitPattern = case(
        csUriStem has_any ("'", "union", "select"), "SQL Injection",
        csUriStem has "script", "XSS",
        csUriStem has_any ("../", "..\\"), "Path Traversal",
        csUriStem has_any ("cmd.exe", "powershell"), "Command Injection",
        "Other")
| order by AttemptCount desc
```

#### Query: Port Scanning Detection
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let honeypot = '<HONEYPOT_NAME>';
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName =~ honeypot
| summarize 
    DistinctPorts = dcount(RemotePort),
    PortsScanned = make_set(RemotePort),
    EventCount = count()
    by RemoteIP
| where DistinctPorts >= 5  // Threshold: 5+ ports = scan
| order by DistinctPorts desc
| take 20
```

#### Query: Brute Force Detection (High Volume from Single IP)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let honeypot = '<HONEYPOT_NAME>';
let threshold = 50;  // 50+ failed attempts = brute force
SecurityEvent
| where TimeGenerated between (start .. end)
| where Computer =~ honeypot
| where EventID == 4625
| extend IpAddress = extract(@"Source Network Address:\s+([^\s]+)", 1, tostring(EventData))
| summarize FailedAttempts = count() by IpAddress
| where FailedAttempts >= threshold
| order by FailedAttempts desc
```

---

## Report Template

Use this structure for executive reports:

```markdown
# Honeypot Security Analysis - <HONEYPOT_NAME>
**Analysis Period:** <START_DATE> to <END_DATE> (<HOURS> hours)  
**Report Generated:** <TIMESTAMP>  
**Classification:** CONFIDENTIAL

---

## Executive Summary

[3 comprehensive paragraphs covering attack overview, threat landscape, and value delivered]

**Key Metrics:**
- **Total Attack Attempts:** [count]
- **Unique Attacking IPs:** [count]
- **Security Incidents Triggered:** [count]
- **Known Malicious IPs (Threat Intel):** [count] ([percentage]%)
- **Current Vulnerabilities:** [count] HIGH, [count] MEDIUM

---

## 1. Attack Surface Analysis
[Failed connections by source IP, geographic distribution, VPN/anonymization summary]

## 2. Threat Intelligence Correlation
[IPs matched in threat intel, highest confidence threats, MSTIC indicators]

## 3. Security Incidents
[Incidents involving honeypot with severity, status, classification, MITRE tactics]

## 4. Attack Pattern Analysis
[Targeted services, credential attacks, web exploitation, port scanning]

## 5. Honeypot Vulnerability Status
[CVE inventory, exploitation risk assessment, cross-reference with attacks]

## 6. Key Detection Insights
[MITRE ATT&CK mapping, novel indicators, threat actor attribution]

## 7. Honeypot Effectiveness
[Detection metrics, recommendations for optimization]

## 8. Conclusion
[Summary, key takeaways, immediate/short-term/long-term actions]

---

**Investigation Timeline:**
[Phase timing breakdown]

**Total Investigation Time:** [duration]
```

---

## Error Handling

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Missing honeypot in DeviceInfo table** | Verify device name; check if device reports to Defender; try Computer field instead |
| **No SecurityEvent logs** | Device may not be sending Windows Security logs; verify log forwarding configuration |
| **W3CIISLog table not found** | IIS logging may not be enabled; query WebAccessLog or HTTP logs instead |
| **IP enrichment script fails** | Check ipinfo.io token in config.json; verify internet connectivity; check temp file exists |
| **Date range returns no results** | Verify date calculation (current date from context + proper offset); expand time range |
| **KQL timeout** | Reduce `take` limit; narrow time range; remove complex aggregations |

### Validation Checklist

Before delivering report, verify:
- ✅ All Phase timestamps reported to user
- ✅ Total elapsed time calculated and displayed
- ✅ IP enrichment data merged with attack logs
- ✅ Incident filtering correctly applied (only honeypot-related incidents)
- ✅ Vulnerability data retrieved (or documented as unavailable)
- ✅ Report saved to correct path: `reports/honeypot/Honeypot_Executive_Report_<hostname>_<timestamp>.md`
- ✅ Absolute path returned to user

---

## Integration with Main Copilot Instructions

This skill follows all patterns from the main `copilot-instructions.md`:
- **Date range handling:** Uses +2 day rule for real-time searches
- **Parallel execution:** Runs independent queries simultaneously
- **Time tracking:** Mandatory reporting after each phase
- **Token management:** Uses `create_file` for all output
- **KQL best practices:** Follows Sample KQL Query patterns
- **IP enrichment:** Uses documented `enrich_ips.py` utility

**Example invocations:**
- "Investigate the honeypot HONEYPOT-01 over the last 48 hours"
- "Run honeypot security analysis for honeypot-server-01 from Dec 10-12"
- "Generate honeypot report for [hostname] last 7 days"

---

## Visualization Options

After completing the investigation, offer to visualize the attack data using the dedicated visualization skills:

### Heatmap Visualization
Use the **heatmap-visualization** skill (`.github/skills/heatmap-visualization/SKILL.md`) to show attack patterns over time with threat intel drill-down.

**When to offer:**
- ✅ After completing honeypot investigation phases
- ✅ When user asks "show me the attack patterns" or "visualize the attacks"
- ✅ For comparing attack volumes across time periods
- ❌ Skip if investigation found minimal activity (<5 unique IPs)

### Geomap Visualization
Use the **geomap-visualization** skill (`.github/skills/geomap-visualization/SKILL.md`) to show attack origins on a world map.

**When to offer:**
- ✅ After completing honeypot investigation phases
- ✅ When user asks "where are the attacks coming from?" or "show on a map"
- ✅ For geographic threat distribution analysis
- ❌ Skip if all IPs are from the same region

**Note:** W3CIISLog includes native `RemoteIPLatitude` and `RemoteIPLongitude` fields - use these directly for geomap visualization without additional enrichment.

---

*Last Updated: January 29, 2026*


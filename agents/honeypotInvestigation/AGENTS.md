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
- **Output File**: `reports/Honeypot_Executive_Report_<hostname>_<timestamp>.md`
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

**CRITICAL:** Microsoft Defender for Endpoint uses a different machine ID format (GUID) than Sentinel's DeviceId (SHA1 hash). You MUST use Advanced Hunting to get the correct MDE machine ID.

**Sequential execution (cannot parallelize - dependencies):**

#### Step 4A: Activate Advanced Hunting Tools
```
activate_advanced_hunting_tools()
```

#### Step 4B: Get MDE Machine ID via Advanced Hunting
```
mcp_sentinel-tria_RunAdvancedHuntingQuery({
  "kqlQuery": "DeviceInfo | where DeviceName =~ '<HONEYPOT_NAME>' | summarize arg_max(Timestamp, *) | project DeviceId, DeviceName, OSPlatform, OSVersion, PublicIP"
})
```

**Extract `DeviceId` (GUID format) from result - this is the MDE machine ID.**

#### Step 4C: Activate Security Alert and Incident Management Tools
```
activate_security_alert_and_incident_management_tools()
```

**This activation provides access to `mcp_sentinel-tria_GetDefenderMachineVulnerabilities` and other security tools.**

#### Step 4D: Query Vulnerabilities
```
mcp_sentinel-tria_GetDefenderMachineVulnerabilities({"id": "<MDE_MACHINE_ID>"})
```

**Use the GUID-format DeviceId from Step 4B result.**

**Parse Response:**
- CVE ID
- Severity (Critical/High/Medium/Low)
- CVSS Score
- Affected Product/Component
- Exploit Availability
- Description

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
2. Use `create_file` to save: `reports/Honeypot_Executive_Report_<hostname>_<timestamp>.md`
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

```markdown
# Honeypot Security Analysis - <HONEYPOT_NAME>
**Analysis Period:** <START_DATE> to <END_DATE> (<HOURS> hours)  
**Report Generated:** <TIMESTAMP>  
**Classification:** CONFIDENTIAL

---

## Executive Summary

[3 comprehensive paragraphs covering:]

**Paragraph 1 - Attack Overview & Threat Intelligence:**
- Total unique attacking IPs and attack volume across all sources (use count from Phase 1 before prioritization)
- Geographic distribution (X countries, top sources) - use enrichment summary statistics
- Threat intelligence hit rate: "X of Y enriched IPs (XX%) matched threat intelligence indicators with X% confidence scores"
- Security incidents generated (X active HIGH severity, X closed)
- Brief mention of attack patterns (credential brute force, web exploitation, reconnaissance)

**Note:** Use aggregated stats from enrichment script output (VPN IPs: X, High confidence abuse: X, Whitelisted: X, Clean: X) instead of listing all IP details

**Paragraph 2 - Attack Landscape & Tactics:**
- Describe dominant attack vectors with quantitative details
- Highlight sophisticated patterns (multi-stage incidents, specific CVE targeting)
- Note attacker behavior patterns (opportunistic scanning vs targeted attacks)
- Mention any active/ongoing incidents requiring investigation

**Paragraph 3 - Vulnerability Context & Value Proposition:**
- Current vulnerability count and severity breakdown
- Cross-reference CVEs with observed attack patterns (exploitation attempts vs potential targets)
- Assess exploitation risk (were vulnerabilities actively targeted?)
- Conclude with honeypot value: threat intelligence contribution, novel indicators discovered, early warning capability

**Key Metrics:**
- **Total Attack Attempts:** [count] (quantify the attack volume)
- **Unique Attacking IPs:** [count] (distinct attackers)
- **Security Incidents Triggered:** [count] (X active HIGH severity) (breakdown by status)
- **Known Malicious IPs (Threat Intel):** [count] (XX%) (show percentage match rate)
- **Current Vulnerabilities:** [count] HIGH, [count] MEDIUM (severity breakdown)

---

## 1. Attack Surface Analysis

### 1.1 Failed Connection Attempts by Source

**Total Connection Attempts:** [sum of all three query results]

#### Windows Security Events (Failed Logons)
| Source IP | Country | Failed Attempts | Target Accounts | Event Type | First Seen | Last Seen |
|-----------|---------|-----------------|-----------------|------------|------------|-----------|
[Merge SecurityEvent results with IP enrichment data - use 'Country' field from enrichment]
[Show top 10-15 IPs by failed attempt count - these should match the prioritized enrichment list]
[For IPs not enriched (low-volume attackers), use query result data only without enrichment details]

**Analysis:** [Quantify dominant attacker - e.g., "Single IP (X.X.X.X) responsible for XX% of attempts over X-hour period". Discuss targeted accounts and attack patterns.]

#### IIS Web Server (HTTP Errors) - By Exploit Pattern
**Total Web Requests:** [sum of all requests]
**Unique Attacking IPs:** [count]

| Source IP | Country | Requests | Targeted URIs (Samples) | Status Codes | First Seen | Last Seen |
|-----------|---------|----------|-------------------------|--------------|------------|-----------|
[Merge W3CIISLog results with IP enrichment data]
[Group by exploit pattern: PHPUnit RCE (4 IPs with 44 requests each), Webshell probes, Router exploits, etc.]
[Show top 10-15 by request count - prioritize unique exploit patterns over volume]
[Note legitimate scanners separately: "Censys security scanning (X IPs, whitelisted)", "Google Cloud scanning (X IPs, whitelisted)"]

**Analysis:** [Identify exploit patterns with CVE references:]
- **PHPUnit RCE (CVE-2017-9841):** [count] requests from [X] IPs probing for vulnerable PHPUnit installations
- **Struts2 Exploit (CVE-2017-5638):** [count] requests targeting Struts2 framework
- **Webshell Upload Attempts:** [count] requests for `/upl.php`, `/systembc/password.php`, etc.
- **Router Exploits:** Any router-specific CVE targeting (e.g., CVE-2023-1389)

#### Network Traffic (Defender) - Connection Failed Events
| Source IP | Events | Targeted Ports | First Seen | Last Seen |
|-----------|--------|----------------|------------|-----------|
[Merge DeviceNetworkEvents results - focus on failed connections]

**Analysis:** [Interpret localhost (127.0.0.1) traffic - potential C2 or internal enumeration. Flag common application server ports (8080, 8443, 7001, etc.)]

### 1.2 Geographic Distribution

**Top Source Countries (from enriched IPs):**
1. **[Country]** - [count] IPs ([percentage]%)
2. **[Country]** - [count] IPs ([percentage]%)
3. **[Country]** - [count] IPs ([percentage]%)
4. **[Country]** - [count] IPs ([percentage]%)
5. **[Country]** - [count] IPs ([percentage]%)
[Continue for top 10, or condense remainder as "Other countries - X IPs each"]

**Top ASNs/Organizations (from enriched IPs):**
1. **[ASN/Org]** - [count] IPs (note infrastructure type: scanning platform, bulletproof hosting, cloud VPS, etc.)
2. **[ASN/Org]** - [count] IPs
3. **[ASN/Org]** - [count] IPs
[Continue for top 5-10]

**VPN/Anonymization Summary (use enrichment script output):**
- VPN endpoints: [count] IPs ([percentage]% of enriched set)
- Proxy servers: [count] IPs
- Tor exit nodes: [count] IPs
- Whitelisted scanners: [count] IPs (Censys, Google Cloud)
- Clean residential: [count] IPs

**Analysis:** [Assess threat actor infrastructure - bulletproof hosting providers (Netherlands, Lithuania), cloud VPS (DigitalOcean, AWS), security scanning platforms (Censys, Shodan), residential ISPs vs datacenter ASNs]

---

## 2. Threat Intelligence Correlation

**IPs Matched in Threat Intelligence:** [count from ThreatIntelIndicators query] of [total enriched IPs] ([percentage]% of enriched attackers)

**Highest Confidence Threats (100% Confidence):**

| IP Address | Threat Description | Confidence | Valid Until | TLP Level |
|------------|-------------------|------------|-------------|-----------|
[Show only 100% confidence matches - MSTIC HoneyPot detections + high-confidence AbuseIPDB]
[Limit to top 10 by threat severity/report count]
[Group similar threats: "X IPs flagged as MSTIC HoneyPot brute force", "X IPs with AbuseIPDB 100% confidence (1000+ reports)"]

**Microsoft Threat Intelligence (MSTIC) Honeypot Indicators:**
[If any IPs flagged by Microsoft's internal honeypot network, list separately with details]
- **[IP Address]** - [Threat type] ([TLP Level], [Confidence]% confidence)

**Analysis:** [Summarize threat intelligence findings - e.g., "X of Y enriched IPs (XX%) confirmed malicious with 100% confidence, appearing in AbuseIPDB with X-XX,XXX reports. Note highest abuse profiles and confirm attack patterns are widespread."]

**Total Matches:** [count]

| IP Address | Threat Description | Activity Groups | Confidence | Valid Until | TLP Level |
|------------|-------------------|-----------------|------------|-------------|-----------|
[Table from ThreatIntelIndicators query results]
= 100% ([count] IPs):**

| IP Address | Country | Org | Total Reports | Attack Volume |
|------------|---------|-----|---------------|---------------|
[Filter IP enrichment where abuse_confidence_score == 100]
[Sort by total_reports DESC, show top 7-10]

**Analysis:** [Discuss sustained abuse history, note bulletproof hosting providers, assess correlation between abuse history and attack volume. Example: "All X IPs show sustained abuse history (XX-XX,XXX reports). [Provider names] are known bulletproof hosting providers with minimal abuse response."
**IPs Flagged as Tor Exit Nodes:** [count]

| IP Address | Country | Type | Org | Attack V]

[For each incident, show in priority order: Active HIGH → Active MEDIUM/LOW → Closed]

### Incident #[IncidentNumber]: [Title]
- **Severity:** [HIGH/MEDIUM/LOW]
- **Status:** [ACTIVE/CLOSED] ([NEW/Undetermined/BenignPositive/etc.])
- **Classification:** [TruePositive/FalsePositive/BenignPositive/Unknown/Undetermined]
- **Created:** [CreatedTime UTC]
- **Last Modified:** [LastModifiedTime UTC] ([X hours ago])
- **Alerts:** [AlertCount] correlated alerts
- **MITRE Tactics:** [List tactics - e.g., CommandAndControl, CredentialAccess, InitialAccess]
- **Owner:** [OwnerUPN if assigned]
- **Investigation Link:** [ProviderIncidentUrl]

**Critical Finding:** [If active HIGH severity, emphasize urgency. If closed, explain classification.]

[Include Analysis paragraph after incident list:]
**Incident Analysis:**
- X of Y incidents correctly classified as BenignPositive (expected honeypot behavior)
- X active [severity] incidents require [action]
- Incident detection rate: X incidents / Y attacks = X% [interpret rate appropriateness]
- Honeypot [successfully/needs improvement in] generating [high/low]-quality threat intelligence signalseports | Attack Volume | Last Reported |
|------------|---------|-------------|---------------|---------------|---------------|
[Filter IP enrichment where abuse_confidence_score >= 75]

---

## 3. Security Incidents

**Total Incidents Involving Honeypot:** [count from filtered results]

[For each incident:]
### Incident #[IncidentNumber]: [Title]
- **Severity:** [High/Medium/Low]
- **Status:** [Active/Resolved/Closed]
- **Classification:** [TruePositive/FalsePositive/BenignPositive]
- **Created:** [CreatedTime]
- **Alerts:** [AlertCount]
- **Investigation Link:** [ProviderIncidentUrl]
- **Description:** [Brief summary from alerts]

---

## 4. Attack Pattern Analysis

### 4.1 Most Targeted Services

**Services Ranked by Attack Volume:**
] unique IPs with [total] requests total

**Exploit Types Detected:**

| Exploit Type | Count | CVEs Targeted |
|-------------|-------|---------------|
| [Exploit name with CVE] | [requests] requests ([X] IPs x [Y] each) | [CVE-YYYY-XXXXX] |
| [Exploit name] | [requests] requests | [CVE or N/A] |
| [Post-exploitation activity] | [requests] requests | N/A (post-exploitation) |
[Examples: PHPUnit RCE (CVE-2017-9841), Struts2 (CVE-2017-5638), OpenWrt Router (CVE-2023-1389), webshell probes, etc.]

**Most Targeted URIs:**
1. `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` - [count] requests
2. `/struts2-showcase/*` - [count] requests
3. `/systembc/password.php` - [count] request ([malware family] backdoor)
4. `/upl.php`, `/1.php`, `/form.html` - [count] requests (webshell names)
5. `/cgi-bin/luci/;stok=/locale` - [count] requests (router exploit)

**Sample Attack Payloads:**
- PHPUnit: `POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` with PHP code in request body
- Struts2: Requests to `/struts2-showcase/struts/utils.js` and associated framework files
- SystemBC: Direct request to `/systembc/password.php` ([malware family] botnet backdoor component)

**Analysis:** [Explain what attackers are probing for - high-profile vulnerabilities, known CVE exploitation attempts, malware backdoor checks. Note response codes (401 = blocked, 200 = potential success). Provide context for each CVE.
...

**Brute Force Indicators:**
- IPs with >50 failed attempts: [count]
- Most aggressive attacker: [IP with highest attempt count] - [count] attempts

**Analysis:** [Common patterns: admin/administrator, service accounts, default usernames]

### 4.3 Web Exploitation Attempts

**Total Suspicious Web Requests:** [count from W3CIISLog with exploit patterns]

**Exploit Types Detected:**
- SQL Injection attempts: [count]
- XSS (Cross-Site Scripting) attempts: [count]
- Path Traversal attempts: [count]
- Command Injection attempts: [count]

**Most Targeted URIs:**
1. [csUriStem] - [count] requests
2. [csUriStem] - [count] requests
...

**Sample Attack Payload:** [Example of most common exploit string from logs]

### 4.4 Port Scanning Activity

**IPs Performing Port Scans:** [count where DistinctPorts >= 5]

| Source IP | Country | Org | Ports Scanned | Total Events |
|-----------|---------|-----|---------------|--------------|
[Table from port scanning detection query]

---

## 5. Honeypot Vulnerability Status

**Last Vulnerability Scan:** [TimeGenerated from DeviceInfo query]  
**Device ID:** [DeviceId]  
**OS Platform:** [OSPlatform] [OSVersion] (Build [OSBuild])  
**Public IP:** [PublicIP]

### 5.1 Critical & High Severity Vulnerabilities

**Total Critical CVEs:** [count where Severity == "Critical"]  
**Total High CVEs:** [count where Severity == "High"]

| CVE ID | Severity | CVSS Score | Affected Product | Exploit Available | Publicly Disclosed |
|--------|----------|------------|------------------|-------------------|-------------------|
[Table of Critical/High CVEs from vulnerability query]

### 5.2 Exploitation Risk Assessment

**CVEs with Known Exploits:** [count where ExploitAvailable == true]

**Cross-Reference with Attack Patterns:**
[Analyze: Are attackers attempting to exploit any of the CVEs found? Check targeted services/ports against CVE vulnerability details]

**Example:**
- CVE-2023-XXXXX (Critical - RCE in [product]): [Port/service targeted? YES/NO]
- Evidence: [If YES, show relevant log entries from Phase 1 queries]

**Recommendation:** [Prioritize patching CVEs that are actively being targeted]

| Tactic | Technique | Evidence | IPs Involved |
|--------|-----------|----------|--------------|
| **Reconnaissance** | T1595.001 - Active Scanning: Scanning IP Blocks | Port scanning ([protocol], multiple ports) | [List specific IPs with counts] |
| **Reconnaissance** | T1595.002 - Active Scanning: Vulnerability Scanning | [Exploit type] probes, [Framework] exploit attempts | [List IPs] |
| **Initial Access** | T1190 - Exploit Public-Facing Application | [Specific CVEs with names] | [List IPs targeting each CVE] |
| **Initial Access** | T1133 - External Remote Services | RDP brute force (TCP/3389) | [List IPs with attempt counts] |
| **Credential Access** | T1110.001 - Brute Force: Password Guessing | [count] failed RDP logon attempts | [Primary attacker IPs] |
| **Discovery** | T1046 - Network Service Scanning | Internal port scan ([ports listed]) | [Localhost or specific IPs] |
| **Persistence** | T1505.003 - Server Software Component: Web Shell | Webshell upload attempts ([filenames]) | [List IPs] |
| **Command & Control** | T1071.001 - Application Layer Protocol: Web Protocols | Attempted C2 communication (localhost → app servers) | [List IPs] |

[Use specific sub-techniques where applicable. Provide concrete evidence with IP addresses, port numbers, CVE IDs, and attack counts.]tification |
|------------|---------|-----|------------ ([count] IPs):**

| IP Address | Attack Volume | Risk Level | Recommendation |
|------------|---------------|------------|----------------|
| [IP with high volume] | [count] [attack type] attempts | HIGH | Share with threat intel - [reason] |
| [IP] | [count] attempts | MEDIUM | Monitor for patterns - [reason] |
| [Localhost or internal] | [count] [activity type] | MEDIUM | [Action - investigate compromise, review logs, etc.] |
| [Low volume IPs] | [count] requests | LOW | Monitoring only |
| [Legitimate services] | [count] each | INFO | Legitimate CDN/services ([Provider names]) |

**New Attack Patterns Observed:**

1. **[Pattern Name]:**
   - Description of unusual behavior with quantitative details
   - Interpretation: What does this suggest about attacker intent/sophistication?
   - Example: "Targeted accounts named 'scanner', 'scan' - reconnaissance for security infrastructure"

2. **[Malware Family] Check:**
   - Specific indicators (e.g., "/systembc/password.php")
   - What this reveals about attacker operational security
   - Example: "Checking if honeypot was previously compromised by this botnet"

3. **[Attack Technique]:**
   - Evidence of post-exploitation or advanced technique
   - Implications for incident response
   - Example: "Localhost reconnaissance suggests web compromise → lateral movement"

**Potential APT/Threat Actor Attribution:**
- [If ActivityGroupNames found]: Discuss specific APT groups and their TTPs
- [If no attribution]: Assess sophistication level - "Attack patterns consistent with [automated botnet/commodity cybercrime/targeted APT] rather than [alternative]"
- Note infrastructure concentration (bulletproof hosting, cloud VPS) and what this suggests about threat actor profile
[Visual timeline showing attack progression:]

**Initial Reconnaissance Phase:**
- [Time range]: Port scanning activity detected from [count] IPs
- Targeted ports: [list]

**Exploitation Attempts Phase:**
- [Time range]: Credential brute force attacks from [count] IPs
- [Time range]: Web exploitation attempts targeting [specific URIs]

**Persistence/Lateral Movement Indicators:**
- [Any successful connections followed by unusual activity?]
- [Any attempts to access sensitProtocol] ([XX]% of attempts) - Port [number] remains primary target for opportunistic attacks  
**Peak Attack Times:**  
- **[Attack type]:** [HH:MM] - [HH:MM] UTC ([X-hour window, Date])
- **[Attack type]:** [HH:MM] - [HH:MM] UTC ([X-hour window spanning dates])
- **Suggests attacker timezone:** [Region] ([time correlation interpretation])

**Average Attack Duration:**
- **Sustained campaigns:** [X.X] hours ([specific IP with longest duration])
- **Hit-and-run scans:** <[X] minute (most [attack type] attempts)
- **Internal enumeration:** [X] seconds ([localhost or specific pattern] burst)

**Sophistication Assessment:**

**Low Sophistication ([XX]% of IPs):**
- [Count] IPs performing basic [protocol]/[attack type] scanning with no evasion techniques
- Using well-known exploit patterns ([CVEs]) without customization
- No credential obfuscation or anti-detection measures
- Consistent with **automated botnet/scanner behavior**

**Medium Sophistication ([XX]% of IPs):**
- [Count] IPs ([list specific examples]) showing deliberate targeting
- [Specific IP]: Low-rate brute force ([X.X]/min) to evade detection thresholds
- Targeted [specific account types] (reconnaissance for [infrastructure type])
- [Malware] backdoor check (operational security - verifying compromise status)

**High Sophistication ([XX]% of IPs):**
- [Count] IP ([specific example]) showing post-exploitation tradecraft
- Rapid port scanning ([X] attempts in [Y] seconds) targeting specific [technology] frameworks
- **Multi-stage attack chain:** [Stage 1] → [Stage 2] → [Stage 3]
- Consistent with **Incident #[number]** ([tactics] incident - [STATUS])
| **Reconnaissance** | T1595 - Active Scanning | Port scanning from [count] IPs |
| **Initial Access** | T1133 - External Remote Services | RDP/SSH brute force attempts |
| **Credential Access** | T1110 - Brute Force | [count] failed logon attempts |
| **Execution** | T1059 - Command and Scripting Interpreter | Command injection attempts in web logs |
| **Exfiltration** | T1048 - Exfiltration Over Alternative Protocol | [If detected] |

### 6.3 Novel Indicators & Emerging Threats
3 comprehensive paragraphs:]

**Paragraph 1 - Threat Landscape Overview:**
The [HONEYPOT NAME] honeypot successfully attracted and logged **[count] unique attackers** over a [duration]-hour period, capturing **[count] attack attempts** spanning [attack types]. The honeypot's threat intelligence value is **[exceptional/high/moderate]**, with **[XX]% of attackers ([count] IPs)** matching known malicious indicators at [confidence]% confidence levels, and the discovery of **[count] novel malicious IPs** not previously cataloged. Attack patterns reveal **[opportunistic mass scanning/targeted APT operations/mixed threat actor profile]** from [infrastructure types] rather than [alternative sources].

**Paragraph 2 - Critical Findings & Incident Response:**
The honeypot generated **[count] security incidents**, including **[count] active [severity] severity [incident type]** (Incident #[number]) involving [tactics], demonstrating its ability to detect sophisticated threats. However, **incident generation efficiency remains [low/moderate/high] ([percentage]%)**, with [assessment of detection coverage]. The threat intelligence value is demonstrated through the identification of [count] novel malicious IPs and actionable indicators for organizational security teams.

**Paragraph 3 - Vulnerabilities & Value Delivered:**
The honeypot contains **[count] exploitable CVEs ([count] [severity], [count] [severity])**, including [vulnerability types] in [affected products], but **[no/some] active exploitation attempts matched these CVEs**, indicating the honeypot [successfully decoyed attackers away from / attracted targeting of] critical vulnerabilities. The system delivered **high-quality threat intelligence** by identifying emerging attack patterns ([specific examples]) and providing early warning indicators for the broader organizational security posture.

### Key Takeaways

1. **[Multi-Stage Attack Detected / Primary Threat Finding]:** [Detailed description with incident numbers, tactics, severity, and required actions. Include specific evidence: IP addresses, attack counts, CVEs, etc.]

1. **Investigate Incident #[number]:** Assign analyst to active [severity] severity [incident type]; perform full forensic analysis; determine if honeypot containment was breached
2. **Analyze [specific suspicious activity]:** Investigate [evidence] to confirm [security concern]; review [logs/systems] for [indicators]
3. **Export IOCs to threat intel:** Submit [count] attacking IPs and novel indicators to organizational threat intelligence platform for community awareness
4. **Patch Critical CVEs:** Apply security updates for [specific CVE IDs with products] within 24 hours

#### Short-Term Actions (1-7 days):
1. **Tune detection rules:** Lower [threshold type] to [new value]; add dedicated rules for [specific attack patterns]
2. **Upgrade [infrastructure component]:** [Specific action to address technical limitation]; [benefit of upgrade]
3. **Review [honeypot configuration aspect]:** [Specific configuration review action]; [expected outcome]
4. **Conduct trend analysis:** Compare [duration]-hour attack patterns to [timeframe] baseline; identify emerging TTPs or threat actor shifts

#### Long-Term Improvements (1-4 weeks):
1. **Deploy additional honeypot services:** Add [protocols/ports] exposure to diversify attack surface and attract [specific attack types]
2. **Enable [logging enhancement]:** Implement [specific logging improvement] for all [protocol] requests (capture [data types] for [analysis purpose])
3. **Integrate secondary threat intel sources:** Add [platform names] enrichment to reduce single-source dependency on [current platform]
4. **Implement vulnerable service intentionally:** Deploy known-vulnerable [software/framework] installations (isolated sandbox) to attract high-value [attack type] intelligence
5. **Establish honeypot effectiveness KPIs:** Define metrics for [metric types]; review [frequency]
**Detection Capability:**
- **Unique Attacking IPs Logged:** [count], Honeypot Operations Team  
**Retention:** Retain per organizational data retention policy (recommend 2 years for threat intelligence value)  
**Next Review:** [Duration] (due to [reason - e.g., "active HIGH severity incident #2325"])

---

**Investigation Timeline:**
- [MM:SS] ✓ Failed connection queries completed ([X] seconds)
- [MM:SS] ✓ IPs extracted ([count] unique IPs saved to temp file) ([X] seconds)
- [MM:SS] ✓ IP enrichment completed ([X] seconds) - [count] IPs flagged in threat intelligence ([confidence]% confidence)
- [MM:SS] ✓ Security incidents query completed ([X] seconds) - [count] incidents found ([breakdown])
- [MM:SS] ✓ Vulnerability scan completed ([X] seconds) - [count] CVEs found ([breakdown])
- [MM:SS] ✓ Report generated ([X] seconds)

**Total Investigation Time:** [M] minute(s) [S] seconds ([total] seconds)

*This report was generated using the Honeypot Investigation Agent with data from Microsoft Sentinel, Defender for Endpoint, and Threat Intelligence sourcesggered incidents]
- **Coverage Percentage:** [percentage]
- **False Negatives:** [Events that should have triggered incidents but didn't]

**Threat Intelligence Value:**
- **Novel IPs Discovered:** [count not in threat intel]
- **Known Threat Actor IPs Confirmed:** [count matches]
- **Enrichment Success Rate:** [percentage of IPs successfully enriched]

### 7.2 Attacker Behavior Insights

**Most Active Attack Vector:** [RDP/SSH/HTTP based on volume]  
**Peak Attack Times:** [Analyze TimeGenerated for patterns]  
**Average Attack Duration:** [LastSeen - FirstSeen for persistent attackers]

**Sophistication Assessment:**
- **Low Sophistication:** [count of IPs using default credentials, non-anonymized]
- **Medium Sophistication:** [count using VPNs, multiple attack vectors]
- **High Sophistication:** [count from known APT groups, zero-day attempts]

### 7.3 Recommendations for Honeypot Optimization

1. **Service Exposure Adjustments:**
   - [Based on attack volume: Expose additional vulnerable services to attract more activity? Or reduce exposure of uninteresting services?]
   
2. **Detection Rule Tuning:**
   - [If low incident generation rate: Tune detection rules to capture more attack types]
   - [If high false positive rate: Adjust thresholds]

3. **IOC Integration:**
   - Share [count] novel indicators with threat intelligence platforms for community awareness

4. **Vulnerability Management:**
   - **IMMEDIATE:** Patch [count] Critical CVEs with known exploits
   - **HIGH PRIORITY:** Remediate [count] High CVEs being actively targeted
   - **MEDIUM PRIORITY:** Address remaining Medium/Low CVEs

5. **Logging Enhancements:**
   - [Any gaps in logging? Missing data sources?]
   - [Increase log retention for forensic analysis?]

---

## 8. Conclusion

### Summary

[2-3 paragraphs covering:]
- Overall threat landscape assessment (HIGH/MEDIUM/LOW severity period)
- Most significant findings (APT activity, exploitation attempts, vulnerabilities)
- Incident detection effectiveness and threat intelligence value
- Honeypot value proposition (insights gained, threat intel contributions)

### Key Takeaways

1. [Primary finding - e.g., "Detected sustained brute force campaign from [country]"]
2. [Secondary finding - e.g., "Identified [count] novel malicious IPs not in threat intel"]
3. [Tertiary finding - e.g., "CVE-XXXX actively exploited, requires immediate patching"]

### Next Steps

**Immediate Actions (0-24 hours):**
1. Patch Critical CVEs: [list CVE IDs]
2. Investigate active security incidents: [list incident numbers]
3. Export novel IOCs to threat intelligence platform

**Short-Term Actions (1-7 days):**
1. Tune detection rules based on false negative analysis
2. Share novel IOCs with threat intelligence team
3. Review and update honeypot service configuration

**Long-Term Improvements (1-4 weeks):**
1. Enhance logging infrastructure for additional data sources
2. Conduct trend analysis comparing this period to historical baseline
3. Implement enhanced threat intelligence enrichment workflow

---

**Report Classification:** CONFIDENTIAL  
**Distribution:** Security Operations, Threat Intelligence, Incident Response  
**Retention:** Retain per organizational data retention policy  
**Next Review:** [Recommended: 48-72 hours for active threat periods, 7 days for routine]

---

*This report was generated using the Honeypot Investigation Agent.*
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
- ✅ Report saved to correct path: `reports/Honeypot_Executive_Report_<hostname>_<timestamp>.md`
- ✅ Absolute path returned to user

---

## Integration with Main Copilot Instructions

This agent follows all patterns from the main `copilot-instructions.md`:
- **Date range handling:** Uses +2 day rule for real-time searches
- **Parallel execution:** Runs independent queries simultaneously
- **Time tracking:** Mandatory reporting after each phase
- **Token management:** Uses `create_file` for all output
- **KQL best practices:** Follows Sample KQL Query patterns
- **IP enrichment:** Uses documented `enrich_ips.py` utility

**When to use this agent:**
- User requests honeypot investigation by name
- User asks to "analyze honeypot" or "investigate honeypot"
- User specifies time range for honeypot analysis

**Example invocations:**
- "Investigate the honeypot HONEYPOT-01 over the last 48 hours"
- "Run honeypot security analysis for honeypot-server-01 from Dec 10-12"
- "Generate honeypot report for [hostname] last 7 days"

---

*Last Updated: December 12, 2025*

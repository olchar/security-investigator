# GitHub Copilot - Security Investigation Integration

This workspace contains a security investigation automation system. GitHub Copilot can help you run investigations using natural language.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Quick Start Guide](#quick-start-tldr)** - 5-step investigation pattern
3. **[Investigation Workflow](#how-copilot-should-use-this)** - Complete process
4. **[Sample KQL Queries](#sample-kql-queries-proven-working)** - Validated query patterns
5. **[Microsoft Graph Queries](#microsoft-graph-identity-protection-queries)** - Identity Protection integration
6. **[Advanced Topics](#appendix-advanced-authentication-analysis)** - Deep-dive analysis techniques
7. **[Troubleshooting](#troubleshooting-guide)** - Common issues and solutions

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**🤖 SPECIALIZED AGENT DETECTION:**

**BEFORE starting any investigation, detect if user request requires a specialized agent:**

| Keywords in Request | Action Required |
|---------------------|-----------------|
| **"honeypot"**, "attack analysis", "threat actor" | Search workspace for `agents/honeypotInvestigation/AGENTS.md` and read it FIRST |
| **Future agents** | Check `agents/` folder with `list_dir` to discover available specialized workflows |

**Detection Pattern:**
1. Parse user request for specialized keywords
2. If match found: `file_search("**/agents/**/AGENTS.md")` to find agent instructions
3. Read agent AGENTS.md file BEFORE proceeding with investigation
4. Follow agent-specific workflow (inherits universal patterns from this file)

**Why this matters:**
- Specialized agents have domain-specific KQL queries and analysis patterns
- Generic investigation workflow will miss critical context
- Agent instructions reference universal patterns (date ranges, IP enrichment, time tracking) from this file

---

**BEFORE writing ANY KQL query:**

1. **ALWAYS check "Sample KQL Queries" section FIRST**
2. **Use documented queries as-is** - they handle common pitfalls
3. **Only write custom queries if no sample exists**

**Why this matters:**
- Sample queries include proper field handling (`Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'`)
- They avoid errors on dynamic fields (LocationDetails, ModifiedProperties, DeviceDetail)
- They're production-validated

**Example: User asks "What's that password reset about?" → Go to Sample Queries → Use Query #4**

---

**🔍 AUTHENTICATION TRACING REQUESTS:**

**When user asks to "trace authentication", "trace back to interactive MFA", or similar:**

**→ YOU MUST FOLLOW THE COMPLETE WORKFLOW IN:**  
**[APPENDIX: Advanced Authentication Analysis](#appendix-advanced-authentication-analysis)**

**DO NOT improvise or use general security knowledge.**

**The documented workflow includes:**
1. **Step 1:** Get SessionId from suspicious IP(s)
2. **Step 2:** Trace complete authentication chain by SessionId
3. **Step 3:** Find interactive MFA (if not in Step 2 results)
4. **Step 4:** Extract ALL unique IPs from Steps 1-3
5. **Step 5:** Analyze IP enrichment data (`ip_enrichment` array in investigation JSON) for ALL discovered IPs
6. **Step 6:** Document risk assessment using enrichment context + quoted instruction criteria

**CRITICAL:** Follow steps in order - extract IPs FIRST (Step 4), THEN analyze enrichment (Step 5).

**Skipping these steps will result in incomplete or incorrect analysis.**

---

## Available Investigation Types

**All investigations use the MCP workflow described in Quick Start section.**

### Standard Investigation (7 days)
**When to use:** General security reviews, routine investigations

**Example prompts:**
- "Investigate user@contoso.com for the last 7 days"
- "Run security investigation for user@domain.com from 2025-11-14 to 2025-11-21"

### Quick Investigation (1 day)
**When to use:** Urgent cases, recent suspicious activity

**Example prompts:**
- "Quick investigate suspicious.user@domain.com"
- "Run quick security check on admin@company.com"

### Comprehensive Investigation (30 days)
**When to use:** Deep-dive analysis, compliance reviews, thorough forensics

**Example prompts:**
- "Full investigation for compromised.user@domain.com"
- "Do a deep dive investigation on external.user@partner.com"

**All types include:** Anomaly detection, sign-in analysis, IP enrichment, Graph identity data, device compliance, audit logs, Office 365 activity, security alerts, threat intelligence, risk assessment, and automated recommendations.

## Quick Start (TL;DR)

When a user requests a security investigation:

1. **Get User ID:**
   ```
   mcp_microsoft_mcp_microsoft_graph_suggest_queries("get user by email")
   mcp_microsoft_mcp_microsoft_graph_get("/v1.0/users/<UPN>?$select=id")
   ```

2. **Run Parallel Queries:**
   - Batch 1: 10 Sentinel queries (anomalies, IP extraction, sign-ins, IP counts, audit logs, incidents, etc.)
   - Batch 2: 6 Graph queries (profile, MFA, devices, Identity Protection)
   - Batch 3: Threat intel enrichment (after extracting IPs from batch 1)

3. **Export to JSON:**
   ```
   create_file("temp/investigation_<upn_prefix>_<timestamp>.json", json_content)
   ```

4. **Generate Report:**
   
   ```powershell
   $env:PYTHONPATH = "<WORKSPACE_ROOT>"
   .venv\Scripts\python.exe generate_report_from_json.py temp/investigation_<upn_prefix>_<timestamp>.json
   ```

5. **Track time after each major step** and report to user

---

## 🔄 CRITICAL: Follow-Up Analysis Workflow (MANDATORY)

**⚠️ BEFORE answering ANY follow-up question, you MUST:**
1. ✅ Check if investigation JSON exists for that user/date range
2. ✅ **Search copilot-instructions.md for relevant guidance** (use grep_search with topic keyword)
3. ✅ **Query Sentinel/Graph if you need addtional data** ONLY query Sentinel/Graph if enriched data AND instructions are insufficient
4. ✅ Search `ip_enrichment` json for relevant IP's if needed before coming to conclusions (contains VPN, ISP, abuse scores, threat intel)


**Common follow-up patterns that REQUIRE using enriched JSON:**
- "Trace authentication for [IP/location]" → Read `ip_enrichment` array + `signin_ip_counts`
- "Is that a VPN?" → Read `ip_enrichment` array, find IP, check `is_vpn` field
- "What's the risk level?" → Read `ip_enrichment` array, check `risk_level` + `abuse_confidence_score`
- "Tell me about [IP address]" → Read `ip_enrichment` array, filter by `ip` field (e.g., `"ip": "203.0.113.42"`)
- "Show me authentication details" → Read `ip_enrichment` array, check `last_auth_result_detail` field
- "Was that IP flagged by threat intel?" → Read `ip_enrichment` array, check `threat_description` field (non-empty = match)

**DO NOT re-query threat intel or sign-in data if it's already in the JSON file!**

**How to read IP enrichment data:**
1. Locate investigation JSON: `temp/investigation_<upn_prefix>_<timestamp>.json`
2. Read file and parse JSON structure
3. Navigate to `ip_enrichment` array (near end of file, after `risk_detections`/`risky_signins`)
4. Find IP entry: `ip_enrichment` is an array of objects - filter by `"ip": "<target_ip>"`
5. Extract relevant fields: `is_vpn`, `abuse_confidence_score`, `threat_description`, `last_auth_result_detail`, etc.

**How to find the investigation JSON:**
- Pattern: `temp/investigation_<upn_prefix>_<timestamp>.json`
- Most recent file for user is usually the one to analyze
- Use `file_search` or `list_dir` to locate existing investigations

---

## How Copilot Should Use This

When a user requests a security investigation (e.g., "Investigate user@domain.com for the last 7 days"), Copilot should:

### Follow-Up Question Handling

**When users ask clarifying questions** (e.g., "What's that password reset about?"):
1. Reference Sample KQL Queries section FIRST
2. Use documented examples (avoid syntax errors)
3. Only write custom queries if no sample exists

**When users ask about EXISTING investigation data** (e.g., "Trace that Hong Kong authentication"):
1. **Check for investigation JSON file FIRST** (temp/investigation_*.json)
2. **Read `ip_enrichment` array** for VPN/ISP/abuse/threat data
3. **Read relevant data sections** (signin_ip_counts, anomalies, etc.)
4. **Only query Sentinel/Graph if data is missing from JSON**

### Sign-In Failure Investigation Pattern

**For error codes 53000, 50074, etc.:**
1. Query ALL sign-in attempts (±15-30 min window)
2. Query CA policy changes (SAME time window)
3. Compare timestamps: Did failures happen BEFORE or AFTER changes?
4. **Critical:** Don't assume policy caused failures - user may have changed policy IN RESPONSE to being blocked
5. Look for patterns: Multiple failures → policy change = user troubleshooting
6. Verify propagation time: Success AFTER policy change (~5-10 min)

### Token Management

**⚠️ NEVER show full script content in chat responses!**
- Investigation data contains thousands of lines
- WILL hit token limits if echoed
- Use `create_file` tool directly
- Show only 1-line summary to user

**🚨 MANDATORY: Time Tracking for ALL Investigations 🚨**
**YOU MUST TRACK AND REPORT TIME AFTER EVERY MAJOR STEP - NO EXCEPTIONS**

**Required Reporting Pattern:**
1. **After User ID retrieval:** Report `[MM:SS] ✓ User ID retrieved (XX seconds)`
2. **After parallel data collection:** Report `[MM:SS] ✓ All data collected in parallel (XX seconds)`
3. **After JSON file creation:** Report `[MM:SS] ✓ Investigation data exported to JSON (XX seconds)`
4. **After report generation:** Report `[MM:SS] ✓ Report generated (XX seconds)`
5. **At completion:** Provide comprehensive timeline breakdown with total elapsed time

**How to Calculate Times:**
- Parse timestamps from tool output headers: `"Date: Sun, 23 Nov 2025 21:30:31 GMT"`
- Compare timestamps between consecutive tool invocations
- Use ACTUAL durations, NOT estimates
- Report in format: `[MM:SS] ✓ Step description (XX seconds)`

**Example (FOLLOW THIS PATTERN EXACTLY):**
```
[00:03] ✓ User ID retrieved (3 seconds)
[01:11] ✓ All data collected in parallel (68 seconds)
[01:12] ✓ Investigation data exported to JSON (72 seconds)
[05:08] ✓ Report generated (308 seconds)

Total elapsed time: 5 minutes 8 seconds (308 seconds)
```

**CRITICAL NOTES:**
- Report generation takes 3-5 minutes due to IP enrichment API calls (this is normal)
- DO NOT skip time reporting - it provides essential performance visibility
- If you fail to report times, you are not following instructions

### Required Field Specifications

**User Profile Query:**
```
/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,mail,userType,jobTitle,department,officeLocation,accountEnabled,onPremisesSecurityIdentifier
```
- All fields REQUIRED for report generation
- Default null values: `department="Unknown"`, `officeLocation="Unknown"`
- `onPremisesSecurityIdentifier` returns Windows SID (format: `S-1-5-21-...`) - REQUIRED for on-premises incident matching

**Device Query:**
```
/v1.0/users/<USER_ID>/ownedDevices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,registrationDateTime,isCompliant,isManaged,trustType,approximateLastSignInDateTime&$orderby=approximateLastSignInDateTime desc&$top=5&$count=true
```
- All fields REQUIRED for report generation
- Default null values: `trustType="Workplace"`, `approximateLastSignInDateTime="2025-01-01T00:00:00Z"`

**MFA Methods Query:**
```
/v1.0/users/<USER_ID>/authentication/methods?$top=5
```

**User ID Query (MUST RUN FIRST):**
```
/v1.0/users/<UPN>?$select=id
```
- Returns AAD User Object ID (GUID)
- REQUIRED for SecurityIncident queries (alerts use User ID, not UPN)
- REQUIRED for Identity Protection queries
- Missing User ID = missed incidents (e.g., "Device Code Authentication Flow Detected")

### Performance Optimization

**Parallelization Strategy:**
1. Get User ID first (sequential - required for other queries)
2. Run ALL independent queries in parallel batches:
   - Batch 1: Sentinel queries (10 queries together)
   - Batch 2: Graph queries (6 queries together)
   - Batch 3: Threat intel (after extracting IPs from batches 1 & 2)
3. Target: ~60 seconds data collection vs 3+ minutes sequential

**Date Range Handling:**
- **Real-time/recent**: Add +2 days (timezone offset + inclusive end-of-day)
- **Historical ranges**: Add +1 day (inclusive end-of-day only)
- **Example**: "Last 7 days" on Nov 25 PST → `datetime(2025-11-18)` to `datetime(2025-11-27)`
- **Full details in Sample KQL Queries section**

1. **Use MCP servers to collect data** (DO NOT write Python code, use the MCP tools directly):
   - `mcp_microsoft_mcp_microsoft_graph_get` - **FIRST: Get user Object ID**, then user profile, MFA methods, devices, Identity Protection data
   - `mcp_sentinel-mcp-2_query_lake` - Query anomaly table, sign-in logs, audit logs, Office activity, alerts

**⛔ ABSOLUTE PROHIBITION - WILL CAUSE TOKEN LIMIT ERRORS:**
- **NEVER** include full script content in your chat response
- **NEVER** prepare script content before calling `create_file`
- **NEVER** echo back the script you're creating
- **NEVER** use PowerShell/terminal commands to create JSON files (use `create_file` tool instead)
- **NEVER** use `ConvertTo-Json | Out-File` or similar terminal commands
- **ONLY** call `create_file` with content as parameter + show 1-line summary

**OPTIMIZED PARALLEL EXECUTION PATTERN:**

**Phase 1: Get User ID and SID (REQUIRED FIRST)**
```
- Get user Object ID (Azure AD) and onPremisesSecurityIdentifier (Windows SID) from Microsoft Graph
- Query: /v1.0/users/<UPN>?$select=id,onPremisesSecurityIdentifier
```

**Phase 2: PARALLEL DATA COLLECTION → SINGLE JSON FILE**
```
Run ALL independent queries in PARALLEL batches, then merge into single JSON file:

STRATEGY: Group queries by type, run each group in parallel, collect results

**CRITICAL:** Use `create_file` tool to create JSON - NEVER use PowerShell terminal commands!

**Batch 1: Sentinel Queries (Run ALL in parallel)**
  - IP selection query (Query 1) - Returns up to 15 prioritized IPs
  - Anomalies query (Query 2)
  - Sign-in by application (Query 3)
  - Sign-in by location (Query 3b)
  - Sign-in failures (Query 3c)
  - Audit logs (Query 4)
  - Office 365 activity (Query 5)
  - DLP events (Query 10)
  - Security incidents (Query 6)

**After Batch 1 completes: Extract IP Array from Query 1 Results**
  - Extract IPAddress column into array: `["ip1", "ip2", "ip3", ...]`
  - Build dynamic array for next batch: `let target_ips = dynamic(["ip1", "ip2", "ip3", ...]);`

**Batch 2: IP Enrichment + Graph Queries (Run ALL in parallel)**
  - Threat Intel query (Query 11) - Uses IPs from Query 1
  - IP frequency query (Query 3d) - Uses IPs from Query 1
  - User profile (Graph)
  - MFA methods (Graph)
  - Registered devices (Graph)
  - User risk profile (Graph)
  - Risk detections (Graph)
  - Risky sign-ins (Graph)

**IP Selection Strategy (Query 1 - Deterministic KQL with Risky IPs):**
  - **Priority 1**: Anomaly IPs (from Signinlogs_Anomalies_KQL_CL where AnomalyType endswith "IP") - **8 slots**
  - **Priority 2**: Risky IPs (from AADUserRiskEvents - Identity Protection flagged IPs) - **4 slots**
  - **Priority 3**: Frequent IPs (top sign-in count for baseline context) - **3 slots**
  - **Deduplication**: Anomaly IPs exclude from risky; Anomaly+Risky exclude from frequent (no duplicates)
  - **Result**: Up to 15 unique IPs (8 anomaly + 4 risky-only + 3 frequent-only)

**After all batches complete:**
Create single JSON file: temp/investigation_{upn_prefix}_{timestamp}.json
Merge all results into one dict structure:
{
  "upn": "user@domain.com",
  "investigation_date": "2025-11-23",
  "start_date": "2025-11-15",
  "end_date": "2025-11-24",
  "timestamp": "20251123_164532",
  "anomalies": [...],
  "signin_apps": [...],
  "signin_locations": [...],
  "signin_failures": [...],
  "signin_ip_counts": [...],     // NEW: Per-IP sign-in counts (only for top 10 enriched IPs)
  "audit_events": [...],
  "office_events": [...],
  "incidents": [...],
  "user_profile": {...},
  "mfa_methods": {...},
  "devices": [...],
  "risk_profile": {...},
  "risk_detections": [...],
  "risky_signins": [...],
  "threat_intel_ips": [...]  // Threat intelligence for top 10 IPs
}

**File Pattern:**
  temp/investigation_<upn_prefix>_<timestamp>.json (ONE FILE - created after parallel collection)

**WHY PARALLEL + SINGLE FILE:**
- Drastically faster data collection (60 seconds vs 3+ minutes)
- All queries are independent - no dependencies between them
- Single JSON file still easy to manage and debug
- MCP server can handle parallel requests efficiently
- Still avoids token limits (no data in script)
```

**Phase 3: Run Report Generation Script**
```
The report generator handles:
  - Single JSON file loading
  - Dataclass transformation logic
  - IP enrichment (prioritized: anomaly IPs first, then frequent sign-in IPs, cap at 10)
  - Dynamic risk assessment (NO hardcoded text - all metrics calculated from data)
  - KQL query template population
  - Result counts calculation
  - HTML report generation with modern, streamlined design
```

**Pattern: Parallel Collection → Single JSON Creation**
```python
# CONCEPTUAL PATTERN (shows tool usage flow, not literal code to execute):

import json
from datetime import datetime

timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
upn_prefix = 'user'  # Extract from UPN (e.g., 'user' from 'user@domain.com')
json_file = f"temp/investigation_{upn_prefix}_{timestamp}.json"

# Phase 2a: Run Sentinel queries in PARALLEL (call all MCP tools together)
# (All Sentinel queries including Query 1 for IP extraction invoked simultaneously)

# Phase 2b: Run Graph queries in PARALLEL (call all MCP tools together)
# (All 6 Graph queries invoked simultaneously)

# After Phase 2a completes: Extract IP array from Query 1 results
ip_extraction_result = [result from Query 1]  # Already executed in Phase 2a
ip_list = [row['IPAddress'] for row in ip_extraction_result]  # Extract IPAddress column
ip_array = json.dumps(ip_list)  # Build JSON array for dynamic() in KQL

# Phase 2c: Run IP enrichment queries in PARALLEL (using Query 1 IP list)
threat_intel_result = mcp_sentinel_query_lake(query_11_with_target_ips)  # Query 11 pattern
ip_frequency_result = mcp_sentinel_query_lake(query_3d_with_target_ips)  # Query 3d pattern

# Phase 2d: After ALL queries complete, merge results into single JSON
investigation_data = {
    "upn": "user@domain.com",
    "investigation_date": datetime.now().strftime('%Y-%m-%d'),
    "start_date": "2025-11-15",
    "end_date": "2025-11-24",
    "timestamp": timestamp,
    "anomalies": anomalies_result,           # From parallel batch 1
    "signin_apps": signin_apps_result,        # From parallel batch 1
    "signin_locations": signin_loc_result,    # From parallel batch 1
    "signin_failures": signin_failures_result,# From parallel batch 1
    "signin_ip_counts": signin_ip_counts_result, # From parallel batch 1
    "ca_status": ca_status_result,            # From parallel batch 1
    "audit_events": audit_result,             # From parallel batch 1
    "office_events": office_result,           # From parallel batch 1
    "incidents": incidents_result,            # From parallel batch 1
    "user_profile": user_profile_result,      # From parallel batch 2
    "mfa_methods": mfa_result,                # From parallel batch 2
    "devices": devices_result,                # From parallel batch 2
    "risk_profile": risk_profile_result,      # From parallel batch 2
    "risk_detections": risk_detections_result,# From parallel batch 2
    "risky_signins": risky_signins_result,    # From parallel batch 2
    "threat_intel_ips": threat_intel_result   # From batch 3 (threat intel enrichment)
}

# CRITICAL: Use create_file TOOL to write JSON (NOT PowerShell/terminal commands!)
# This prevents token bloat from echoing JSON in chat
create_file(json_file, json.dumps(investigation_data, indent=2))
```

3. **Run the reusable report generation script**

   ```powershell
   # Set PYTHONPATH to workspace directory, then run script
   $env:PYTHONPATH = "<WORKSPACE_ROOT>"
   cd "<WORKSPACE_ROOT>"
   .\.venv\Scripts\python.exe generate_report_from_json.py temp/investigation_<upn_prefix>_<timestamp>.json
   ```

4. **Return the absolute path** to the generated HTML file

### CRITICAL: Use the Reusable Script Workflow
The `run_investigation.py` functions are NOT yet connected to MCP servers. Instead:
1. Use MCP tools to collect data in parallel batches
2. Export all results to a single JSON file in temp/
3. Run `generate_report_from_json.py` with the JSON file path
4. The script handles IP enrichment, risk assessment, and HTML generation

This is the proven working approach - DO NOT create new scripts per investigation.

## JSON Export Structure

Export MCP query results to a single JSON file with these required keys:

```json
{
  "upn": "user@domain.com",
  "user_id": "<USER_OBJECT_ID>",  // REQUIRED: AAD Object ID from Graph
  "user_sid": "<WINDOWS_SID>",  // REQUIRED: Windows SID from Graph (onPremisesSecurityIdentifier)
  "investigation_date": "2025-11-23",
  "start_date": "2025-11-15",
  "end_date": "2025-11-24",
  "timestamp": "20251123_164532",
  "anomalies": [...],              // Raw results from Signinlogs_Anomalies_KQL_CL
  "signin_apps": [...],            // Top 5 apps from sign-in query
  "signin_locations": [...],       // Sign-ins by location
  "signin_failures": [...],        // Sign-in failures breakdown
  "signin_ip_counts": [...],       // Per-IP sign-in counts (Query 3d) - REQUIRED for accurate frequency and auth pattern detection
  "audit_events": [...],           // AuditLogs aggregated results
  "office_events": [...],          // OfficeActivity results
  "dlp_events": [...],             // DLP events from CloudAppEvents (limit 10)
  "incidents": [...],              // SecurityIncident+Alert join (may have duplicates)
  "user_profile": {                // Microsoft Graph user object - REQUIRED FIELDS:
    "id": "...",
    "displayName": "...",
    "userPrincipalName": "...",
    "mail": "...",
    "userType": "...",
    "jobTitle": "...",
    "department": "...",           // REQUIRED - use "Unknown" if not available
    "officeLocation": "...",       // REQUIRED - use "Unknown" if not available
    "accountEnabled": true
  },
  "mfa_methods": {...},            // Graph authentication methods
  "devices": [                     // Graph owned devices - REQUIRED FIELDS:
    {
      "id": "...",
      "deviceId": "...",
      "displayName": "...",
      "operatingSystem": "...",
      "operatingSystemVersion": "...",
      "registrationDateTime": "...",
      "isCompliant": true,
      "isManaged": true,
      "trustType": "AzureAd",      // REQUIRED - "AzureAd" or "Workplace"
      "approximateLastSignInDateTime": "2025-11-23T00:00:00Z"  // REQUIRED
    }
  ],
  "risk_profile": {...},           // Graph riskyUsers object
  "risk_detections": [...],        // Graph riskDetections array
  "risky_signins": [...]           // Graph risky signIns array
}
```

**The `generate_report_from_json.py` script handles:**
- Dataclass transformation
- IP enrichment via ipinfo.io
- Incident deduplication
- Dynamic risk assessment
- KQL query template population
- Result counts calculation
- HTML report generation

## Integration with MCP Servers

The investigation system integrates with these MCP servers (which Copilot has access to):

### Microsoft Sentinel MCP
- **mcp_sentinel-mcp-2_query_lake**: Execute KQL queries
- **mcp_sentinel-mcp-2_search_tables**: Discover table schemas
- **mcp_sentinel-mcp-2_list_sentinel_workspaces**: List available workspaces

### Microsoft Graph MCP
- **mcp_microsoft_mcp_microsoft_graph_suggest_queries**: Find Graph API endpoints
- **mcp_microsoft_mcp_microsoft_graph_get**: Execute Graph API calls
- **mcp_microsoft_mcp_microsoft_graph_list_properties**: Explore entity schemas

## Configuration

Configuration is stored in `config.json`:
```json
{
  "sentinel_workspace_id": "<YOUR_WORKSPACE_ID>",
  "tenant_id": "your-tenant-id-here",
  "ipinfo_token": null,
  "output_dir": "reports"
}
```

## Investigation Process Flow

### What Copilot Does (Data Collection via MCP Tools)

**Phase 1: Get User Object ID (REQUIRED FIRST)**
- Query Microsoft Graph: `/v1.0/users/<UPN>?$select=id`
- Extract user Object ID (needed for SecurityIncident and Identity Protection queries)

**Phase 2a: Batch 1 - Sentinel Queries (Run ALL in parallel)**
1. **Anomalies** - Query `Signinlogs_Anomalies_KQL_CL` (Query 2)
2. **Sign-in by application** - Top 5 apps (Query 3)
3. **Sign-in by location** - Top 5 locations (Query 3b)
4. **Sign-in failures** - Detailed breakdown (Query 3c)
5. **Audit logs** - Aggregated by category (Query 4)
6. **Office 365 activity** - Email, Teams, SharePoint (Query 5)
7. **DLP events** - CloudAppEvents with sensitive data violations (Query 10)
8. **Security incidents** - SecurityIncident + Alert join (Query 6)

**Phase 2b: Batch 2 - Microsoft Graph Queries (Run ALL in parallel)**
1. **User profile** - Full profile with department/location
2. **MFA methods** - Authentication methods
3. **Registered devices** - Top 5 devices with compliance status
4. **User risk profile** - Identity Protection risk state
5. **Risk detections** - Top 5 risk events
6. **Risky sign-ins** - Top 5 risky authentications

**Phase 2c: IP Extraction (AFTER Batch 1 completes)**
- Run IP selection query (Query 1) to get prioritized IP list (up to 15 IPs)
- Extract IPAddress column into array: `["ip1", "ip2", "ip3", ...]`
- Build dynamic array: `let target_ips = dynamic([...]);`

**Phase 2d: Batch 3 - IP Enrichment (Run in parallel using Query 1 IP list)**
1. **Threat Intel** - ThreatIntelIndicators query with all IPs (Query 11)
2. **IP Frequency** - Targeted sign-in counts by IP (Query 3d)

**Phase 3: Export to JSON**
- Merge all MCP query results into single JSON file
- Use `create_file` tool (NOT PowerShell commands)
- Save to `temp/investigation_<upn>_<timestamp>.json`

### What Report Generator Does (Automated - DO NOT Implement)

The `generate_report_from_json.py` script automatically handles:

- **IP Enrichment** - Calls ipinfo.io API for geolocation, ASN, org details
- **Risk Assessment** - Calculates risk score from collected data
- **Recommendations** - Generates prioritized action items
- **HTML Report** - Creates professional browser-ready report

**You only need to:** Collect data → Export JSON → Run report script

## Sample KQL Queries (Proven Working)

Use these exact patterns with `mcp_sentinel-mcp-2_query_lake`. Replace `<UPN>`, `<StartDate>`, `<EndDate>`.

**⚠️ CRITICAL: START WITH THESE EXACT QUERY PATTERNS**
**These queries have been tested and validated. Use them as your PRIMARY reference.**

**⚠️ When extending queries with additional fields:**
- **First try the documented query as-is** to verify it works
- If you need additional fields, use `| take 1` first to inspect the raw schema
- **Common pitfall:** `LocationDetails`, `ModifiedProperties`, `DeviceDetail` are dynamic JSON - parse with `tostring()` or `parse_json()`
- If you get SemanticError on a field, it doesn't exist - remove it or find the correct field name

---

### 📅 Date Range Quick Reference

**⚠️ CRITICAL: AUTHORITATIVE DATE HANDLING RULES - ALL QUERIES MUST FOLLOW THIS ⚠️**

**🔴 STEP 0: GET CURRENT DATE FIRST (MANDATORY) 🔴**
- **ALWAYS check the current date from the context header BEFORE calculating date ranges**
- **NEVER use hardcoded years** - the year changes and you WILL query the wrong timeframe
- **Example Context:** "The current date is November 27, 2025" → Use 2025 in all datetime() calls
- **Common Error:** Using 2024 dates when it's 2025 → queries data from 1 year ago (empty results!)

**Timezone Context:**
- All KQL queries use **PST/PDT timezone** (UTC-8/UTC-7) - Sentinel workspace local time
- Sentinel stores timestamps in **UTC**, but user is in **PST (UTC-8)**
- KQL `datetime()` function interprets dates as local workspace time (PST)
- **DO NOT manually convert to UTC** - KQL handles timezone conversion automatically

**Why Date Ranges Are Tricky:**
- `datetime(2025-11-23)` means **Nov 23 at 00:00:00 (midnight)** - only the first second!
- `between (start .. end)` is **INCLUSIVE** but without adding days, you miss ~24 hours of data
- Evening PST time (8 PM Nov 25 PST) = early morning UTC (4 AM Nov 26 UTC)
- Data timestamped "tomorrow" in UTC is actually "today" in PST evening hours

**RULE 1: Real-Time/Recent Searches (Current Activity)**
- **Add +2 days to current date for end range**
- **Why +2?** +1 for timezone offset (PST behind UTC) + +1 for inclusive end-of-day
- **Pattern**: Today is Nov 25 (PST) → Use `datetime(2025-11-27)` as end date
- **Applies to**: "recent activity", "current", "last X days", any relative time reference

**RULE 2: Historical Searches (User-Specified Dates)**
- **Add +1 day to user's specified end date**
- **Why +1?** To include all 24 hours of the final day
- **Pattern**: User says "Nov 21 to Nov 23" → Use `datetime(2025-11-21)` to `datetime(2025-11-24)`
- **Applies to**: Any explicit date range like "from X to Y" or "between X and Y"

**Examples Table (Assuming Current Date = November 27, 2025):**

| User Request | `<StartDate>` | `<EndDate>` | Rule Applied | Explanation |
|--------------|---------------|-------------|--------------|-------------|
| "Last 7 days" | `2025-11-20` | `2025-11-29` | Rule 1 (+2) | Nov 27 - 7 days = Nov 20; Nov 27 + 2 = Nov 29 |
| "Last 30 days" | `2025-10-28` | `2025-11-29` | Rule 1 (+2) | Nov 27 - 30 days = Oct 28; Nov 27 + 2 = Nov 29 |
| "Recent activity" | `2025-11-20` | `2025-11-29` | Rule 1 (+2) | Default to last 7 days for "recent" |
| "Current sign-ins" | `2025-11-20` | `2025-11-29` | Rule 1 (+2) | Captures all activity through right now |
| "Last 2 days" | `2025-11-25` | `2025-11-29` | Rule 1 (+2) | Nov 27 - 2 days = Nov 25; Nov 27 + 2 = Nov 29 |
| "Nov 21 to Nov 23" | `2025-11-21` | `2025-11-24` | Rule 2 (+1) | Historical range - includes all 24 hours of Nov 23 |
| "From Nov 15 to Nov 20" | `2025-11-15` | `2025-11-21` | Rule 2 (+1) | Historical range - includes all 24 hours of Nov 20 |

**⚠️ CRITICAL REMINDER:** Always use the CURRENT YEAR from context! If today is November 27, 2025, use `datetime(2025-XX-XX)`, NOT `datetime(2024-XX-XX)`!

**Common Mistakes to Avoid:**
- ❌ Using `datetime(2025-11-25)` for "last 7 days" on Nov 25 → Misses evening data
- ❌ Using `datetime(2025-11-23)` for "through Nov 23" → Only captures midnight (first second)
- ❌ Manually converting to UTC → KQL already does this, you'll double-convert
- ✅ Always use Rule 1 (+2) for relative/recent time queries
- ✅ Always use Rule 2 (+1) for explicit historical date ranges

---

**🚨 CRITICAL - SIGN-IN QUERIES REQUIREMENT 🚨**
**You MUST run ALL THREE sign-in queries (3, 3b, 3c) to populate the `signin_events` dict!**
- **Query 3**: Sign-ins by application (TOP 5 RESULTS)
- **Query 3b**: Sign-ins by location
- **Query 3c**: Sign-in failures (detailed breakdown) ← **REQUIRED for "Sign-in Failures" section**

**If you skip query 3c, that section will be BLANK in the HTML report!**

### 1. Extract Top Priority IPs (Deterministic IP Selection with Risky IPs)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let upn = '<UPN>';

// Priority 1: Anomaly IPs (top 8 by anomaly count)
let anomaly_ips = 
    Signinlogs_Anomalies_KQL_CL
    | where DetectedDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where AnomalyType endswith "IP"
    | summarize AnomalyCount = count(), FirstSeen = min(DetectedDateTime) by IPAddress = Value
    | order by AnomalyCount desc, FirstSeen asc
    | take 8
    | extend Priority = 1, Source = "Anomaly";

// Priority 2: Risky IPs from Identity Protection (top 10 for selection pool)
let risky_ips_pool = 
    AADUserRiskEvents
    | where ActivityDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where isnotempty(IpAddress)
    | summarize RiskCount = count(), FirstSeen = min(ActivityDateTime) by IPAddress = IpAddress
    | order by RiskCount desc, FirstSeen asc
    | take 10
    | extend Priority = 2, Source = "RiskyIP";

// Priority 3: Frequent Sign-in IPs (top 10 for selection pool)
let frequent_ips_pool =
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ upn
    | summarize SignInCount = count(), FirstSeen = min(TimeGenerated) by IPAddress
    | order by SignInCount desc, FirstSeen asc
    | take 10
    | extend Priority = 3, Source = "Frequent";

// Get anomaly IP list for exclusion from risky slot
let anomaly_ip_list = anomaly_ips | project IPAddress;

// Get anomaly + risky IP list for exclusion from frequent slot
let priority_ip_list = 
    union anomaly_ips, risky_ips_pool
    | project IPAddress;

// Reserve slots with deduplication: 8 anomaly + 4 risky + 3 frequent
let anomaly_slot = anomaly_ips | extend Count = AnomalyCount;
let risky_slot = risky_ips_pool 
    | join kind=anti anomaly_ip_list on IPAddress  // Exclude IPs already in anomaly list
    | order by RiskCount desc, FirstSeen asc
    | take 4
    | extend Count = RiskCount;
let frequent_slot = frequent_ips_pool 
    | join kind=anti priority_ip_list on IPAddress  // Exclude IPs already in anomaly/risky lists
    | order by SignInCount desc, FirstSeen asc
    | take 3
    | extend Count = SignInCount;

union anomaly_slot, risky_slot, frequent_slot
| project IPAddress, Priority, Count, Source
| order by Priority asc, Count desc
| project IPAddress
```
**CRITICAL: Run this query AFTER Batch 1 (needs anomaly data) but BEFORE Batch 3 (threat intel) and Batch 4 (IP counts)**

**Usage Pattern**:
1. Execute query and extract IPAddress column as array: `["ip1", "ip2", "ip3", ...]`
2. Build dynamic array: `let target_ips = dynamic(["ip1", "ip2", "ip3", ...]);`
3. Pass `target_ips` to Query 11 (threat intel) and Query 3d (signin counts)

**Slot Allocation Strategy (15 IPs max)**:
- **8 slots**: Anomaly IPs (highest priority - triggered detection rules)
- **4 slots**: Risky IPs from Identity Protection (excluding those already in anomaly slots)
- **3 slots**: Frequent IPs (baseline context - excluding anomaly/risky IPs)

**Why This Works**:
- ✅ **Deterministic** (same inputs → same outputs) - Uses `order by` + `take` instead of `top` to ensure stable sorting
- ✅ Multi-source prioritization (anomaly > risky > frequent)
- ✅ No duplicates (automatic deduplication via anti-join)
- ✅ Fast execution (~5 seconds)
- ✅ Balanced coverage (security findings + user baseline)
- ✅ Identity Protection integration (anonymizedIPAddress, unfamiliarFeatures, unlikelyTravel, etc.)
- ✅ **Stable tie-breaking** - `FirstSeen` timestamp ensures consistent ordering when counts are equal

**NOTE:** This replaces the manual Python-like IP extraction in the workflow pseudocode. Use this query result to build the `target_ips` array for subsequent queries.

### 2. Anomalies (Signinlogs_Anomalies_KQL_CL)
```kql
Signinlogs_Anomalies_KQL_CL
| where DetectedDateTime between (datetime(<StartDate>) .. datetime(<EndDate>))
| where UserPrincipalName =~ '<UPN>'
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10, "Medium",
    (CountryNovelty or CityNovelty or StateNovelty), "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| extend SeverityOrder = case(Severity == 'High', 1, Severity == 'Medium', 2, Severity == 'Low', 3, 4)
| project
    DetectedDateTime,
    UserPrincipalName,
    AnomalyType,
    Value,
    Severity,
    SeverityOrder,
    Country,
    City,
    State,
    CountryNovelty,
    CityNovelty,
    StateNovelty,
    ArtifactHits,
    FirstSeenRecent,
    BaselineSize,
    OS,
    BrowserFamily,
    RawBrowser
| order by SeverityOrder asc, DetectedDateTime desc
| take 10
```
**NOTE:** Results are sorted by severity (High → Medium → Low → Informational) then by date (newest first), limited to top 10. This matches the threat intelligence IP limit to ensure all anomalous IPs are captured (both Interactive and NonInteractive types for each unique IP).
### 3. Interactive & Non-Interactive Sign-ins (Summary by Application)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| summarize 
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    IPAddresses=make_set(IPAddress),
    UniqueLocations=dcount(Location)
    by AppDisplayName
| order by SignInCount desc
| take 5
```

### 3b. Sign-ins Summary by Location
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where isnotempty(Location)
| summarize 
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    IPAddresses=make_set(IPAddress),
    Applications=make_set(AppDisplayName, 5)
    by Location
| order by SignInCount desc
| take 5
```

### 3c. Sign-in Failures (Detailed)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where ResultType != '0'
| summarize 
    FailureCount=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Applications=make_set(AppDisplayName, 3),
    Locations=make_set(Location, 3)
    by ResultType, ResultDescription
| order by FailureCount desc
| take 5
```

### 3d. Sign-in Counts by IP Address
```kql
let target_ips = dynamic(["<IP_1>", "<IP_2>", "<IP_3>", ...]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
// Get the most recent sign-in per IP with full event context
let most_recent_signins = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where IPAddress in (target_ips)
| summarize arg_max(TimeGenerated, *) by IPAddress;
// Expand authentication details for the most recent sign-in per IP
most_recent_signins
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend HasAuthDetails = array_length(AuthDetails) > 0
| extend AuthDetailsToExpand = iif(HasAuthDetails, AuthDetails, dynamic([{"authenticationStepResultDetail": ""}]))
| mv-expand AuthDetailsToExpand
| extend AuthStepResultDetail = tostring(AuthDetailsToExpand.authenticationStepResultDetail)
| extend AuthPriority = case(
    AuthStepResultDetail has "MFA requirement satisfied", 1,
    AuthStepResultDetail has "Correct password", 2,
    AuthStepResultDetail has "Passkey", 2,
    AuthStepResultDetail has "Phone sign-in", 2,
    AuthStepResultDetail has "SMS verification", 2,
    AuthStepResultDetail has "First factor requirement satisfied", 3,
    AuthStepResultDetail has "MFA required", 4,
    999)
| summarize 
    MostRecentTime = any(TimeGenerated),
    MostRecentResultType = any(ResultType),
    HasAuthDetails = any(HasAuthDetails),
    MinPriority = min(AuthPriority),
    AllAuthDetails = make_set(AuthStepResultDetail)
    by IPAddress
| extend LastAuthResultDetail = case(
    MostRecentResultType != "0", "Authentication failed",  // Failure takes priority over auth details
    not(HasAuthDetails) and MostRecentResultType == "0", "Token",  // Non-interactive token-based auth
    MinPriority == 1 and AllAuthDetails has "MFA requirement satisfied", "MFA requirement satisfied by claim in the token",  // Catches all MFA variants
    MinPriority == 2 and AllAuthDetails has "Correct password", "Correct password",
    MinPriority == 2 and AllAuthDetails has "Passkey (device-bound)", "Passkey (device-bound)",
    MinPriority == 3 and AllAuthDetails has "First factor requirement satisfied by claim in the token", "First factor requirement satisfied by claim in the token",
    MinPriority == 4 and AllAuthDetails has "MFA required in Azure AD", "MFA required in Azure AD",
    tostring(AllAuthDetails[0]))
// Join back to get aggregate sign-in counts across all time
| join kind=inner (
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ '<UPN>'
    | where IPAddress in (target_ips)
    | summarize 
        SignInCount = count(),
        SuccessCount = countif(ResultType == '0'),
        FailureCount = countif(ResultType != '0'),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by IPAddress
) on IPAddress
| project IPAddress, SignInCount, SuccessCount, FailureCount, FirstSeen, LastSeen, LastAuthResultDetail
| order by SignInCount desc
```
**NOTE:** Uses IPs from Query 1 (deterministic IP selection). Includes `LastAuthResultDetail` showing the **most recent** authentication result detail for each IP. This approach prioritizes temporal relevance over historical capability, making it easier to identify expired sessions, failed recent authentications, and current session status.

**WHY MOST RECENT AUTH MATTERS:**
- **Security investigation value:** Shows current session state (active vs expired/failed)
- **Threat detection:** Highlights token expiration, VPN disconnections, and recent failures
- **Example:** IP with 100 successful sign-ins but most recent = "MFA required (failed)" → session expired (needs investigation)
- **Contrast:** Priority-based approach would show "MFA satisfied" (misleading - hides the recent failure)

**CRITICAL KQL BUG FIX:** This query uses `arg_max(TimeGenerated, *)` to capture the complete most recent event BEFORE `mv-expand`, avoiding the `arg_max().ResultType` accessor bug. After `mv-expand`, accessing `arg_max()` tuple properties returns null or incorrect types. This pattern is required whenever you need to preserve event context through `mv-expand` operations.

### 4. Azure AD Audit Log Activity (Aggregated Summary)
```kql
AuditLogs
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'
| summarize 
    Count=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Operations=make_set(OperationName, 10)
    by Category, Result
| order by Count desc
| take 10
```

**IMPORTANT:** Audit logs contain very verbose data (large `TargetResources` and `ModifiedProperties` fields). Always aggregate/summarize to reduce data volume. For detailed investigation, query specific operations separately.

**IMPORTANT:** Always include Office 365 activity in the `office_events` field of InvestigationResult. This shows email, Teams, and SharePoint usage patterns.
### 5. Office 365 (Email / Teams / SharePoint) Activity Distribution
```kql
OfficeActivity
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where UserId =~ '<UPN>'
| summarize ActivityCount = count() by RecordType, Operation
| order by ActivityCount desc
| take 5
```

### 6. Security Incidents with Alerts Correlated to User
```kql
let targetUPN = "<UPN>";
let targetUserId = "<USER_OBJECT_ID>";  // REQUIRED: Get from Microsoft Graph API (/v1.0/users/<UPN>?$select=id)
let targetSid = "<WINDOWS_SID>";  // REQUIRED: Get from Microsoft Graph API (/v1.0/users/<UPN>?$select=onPremisesSecurityIdentifier)
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has targetUPN or Entities has targetUserId or Entities has targetSid
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)  // Filter on CreatedTime for incidents created in range
| summarize arg_max(TimeGenerated, *) by IncidentNumber  // Get most recent update for each incident
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
    AlertCount = count()
    by ProviderIncidentId
| order by LastModifiedTime desc
| take 10
```

**CRITICAL REQUIREMENT:** 
- **ALWAYS retrieve the AAD User Object ID AND Windows SID from Microsoft Graph BEFORE running this query**
- Query: `/v1.0/users/<UPN>?$select=id,onPremisesSecurityIdentifier` returns both identifiers
- **ALL THREE identifiers are REQUIRED** (`targetUPN`, `targetUserId`, `targetSid`) - different alert types use different entity formats:
  - Cloud alerts: Use Azure AD UPN or Object ID (e.g., "Device Code Authentication Flow Detected")
  - On-premises alerts: Use Windows SID only (e.g., "Rare RDP Connections", "RDP Nesting")
- Without all three identifiers, you will miss critical incidents!

**IMPORTANT:** 
- This query joins SecurityIncident with SecurityAlert to provide full incident context
- **Deduplication**: The final `summarize` statement collapses multiple alerts per incident into a single row (groups by ProviderIncidentId)
- **AlertNames**: Array of all alert names associated with the incident
- **AlertCount**: Number of alerts in the incident (useful for multi-alert incidents)
- **Filter on `CreatedTime`** to find incidents created in the investigation period
- **Use `arg_max(TimeGenerated, *) by IncidentNumber`** to get the most recent update for each incident (includes status changes, comments, etc.) before the final grouping
- **ALWAYS use `arg_max(TimeGenerated, *) by SystemAlertId`** to deduplicate alerts before joining
- The join provides incident-level metadata: ProviderIncidentId, Title, Severity, Status, Classification, OwnerUPN, ProviderIncidentUrl
- `ProviderIncidentId` is the unique identifier from the security provider (e.g., Microsoft Defender incident ID like "2273")
- **Returns up to 10 unique incidents** (grouped by ProviderIncidentId to ensure one row per external incident ID)

### 7. Recent High-Risk Sign-in Failures (Optional Focus)
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ '<UPN>'
| where ResultType !in ('0','50140')  // exclude success + expected auth required
| project TimeGenerated, ResultType, ResultDescription, IPAddress, Location, AppDisplayName, ConditionalAccessStatus
| order by TimeGenerated desc
```

### 8. Conditional Access Policy Changes by User

**⚠️ CRITICAL: Always query ALL CA policy changes in chronological order to see the complete sequence**

```kql
let target_time = datetime(<TARGET_TIMESTAMP>);  // e.g., time of sign-in failure
let start = target_time - 2d;  // ±2 days for context
let end = target_time + 2d;
AuditLogs
| where TimeGenerated between (start .. end)
| where OperationName has_any ("Conditional Access", "policy")
| where Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'
| extend InitiatorUPN = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| extend InitiatorIPAddress = tostring(parse_json(InitiatedBy).user.ipAddress)
| extend TargetName = tostring(parse_json(TargetResources)[0].displayName)
| extend TargetId = tostring(parse_json(TargetResources)[0].id)
| project TimeGenerated, OperationName, Result, InitiatorUPN, InitiatorIPAddress, 
    TargetName, TargetId, Category, CorrelationId
| order by TimeGenerated asc  // CRITICAL: Chronological order to see sequence
| take 20
```

**To get detailed policy state changes (after identifying the specific change):**
```kql
AuditLogs
| where CorrelationId == "<CORRELATION_ID_FROM_ABOVE>"
| extend ModifiedProperties = parse_json(TargetResources)[0].modifiedProperties
| mv-expand ModifiedProperties
| extend PropertyName = tostring(ModifiedProperties.displayName)
| extend OldValue = tostring(ModifiedProperties.oldValue)
| extend NewValue = tostring(ModifiedProperties.newValue)
| project TimeGenerated, PropertyName, OldValue, NewValue
```

**Parse the JSON to extract policy state:**
- Look for `"state":"enabled"` vs `"state":"disabled"` vs `"state":"enabledForReportingButNotEnforced"`
- **enabled** = Policy actively blocking non-compliant access
- **disabled** = Policy not enforcing (security control bypassed)
- **enabledForReportingButNotEnforced** = Report-only mode (logs violations but doesn't block)

### 9. IP Geolocation Aggregation (If Location Field Available)
```kql
SigninLogs
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where UserPrincipalName =~ '<UPN>' and isnotempty(Location)
| summarize SignInCount=count() by Location
| order by SignInCount desc
```

### 10. DLP Events (Data Loss Prevention)

**Purpose**: Detect sensitive data exfiltration attempts (file copies to removable media, cloud uploads, network shares)

**Query Pattern**:
```kql
let upn = '<UPN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
CloudAppEvents
| where TimeGenerated between (start .. end)
| where ActionType in ("FileCopiedToRemovableMedia", "FileUploadedToCloud", "FileCopiedToNetworkShare")
| extend DlpAudit = parse_json(RawEventData)["DlpAuditEventMetadata"]
| extend File = parse_json(RawEventData)["ObjectId"]
| extend UserId = parse_json(RawEventData)["UserId"]
| extend DeviceName = parse_json(RawEventData)["DeviceName"]
| extend ClientIP = parse_json(RawEventData)["ClientIP"]
| extend RuleName = parse_json(RawEventData)["PolicyMatchInfo"]["RuleName"]
| extend Operation = parse_json(RawEventData)["Operation"]
| extend TargetDomain = parse_json(RawEventData)["TargetDomain"]
| extend TargetFilePath = parse_json(RawEventData)["TargetFilePath"]
| where isnotnull(DlpAudit)
| where UserId == upn
| summarize by TimeGenerated, tostring(UserId), tostring(DeviceName), tostring(ClientIP), tostring(RuleName), tostring(File), tostring(Operation), tostring(TargetDomain), tostring(TargetFilePath)
| order by TimeGenerated desc
| take 5
```

**Expected Result Structure**:
```json
{
  "dlp_events": [
    {
      "TimeGenerated": "2025-11-20T15:58:26Z",
      "UserId": "user@example.com",
      "DeviceName": "workstation-01",
      "ClientIP": "198.51.100.42",
      "RuleName": "All Sensitive Information",
      "File": "Sensitive.docx",
      "Operation": "FileCopiedToNetworkShare",
      "TargetDomain": "",
      "TargetFilePath": "\\\\192.0.2.10\\Share\\Sensitive.docx"
    }
  ]
}
```

**Performance Notes**:
- CloudAppEvents is an external data source (Microsoft Defender for Cloud Apps)
- Time filters are applied client-side after downloading ~132 MB of data
- Query execution time: ~4-5 seconds (acceptable for current dataset)
- DLP events are HIGH SEVERITY - always flag in critical actions if detected

### 11. Threat Intelligence IP Enrichment (Bulk IP Query)

**Purpose**: Check if IPs from anomalies, sign-ins, or audit logs match known threat intelligence indicators

**Query Pattern** (single query for multiple IPs):
```kql
let target_ips = dynamic(["198.51.100.10", "203.0.113.25", "192.0.2.50"]);  // List of IPs to check (cap at 10)
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
| summarize arg_max(TimeGenerated, *) by NetworkSourceIP  // Deduplicate - get most recent indicator per IP
| project 
    TimeGenerated,
    IPAddress = NetworkSourceIP,
    ThreatDescription = Description,
    ActivityGroupNames,
    Confidence,
    ValidUntil,
    TrafficLightProtocolLevel,
    Pattern,
    IsActive
| order by Confidence desc, TimeGenerated desc
```

**Workflow Integration**:
1. After Batch 1 completes, run Query 1 (deterministic IP selection) to get up to 15 prioritized IPs
2. Extract IPAddress column from Query 1 results into array: `["ip1", "ip2", "ip3", ...]`
3. Build dynamic array for KQL: `let target_ips = dynamic(["ip1", "ip2", "ip3", ...]);`
4. Run threat intel query (Query 11) with `target_ips` array (Batch 3)
5. Run IP frequency query (Query 3d) with same `target_ips` array (Batch 3)
6. Store results in `threat_intel_ips` and `signin_ip_counts` arrays in JSON export
7. Report generator will merge this data with IP geolocation enrichment
8. **CRITICAL**: Include `LastAuthResultDetail` from Query 3d (Sign-in Counts by IP Address) in `signin_ip_counts` JSON field
   - This field shows authentication pattern per IP (interactive vs token reuse)
   - Examples: "MFA requirement satisfied by claim in the token", "Correct password", "MFA required in Azure AD"
   - Report generators use this to assess IP legitimacy and prioritize investigation

**Expected Result Structure** (EXAMPLE ONLY - DO NOT USE SAMPLE VALUES IN RESPONSES):
```json
{
  "threat_intel_ips": [
    {
      "IPAddress": "203.0.113.42",
      "ThreatDescription": "[SAMPLE] Malicious activity detected - do not reference this sample data",
      "ActivityGroupNames": "[SAMPLE]",
      "Confidence": 100,
      "ValidUntil": "2025-12-31T00:00:00Z",
      "TrafficLightProtocolLevel": "Amber",
      "IsActive": true
    }
  ]
}
```
**NOTE**: This is example JSON structure only. Always use actual query results, never sample/example data from documentation.

**Performance Notes**:
- Threat intel table contains ~26,000 indicators
- Single query for multiple IPs is MUCH faster than per-IP queries (~28 seconds for batch vs ~28 seconds each)
- Use `dynamic()` array for IP list: `dynamic(["ip1", "ip2", "ip3"])`
- Prioritize risk detection IPs first, then anomaly IPs, then top 3 locations + top 2 apps (most important)
- Cap at 10 IPs total to keep query response manageable and focus on highest-priority IPs
- Use `arg_max()` to deduplicate if an IP has multiple threat intel entries

### Usage Guidance
- **Timezone**: All queries use PST/PDT timezone (Sentinel workspace local time). Use `datetime(YYYY-MM-DD)` format without manual UTC conversion.
- **Result Limit**: All queries standardized to `| take 5` for optimized token consumption (50% reduction from previous take 10).
- Always bind date range first to reduce scan cost.
- Use `=~` for case-insensitive equality on UPN.
- Prefer explicit projection to reduce payload size.
- **For IP enrichment**: Combine ipinfo.io geolocation + Sentinel threat intel (Batch 3) for complete context.
- If a table is missing, first discover: `mcp_sentinel-mcp-2_search_tables` with natural language intent.

---

## Microsoft Graph Identity Protection Queries

**CRITICAL: Always query Identity Protection data in Phase 2 (Batch 2) of investigation workflow**

Identity Protection provides crucial context for anomaly investigation by revealing:
- **User Risk Profile**: Overall user risk state and level from Microsoft's ML models
- **Risk Detections**: Specific risk events (unlikely travel, unfamiliar features, anonymous IP, etc.)
- **Risky Sign-ins**: Authentication attempts flagged as risky by Identity Protection

### Workflow Pattern

**Step 1: Get User Object ID and Windows SID** (required for all Identity Protection and Security Incident queries)
```
mcp_microsoft_mcp_microsoft_graph_suggest_queries("get user by email")
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,onPremisesSecurityIdentifier")
```
Extract `user_id` (Azure AD Object ID) and `onPremisesSecurityIdentifier` (Windows SID) from response for subsequent queries.

**Step 2: Get User Risk Profile**
```
mcp_microsoft_mcp_microsoft_graph_suggest_queries("get risky users by user id")
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/identityProtection/riskyUsers/<USER_ID>")
```
Returns: riskLevel (low/medium/high/none), riskState (atRisk/confirmedCompromised/dismissed/remediated), riskDetail, riskLastUpdatedDateTime

**Step 3: Get Risk Detections**
```
mcp_microsoft_mcp_microsoft_graph_suggest_queries("get risk detections for user")
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/identityProtection/riskDetections?$filter=userId eq '<USER_ID>'&$select=id,detectedDateTime,riskEventType,riskLevel,riskState,riskDetail,ipAddress,location,activity,activityDateTime&$orderby=detectedDateTime desc&$top=5")
```
Returns: Array of risk events (top 5 most recent) with riskEventType (unlikelyTravel, unfamiliarFeatures, anonymizedIPAddress, maliciousIPAddress, etc.), riskState, riskLevel, detectedDateTime, activity, ipAddress, location

**Step 4: Get Risky Sign-ins**
```
mcp_microsoft_mcp_microsoft_graph_suggest_queries("get risky sign-ins for user")
mcp_microsoft_mcp_microsoft_graph_get("/beta/auditLogs/signIns?$filter=userPrincipalName eq '<UPN>' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&$select=id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,location,riskState,riskLevelDuringSignIn,riskEventTypes_v2,riskDetail,status&$orderby=createdDateTime desc&$top=5")
```
**NOTE**: Risky sign-ins are ONLY available in `/beta` endpoint, not `/v1.0`

Returns: Array of sign-in events (top 5 most recent) with riskLevelDuringSignIn, riskEventTypes_v2, riskState, riskDetail, status (errorCode, failureReason)

### Identity Protection Risk Event Types

Common `riskEventType` values you'll encounter:
- **unlikelyTravel**: User traveled impossible distance between sign-ins
- **unfamiliarFeatures**: Sign-in from unfamiliar location/device/IP
- **anonymizedIPAddress**: Sign-in from Tor, VPN, or proxy
- **maliciousIPAddress**: Sign-in from known malicious IP
- **malwareInfectedIPAddress**: Sign-in from IP with malware activity
- **suspiciousIPAddress**: Sign-in from suspicious IP patterns
- **leakedCredentials**: User credentials found in leak databases
- **investigationsThreatIntelligence**: Microsoft threat intel flagged activity

### Risk State Transitions

Understanding `riskState` values:
- **atRisk**: Active risk detection requiring investigation
- **confirmedCompromised**: Admin or automation confirmed account compromise
- **dismissed**: Admin reviewed and dismissed as false positive
- **remediated**: Risk automatically remediated (e.g., password reset, MFA completed)

### Integration with Anomaly Analysis

**CRITICAL PATTERN**: Cross-reference Identity Protection with Sentinel anomalies

```python
# Example: Tokyo IP appears in BOTH sources
# From Sentinel Anomalies: NewNonInteractiveIP 198.51.100.10 (Tokyo, JP)
# From Risk Detections: unlikelyTravel from 198.51.100.10 (Tokyo, JP)

# This confirms the anomaly is NOT a false positive - Microsoft's ML also flagged it
# Check risk_state to see if investigation occurred:
# - "dismissed" = Admin reviewed and cleared
# - "atRisk" = Still requires investigation
# - "remediated" = Automatically resolved
```

---

## APPENDIX: Advanced Authentication Analysis

### Deep-Dive: Distinguishing Interactive MFA vs Token Reuse

**⚠️ MANDATORY WORKFLOW - READ THIS FIRST ⚠️**

**🚨 CRITICAL CHECKPOINT: Before providing ANY risk assessment for authentication anomalies:**

1. **STOP** - Do not improvise or use general security knowledge
2. **READ** the complete risk assessment framework in this section
3. **QUOTE** specific instruction sections in your analysis
4. **VERIFY** your conclusions match documented guidance before responding to user

Before executing ANY authentication tracing queries, you MUST:

1. **Read the SessionId-based workflow** (Steps 1-4 below) in full
2. **Search** the investigation JSON for IP enrichment data (`ip_enrichment` array) - **PRIMARY DATA SOURCE**
3. **Follow the documented steps** in order (SessionId → Authentication chain → Interactive MFA → Risk assessment)
4. **Use IP enrichment context** in your final risk assessment (VPN status, abuse scores, threat intel, auth patterns)

**Skipping these steps will result in incomplete or incorrect analysis.**

---

### IP Enrichment Data Structure (PRIMARY EVIDENCE SOURCE)

**CRITICAL: The investigation JSON contains a comprehensive `ip_enrichment` array with authoritative detection flags.**

**Always reference this data FIRST before making VPN/proxy/Tor determinations.**

**Example IP Enrichment Entry (Actual JSON Structure):**
```json
{
  "ip": "203.0.113.42",           // ← KEY: Use "ip" field, not "ip_address"
  "city": "Singapore",
  "region": "Singapore",
  "country": "SG",
  "org": "AS12345 Example Hosting Ltd",
  "asn": "AS12345",
  "timezone": "Asia/Singapore",
  "risk_level": "HIGH",           // ← Overall risk assessment (LOW/MEDIUM/HIGH)
  "assessment": "⚠️ Threat Intelligence Match: Commercial VPN Service Detected",
  "is_vpn": true,                 // ← PRIMARY VPN DETECTION FLAG (ipinfo.io detection)
  "is_proxy": false,              // ← PRIMARY PROXY DETECTION FLAG
  "is_tor": false,                // ← PRIMARY TOR DETECTION FLAG
  "abuse_confidence_score": 0,    // ← AbuseIPDB score 0-100 (0=clean, 75+=high risk)
  "total_reports": 2,             // ← Number of abuse reports in AbuseIPDB
  "is_whitelisted": false,
  "threat_description": "Commercial VPN Service: Known Anonymization Infrastructure",  // ← Threat intel match details
  "anomaly_type": "NewInteractiveIP",  // ← Anomaly that triggered IP selection
  "first_seen": "2025-10-16",     // ← First sign-in from this IP (date string)
  "last_seen": "2025-10-16",      // ← Last sign-in from this IP (date string)
  "hit_count": 5,                  // ← Number of anomaly detections
  "signin_count": 8,               // ← Total sign-ins from this IP
  "success_count": 7,              // ← Successful authentications
  "failure_count": 1,              // ← Failed authentications
  "last_auth_result_detail": "MFA requirement satisfied by claim in the token",  // ← Auth pattern
  "threat_detected": false,        // ← Legacy field (use threat_description instead)
  "threat_confidence": 0,          // ← Legacy field
  "threat_tlp_level": "",          // ← Traffic Light Protocol level (if threat intel match)
  "threat_activity_groups": ""     // ← APT/threat actor attribution (if available)
}
```

**CRITICAL: Always use `ip_enrichment[].ip` to match IPs, NOT `ip_address`!**

**Key Fields for Analysis:**

| Field | Purpose | Usage Example |
|-------|---------|---------------|
| **is_vpn** | Definitive VPN detection | `is_vpn: true` → Confirmed VPN endpoint (don't infer, use this flag) |
| **is_proxy** | Definitive proxy detection | `is_proxy: true` → Confirmed proxy (anonymized traffic) |
| **is_tor** | Definitive Tor detection | `is_tor: true` → Confirmed Tor exit node (high anonymity risk) |
| **abuse_confidence_score** | AbuseIPDB reputation (0-100) | `>= 75` = High risk, `>= 25` = Medium risk, `0` = Clean |
| **threat_detected** | Threat intel match flag | `true` → IP matches ThreatIntelIndicators table |
| **threat_description** | Threat intel details | "Surfshark VPN", "Malicious activity detected", etc. |
| **org / asn** | Network ownership | AS9009 = M247 Europe (VPN infrastructure provider) |
| **signin_count** | Total sign-ins from IP | High count (>100) = established pattern vs transient |
| **last_auth_result_detail** | Authentication method | "MFA satisfied by token" vs "Correct password" = interactive vs token reuse |
| **first_seen / last_seen** | Temporal pattern | Single day = transient, multi-day = established behavior |

**Analysis Priority Hierarchy:**
1. **IP enrichment flags** (`is_vpn`, `is_proxy`, `is_tor`) - Most authoritative source
2. **Abuse reputation** (`abuse_confidence_score`, `total_reports`) - Community-validated risk data
3. **Threat intelligence** (`threat_detected`, `threat_description`) - IOC matches from Sentinel
4. **Network ownership** (`org`, `asn`, `company_type`) - Infrastructure context (hosting, ISP, etc.)
5. **Authentication patterns** (`last_auth_result_detail`, `signin_count`) - Behavioral context
6. **Identity Protection** (risk detections) - Microsoft ML-based risk signals

**NEVER say "likely VPN" or "probably proxy" if enrichment data has explicit boolean flags!**

---

When investigating anomalous sign-ins (e.g., from new countries, IPs, or devices), it's critical to determine whether the user **actively performed MFA** at that location or if the authentication used a **refresh token from a prior session**.

**Key Forensic Indicators:**

1. **RequestSequence Field**: 
   - `RequestSequence: 1` or higher → **Interactive authentication** (user was challenged)
   - `RequestSequence: 0` → **Token-based authentication** (no user interaction)

2. **AuthenticationDetails Array Structure**:
   - **Interactive Pattern**: Array contains authentication method (e.g., "Passkey (device-bound)") with `RequestSequence > 0`, followed by "Previously satisfied" entry
   - **Token Reuse Pattern**: Array contains ONLY "Previously satisfied" entries with "MFA requirement satisfied by claim in the token"

3. **authenticationStepDateTime Correlation**:
   - If `authenticationStepDateTime` references a time when NO interactive auth occurred, it indicates token reuse
   - Cross-reference timestamps with events that have `RequestSequence > 0` to trace token origin

### Forensic Workflow: Tracing Authentication Chains

**Scenario:** Anomalous sign-ins detected from new IP/location. Determine if user performed fresh MFA or reused token.

**CRITICAL: START WITH SessionId - This is Your Primary and Most Efficient Investigation Pattern:**

1. **Query suspicious IP(s) to get SessionId** (single query for all suspicious IPs)
2. **Query SessionId for interactive MFA** - Expand date range progressively:
   - **First attempt:** Investigation window (same as anomaly detection query)
   - **If no results:** Expand to 7 days before suspicious activity
   - **If still no results:** Expand to 90 days before suspicious activity
   - Tokens can be valid for up to 90 days depending on tenant policy

**AVOID chronological searching without SessionId** - it requires multiple queries and is less efficient.

---

#### Step 1: Get SessionId from Suspicious Authentication (ALWAYS START HERE)

**This single query gives you SessionId AND enough context to determine next steps:**

```kql
let suspicious_ips = dynamic(["<IP_1>", "<IP_2>"]);  // All suspicious IPs
let start = datetime(<INVESTIGATION_START_DATE>);
let end = datetime(<INVESTIGATION_END_DATE>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where IPAddress in (suspicious_ips)
| project TimeGenerated, IPAddress, Location, AppDisplayName, 
    SessionId = tostring(SessionId),
    UserAgent,
    ResultType,
    CorrelationId
| order by TimeGenerated asc
| take 20
```

**What This Returns:**
- **SessionId(s)** for suspicious authentications (your primary key for Step 2)
- Device fingerprint (UserAgent) to check for device consistency
- Application context
- Initial timeline

**Critical Decision Point:**
- **All suspicious IPs share same SessionId?** → Session continuity detected → Investigate further (could be legitimate user OR stolen token)
- **Different SessionIds across IPs?** → Different authentication flows → Investigate device and authentication patterns
- **IMPORTANT**: SessionId alone does NOT determine legitimacy - must correlate with UserAgent, geography, and behavior patterns

---

#### Step 2: Trace Complete Authentication Chain by SessionId (DEFINITIVE PROOF)

**Once you have SessionId from Step 1, query ALL authentications in that session:**

```kql
let target_session_id = "<SESSION_ID_FROM_STEP_1>";
let start = datetime(<INVESTIGATION_START_DATE>);
let end = datetime(<INVESTIGATION_END_DATE>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where SessionId == target_session_id
| extend AuthDetails = parse_json(AuthenticationDetails)
| mv-expand AuthDetails
| extend AuthMethod = tostring(AuthDetails.authenticationMethod)
| extend AuthStepDateTime = todatetime(AuthDetails.authenticationStepDateTime)
| extend RequestSeq = toint(AuthDetails.RequestSequence)
| project TimeGenerated, IPAddress, Location, AppDisplayName, 
    AuthMethod, AuthStepDateTime, RequestSeq,
    UserAgent, ResultType, SessionId
| order by TimeGenerated asc
```

**This Single Query Reveals:**
- **Complete geographic progression** (all IPs/locations in chronological order)
- **Where interactive MFA occurred** (RequestSeq > 0, AuthMethod != "Previously satisfied")
- **Token reuse pattern** (all subsequent authentications with "Previously satisfied")
- **Device consistency** (UserAgent should match across all sessions)
- **Time gaps** between locations (assess physical possibility of travel)

**Critical Evidence - What SessionId Indicates:**
- SessionId is a browser session identifier that tracks authentication flows
- **Same SessionId across IPs** = Session continuity (could be legitimate user OR stolen token replay)
- **SessionId does NOT prove device identity** - stolen refresh tokens maintain session continuity
- **Same SessionId + Same UserAgent + Geographic impossibility** = Possible token theft
- **Token theft attacks maintain the original SessionId** - attacker inherits session from stolen token
- **CRITICAL**: Same SessionId does NOT rule out credential/token theft

**Analysis Pattern:**
1. Look at FIRST authentication in session (earliest TimeGenerated)
2. Check if RequestSeq > 0 → User performed interactive MFA at that IP/location
3. All subsequent authentications should show "Previously satisfied" (token reuse)
4. Verify UserAgent consistency (same = likely same device; different = possible token theft)
5. Assess geographic progression (impossible travel = high risk; reasonable = needs user confirmation)

---

#### Step 3: Find Interactive MFA with Progressive Date Range Expansion

**Use this when Step 2 shows all "Previously satisfied" (no interactive MFA in the SessionId)**

**Progressive date range strategy:**
1. Start with investigation window
2. If no results, expand to 7 days
3. If still no results, expand to 90 days

**Query Pattern (adjust date range as needed):**

```kql
let suspicious_event_time = datetime(<FIRST_SUSPICIOUS_SIGNIN_TIME>);
let start = suspicious_event_time - 7d;  // Start with 7 days, then try 90d if no results
let end = suspicious_event_time;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| extend AuthDetails = parse_json(AuthenticationDetails)
| mv-expand AuthDetails
| extend AuthMethod = tostring(AuthDetails.authenticationMethod)
| extend AuthStepDateTime = todatetime(AuthDetails.authenticationStepDateTime)
| extend RequestSeq = toint(AuthDetails.RequestSequence)
| where AuthMethod != "Previously satisfied"
| where RequestSeq > 0
| project TimeGenerated, IPAddress, Location, AppDisplayName, AuthMethod, AuthStepDateTime, 
    RequestSeq, SessionId = tostring(SessionId), CorrelationId, ResultType, UserAgent
| order by TimeGenerated desc
| take 20
```

**Date Range Progression:**
- **Attempt 1:** Investigation window (e.g., last 48 hours, 7 days)
- **Attempt 2:** 7 days before suspicious activity: `suspicious_event_time - 7d`
- **Attempt 3:** 90 days before suspicious activity: `suspicious_event_time - 90d`

**This returns all interactive MFA sessions in the specified period.**
**Check if any SessionId matches the suspicious SessionId from Step 1.**

---

#### Step 4: Collect All IPs from Authentication Chain

**CRITICAL: After completing the SessionId trace, extract ALL unique IP addresses discovered:**

1. **From Interactive MFA session** (Step 3 results)
2. **From Suspicious session** (Step 1 results)
3. **From Complete SessionId chain** (Step 2 results)

**Build comprehensive IP list for enrichment analysis.**

---

#### Step 5: Analyze IP Enrichment Data for ALL Discovered IPs

**MANDATORY: Search investigation JSON `ip_enrichment` array for EVERY IP in the authentication chain:**

For each IP address discovered in Steps 1-3:
1. **Locate IP in `ip_enrichment` array** (search by `"ip": "<IP_ADDRESS>"` field)
2. **Extract key risk indicators:**
   - `is_vpn`, `is_proxy`, `is_tor` (anonymization detection)
   - `abuse_confidence_score`, `total_reports` (reputation)
   - `threat_description`, `threat_detected` (threat intel matches)
   - `org`, `asn` (network ownership - hosting vs ISP)
   - `last_auth_result_detail` (authentication pattern)
   - `signin_count`, `success_count`, `failure_count` (frequency/behavior)
   - `first_seen`, `last_seen` (temporal pattern - transient vs established)

3. **Document findings for EACH IP in the chain:**
   - Geographic location + ISP/VPN status
   - Risk level + threat intelligence status
   - Authentication pattern (interactive vs token reuse)
   - Behavioral context (frequency, success rate, temporal pattern)

**This creates a complete evidence picture showing the full authentication journey with enrichment context.**

---

#### Step 6: Document Risk Assessment

**⚠️ MANDATORY CHECKPOINT - Before writing risk assessment:**
- **SEARCH copilot-instructions.md** for "When to Escalate Authentication Anomalies" section
- **READ the risk classification criteria** (High/Medium/Low)
- **QUOTE the specific criteria** that applies to your case
- **DO NOT improvise** - follow documented classification exactly

Present findings in clear evidence trail:
1. **Interactive Session**: IP, Location, Timestamp, AuthMethod, SessionId
2. **Subsequent Session**: IP, Location, Timestamp, AuthMethod (token-based), SessionId
3. **IP Enrichment Analysis for ALL IPs**: Present enrichment data for EVERY IP discovered in trace (VPN status, abuse scores, threat intel, auth patterns, frequency, temporal context)
4. **Connection Proof**: SessionId match + time gap + geographic distance + comprehensive enrichment context from all IPs
5. **Risk Assessment**: Evaluate based on context (see "When to Escalate" section below) - **MUST quote specific instruction criteria**

**Risk Assessment Framework:**

**CRITICAL - SessionId Interpretation:**
- **SessionId does NOT prove device identity** - token theft maintains session continuity
- **Same SessionId across geographically distant IPs** = Requires investigation (VPN/travel OR stolen token)
- **Different SessionIds** = Different authentication flows (not necessarily more suspicious)
- **Must correlate multiple signals**: SessionId + UserAgent + Geography + Behavior + Time patterns + **IP enrichment data**

**For detailed risk escalation criteria, see "When to Escalate Authentication Anomalies" section below.**

### Real-World Example: Geographic Anomaly Authentication Analysis

**Scenario:** User sign-ins detected from two geographically distant locations within 18 hours.

**Step 1: Interactive MFA Analysis**

**Location A Analysis:**
1. Query 1: Found 2 events with `SMS verification` and `RequestSeq: 1`
2. Result: **User performed fresh interactive SMS authentication at Location A**
3. Evidence: `authenticationStepDateTime: 2025-10-15T14:23:05Z` with `RequestSequence: 1`

**Location B Analysis:**
1. Query 1: Zero results (no non-"Previously satisfied" methods)
2. Result: **Location B authentications used only token reuse - NO interactive MFA**
3. Evidence: All events show `"MFA requirement satisfied by claim in the token"`

**Step 2: SessionId Verification (SMOKING GUN)**

Query to compare sessions across both IPs:
```kql
let suspicious_ips = dynamic(["<IP_ADDRESS_1>", "<IP_ADDRESS_2>"]);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(<START_DATE>) .. datetime(<END_DATE>))
| where UserPrincipalName =~ '<UPN>'
| where IPAddress in (suspicious_ips)
| project TimeGenerated, IPAddress, Location, SessionId, UserAgent
| order by TimeGenerated asc
```

**CRITICAL FINDING:**
- **SessionId: `<SESSION_ID_EXAMPLE>`**
- **ALL Location A authentications**: Same SessionId (over time period 1)
- **ALL Location B authentications**: Same SessionId (over time period 2)
- **Time gap**: Varies (analyze based on context)
- **Geographic distance**: Varies (analyze based on context)

**Initial Appearance:** Potential geographic anomaly requiring investigation
**Further Analysis Required:** Correlate SessionId with UserAgent, behavior patterns, and user confirmation

**Step 3: Evidence Summary and Interpretation**

| Evidence Type | Finding | Observation |
|--------------|---------|-------------|
| Interactive MFA | Location A only | User performed SMS authentication |
| Location B Auth Methods | "Previously satisfied" only | Token reuse (normal OAuth flow) |
| SessionId | Same across both locations | **Session continuity maintained** |
| Time Gap | 18 hours | Within typical refresh token lifetime (24-90 days) |
| User Agent | Same | **Consistent device fingerprint** |
| Applications | Consistent across locations | Consistent workflow pattern |

**Critical Analysis - SessionId Does NOT Prove Legitimacy:**

The **same SessionId** requires careful analysis because:
- SessionId is a browser session identifier that tracks authentication flows
- **Same SessionId = Session continuity** (could be legitimate user OR stolen token)
- **Stolen refresh tokens maintain the original SessionId** - attacker inherits session state
- **Same SessionId does NOT rule out token theft or credential compromise**

**Possible Scenarios Requiring Investigation:**

- **Legitimate VPN Connection** - User switched VPN exit nodes (same device, different apparent location) → **Requires user confirmation**
- **Legitimate User Travel** - User traveled between locations with sufficient time gap (tokens remained valid) → **Requires user confirmation**
- **Stolen Token Replay** - Attacker obtained refresh token (SessionId stays same, may show different UserAgent) → **Cannot be ruled out by SessionId alone**
- **Mobile Carrier Routing** - Carrier routes traffic through regional gateways (device in one location, exits another) → **Check IP enrichment for ISP org**

**Additional Investigation Required:**
- ✅ Check UserAgent consistency across all sessions
- ✅ Verify geographic progression is physically possible  
- ✅ Review applications accessed (any unusual admin tools?)
- ✅ Check for failed authentication attempts before success
- ✅ Look for account modifications or privilege changes
- ✅ **Check IP enrichment data in investigation JSON** - Use `ip_enrichment` array to verify:
  - VPN/proxy/Tor status (`is_vpn`, `is_proxy`, `is_tor`)
  - Abuse reputation (`abuse_confidence_score`, `total_reports`)
  - Threat intelligence matches (`threat_detected`, `threat_description`)
  - Authentication patterns (`last_auth_result_detail`, `signin_count`, `success_count`, `failure_count`)
  - Temporal context (`first_seen`, `last_seen` - transient vs established pattern)
- ✅ **Most important: Confirm with user directly**

**Recommendation:** 
**Use IP enrichment data from investigation JSON to strengthen your analysis, then confirm with user:**

1. "Were you using a VPN on [date] around [time]?" (if `is_vpn: true`)
2. "Did you travel between [Location A] and [Location B] during this timeframe?"
3. "Do you recognize [applications] activity during this timeframe?"
4. "Have you noticed any unusual device or account behavior recently?"

**Only after user confirmation** can you conclude VPN usage or travel is legitimate. **Same SessionId + IP enrichment data together provide strong evidence, but user confirmation is still required.**
### Best Practices for Authentication Tracing

1. **START WITH SessionId** - Query suspicious IPs to get SessionId first (most efficient approach)
2. **Use SessionId to trace complete chain** - Single query shows entire authentication progression
3. **Check IP enrichment data** - Use investigation JSON `ip_enrichment` array for VPN, abuse scores, threat intel
4. **Verify device consistency** - Same SessionId + Same UserAgent + Geographic reasonableness = Likely legitimate
5. **SessionId alone is NOT conclusive** - Must correlate with UserAgent, geography, behavior, and user confirmation
6. **Check first authentication in session** - RequestSeq > 0 shows where user performed interactive MFA
7. **Assess geographic progression** - Evaluate if travel is physically possible or if VPN is likely
8. **Widen time ranges if needed** - Tokens can be valid for 24-90 days depending on policy
9. **Always confirm with user** - Geographic anomalies require user verification regardless of SessionId

### Common Authentication Methods and RequestSequence Patterns

| Authentication Method | RequestSeq > 0 Meaning | RequestSeq = 0 Meaning |
|----------------------|------------------------|------------------------|
| Passkey (device-bound) | User physically approved with biometric/PIN | Passkey used in prior session, token reused |
| Phone sign-in | User approved notification on phone | Phone approval in prior session, token reused |
| SMS verification | User entered SMS code | SMS verification in prior session, token reused |
| Microsoft Authenticator app | User approved push notification | Authenticator used in prior session, token reused |
| Previously satisfied | N/A - never has RequestSeq > 0 | Always indicates token/claim reuse |

### When to Escalate Authentication Anomalies

**CRITICAL: Always check IP enrichment data before making risk determination!**

**High Risk (Escalate Immediately):**
- Token reuse from geographically impossible locations (regardless of SessionId)
- Token reuse after user reports device loss/theft
- Concurrent sessions from multiple countries simultaneously
- Token reuse from IPs matching ThreatIntelIndicators OR `threat_detected: true` in IP enrichment
- Unusual application access (admin portals, sensitive resources not in user's normal pattern)
- Failed authentication attempts followed by successful token reuse
- Account modifications or privilege escalations during suspicious sessions
- **Geographic anomaly + Same SessionId + Different UserAgent** = Likely token theft
- **Impossible travel time between authentications** (regardless of SessionId)
- **IP enrichment shows**: `abuse_confidence_score >= 75`, `is_tor: true`, or malicious `threat_description`

**Medium Risk (Investigate Further - Confirm with User):**
- **Same SessionId + Geographically distant locations** = Could be VPN/travel OR token theft - VERIFY with IP enrichment
- Token reuse from unexpected country without prior user notification
- Token reuse spanning >30 days (excessive token lifetime - increases theft window)
- Pattern of token-only authentications without any interactive MFA in 30+ days
- Sign-ins during unusual hours for user's timezone
- Access to sensitive data repositories during suspicious sessions
- **Same SessionId + Same UserAgent + Unusual geographic pattern** = Needs user confirmation
- **IP enrichment shows**: `abuse_confidence_score >= 25`, `is_vpn: true` without user confirmation, or `total_reports > 0`

**Low Risk / Likely Legitimate (Monitor Only):**
- Token reuse from nearby IPs in same city (mobile carrier IP rotation)
- Token reuse following confirmed interactive MFA from expected location
- Token reuse from known corporate VPN IP ranges
- Applications and access patterns consistent with user's role
- **User confirms VPN usage or travel** when questioned
- No unusual data access or configuration changes
- **Consistent UserAgent + Reasonable geographic progression + User confirmation**
- **IP enrichment shows**: `abuse_confidence_score: 0`, residential ISP org (TELUS, Comcast, etc.), `is_vpn: false`, high `signin_count` with consistent success rate

## APPENDIX: Conditional Access Policy Investigation Workflow

### Critical Investigation Rules

When investigating sign-in failures (error codes 53000, 50074) with CA policy correlation:

**⚠️ MANDATORY STEPS - DO NOT SKIP:**

1. **Query ALL CA policy changes in chronological order** (±2 days from failure time)
2. **Parse policy state transitions** from the JSON (enabled → disabled → report-only)
3. **Compare failure timeline with policy change timeline**
4. **Verify logical consistency**: Ask "does this make sense?"

### Common Error Codes

| Error Code | Description | Typical Cause |
|------------|-------------|---------------|
| **53000** | Device not compliant | Device not enrolled in Intune or failing compliance checks |
| **50074** | Strong authentication required | MFA not satisfied |
| **50074** | User must enroll in MFA | MFA not configured for user |
| **530032** | Blocked by CA policy | Generic CA policy block |
| **65001** | User consent required | Application consent needed |

### CA Policy State Meanings

| State | What It Means | Security Impact |
|-------|---------------|----------------|
| **enabled** | Policy actively enforcing | Blocks non-compliant access (intended behavior) |
| **disabled** | Policy not enforcing | **Security control bypassed** - all access allowed |
| **enabledForReportingButNotEnforced** | Report-only mode | Logs violations but **doesn't block** - defeats purpose |

### Investigation Workflow Pattern

**Step 1: Identify Sign-In Failures**
```kql
// Get failures with CA context
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where UserPrincipalName =~ '<UPN>'
| where ResultType != '0'
| where AppDisplayName has '<APPLICATION>'  // e.g., "Visual Studio Code"
| project TimeGenerated, IPAddress, Location, ResultType, ResultDescription, 
    ConditionalAccessStatus, UserAgent
| order by TimeGenerated asc
```

**Step 2: Query ALL CA Policy Changes in Timeframe**
```kql
let failure_time = datetime(<FIRST_FAILURE_TIME>);
let start = failure_time - 2d;
let end = failure_time + 2d;
AuditLogs
| where TimeGenerated between (start .. end)
| where OperationName has_any ("Conditional Access", "policy")
| where Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'
| extend InitiatorUPN = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| extend InitiatorIPAddress = tostring(parse_json(InitiatedBy).user.ipAddress)
| extend TargetName = tostring(parse_json(TargetResources)[0].displayName)
| project TimeGenerated, OperationName, Result, InitiatorUPN, InitiatorIPAddress, 
    TargetName, CorrelationId
| order by TimeGenerated asc  // CRITICAL: Chronological order
```

**Step 3: Parse Policy State Changes**
```kql
// For each CorrelationId from Step 2, get detailed changes
AuditLogs
| where CorrelationId == "<CORRELATION_ID>"
| extend ModifiedProperties = parse_json(TargetResources)[0].modifiedProperties
| mv-expand ModifiedProperties
| extend PropertyName = tostring(ModifiedProperties.displayName)
| extend OldValue = tostring(ModifiedProperties.oldValue)
| extend NewValue = tostring(ModifiedProperties.newValue)
| project TimeGenerated, PropertyName, OldValue, NewValue
```

**Step 4: Extract Policy State from JSON**
- Parse `OldValue` and `NewValue` JSON for `"state":"<value>"`
- Build timeline: `enabled` → `disabled` → `enabledForReportingButNotEnforced`

**Step 5: Security Assessment**

Compare timelines and assess intent:

| Pattern | Interpretation | Risk Level |
|---------|----------------|------------|
| **Failures → Policy Disabled** | User bypassed security control to unblock self | **HIGH** - Privilege abuse |
| **Failures → Policy Changed to Report-Only** | User weakened security control | **MEDIUM-HIGH** - Partial bypass |
| **Policy Disabled → Failures Continue** | Cached tokens (5-15 min propagation delay) | **INFO** - Expected behavior |
| **Policy Changed → No More Failures** | Policy change resolved issue | **Context-dependent** - May be legitimate troubleshooting |

### Real-World Example Analysis

**Scenario:** User blocked by device compliance policy, then modifies policy

**Timeline:**
- 19:05 - User blocked (error 53000: device not compliant)
- 19:09 - User changes policy: `enabled` → `disabled`
- 19:09 - User changes policy again: `disabled` → `enabledForReportingButNotEnforced`
- 19:12 - User still blocked (cached token)
- 19:14 - User access succeeds (policy propagated)

**Analysis:**
1. ✅ Policy was correctly blocking non-compliant device
2. 🚨 User disabled security control to bypass block
3. ⚠️ User partially reversed by enabling report-only (shows some awareness)
4. ❌ Report-only mode still defeats the purpose (doesn't block)

**Assessment:**
- **Risk Level:** MEDIUM-HIGH
- **Finding:** Self-service security bypass using privileged role
- **Root Cause:** User's device is non-compliant (not enrolled/failing compliance)
- **Recommendation:** 
  - Investigate why device is non-compliant
  - Implement approval workflow for CA policy changes
  - Alert on policy state changes (enabled → disabled/report-only)
  - Review if user should have permission to modify CA policies

### Critical Mistakes to Avoid

❌ **DON'T:**
- Query only ONE policy change event (you'll miss the sequence)
- Read policy changes in reverse chronological order (confuses cause/effect)
- Assume policy was already disabled without checking the starting state
- Skip verifying "does this make logical sense?" (disabled policies can't block users)

✅ **DO:**
- Query ALL policy changes in the timeframe
- Order chronologically (oldest first) to see the sequence
- Parse the full JSON to extract policy state transitions
- Cross-check: If user was blocked, policy must have been enabled at that time
- Ask: "Why would user disable this policy?" (Usually to bypass a legitimate block)

### Security Recommendations

**When CA Policy Changes Are Detected:**

1. **Determine Legitimacy:**
   - Was the policy change authorized?
   - Was there a valid business reason?
   - Did the user have approval to make this change?

2. **Assess Impact:**
   - How many users affected by policy change?
   - What applications/resources are now unprotected?
   - How long was the policy disabled/weakened?

3. **Remediation Actions:**
   - Restore policy to `enabled` state if change was unauthorized
   - Investigate root cause (why was user blocked?)
   - Fix underlying issue (device compliance, MFA enrollment, etc.)
   - Review who has permission to modify CA policies
   - Implement approval workflows for policy changes
   - Alert on future CA policy modifications

4. **Long-Term Improvements:**
   - Use PIM for Security Administrator role (require approval)
   - Implement CA policy change alerts
   - Require multi-admin approval for policy state changes
   - Document approved procedures for policy troubleshooting

---

## APPENDIX: Ad-Hoc Query Examples

### Ad-Hoc IP Enrichment Utility

For quick IP enrichment during investigation follow-ups, use the `enrich_ips.py` utility:

```powershell
# Enrich specific IPs from anomaly analysis
python enrich_ips.py 203.0.113.42 198.51.100.10 192.0.2.1

# Enrich all unenriched IPs from an investigation file
python enrich_ips.py --file temp/investigation_user_20251130.json
```

**Features:** Enriches IPs using ipinfo.io, vpnapi.io, and AbuseIPDB. Detects VPN, proxy, Tor, hosting, and abuse scores. Exports results to JSON.

**When to use:** Follow-up analysis, spot-checking suspicious IPs, completing partial investigations. **DO NOT use in main investigation workflow** (IP enrichment is already built into report generation).

---

### Best Practices for AuditLogs Queries

**CRITICAL: Use broad, simple filters for OperationName searches**

When searching AuditLogs for specific operations (password resets, role changes, policy modifications, etc.):

**❌ DON'T use overly specific filters:**
```kql
| where OperationName has_any ("password", "reset")  // May miss operations
| where OperationName == "Reset user password"       // Too restrictive - misses variations
```

**✅ DO use broad keyword matching:**
```kql
| where OperationName has "password"  // Catches all password-related operations
| where OperationName has "role"      // Catches all role-related operations
| where OperationName has "policy"    // Catches all policy-related operations
```

**Why this matters:**
- OperationName values vary: "Reset user password", "Change user password", "Self-service password reset", "Update password"
- `has_any()` requires exact word matches and can be unpredictable
- Simple `has "keyword"` is more reliable for exploratory queries
- You can always filter results further in subsequent `summarize` or `where` clauses

**Example - Finding password operations:**
```kql
AuditLogs
| where TimeGenerated between (start .. end)
| where OperationName has "password"  // Broad search
| where tostring(InitiatedBy) has '<UPN>' or tostring(TargetResources) has '<UPN>'
| summarize Count = count() by OperationName  // Then see what operations exist
| order by Count desc
```

**Then refine if needed:**
```kql
// After seeing results, target specific operation if necessary
| where OperationName == "Reset user password"
```

**Field Matching Best Practices:**
- **Always use `tostring()` for dynamic fields:** `tostring(InitiatedBy)`, `tostring(TargetResources)`
- **Use `has` for substring matching:** `tostring(InitiatedBy) has '<UPN>'`
- **Use `=~` for exact case-insensitive match:** `Identity =~ '<UPN>'`
- **Avoid direct field access on complex JSON:** Parse first with `parse_json()` then extract

---

### Enumerating User Permissions and Roles

When asked to check permissions or roles for a user account, **ALWAYS query BOTH**:

1. **Permanent Role Assignments** (active roles)
2. **PIM-Eligible Roles** (roles that can be activated on-demand)

**Step 1: Get User Object ID**
```
/v1.0/users/<UPN>?$select=id
```

**Step 2: Get Permanent Role Assignments**
```
/v1.0/roleManagement/directory/roleAssignments?$select=principalId&$filter=principalId eq '<USER_ID>'&$expand=roleDefinition($select=templateId,displayName,description)
```

**Step 3: Get PIM-Eligible Roles**
```
/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$select=memberType,startDateTime,endDateTime&$filter=principalId eq '<USER_ID>'&$expand=principal($select=id),roleDefinition($select=id,displayName,description)
```

**Step 4: Get Active PIM Role Assignments (time-bounded)**
```
/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$select=assignmentType,memberType,startDateTime,endDateTime&$filter=principalId eq '<USER_ID>' and startDateTime le <CURRENT_DATETIME> and endDateTime ge <CURRENT_DATETIME>&$expand=principal($select=id),roleDefinition($select=id,displayName,description)
```

**Example Output Format:**
```
Total Role Inventory for <USER>:

Permanent Active Roles (X):
1. Global Administrator
2. Security Administrator
...

PIM-Eligible Roles (Y):
1. Exchange Administrator (Eligible since: <date>, Expiration: <date or ∞>)
2. Intune Administrator (Eligible since: <date>, Expiration: <date or ∞>)
...

Active PIM Role Assignments (Z):
1. [Role Name] (Activated: <start>, Expires: <end>, Assignment Type: <type>)
...
```

**Security Analysis Guidance:**
- Flag if high-privilege roles (Global Admin, Security Admin, Application Admin) are **permanently assigned** instead of PIM-eligible
- Recommend converting permanent privileged roles to PIM-eligible with approval workflows
- Note if PIM eligibilities have no expiration (should be reviewed periodically)

---

## Output

The investigation generates:
- **JSON data file**: Raw investigation results
- **HTML report**: Professional, browser-ready report with:
  - Executive summary
  - Key metrics dashboard
  - Anomaly findings
  - IP intelligence cards
  - User profile & MFA status
  - Device inventory
  - Audit log timeline
  - Security alerts table
  - Risk assessment
  - Prioritized recommendations
  - Investigation conclusion

**Report Theme:**
- **Default**: Dark theme with Microsoft brand colors
  - Background: Dark gray gradients (#1a1a1a → #2d2d2d)
  - Primary accent: Microsoft blue (#00a1f1, #0078d4)
  - Highlights: Microsoft orange (#f65314), gold (#ffbb00), green (#7cbb00)
  - High contrast text for accessibility (#e0e0e0 on dark backgrounds)
- **Color Palette**:
  - Orange: #f65314 (critical alerts)
  - Gold: #ffbb00 (high priority)
  - Blue: #00a1f1 (medium/info)
  - Green: #7cbb00 (low/success)
  - Gray: #737373 (neutral elements)

## Example Workflow

User says: **"Investigate user@domain.com for suspicious activity in the last 7 days"**

Copilot should:
1. **Phase 1:** Get user Object ID from Microsoft Graph
2. **Phase 2:** Run all Sentinel and Graph queries in parallel batches
3. **Phase 2c:** Extract IPs and run threat intelligence query
4. **Phase 2d:** Create single JSON file with all results in temp/
5. **Phase 3:** Run `generate_report_from_json.py` script with JSON file path
6. Show the user the report path and provide brief summary

See "OPTIMIZED PARALLEL EXECUTION PATTERN" section above for detailed workflow.

## Error Handling

If the investigation encounters issues:
- Missing configuration: Falls back to defaults
- MCP query failures: Logs warnings, continues with available data
- IP enrichment failures: Returns "Error" status, continues investigation
- Missing user data: Shows "Unknown" in report, continues

The investigation is designed to be resilient and complete successfully even with partial data.

## Troubleshooting Guide

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Missing `department` or `officeLocation` in Graph API response** | Use `"Unknown"` as default value in JSON |
| **No anomalies found in Sentinel query** | Export empty array: `"anomalies": []` |
| **Graph API returns 404 for user** | Verify UPN is correct; check if user exists with different UPN |
| **Sentinel query timeout** | Reduce date range or add `| take 5` to limit results |
| **Missing `trustType` in device query** | Use default: `"trustType": "Workplace"` |
| **Null `approximateLastSignInDateTime`** | Use default: `"approximateLastSignInDateTime": "2025-01-01T00:00:00Z"` |
| **Report generation fails** | Check JSON file has ALL required fields; validate JSON syntax |
| **KQL syntax error** | Use EXACT query patterns from Sample KQL Queries section |
| **SemanticError: Failed to resolve column** | Field doesn't exist in table schema - remove it or check Sample KQL Queries for correct field names |
| **DeviceDetail, LocationDetails, ModifiedProperties errors** | These are dynamic fields - use `| take 1` to see raw structure, then parse with `parse_json()` or remove from query |
| **No results from SecurityIncident query** | Ensure you're using BOTH `targetUPN` and `targetUserId` variables |
| **Risky sign-ins query fails** | Must use `/beta` endpoint, not `/v1.0` |

### Required Field Defaults

If Graph API returns null for these fields, use these defaults:

```json
{
  "department": "Unknown",
  "officeLocation": "Unknown",
  "trustType": "Workplace",
  "approximateLastSignInDateTime": "2025-01-01T00:00:00Z"
}
```

### Empty Result Handling

If a Sentinel query returns no results, include empty arrays:

```json
{
  "anomalies": [],
  "signin_apps": [],
  "signin_locations": [],
  "signin_failures": [],
  "audit_events": [],
  "office_events": [],
  "dlp_events": [],
  "incidents": [],
  "risk_detections": [],
  "risky_signins": [],
  "threat_intel_ips": []
}
```

## Security Notes

- All reports are marked CONFIDENTIAL
- Reports contain sensitive user information
- Store reports securely
- Follow organizational data classification policies
- Investigation actions are logged for audit trail

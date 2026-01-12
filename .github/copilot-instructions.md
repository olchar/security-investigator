# GitHub Copilot - Security Investigation Integration

This workspace contains a security investigation automation system. GitHub Copilot can help you run investigations using natural language.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Available Skills](#available-skills)** - Specialized investigation workflows
3. **[Universal Patterns](#universal-patterns)** - Date ranges, time tracking, token management
4. **[Follow-Up Analysis](#-critical-follow-up-analysis-workflow-mandatory)** - Working with existing data
5. **[Advanced Topics](#appendix-advanced-authentication-analysis)** - Authentication tracing, CA policy analysis
6. **[Ad-Hoc Queries](#appendix-ad-hoc-query-examples)** - Quick reference patterns
7. **[Troubleshooting](#troubleshooting-guide)** - Common issues and solutions

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**🤖 SPECIALIZED SKILLS DETECTION:**

**BEFORE starting any investigation, detect if user request requires a specialized skill:**

| Keywords in Request | Action Required |
|---------------------|-----------------|
| **"investigate user"**, "security investigation", "check user activity", UPN/email with investigation context | Use the **user-investigation** skill at `.github/skills/user-investigation/SKILL.md` |
| **"honeypot"**, "attack analysis", "threat actor" | Use the **honeypot-investigation** skill at `.github/skills/honeypot-investigation/SKILL.md` |
| **Future skills** | Check `.github/skills/` folder with `list_dir` to discover available specialized workflows |

**Detection Pattern:**
1. Parse user request for specialized keywords
2. If match found: Read the appropriate SKILL.md file from `.github/skills/<skill-name>/SKILL.md`
3. Follow skill-specific workflow (inherits universal patterns from this file)

---

## Available Skills

| Skill | Description | Trigger Keywords |
|-------|-------------|------------------|
| **user-investigation** | Azure AD user security analysis: sign-ins, anomalies, MFA, devices, audit logs, incidents, Identity Protection, HTML reports | "investigate user", "security investigation", "check user activity", UPN/email |
| **honeypot-investigation** | Honeypot security analysis: attack patterns, threat intel, vulnerabilities, executive reports | "honeypot", "attack analysis", "threat actor" |

**Skill files location:** `.github/skills/<skill-name>/SKILL.md`

---

## Universal Patterns

**These patterns apply to ALL skills and ad-hoc queries:**

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

---
name: authentication-tracing
description: Use this skill when asked to trace authentication flows, analyze SessionId chains, investigate token reuse vs interactive MFA, or assess geographic anomalies in sign-ins. Triggers on keywords like "trace authentication", "trace back to interactive MFA", "SessionId analysis", "token reuse", "geographic anomaly", "impossible travel", or when investigating suspicious sign-in locations. This skill provides forensic analysis of Entra ID authentication chains to distinguish legitimate activity from credential/token theft.
---

# Authentication Tracing - Instructions

## Purpose

This skill performs forensic analysis of Entra ID authentication flows to determine whether anomalous sign-ins represent:
- **Legitimate activity** (VPN usage, user travel, mobile carrier routing)
- **Token theft/credential compromise** (stolen refresh tokens, session hijacking)

The key distinction is whether the user **actively performed MFA** at a suspicious location or if the authentication used a **refresh token from a prior session**.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Key Forensic Indicators](#key-forensic-indicators)** - Understanding authentication signals
3. **[IP Enrichment Data](#ip-enrichment-data-structure-primary-evidence-source)** - JSON structure reference
4. **[6-Step Forensic Workflow](#forensic-workflow-tracing-authentication-chains)** - SessionId-based investigation
5. **[Real-World Example](#real-world-example-geographic-anomaly-analysis)** - Complete walkthrough
6. **[Authentication Methods Reference](#common-authentication-methods-and-requestsequence-patterns)** - Method patterns
7. **[Risk Escalation Criteria](#when-to-escalate-authentication-anomalies)** - High/Medium/Low classification
8. **[Best Practices](#best-practices-for-authentication-tracing)** - Summary checklist

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**🚨 MANDATORY CHECKPOINT: Before providing ANY risk assessment for authentication anomalies:**

1. **STOP** - Do not improvise or use general security knowledge
2. **READ** the complete risk assessment framework in this document
3. **QUOTE** specific instruction sections in your analysis
4. **VERIFY** your conclusions match documented guidance before responding to user

**Before executing ANY authentication tracing queries, you MUST:**

1. **Read the SessionId-based workflow** (Steps 1-6 below) in full
2. **Search** the investigation JSON for IP enrichment data (`ip_enrichment` array) - **PRIMARY DATA SOURCE**
3. **Follow the documented steps** in order (SessionId → Authentication chain → Interactive MFA → Risk assessment)
4. **Use IP enrichment context** in your final risk assessment (VPN status, abuse scores, threat intel, auth patterns)

**Skipping these steps will result in incomplete or incorrect analysis.**

---

## Key Forensic Indicators

When investigating anomalous sign-ins (e.g., from new countries, IPs, or devices), it's critical to determine whether the user **actively performed MFA** at that location or if the authentication used a **refresh token from a prior session**.

### RequestSequence Field

| Value | Meaning | Implication |
|-------|---------|-------------|
| `RequestSequence: 1` or higher | **Interactive authentication** | User was challenged and responded |
| `RequestSequence: 0` | **Token-based authentication** | No user interaction required |

### AuthenticationDetails Array Patterns

**Interactive Pattern:**
- Array contains authentication method (e.g., "Passkey (device-bound)") with `RequestSequence > 0`
- Followed by "Previously satisfied" entry

**Token Reuse Pattern:**
- Array contains ONLY "Previously satisfied" entries
- Shows "MFA requirement satisfied by claim in the token"

### authenticationStepDateTime Correlation

- If `authenticationStepDateTime` references a time when NO interactive auth occurred, it indicates token reuse
- Cross-reference timestamps with events that have `RequestSequence > 0` to trace token origin

---

## IP Enrichment Data Structure (PRIMARY EVIDENCE SOURCE)

**CRITICAL: The investigation JSON contains a comprehensive `ip_enrichment` array with authoritative detection flags.**

**Always reference this data FIRST before making VPN/proxy/Tor determinations.**

### Example IP Enrichment Entry (Actual JSON Structure)

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
  "threat_description": "Commercial VPN Service: Known Anonymization Infrastructure",
  "anomaly_type": "NewInteractiveIP",
  "first_seen": "2025-10-16",     // ← First sign-in from this IP (date string)
  "last_seen": "2025-10-16",      // ← Last sign-in from this IP (date string)
  "hit_count": 5,                  // ← Number of anomaly detections
  "signin_count": 8,               // ← Total sign-ins from this IP
  "success_count": 7,              // ← Successful authentications
  "failure_count": 1,              // ← Failed authentications
  "last_auth_result_detail": "MFA requirement satisfied by claim in the token",
  "threat_detected": false,        // ← Legacy field (use threat_description instead)
  "threat_confidence": 0,
  "threat_tlp_level": "",
  "threat_activity_groups": ""
}
```

**CRITICAL: Always use `ip_enrichment[].ip` to match IPs, NOT `ip_address`!**

### Key Fields for Analysis

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

### Analysis Priority Hierarchy

1. **IP enrichment flags** (`is_vpn`, `is_proxy`, `is_tor`) - Most authoritative source
2. **Abuse reputation** (`abuse_confidence_score`, `total_reports`) - Community-validated risk data
3. **Threat intelligence** (`threat_detected`, `threat_description`) - IOC matches from Sentinel
4. **Network ownership** (`org`, `asn`, `company_type`) - Infrastructure context (hosting, ISP, etc.)
5. **Authentication patterns** (`last_auth_result_detail`, `signin_count`) - Behavioral context
6. **Identity Protection** (risk detections) - Microsoft ML-based risk signals

**⚠️ NEVER say "likely VPN" or "probably proxy" if enrichment data has explicit boolean flags!**

---

## Forensic Workflow: Tracing Authentication Chains

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

### Step 1: Get SessionId from Suspicious Authentication (ALWAYS START HERE)

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

### Step 2: Trace Complete Authentication Chain by SessionId (DEFINITIVE PROOF)

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

### Step 3: Find Interactive MFA with Progressive Date Range Expansion

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

### Step 4: Collect All IPs from Authentication Chain

**CRITICAL: After completing the SessionId trace, extract ALL unique IP addresses discovered:**

1. **From Interactive MFA session** (Step 3 results)
2. **From Suspicious session** (Step 1 results)
3. **From Complete SessionId chain** (Step 2 results)

**Build comprehensive IP list for enrichment analysis.**

---

### Step 5: Analyze IP Enrichment Data for ALL Discovered IPs

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

### Step 6: Document Risk Assessment

**⚠️ MANDATORY CHECKPOINT - Before writing risk assessment:**
- **READ** the "When to Escalate Authentication Anomalies" section below
- **IDENTIFY** which risk classification criteria applies to your case
- **QUOTE** the specific criteria in your analysis
- **DO NOT improvise** - follow documented classification exactly

**Present findings in clear evidence trail:**

1. **Interactive Session**: IP, Location, Timestamp, AuthMethod, SessionId
2. **Subsequent Session**: IP, Location, Timestamp, AuthMethod (token-based), SessionId
3. **IP Enrichment Analysis for ALL IPs**: Present enrichment data for EVERY IP discovered in trace (VPN status, abuse scores, threat intel, auth patterns, frequency, temporal context)
4. **Connection Proof**: SessionId match + time gap + geographic distance + comprehensive enrichment context from all IPs
5. **Risk Assessment**: Evaluate based on context - **MUST quote specific instruction criteria**

**Risk Assessment Framework - SessionId Interpretation:**

- **SessionId does NOT prove device identity** - token theft maintains session continuity
- **Same SessionId across geographically distant IPs** = Requires investigation (VPN/travel OR stolen token)
- **Different SessionIds** = Different authentication flows (not necessarily more suspicious)
- **Must correlate multiple signals**: SessionId + UserAgent + Geography + Behavior + Time patterns + **IP enrichment data**

---

## Real-World Example: Geographic Anomaly Analysis

**Scenario:** User sign-ins detected from two geographically distant locations within 18 hours.

### Step 1: Interactive MFA Analysis

**Location A Analysis:**
1. Query 1: Found 2 events with `SMS verification` and `RequestSeq: 1`
2. Result: **User performed fresh interactive SMS authentication at Location A**
3. Evidence: `authenticationStepDateTime: 2025-10-15T14:23:05Z` with `RequestSequence: 1`

**Location B Analysis:**
1. Query 1: Zero results (no non-"Previously satisfied" methods)
2. Result: **Location B authentications used only token reuse - NO interactive MFA**
3. Evidence: All events show `"MFA requirement satisfied by claim in the token"`

### Step 2: SessionId Verification (SMOKING GUN)

**Query to compare sessions across both IPs:**

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

### Step 3: Evidence Summary and Interpretation

| Evidence Type | Finding | Observation |
|--------------|---------|-------------|
| Interactive MFA | Location A only | User performed SMS authentication |
| Location B Auth Methods | "Previously satisfied" only | Token reuse (normal OAuth flow) |
| SessionId | Same across both locations | **Session continuity maintained** |
| Time Gap | 18 hours | Within typical refresh token lifetime (24-90 days) |
| User Agent | Same | **Consistent device fingerprint** |
| Applications | Consistent across locations | Consistent workflow pattern |

### Critical Analysis - SessionId Does NOT Prove Legitimacy

The **same SessionId** requires careful analysis because:
- SessionId is a browser session identifier that tracks authentication flows
- **Same SessionId = Session continuity** (could be legitimate user OR stolen token)
- **Stolen refresh tokens maintain the original SessionId** - attacker inherits session state
- **Same SessionId does NOT rule out token theft or credential compromise**

**Possible Scenarios Requiring Investigation:**

| Scenario | Description | Action Required |
|----------|-------------|-----------------|
| **Legitimate VPN Connection** | User switched VPN exit nodes (same device, different apparent location) | **Requires user confirmation** |
| **Legitimate User Travel** | User traveled between locations with sufficient time gap (tokens remained valid) | **Requires user confirmation** |
| **Stolen Token Replay** | Attacker obtained refresh token (SessionId stays same, may show different UserAgent) | **Cannot be ruled out by SessionId alone** |
| **Mobile Carrier Routing** | Carrier routes traffic through regional gateways (device in one location, exits another) | **Check IP enrichment for ISP org** |

### Additional Investigation Checklist

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

### Recommendation: User Confirmation Questions

**Use IP enrichment data from investigation JSON to strengthen your analysis, then confirm with user:**

1. "Were you using a VPN on [date] around [time]?" (if `is_vpn: true`)
2. "Did you travel between [Location A] and [Location B] during this timeframe?"
3. "Do you recognize [applications] activity during this timeframe?"
4. "Have you noticed any unusual device or account behavior recently?"

**Only after user confirmation** can you conclude VPN usage or travel is legitimate. **Same SessionId + IP enrichment data together provide strong evidence, but user confirmation is still required.**

---

## Common Authentication Methods and RequestSequence Patterns

| Authentication Method | RequestSeq > 0 Meaning | RequestSeq = 0 Meaning |
|----------------------|------------------------|------------------------|
| Passkey (device-bound) | User physically approved with biometric/PIN | Passkey used in prior session, token reused |
| Phone sign-in | User approved notification on phone | Phone approval in prior session, token reused |
| SMS verification | User entered SMS code | SMS verification in prior session, token reused |
| Microsoft Authenticator app | User approved push notification | Authenticator used in prior session, token reused |
| Previously satisfied | N/A - never has RequestSeq > 0 | Always indicates token/claim reuse |

---

## When to Escalate Authentication Anomalies

**CRITICAL: Always check IP enrichment data before making risk determination!**

### High Risk (Escalate Immediately)

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

### Medium Risk (Investigate Further - Confirm with User)

- **Same SessionId + Geographically distant locations** = Could be VPN/travel OR token theft - VERIFY with IP enrichment
- Token reuse from unexpected country without prior user notification
- Token reuse spanning >30 days (excessive token lifetime - increases theft window)
- Pattern of token-only authentications without any interactive MFA in 30+ days
- Sign-ins during unusual hours for user's timezone
- Access to sensitive data repositories during suspicious sessions
- **Same SessionId + Same UserAgent + Unusual geographic pattern** = Needs user confirmation
- **IP enrichment shows**: `abuse_confidence_score >= 25`, `is_vpn: true` without user confirmation, or `total_reports > 0`

### Low Risk / Likely Legitimate (Monitor Only)

- Token reuse from nearby IPs in same city (mobile carrier IP rotation)
- Token reuse following confirmed interactive MFA from expected location
- Token reuse from known corporate VPN IP ranges
- Applications and access patterns consistent with user's role
- **User confirms VPN usage or travel** when questioned
- No unusual data access or configuration changes
- **Consistent UserAgent + Reasonable geographic progression + User confirmation**
- **IP enrichment shows**: `abuse_confidence_score: 0`, residential ISP org (TELUS, Comcast, etc.), `is_vpn: false`, high `signin_count` with consistent success rate

---

## Best Practices for Authentication Tracing

1. **START WITH SessionId** - Query suspicious IPs to get SessionId first (most efficient approach)
2. **Use SessionId to trace complete chain** - Single query shows entire authentication progression
3. **Check IP enrichment data** - Use investigation JSON `ip_enrichment` array for VPN, abuse scores, threat intel
4. **Verify device consistency** - Same SessionId + Same UserAgent + Geographic reasonableness = Likely legitimate
5. **SessionId alone is NOT conclusive** - Must correlate with UserAgent, geography, behavior, and user confirmation
6. **Check first authentication in session** - RequestSeq > 0 shows where user performed interactive MFA
7. **Assess geographic progression** - Evaluate if travel is physically possible or if VPN is likely
8. **Widen time ranges if needed** - Tokens can be valid for 24-90 days depending on policy
9. **Always confirm with user** - Geographic anomalies require user verification regardless of SessionId

---

## Prerequisites

### Required MCP Servers

This skill requires:

1. **Microsoft Sentinel MCP** - For KQL queries against SigninLogs and AADNonInteractiveUserSignInLogs
   - `mcp_sentinel-data_query_lake`: Execute KQL queries
   - `mcp_sentinel-data_search_tables`: Discover table schemas

### Required Data Sources

- **SigninLogs** - Interactive sign-in events
- **AADNonInteractiveUserSignInLogs** - Non-interactive (token-based) sign-in events
- **Investigation JSON** - Pre-generated investigation file with `ip_enrichment` array (from user-investigation skill)

### How to Find Investigation JSON

- **Pattern**: `temp/investigation_<upn_prefix>_<timestamp>.json`
- Most recent file for user is usually the one to analyze
- Use `file_search` or `list_dir` to locate existing investigations

---

## Integration with User Investigation Skill

Authentication tracing is typically performed as a **follow-up analysis** after running a user investigation:

1. **Run user-investigation skill** → Generates investigation JSON with `ip_enrichment` array
2. **Review anomalies** → Identify suspicious IPs/locations requiring deeper analysis
3. **Run authentication-tracing skill** → Trace SessionId chains, correlate with IP enrichment
4. **Document findings** → Provide risk assessment with evidence trail

**Key Integration Points:**
- IP enrichment data comes from investigation JSON (already queried by user-investigation)
- SessionId queries are NEW queries specific to authentication tracing
- Risk assessment combines both data sources

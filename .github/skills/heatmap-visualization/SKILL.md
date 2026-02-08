---
name: heatmap-visualization
description: Use this skill when asked to create heatmaps, visualize patterns over time, show activity grids, or display aggregated data in a matrix format. Triggers on keywords like "heatmap", "show heatmap", "visualize patterns", "activity grid", "time-based visualization", or when analyzing attack patterns, sign-in activity, or event distributions by time period.
---

# Heatmap Visualization Skill

## Purpose

Generate interactive heatmap visualizations from Microsoft Sentinel data using the Sentinel Heatmap MCP App. Heatmaps display aggregated data in a row/column grid with color-coded intensity, ideal for identifying patterns across time periods, comparing entities, or spotting anomalies.

---

## 📑 TABLE OF CONTENTS

1. **[Quick Start](#quick-start)** - Minimal example to get started
2. **[MCP Tool Reference](#mcp-tool-reference)** - Parameters and schemas
3. **[KQL Query Patterns](#kql-query-patterns)** - Ready-to-use queries by scenario
4. **[Enrichment Integration](#enrichment-integration)** - Adding threat intel drill-down
5. **[Color Scale Guide](#color-scale-guide)** - Choosing the right colors
6. **[Examples](#complete-examples)** - End-to-end workflows

---

## Quick Start

### Minimal Heatmap (3 Steps)

```
# 1. Query Sentinel for aggregated data
mcp_sentinel-data_query_lake({
  "query": "SigninLogs | where TimeGenerated > ago(24h) | summarize value = count() by row = AppDisplayName, column = format_datetime(bin(TimeGenerated, 1h), 'HH:mm') | project row, column, value"
})

# 2. Display heatmap
mcp_sentinel-heat_show-signin-heatmap({
  "data": [<query results>],
  "title": "Sign-Ins by Application (Last 24h)",
  "rowLabel": "Application",
  "colLabel": "Hour (UTC)",
  "valueLabel": "Sign-ins",
  "colorScale": "green-red"
})
```

---

## MCP Tool Reference

### Tool: `mcp_sentinel-heat_show-signin-heatmap`

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `data` | ✅ | array | Array of `{row, column, value}` objects |
| `title` | ❌ | string | Title displayed above heatmap |
| `rowLabel` | ❌ | string | Label for row axis (e.g., "IP Address") |
| `colLabel` | ❌ | string | Label for column axis (e.g., "Hour") |
| `valueLabel` | ❌ | string | Label for cell values (e.g., "Events") |
| `colorScale` | ❌ | string | `green-red`, `blue-red`, or `blue-yellow` |
| `enrichment` | ❌ | array | IP enrichment data for click-to-expand panels |

### Data Schema

```json
{
  "data": [
    {"row": "192.168.1.1", "column": "10:00", "value": 45},
    {"row": "192.168.1.1", "column": "11:00", "value": 62},
    {"row": "10.0.0.5", "column": "10:00", "value": 128}
  ]
}
```

### Enrichment Schema (Optional)

```json
{
  "enrichment": [
    {
      "ip": "80.94.95.83",
      "city": "Timișoara",
      "country": "RO",
      "org": "AS204428 SS-Net",
      "is_vpn": false,
      "abuse_confidence_score": 100,
      "total_reports": 975,
      "last_reported": "2026-01-29",
      "threat_categories": ["RDP Brute-Force", "Hacking", "Port Scan"]
    }
  ]
}
```

---

## KQL Query Patterns

**All queries must return `row`, `column`, `value` columns.**

### Pattern 1: Activity by Entity and Hour

```kql
<Table>
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| summarize value = count() 
    by row = <entity_field>, 
       column = format_datetime(bin(TimeGenerated, 1h), "HH:mm")
| project row, column, value
| order by column asc
```

### Pattern 2: Activity by Entity and Day

```kql
<Table>
| where TimeGenerated > ago(30d)
| summarize value = count() 
    by row = <entity_field>, 
       column = format_datetime(bin(TimeGenerated, 1d), "yyyy-MM-dd")
| project row, column, value
| order by column asc
```

### Pattern 3: Cross-Tabulation (Two Dimensions)

```kql
<Table>
| where TimeGenerated > ago(7d)
| summarize value = count() 
    by row = <dimension1>, 
       column = <dimension2>
| project row, column, value
| order by value desc
```

---

## Scenario-Specific KQL Queries

### Scenario: Sign-In Activity by Application and Hour

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0  // Successful sign-ins
| summarize value = count() 
    by row = AppDisplayName, 
       column = format_datetime(bin(TimeGenerated, 1h), "HH:mm")
| project row, column, value
| order by column asc
```

**Recommended:** `colorScale: "green-red"` (activity = good)

### Scenario: Failed Sign-Ins by IP and Hour

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0  // Failed sign-ins
| summarize value = count() 
    by row = IPAddress, 
       column = format_datetime(bin(TimeGenerated, 1h), "HH:mm")
| project row, column, value
| order by column asc, value desc
| take 500  // Limit to top patterns
```

**Recommended:** `colorScale: "blue-red"` (failures = threat)

### Scenario: Honeypot Attack Patterns (SecurityEvent)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let honeypot = '<HONEYPOT_NAME>';
SecurityEvent
| where TimeGenerated between (start .. end)
| where Computer contains honeypot
| where EventID in (4625, 4771, 4776)  // Failed auth events
| where isnotempty(IpAddress) and IpAddress != "-" and IpAddress != "127.0.0.1"
| summarize value = count() 
    by row = IpAddress, 
       column = format_datetime(bin(TimeGenerated, 1h), "HH:mm")
| project row, column, value
| order by column asc, value desc
```

**Recommended:** `colorScale: "blue-red"` (attacks = threat)

### Scenario: Web Attack Patterns (W3CIISLog)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
W3CIISLog
| where TimeGenerated between (start .. end)
| where tolong(scStatus) >= 400  // HTTP errors
| where cIP != "127.0.0.1"
| summarize value = count() 
    by row = cIP, 
       column = format_datetime(bin(TimeGenerated, 1h), "HH:mm")
| project row, column, value
| order by column asc, value desc
| take 300
```

**Recommended:** `colorScale: "blue-red"`

### Scenario: Defender Alerts by Severity and Day

```kql
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize value = count() 
    by row = AlertSeverity, 
       column = format_datetime(bin(TimeGenerated, 1d), "yyyy-MM-dd")
| project row, column, value
| order by column asc
```

**Recommended:** `colorScale: "blue-yellow"` (neutral overview)

### Scenario: User Activity by Application

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ '<UPN>'
| summarize value = count() 
    by row = AppDisplayName, 
       column = format_datetime(bin(TimeGenerated, 1d), "MM-dd")
| project row, column, value
| order by column asc
```

**Recommended:** `colorScale: "green-red"`

### Scenario: Multi-Source Combined Heatmap

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let honeypot = '<HONEYPOT_NAME>';
union
  (SecurityEvent
   | where TimeGenerated between (start .. end)
   | where Computer contains honeypot
   | where EventID in (4625, 4771, 4776)
   | where isnotempty(IpAddress) and IpAddress != "-"
   | extend Source = "RDP/SMB", IP = IpAddress),
  (W3CIISLog
   | where TimeGenerated between (start .. end)
   | where Computer contains honeypot
   | where tolong(scStatus) >= 400
   | extend Source = "IIS", IP = cIP),
  (DeviceNetworkEvents
   | where TimeGenerated between (start .. end)
   | where DeviceName contains honeypot
   | where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
   | extend Source = "Network", IP = RemoteIP)
| where IP != "127.0.0.1" and IP != "::1"
| summarize value = count()
    by row = strcat(IP, " (", Source, ")"), 
       column = format_datetime(bin(TimeGenerated, 1h), "HH:mm")
| project row, column, value
| order by column asc, value desc
```

---

## Enrichment Integration

### Adding Threat Intel Drill-Down

When displaying IP-based heatmaps, add enrichment data for click-to-expand threat panels:

**Step 1:** Extract unique IPs from your query results

**Step 2:** Enrich IPs using the enrichment script:
```powershell
python enrich_ips.py 80.94.95.83 193.142.147.209 101.36.107.228
```

**Step 3:** Transform enrichment output to heatmap format:
```python
enrichment_out = []
for e in enrichment_data:
    threat_cats = []
    for c in e.get('recent_comments', [])[:5]:
        threat_cats.extend(c.get('categories', []))
    
    enrichment_out.append({
        'ip': e['ip'],
        'city': e.get('city', 'Unknown'),
        'country': e.get('country', '??'),
        'org': e.get('org', 'Unknown'),
        'is_vpn': e.get('is_vpn') or e.get('vpnapi_security_vpn', False),
        'abuse_confidence_score': e.get('abuse_confidence_score', 0),
        'total_reports': e.get('total_reports', 0),
        'last_reported': e.get('recent_comments', [{}])[0].get('date', '')[:10],
        'threat_categories': list(set(threat_cats))[:5]
    })
```

**Step 4:** Include in heatmap call:
```
mcp_sentinel-heat_show-signin-heatmap({
  "data": [...],
  "enrichment": [<enrichment_out>],
  ...
})
```

### Interactive Features with Enrichment

When enrichment is provided:
- **Click any IP row** → Opens threat intel panel showing:
  - 📍 Location (city, country)
  - 🏢 Organization/ISP
  - 🏷️ VPN/Proxy/Tor badges
  - 📊 AbuseIPDB confidence meter (0-100)
  - 📈 Total reports count
  - 🔴 Threat category tags
- **Hover any cell** → Tooltip with row, column, exact value

---

## Color Scale Guide

| Scale | Low Value | High Value | Best For |
|-------|-----------|------------|----------|
| `green-red` | Teal/Blue | Green | Positive activity (sign-ins, successful ops) |
| `blue-red` | Blue | Red | Threats/failures (attacks, errors, risks) |
| `blue-yellow` | Blue | Yellow | Neutral data (general distributions) |

### Decision Tree

```
Is the data about threats/failures/attacks?
  → YES: Use "blue-red" (red = danger)
  → NO: Is high volume a positive indicator?
    → YES: Use "green-red" (green = success)
    → NO: Use "blue-yellow" (neutral)
```

---

## Complete Examples

### Example 1: Honeypot Attack Heatmap with Enrichment

```
# Query attack data
mcp_sentinel-data_query_lake({
  "query": "SecurityEvent | where TimeGenerated between (datetime(<START_DATE>) .. datetime(<END_DATE>)) | where Computer contains '<HONEYPOT_SERVER>' | where EventID == 4625 | where IpAddress != '127.0.0.1' | summarize value = count() by row = IpAddress, column = format_datetime(bin(TimeGenerated, 1h), 'HH:mm') | project row, column, value | order by column asc, value desc | take 200"
})

# Enrich top IPs
python enrich_ips.py 80.94.95.83 193.142.147.209 101.36.107.228

# Display heatmap
mcp_sentinel-heat_show-signin-heatmap({
  "data": [
    {"row": "80.94.95.83", "column": "19:00", "value": 636},
    {"row": "193.142.147.209", "column": "20:00", "value": 245},
    ...
  ],
  "title": "Honeypot Attack Analysis - Click IP for Threat Intel",
  "rowLabel": "Attacker IP",
  "colLabel": "Hour (UTC)",
  "valueLabel": "Failed Auth Attempts",
  "colorScale": "blue-red",
  "enrichment": [
    {"ip": "80.94.95.83", "city": "Timișoara", "country": "RO", "org": "AS204428 SS-Net", "is_vpn": false, "abuse_confidence_score": 100, "total_reports": 975, "threat_categories": ["RDP Brute-Force", "Hacking"]},
    {"ip": "193.142.147.209", "city": "Amsterdam", "country": "NL", "org": "AS213438 ColocaTel Inc.", "is_vpn": true, "abuse_confidence_score": 100, "total_reports": 30972, "threat_categories": ["SSH Brute-Force", "Port Scan"]}
  ]
})
```

### Example 2: Sign-In Activity Overview

```
# Query sign-in data
mcp_sentinel-data_query_lake({
  "query": "SigninLogs | where TimeGenerated > ago(24h) | where ResultType == 0 | summarize value = count() by row = AppDisplayName, column = format_datetime(bin(TimeGenerated, 1h), 'HH:mm') | project row, column, value | order by column asc"
})

# Display heatmap (no enrichment needed - not IP-based)
mcp_sentinel-heat_show-signin-heatmap({
  "data": [
    {"row": "Microsoft Teams", "column": "09:00", "value": 145},
    {"row": "Outlook", "column": "09:00", "value": 312},
    ...
  ],
  "title": "Sign-In Activity by Application (Last 24h)",
  "rowLabel": "Application",
  "colLabel": "Hour (UTC)",
  "valueLabel": "Sign-ins",
  "colorScale": "green-red"
})
```

---

## Known Pitfalls

### Column Sorting Is Lexicographic
**Problem:** The heatmap MCP app sorts columns alphabetically. Labels like `Nov 10`, `Dec 01`, `Jan 05`, `Feb 02` will render as `Dec → Feb → Jan → Nov` — completely out of chronological order.  
**Solution:** Always use ISO date format (`YYYY-MM-DD`) for time-based column labels. `2025-11-10`, `2025-12-01`, `2026-01-05` sorts correctly both alphabetically and chronologically.

```kql
// ✅ CORRECT — sortable column labels
| summarize value = count() by row = ..., column = format_datetime(bin(TimeGenerated, 7d), "yyyy-MM-dd")

// ❌ WRONG — alphabetic sort breaks chronological order
| summarize value = count() by row = ..., column = format_datetime(bin(TimeGenerated, 7d), "MMM dd")
```

For hourly heatmaps within a single day, `HH:mm` is fine (00:00–23:00 sorts correctly). The issue only affects multi-day/week/month labels.

---

## When to Use Heatmaps

✅ **Good Use Cases:**
- Attack patterns over time (by hour/day)
- Comparing activity across entities (IPs, apps, users)
- Identifying peak activity periods
- Spotting anomalies in regular patterns
- Executive-friendly threat visualization

❌ **Skip Heatmaps When:**
- Fewer than 5 unique rows or columns (too sparse)
- Single-dimension data (use bar chart instead)
- Geographic data (use geomap skill instead)
- Real-time streaming data (heatmaps are for aggregated snapshots)

---

*Last Updated: January 29, 2026*

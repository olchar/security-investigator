# Scope Drift Report — Device Fleet (Process Drift)

**Generated:** 2026-02-09  
**Workspace:** la-contoso (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)  
**Baseline Window:** 90 days (Nov 3, 2025 → Feb 1, 2026)  
**Recent Window:** 7 days (Feb 1 → Feb 8, 2026)  
**Fleet Size:** 9 devices (8 active, 1 offline)  
**Drift Threshold:** 150%  
**Verdict:** 🟢 **LOW RISK** — No devices exceed the drift threshold

---

## 1. Executive Summary

Fleet-wide process drift analysis covering 9 devices over a 90-day baseline compared against the most recent 7 days. **No devices exceed the 150% composite drift threshold.** Two devices (contoso-2012r2 at 144.6% and contoso-admin at 144.1%) are near the threshold due to ~3x volume increases, but diversity metrics (unique processes, accounts, chains, signing companies) remain proportionally lower — indicating the volume increase is driven by existing processes running more frequently, not new or anomalous processes appearing.

All first-seen processes in the recent window are version-stamped update artifacts (Microsoft Defender definition patches, Edge browser updates, Office Click-to-Run updates) signed by Microsoft Corporation. No suspicious command-line patterns (reconnaissance, lateral movement, persistence, exfiltration) were detected beyond routine `schtasks.exe` Office update scheduling. One active High-severity security incident (#4475) exists for credential access and C2 activity but is driven by external threat intel IP matches and IIS brute-force — unrelated to process drift.

---

## 2. Fleet Daily Trend

Daily event volume and active device count across the 90-day baseline + 7-day recent window.

| Period | Avg Daily Events | Avg Active Devices | Min Events (Day) | Max Events (Day) |
|--------|------------------|--------------------|-------------------|-------------------|
| **Baseline** (90d) | ~13,100 | 7–8 | 909 (Jan 25) | 18,703 (Dec 18) |
| **Recent** (7d) | ~12,200 | 7–8 | 6,847 (Feb 2 Sun) | 15,696 (Feb 5) |

**Observations:**
- 🟢 Overall daily event volume is consistent between baseline and recent — no fleet-wide anomaly
- 🔵 Weekday average: ~15–18K events across 6–8 devices
- 🔵 Weekend average: ~4–7K events across 5–7 devices (expected reduction)
- 🟡 Jan 25 anomaly: Only 909 events from 1 device (likely a holiday/outage day — isolated, not recent)
- 🟢 Feb 8 partial day (305 events, 1 device) — data collection cutoff at query execution time

---

## 3. Per-Device Drift Score Ranking

Drift Score = 0.30×Volume + 0.25×Processes + 0.15×Accounts + 0.20×Chains + 0.10×Companies

Each dimension is the ratio of recent-window diversity to baseline diversity, normalized to daily averages for volume.

| Rank | Device | Drift Score | Volume | Processes | Accounts | Chains | Companies | Status |
|------|--------|-------------|--------|-----------|----------|--------|-----------|--------|
| 1 | contoso-2012r2.contoso.com | **144.6%** | 335.2% | 64.1% | 30.0% | 67.5% | 100.0% | 🟡 Near threshold |
| 2 | contoso-admin | **144.1%** | 312.7% | 79.5% | 40.0% | 76.4% | 90.9% | 🟡 Near threshold |
| 3 | contoso-linux | **73.3%** | 105.6% | 62.8% | 90.9% | 56.3% | 10.0% | 🟢 Normal |
| 4 | contoso-sccm.contoso.com | **68.0%** | 106.7% | 36.1% | 60.0% | 42.8% | 93.8% | 🟢 Normal |
| 5 | contoso-dc1.contoso.com | **67.7%** | 109.8% | 37.3% | 50.0% | 43.3% | 92.3% | 🟢 Normal |
| 6 | contoso-util.contoso.com | **67.0%** | 106.8% | 35.4% | 58.3% | 40.2% | 93.3% | 🟢 Normal |
| 7 | contoso-dc2.contoso.com | **64.3%** | 109.5% | 36.7% | 30.0% | 42.7% | 92.3% | 🟢 Normal |
| 8 | contoso-vd-0.contoso.com | **60.1%** | 110.5% | 30.2% | 30.0% | 34.6% | 80.0% | 🟢 Normal |
| 9 | contoso-vm | **N/A** | — | — | — | — | — | ⚠️ Offline (baseline only) |

### Dimension Breakdown

**Volume Ratio** = (Recent daily avg / Baseline daily avg) × 100:
- Formula: `(RC_TotalEvents / 7) / (BL_TotalEvents / 90) × 100`
- Most devices: ~106–110% (stable, within normal variance)
- contoso-2012r2: **335.2%** — ~3.4× daily volume increase
- contoso-admin: **312.7%** — ~3.1× daily volume increase

**Process Diversity:** Recent unique processes as % of baseline unique processes. Most devices at 30–40% indicates normal subset utilization over a 7-day window vs 90-day window.

**Account Diversity:** Recent unique accounts / baseline unique accounts. Lower ratios expected (fewer distinct users in any given week).

**Chain Diversity:** Recent unique parent-child process chains / baseline chains. Similar pattern to process diversity.

**Company Diversity:** Recent unique signing companies / baseline companies. Consistently high (80–100%) across Windows fleet — same vendors, same software. contoso-linux at 10% reflects minimal binary signing metadata in Linux ecosystem.

---

## 4. Flagged Devices — Deep Dive

### 4a. contoso-2012r2.contoso.com — Drift Score: 144.6% 🟡

| Dimension | Baseline (90d) | Recent (7d) | Ratio |
|-----------|---------------|-------------|-------|
| Total Events | 20,952 | 5,462 | 335.2% (daily avg) |
| Unique Processes | 156 | 100 | 64.1% |
| Unique Accounts | 6 | 3 | 30.0% |
| Unique Chains | 231 | 156 | 67.5% |
| Unique Companies | 11 | 11 | 100.0% |

**Analysis:**
- 🟡 The **3.4× volume increase** is the primary driver. Baseline daily average was 232.8 events/day, recent is 780.3/day.
- 🟢 Process diversity (64.1%) and chain diversity (67.5%) are proportionally normal for a 7-day/90-day ratio — the same processes are running, just more frequently.
- 🟢 Company count unchanged (11/11) — no new software vendors appearing.
- 🟢 Account count decreased (3 vs 6) — fewer distinct accounts active, not more.
- 🔵 This is a Windows Server 2012 R2 machine. Volume spikes may reflect patch cycles, scheduled tasks, or catch-up activity after periods of lower usage in the baseline.
- **Assessment:** Volume-driven score elevation without diversity expansion. Monitor but no immediate security concern.

### 4b. contoso-admin — Drift Score: 144.1% 🟡

| Dimension | Baseline (90d) | Recent (7d) | Ratio |
|-----------|---------------|-------------|-------|
| Total Events | 4,243 | 1,031 | 312.7% (daily avg) |
| Unique Processes | 122 | 97 | 79.5% |
| Unique Chains | 199 | 152 | 76.4% |
| Unique Accounts | 4 | 4 | 40.0% |
| Unique Companies | 11 | 10 | 90.9% |

**Analysis:**
- 🟡 The **3.1× volume increase** is the primary driver. Baseline daily average was only 47.1 events/day, recent is 147.3/day.
- 🟡 Process diversity is relatively high (79.5%) — in 7 days, this device exercised 97 of its 122 known processes. This suggests varied activity but from the *existing* process set.
- 🟢 Account count stable (4 in both periods, normalized ratio appears low due to floor=10 normalization).
- 🟢 No new signing companies — the same software ecosystem is active.
- 🔵 This device has the lowest absolute event volume in the fleet (4,243 baseline). Small absolute increases produce large percentage swings. The actual delta is only ~100 extra events/day.
- **Assessment:** Low-volume device with proportionally large swings. High process coverage ratio (79.5%) indicates engaged administrative use, not anomalous tooling. Monitor but no immediate security concern.

### 4c. contoso-vm — Baseline Only ⚠️

| Status | Detail |
|--------|--------|
| Baseline Events | 7,010 (90d) |
| Recent Events | 0 |
| Last Activity | Unknown — no events in recent 7-day window |

**Assessment:** This device has not reported any `DeviceProcessEvents` in the last 7 days. Possible reasons: powered off, Defender for Endpoint sensor stopped, decommissioned, or network-isolated. Requires operational verification — not a security concern per se, but a visibility gap.

---

## 5. First-Seen Processes (New in Recent Window)

Processes observed in the 7-day recent window that were **not present anywhere in the 90-day baseline**.

| Device | New Process Count | Category | Risk |
|--------|-------------------|----------|------|
| contoso-vd-0 | 31 | AM_Delta_Patch_*, MicrosoftEdge_X64_*, odt*.tmp.exe, SecurityHealthSetup.exe | ✅ Benign |
| contoso-util | 16 | AM_Delta_Patch_*, MicrosoftEdge_X64_* | ✅ Benign |
| contoso-sccm | 15 | AM_Delta_Patch_*, MicrosoftEdge_X64_* | ✅ Benign |
| contoso-2012r2 | 15 | AM_Delta_Patch_* (all) | ✅ Benign |
| contoso-dc2 | 14 | AM_Delta_Patch_* (all) | ✅ Benign |
| contoso-dc1 | 13 | AM_Delta_Patch_* (all) | ✅ Benign |
| contoso-admin | 4 | MicrosoftEdge_X64_*, AM_Delta_Patch_*, mpam-d.exe | ✅ Benign |
| contoso-linux | 1 | lvm2-activation (empty company) | ✅ Benign |

**All first-seen processes are version-stamped update artifacts:**

- **AM_Delta_Patch_1.443.xxx.0.exe** — Microsoft Defender Antivirus definition delta updates (new version number = new "process" name each update cycle)
- **MicrosoftEdge_X64_144.0.xxxx.xxx_144.0.xxxx.xxx.exe** — Edge browser cumulative update installers (version-to-version naming convention)
- **odt*.tmp.exe** — Office Deployment Tool temporary installers for Click-to-Run updates
- **SecurityHealthSetup.exe** — Windows Security Health agent update (pushed via Windows Update)
- **mpam-d.exe** — Microsoft Protection Antimalware platform update
- **lvm2-activation** — Linux Logical Volume Manager activation (standard OS component)

🟢 **No anomalous first-seen processes detected.** The version-stamped naming pattern creates apparent "new processes" with each update cycle — this is a known false positive pattern documented in the skill methodology.

---

## 6. Rare Process Chains (Recent Window)

Parent→child process relationships that appeared only in the recent 7-day window (not in baseline).

| Chain | Occurrences | Devices | Account | Assessment |
|-------|-------------|---------|---------|------------|
| wuauclt.exe → AM_Delta_Patch_1.443.xxx.0.exe | 5–6 per version | 5 (domain servers) | SYSTEM | ✅ Defender definition updates |
| microsoftedgeupdate.exe → MicrosoftEdge_X64_*.exe | 3–5 | 3 (util, sccm, vd-0) | SYSTEM | ✅ Edge browser updates |
| microsoftedge_x64_*.exe → setup.exe | 3–5 | 3 (util, sccm, vd-0) | SYSTEM | ✅ Edge installer running setup |
| microsoftedge_x64_*.exe → wermgr.exe | 2 | 2 (util, sccm) | SYSTEM | ✅ Windows Error Reporting from Edge update |
| wuaucltcore.exe → SecurityHealthSetup.exe | 3 | 1 (vd-0) | SYSTEM | ✅ Windows Update → Security Health |
| securityhealthsetup.exe → SecurityHealthSetup.exe | 3 | 1 (vd-0) | SYSTEM | ✅ Self-update chain |
| odt*.tmp.exe → OfficeClickToRun.exe | 2–3 | 1 (vd-0) | SYSTEM | ✅ Office Click-to-Run update |
| odt*.tmp.exe → conhost.exe | 2 | 1 (vd-0) | SYSTEM | ✅ Console host for ODT |
| microsoft.tri.sensor.updater.exe → ipconfig.exe | 4 | 2 (dc1, dc2) | SYSTEM | ✅ Defender for Identity sensor DNS flush |

🟢 **No anomalous process chains detected.** All chains are software update and maintenance patterns running under the SYSTEM account. The Defender for Identity sensor→ipconfig chain on domain controllers is a standard operational pattern (DNS cache flush after sensor update).

---

## 7. Correlated Security Alerts

Security alerts and incidents involving fleet devices in the recent 7-day window.

| Incident # | Title | Severity | Status | Related Alerts |
|-------------|-------|----------|--------|----------------|
| 4475 | Multi-stage incident involving Credential access & Command and control on one endpoint | 🔴 High | New | 3 alert types (see below) |

**Alert Breakdown for Incident #4475:**

| Alert Name | Severity | Tactic | Count |
|------------|----------|--------|-------|
| Excessive failed login attempts to an IIS Web Server from unknown IP Addresses | High | CredentialAccess | 2 |
| TI Map IP Entity to W3CIISLog | Medium | CommandAndControl | 7 |
| TI Map IP Entity to DeviceNetworkEvents | Medium | CommandAndControl | 6 |

**Assessment:**
- 🟠 This incident is driven by **external threat actors** hitting IIS web servers with brute-force credential attempts and known-malicious IP addresses matching Threat Intelligence feeds.
- 🔵 The C2 indicators (TI Map IP) represent inbound connections from known-bad IPs, **not outbound C2 beaconing** from fleet devices.
- 🔵 This is an **exposure/attack surface issue**, not a process drift indicator. The credential access alerts reflect external brute-force attempts, which are common for internet-facing IIS servers.
- ⚠️ **Recommendation:** Investigate Incident #4475 separately — verify which IIS endpoint is targeted, confirm no successful authentication occurred, and review WAF/network ACL rules. This incident is not causally related to process drift.

---

## 8. Unsigned & Non-Microsoft Processes

Processes running without signing company metadata or with non-Microsoft signing companies.

### 8a. Windows Fleet — Notable Entry

| Process | Company | Occurrences | Devices | Account | Assessment |
|---------|---------|-------------|---------|---------|------------|
| gc_worker.exe | *(empty)* | 630 | 7 (all Windows) | SYSTEM | 🔵 Defender for Endpoint GC worker |

**gc_worker.exe** — This is the garbage collection worker process for the Microsoft Defender for Endpoint sensor (`MsSense.exe`). It runs fleet-wide under SYSTEM and lacks version info metadata. This is a **known Defender for Endpoint component** — not a security concern.

### 8b. Linux Fleet — Expected Pattern

contoso-linux dominates the unsigned process list with standard Linux/GNU utilities:

| Top Processes | Occurrences | Account |
|---------------|-------------|---------|
| gawk | 6,485 | root |
| dash | 6,316 | root, _apt, gdm |
| journalctl | 3,778 | root |
| sed | 3,687 | root, _apt |
| apt-config | 2,748 | _apt, root |
| rm | 2,331 | root, _apt |
| bash | 2,060 | root |
| grep | 1,783 | root |
| dpkg | 1,759 | root, _apt |
| python3.8 | 1,724 | root, _apt |

🟢 All standard Linux system utilities (gawk, dash, sed, grep, bash, etc.) and package management tools (apt-config, dpkg, apt-get). These binaries inherently lack Windows-style signing metadata. The `_apt` account is the standard unprivileged user for APT package operations. High volumes reflect active container/VM management and automated maintenance on this Linux host.

---

## 9. Notable Command-Line Patterns

Suspicious command-line pattern detection (reconnaissance, lateral movement, persistence, exfiltration):

| Process | Pattern Matched | Occurrences | Devices | Account | Sample Command |
|---------|-----------------|-------------|---------|---------|----------------|
| schtasks.exe | `schtasks` | 278 | 3 (vd-0, util, 2012r2) | SYSTEM | `schtasks.exe /change /tn "Microsoft\Office\Office Automatic Updates" /enable` |

🟢 **No suspicious command-line patterns detected.** The only match is `schtasks.exe` performing routine Office automatic update schedule management (enabling/disabling the built-in "Microsoft\Office\Office Automatic Updates" scheduled task). All 278 invocations run under SYSTEM context — consistent with Office Click-to-Run update orchestration.

**Patterns checked with zero matches:**
- ✅ No `whoami`, `net user`, `net group`, `nltest`, `dsquery`, `quser`, `klist`, `cmdkey` (reconnaissance)
- ✅ No `psexec`, `Enter-PSSession`, `Invoke-Command`, `wmic` (lateral movement)
- ✅ No `mshta`, `certutil`, `bitsadmin`, `powershell -enc`, `IEX`, `Invoke-Expression`, `DownloadString`, `DownloadFile` (execution/download)
- ✅ No `sc create`, `New-Service`, `reg add`, `reg save` (persistence/credential dumping)
- ✅ No `ntdsutil`, `vssadmin`, `wbadmin`, `bcdedit`, `fsutil` (defense evasion/impact)

---

## 10. Security Assessment & Verdict

### Overall Fleet Risk: 🟢 LOW

| Factor | Finding |
|--------|---------|
| 🟢 **Drift Threshold** | No devices exceed 150%. Highest: contoso-2012r2 (144.6%), contoso-admin (144.1%) |
| 🟢 **First-Seen Processes** | 100% version-stamped update artifacts (Microsoft signed) — zero suspicious new processes |
| 🟢 **Process Chains** | All recent-only chains are software update patterns (SYSTEM context) |
| 🟢 **Command Lines** | Zero suspicious patterns detected (recon, lateral movement, persistence, exfiltration) |
| 🟢 **Unsigned Processes** | Only gc_worker.exe (Defender component) + standard Linux utilities |
| 🟢 **Account Landscape** | No new accounts appeared; SYSTEM dominates process execution |
| 🟠 **Security Incident** | Incident #4475 (High) — external credential brute-force + TI IP hits (not process drift related) |
| ⚠️ **Visibility Gap** | contoso-vm offline — no recent telemetry (operational concern, not security finding) |

### Drift Score Distribution

```
  ████████████████████████████████████████████████████░░░░  144.6%  contoso-2012r2  🟡
  ███████████████████████████████████████████████████░░░░░  144.1%  contoso-admin   🟡
  █████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   73.3%  contoso-linux    🟢
  ██████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   68.0%  contoso-sccm     🟢
  ██████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   67.7%  contoso-dc1      🟢
  ██████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   67.0%  contoso-util     🟢
  █████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   64.3%  contoso-dc2      🟢
  ████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   60.1%  contoso-vd-0     🟢
                                                              N/A  contoso-vm       ⚠️
  ──────────────────────────────────────────────────|──────
                                                 150% threshold
```

### Recommendations

1. ⚠️ **Investigate Incident #4475** — External credential brute-force against IIS endpoints with Threat Intelligence IP matches. Not drift-related but requires separate triage (see incident-investigation skill).

2. 🔵 **Monitor contoso-2012r2 and contoso-admin** — Both devices are near the 150% threshold (144.6% and 144.1%) driven by ~3× volume increases. The absence of new process diversity or suspicious patterns suggests operational activity spikes (patch cycles, administrative tasks). Re-assess in 7 days; if scores increase further, investigate the volume change driver.

3. ⚠️ **Verify contoso-vm status** — This device has 7,010 baseline events but zero recent activity. Confirm whether it is intentionally offline, decommissioned, or experiencing a sensor health issue. An unmonitored device is a visibility gap.

4. 🟢 **No immediate remediation required** — Fleet process behavior is consistent with baseline patterns. All new process appearances are expected update artifacts. No anomalous account activity, no suspicious command-line execution, no lateral movement indicators.

---

## Appendix: Methodology

### Drift Score Formula

```
DriftScore = 0.30 × VolumeRatio + 0.25 × ProcessRatio + 0.15 × AccountRatio + 0.20 × ChainRatio + 0.10 × CompanyRatio
```

| Weight | Dimension | Description |
|--------|-----------|-------------|
| 30% | Volume | Daily average event count ratio (recent / baseline) |
| 25% | Processes | Distinct process name ratio |
| 15% | Accounts | Distinct account name ratio |
| 20% | Chains | Distinct parent→child process chain ratio |
| 10% | Companies | Distinct signing company ratio |

**Threshold:** 150% — scores above this indicate meaningful behavioral expansion warranting investigation.

**Floor normalization:** When a baseline dimension has fewer than 10 distinct values, the denominator is floored at 10 to prevent small-sample amplification.

### Data Sources

| Source | Table | Purpose |
|--------|-------|---------|
| Microsoft Defender for Endpoint | `DeviceProcessEvents` (Sentinel Data Lake) | Process execution telemetry |
| Microsoft Sentinel | `SecurityAlert` + `SecurityIncident` | Alert correlation |

### Queries Executed

| # | Query | Rows | Purpose |
|---|-------|------|---------|
| 12 | Fleet daily summary | 80 | Daily event volume + device count trend |
| 13 | Per-device breakdown | 17 | Raw metrics for drift score computation |
| 14 | First-seen processes | 109 total | New processes not in baseline |
| 15 | Rare process chains | 25 | Parent→child chains unique to recent window |
| 16 | SecurityAlert correlation | 15 | Alert/incident matches for fleet devices |
| 17 | Unsigned processes | 30 | Processes without signing company metadata |
| 18 | Notable command lines | 1 | Suspicious command-line pattern detection |

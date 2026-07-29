# Splunk SOC Detection Lab

## Overview
A hands-on SIEM detection lab built with Splunk Enterprise, covering two phases:
onboarding and analyzing live Windows telemetry from a local host, then
investigating a multi-stage attack in the Boss of the SOC (BOTS v1) dataset.
Detections are mapped to MITRE ATT&CK.

## Environment

**Phase 1: Live host telemetry**
- Splunk Enterprise (local install)
- Windows Security, System, Application channels
- Sysmon (installed and configured)
- ~38,000 events across 4 sourcetypes

**Phase 2: BOTS v1 attack dataset**
- Boss of the SOC Version 1, attack-only subset
- 955,807 events across 22 sourcetypes
- Sysmon, Suricata IDS, Fortinet firewall, Windows Security, Windows Registry,
  Splunk Stream (HTTP, DNS, SMB, TCP, IP, ICMP, MAPI, LDAP), IIS

---

# Phase 1: Live Host Telemetry

## Log Sources Onboarded

| Sourcetype | Events | Purpose |
|---|---|---|
| WinEventLog:Security | 24,853 | Authentication, logons, privilege use |
| XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | 10,471 | Process creation, network connections |
| WinEventLog:System | 2,146 | Services, drivers, hardware |
| WinEventLog:Application | 528 | Installed application events |

## 1. EventCode Baseline

Ran a full distribution query before writing any detections, to understand what
activity actually existed.

```spl
sourcetype=WinEventLog:Security
| stats count by EventCode
| sort - count
```

**Finding:** 32 distinct event types. Two codes (4907 and 5379) accounted for
over 90% of total volume.

## 2. Noise Source Investigation

EventCode 4907 (auditing settings on object changed) appeared 16,947 times,
roughly 70% of all events. Rather than filtering it blindly, I traced it to
its source.

```spl
sourcetype=WinEventLog:Security EventCode=4907
| stats count by Process_Name
| sort - count
```

**Finding:** 100% of 4907 events came from three Windows Update processes:
TiWorker.exe (9,864), wuaucltcore.exe (6,160), and DismHost.exe (923). The
spike was a patch cycle, not malicious activity. These are tuning candidates:
filtering known-good update processes removes ~70% of log volume and surfaces
higher-value events.

**Takeaway:** high volume from a single event code always warrants
investigation before dismissal. Equally, absence of events is not absence of
activity, it may mean the relevant audit policy is disabled.

## 3. Authentication and Privilege Baseline

```spl
sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name
| sort - count
```

```spl
sourcetype=WinEventLog:Security EventCode=4672
| stats count by Account_Name
| sort - count
```

**Finding:** 11 accounts with successful logons, 7 receiving admin-level
privileges. Most were expected (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM,
Splunkd). One was a GUID-named virtual service account that would warrant
follow-up in a production environment.

**MITRE ATT&CK:** T1078 Valid Accounts

## 4. Sysmon Process Telemetry

Installed Sysmon to capture host telemetry beyond what the built-in Windows
channels provide. Sysmon events are stored as raw XML, so field extraction
required `rex` rather than relying on parsed fields.

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| where EventID="1"
| stats count by Image
| sort - count
```

**Finding:** 69 distinct executables. Splunk's own processes dominated
post-installation, reinforcing that a baseline must be established after any
major software change before anomaly detection is meaningful.

## 5. Parent-Child Process Detection Logic

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| where EventID="1"
| stats count by ParentImage, Image
| sort - count
```

**Detection logic:** parent-child chains reveal execution that is anomalous in
context. Word.exe spawning cmd.exe indicates a malicious macro. svchost.exe
spawning reconnaissance tooling indicates a compromised service. On this host
all cmd.exe instances traced back to Splunk internals, which was expected.

**MITRE ATT&CK:** T1059 Command and Scripting Interpreter

---

# Phase 2: BOTS v1 Attack Investigation

## Loading the Dataset

The pre-indexed BOTS buckets are timestamped August 2016. Splunk's default
`frozenTimePeriodInSecs` (188,697,600 seconds, roughly 6 years) caused it to
freeze and delete the buckets on every restart. Diagnosed via
`splunkd.log` (`Reason=' frozen_buckets'`) and resolved by setting a 100-year
retention override on the `[botsv1]` index stanza before copying the buckets in.

**Takeaway:** retention policy silently governs data availability. Data can be
present on disk and still be unsearchable.

## 6. Attacker Identification via Traffic Volume

```spl
index=botsv1 sourcetype=stream:http
| stats count by src_ip, dest_ip
| sort - count
```

**Finding:** 40.80.148.42 sent 17,546 HTTP requests to internal host
192.168.250.70. The next highest external source sent 1,429, a 12x gap.
Internal sources were all in the low hundreds. External-to-internal traffic at
that volume against a web server is automated, not human.

## 7. Web Attack Analysis

```spl
index=botsv1 sourcetype=stream:http src_ip="40.80.148.42"
| stats count by http_method, uri_path
| sort - count
```

**Finding:** the attack was not primarily credential-based.
- 11,923 POST requests to `/joomla/index.php/component/search/` (68% of
  traffic), consistent with automated injection testing against a form input
- Only 14 POSTs to `/joomla/administrator/index.php`, far too few for a
  credential brute force
- `GET /windows/win.ini` (75), `GET /boot.ini` (25), and
  `GET /windows/win.ini%00.jpg` (25), which are path traversal and local file
  inclusion probes. The `%00` is a null byte injection used to defeat file
  extension filtering

**MITRE ATT&CK:** T1595.002 Active Scanning: Vulnerability Scanning,
T1190 Exploit Public-Facing Application, T1027 Obfuscated Files or Information

## 8. Attack Timeline Reconstruction

```spl
index=botsv1 sourcetype=stream:http src_ip="40.80.148.42"
| timechart span=5m count by http_method
```

**Finding:** the attack ran roughly 45 minutes with a clear phase change.
- **17:35** reconnaissance: 2,395 GET vs 102 POST, plus scanner-characteristic
  methods (OPTIONS, PROPFIND, TRACE, CONNECT) used to enumerate server
  capabilities
- **17:40 to 17:45** transition: GET declining, POST volume shifting
- **17:50 onward** exploitation: GET drops to zero, POST sustains at roughly
  1,500 to 2,200 per five-minute interval

The GET-to-POST crossover marks the shift from enumeration to payload
delivery. Sustained volume over 45 minutes confirms automation. Scattered
malformed requests throughout align with the null byte injection attempts.

## 9. Windows Credential Attack

```spl
index=botsv1 sourcetype=wineventlog:security
| rex field=_raw "EventCode=(?<EventCode>\d+)"
| rex field=_raw "Logon Account:\s+(?<acct>\S+)"
| rex field=_raw "Source Workstation:\s+(?<workstation>\S+)"
| where EventCode="4776"
| stats count by acct, workstation
| sort - count
```

**Finding:** 2,382 of 2,384 credential validation events (EventCode 4776)
targeted a single account, `Administrator`, against the `waynecorpinc.local`
domain. The remaining two were single events from workstation WE8105DESK. That
degree of concentration on one privileged account is the signature of a
password guessing attack.

**MITRE ATT&CK:** T1110.001 Brute Force: Password Guessing

Note: EventCode 4776 fires on both successful and failed validation. The Error
Code field distinguishes them (0x0 success, 0xC000006A bad password) and
breaking down by error code is a logical next step for confirming attempt
outcomes.

## 10. BOTS Sysmon Telemetry

```spl
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort - count
```

**Finding:** 270,597 Sysmon events across 6 event types.

| EventID | Meaning | Count |
|---|---|---|
| 7 | Image (DLL) loaded | 168,374 |
| 3 | Network connection | 99,320 |
| 2 | File creation time changed | 1,434 |
| 1 | Process creation | 767 |
| 5 | Process terminated | 684 |
| 6 | Driver loaded | 18 |

**Event ID 2 is the notable one.** It fires when a process modifies a file's
creation timestamp, which is timestomping, an anti-forensics technique used to
backdate malicious files so they blend with legitimate system files and evade
timeline analysis. 1,434 occurrences is well above benign background levels.

**MITRE ATT&CK:** T1070.006 Indicator Removal: Timestomp

The volume profile also differs sharply from the live host, where process
creation dominated. Here DLL loads and network connections dominate, which is
why Event ID 7 is commonly filtered in production deployments.

---

## Detection Alerting

Built a scheduled alert (`Failed Credential Validation Spike`) on the 4776
query with a results-based trigger condition, demonstrating the transition from
ad-hoc search to standing detection.

## Dashboard

Three-panel Classic Dashboard covering EventCode distribution, privilege
assignment by account, and Sysmon process creation activity.

---

## Windows Event Codes Referenced

| Code | Meaning | Security Relevance |
|---|---|---|
| 4624 | Successful logon | Baseline; anomalies suggest lateral movement |
| 4625 | Failed logon | Brute force detection |
| 4648 | Explicit credential use | Lateral movement, runas abuse |
| 4672 | Special privileges assigned | Privilege escalation monitoring |
| 4688 | Process created | Malicious execution |
| 4689 | Process exited | Process lifecycle correlation |
| 4720 | User account created | Persistence |
| 4776 | Credential validation attempted | NTLM brute force detection |
| 4907 | Audit settings changed | High noise; tune against known-good |
| 5140 | Network share accessed | Lateral movement via SMB |
| 5145 | Share object access check | Detailed share access auditing |
| 5379 | Credential Manager read | Mostly benign browser activity |

## Sysmon Event IDs Referenced

| ID | Meaning | Security Relevance |
|---|---|---|
| 1 | Process creation | Malicious execution, T1059 |
| 2 | File creation time changed | Timestomping, T1070.006 |
| 3 | Network connection | C2 beaconing, T1071 |
| 5 | Process terminated | Lifecycle tracking |
| 6 | Driver loaded | Rootkit and driver abuse |
| 7 | Image loaded | DLL side-loading, T1574.002 |
| 16 | Sysmon config changed | Tampering with logging itself |

## SPL Concepts Demonstrated

- `sourcetype` and `index` filtering to scope searches
- `stats count by` for aggregation across one or more fields
- `timechart span=` for time-series reconstruction
- `rex` named capture groups for extracting fields from raw XML and
  unstructured text where add-on field extractions were unavailable
- `where` for post-aggregation filtering
- Pipeline chaining to transform results through successive stages
- Scheduled alerting with trigger conditions

## Screenshots

| File | Description |
|---|---|
| 01_eventcode_baseline.png | EventCode distribution, 32 types across 24,000+ events |
| 02_4907_drilldown.png | Windows Update processes identified as noise source |
| 03_successful_logons.png | Logon frequency baseline by account |
| 04_privilege_assignment.png | Admin privilege assignment by account |
| 05_sourcetype_overview.png | Four live log sources confirmed in index |
| 06_sysmon_process_creation.png | 69 executables captured via Sysmon Event ID 1 |
| 07_sysmon_parent_child.png | Parent-child process relationships |
| 08_dashboard.png | Three-panel SOC Detection Lab dashboard |
| 09_botsv1_sourcetypes.png | 955,807 BOTS events across 22 sourcetypes |
| 10_botsv1_attacker_identification.png | Attacker isolated by traffic volume |
| 11_botsv1_web_attack_analysis.png | Scanner activity and path traversal probes |
| 12_botsv1_attack_timeline.png | 45-minute attack timeline, recon to exploitation |
| 13_botsv1_credential_attack.png | 2,382 credential attempts against Administrator |
| 14_botsv1_sysmon_eventids.png | BOTS Sysmon distribution, timestomping identified |
| 15_splunk_alert.png | Scheduled detection alert |

## Next Steps

- [ ] Break down 4776 error codes to separate failed from successful validations
- [ ] Investigate the phishing scenario via stream:smtp and stream:mapi
- [ ] Investigate data exfiltration indicators in stream:http POST bodies
- [ ] Correlate Sysmon Event ID 3 network connections against Suricata IDS alerts
- [ ] Cross-reference EventCode 5145 share access against stream:smb traffic
- [ ] Build a dedicated BOTS investigation dashboard

# Windows Event Log Clearing Detection Lab

## Overview

This lab demonstrates detection of Windows Event Log clearing behavior using Elastic Security and Windows Security Event ID 4688 process creation telemetry.

The goal of this lab was to simulate event log clearing in a controlled Windows lab environment, detect the activity in Elastic, validate alert generation, and document the investigation from a SOC analyst perspective.

This activity maps to MITRE ATT&CK technique **T1070.001 - Clear Windows Event Logs**, which falls under the **Defense Evasion** tactic.

---

## Objective

The objectives of this lab were to:

- Validate that Windows process creation telemetry was being collected by Elastic
- Confirm that command-line arguments were captured for process creation events
- Simulate Windows Event Log clearing using `wevtutil.exe`
- Detect `wevtutil.exe` execution with log-clearing arguments
- Create and validate an Elastic detection rule
- Analyze the generated alert using SOC investigation fields
- Connect PowerShell execution context to log-clearing behavior
- Document the detection logic, validation steps, and lessons learned for portfolio use

---

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 11 Enterprise Evaluation |
| Hostname | `desktopwin11` |
| User | `User1` |
| SIEM | Elastic Security |
| Agent | Elastic Agent / Filebeat |
| Data Stream | `logs-system.security-default` |
| Windows Log Source | Security Event Log |
| Primary Event ID | `4688` |
| Main Utility Tested | `wevtutil.exe` |
| Parent Process Observed | `powershell.exe` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion | Clear Windows Event Logs | T1070.001 |

---

## Why This Detection Matters

Attackers may attempt to clear Windows Event Logs after gaining access to a system in order to remove evidence of their activity. Detecting log-clearing behavior helps identify potential post-compromise activity and defense evasion attempts.

This lab focuses on detecting use of the native Windows utility `wevtutil.exe` when it is used with the `cl` argument to clear an event log.

Example command:

```powershell
wevtutil cl Application
```

While administrators may use this utility for legitimate maintenance, unexpected use of `wevtutil.exe` to clear logs should be investigated, especially when launched from scripting environments such as PowerShell.

---

## Telemetry Validation

Before creating the detection rule, I validated that Windows process creation telemetry was flowing into Elastic.

A benign test process, `Notepad.exe`, was executed on the Windows 11 lab endpoint. Elastic successfully ingested the event as a Windows Security Event ID 4688 process creation event.

Observed validation fields included:

| Field | Value |
|---|---|
| `event.action` | `created-process` |
| `event.code` | `4688` |
| `event.category` | `process` |
| `event.dataset` | `system.security` |
| `process.name` | `Notepad.exe` |
| `process.command_line` | Captured successfully |
| `user.name` | `User1` |
| `host.name` | `desktopwin11` |
| `winlog.channel` | `Security` |

This confirmed that process creation auditing and command-line logging were functioning before moving into the log-clearing simulation.

### Validation Query

```kql
event.action: "created-process" and process.name.caseless: "notepad.exe"
```

Alternative validation query:

```kql
event.code: "4688" and process.name.caseless: "notepad.exe"
```

---

## Simulation

The following command was executed from an elevated PowerShell session in the lab environment:

```powershell
wevtutil cl Application
```

This command clears the Windows Application event log.

Elastic captured the activity as a Windows Security Event ID 4688 process creation event.

Observed fields included:

| Field | Value |
|---|---|
| `event.action` | `created-process` |
| `event.code` | `4688` |
| `event.category` | `process` |
| `process.name` | `wevtutil.exe` |
| `process.executable` | `C:\Windows\System32\wevtutil.exe` |
| `process.command_line` | `"C:\WINDOWS\system32\wevtutil.exe" cl Application` |
| `process.args` | `"cl"`, `"Application"` |
| `process.parent.name` | `powershell.exe` |
| `process.parent.executable` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `user.name` | `User1` |
| `host.name` | `desktopwin11` |
| `winlog.channel` | `Security` |

---

## Hunt Queries

The initial hunt query used to locate process creation activity was:

```kql
event.action: "created-process"
```

The query was then narrowed to locate `wevtutil.exe` execution:

```kql
event.action: "created-process" and process.name.caseless: "wevtutil.exe"
```

A broader command-line search was also tested:

```kql
event.action: "created-process" and process.command_line: "*wevtutil*"
```

To identify log-clearing behavior specifically, the query was refined to include the `cl` argument:

```kql
event.action: "created-process" and process.name.caseless: "wevtutil.exe" and process.args: "cl"
```

---

## Detection Logic

### Primary Detection Query

```kql
event.action: "created-process" and
event.code: "4688" and
process.name.caseless: "wevtutil.exe" and
process.args: "cl"
```

This query detects creation of the `wevtutil.exe` process when the `cl` argument is used, indicating an attempt to clear a Windows Event Log.

---

## Higher-Confidence Detection Logic

A higher-confidence version of the detection includes the parent process relationship observed during testing:

```kql
event.action: "created-process" and
event.code: "4688" and
process.name.caseless: "wevtutil.exe" and
process.args: "cl" and
process.parent.name.caseless: "powershell.exe"
```

This version is more suspicious because PowerShell launched `wevtutil.exe`.

PowerShell is commonly used by administrators, but it is also frequently abused by attackers to execute native Windows utilities during post-compromise activity. The parent-child process relationship helps provide additional investigation context.

---

## Detection Rule

| Setting | Value |
|---|---|
| Rule Name | Windows Event Log Clearing via Wevtutil |
| Rule Type | Custom Query |
| Severity | Medium |
| Risk Score | 47 |
| Data Source | Windows Security Event ID 4688 |
| MITRE Tactic | Defense Evasion |
| MITRE Technique | Clear Windows Event Logs |
| MITRE ID | T1070.001 |

### Rule Query

```kql
event.action: "created-process" and
event.code: "4688" and
process.name.caseless: "wevtutil.exe" and
process.args: "cl"
```

---

## Alert Validation

After creating the Elastic detection rule, the simulation command was executed again:

```powershell
wevtutil cl Application
```

The detection rule successfully generated an alert in Elastic Security.

The alert confirmed that Elastic detected the log-clearing behavior using Windows Security Event ID 4688 process creation telemetry.

Key alert fields reviewed:

| Question | Field |
|---|---|
| What process executed? | `process.name` |
| What command was run? | `process.command_line` |
| What arguments were used? | `process.args` |
| Who executed it? | `user.name` |
| What host was affected? | `host.name` |
| What launched it? | `process.parent.name` |
| What event captured it? | `event.code` |
| What log source captured it? | `winlog.channel` |

---

## Analyst Investigation Summary

An Elastic Security alert was generated after `wevtutil.exe` was executed with the `cl` argument to clear the Windows Application event log.

The event was captured as Windows Security Event ID 4688 with `event.action` set to `created-process`.

The observed command line was:

```text
"C:\WINDOWS\system32\wevtutil.exe" cl Application
```

The process was launched by:

```text
powershell.exe
```

The activity occurred on:

```text
desktopwin11
```

The user context was:

```text
User1
```

This behavior may indicate an attempt to remove forensic evidence from a Windows endpoint. The use of PowerShell as the parent process increases investigative interest because scripting environments are commonly used to execute native Windows utilities during attacker activity.

---

## Detection Value

This detection provides visibility into defense evasion behavior involving Windows Event Log clearing.

The detection is valuable because it identifies:

- Use of a native Windows utility associated with clearing logs
- Command-line arguments showing log-clearing intent
- The user account associated with the activity
- The host where the activity occurred
- The parent process that launched the utility
- A behavior mapped to MITRE ATT&CK T1070.001

Detecting this activity can help analysts identify potential attempts to cover tracks after suspicious activity has occurred on a system.

---

## Screenshots

Suggested screenshots for this lab:

| Screenshot | Description |
|---|---|
| `01-telemetry-validation-notepad.png` | Benign Notepad process creation event proving 4688 telemetry is working |
| `02-wevtutil-discover-event.png` | `wevtutil.exe` event showing command line, arguments, user, host, and parent process |
| `03-alert-fired.png` | Elastic Security alert generated by the detection rule |

Suggested image path:

```text
/images/log-clearing/
```

Example Markdown image links:

```markdown
![Telemetry validation showing Notepad process creation](../images/log-clearing/01-telemetry-validation-notepad.png)

![wevtutil event in Elastic Discover](../images/log-clearing/02-wevtutil-discover-event.png)

![Elastic alert generated by log clearing detection rule](../images/log-clearing/03-alert-fired.png)
```

Note: Screenshots should be reviewed and sanitized before publishing. Internal IP addresses, host identifiers, usernames, or environment-specific details can be cropped or blurred if needed.

---

## Lessons Learned

- Windows Security Event ID 4688 provides valuable process creation telemetry
- Command-line logging is important for determining process intent
- `process.args` can provide cleaner detection logic than raw command-line wildcard searches
- Parent process context helps distinguish basic execution from potentially more suspicious execution chains
- PowerShell launching `wevtutil.exe` creates a stronger detection story than detecting `wevtutil.exe` alone
- Validating benign process telemetry before testing suspicious behavior helps confirm that the data pipeline is working
- Detection engineering requires connecting behavior, telemetry, logic, alerting, and investigation context

---

## Possible Improvements

Future improvements for this lab could include:

- Testing log clearing for `System`, `Security`, and `Application` logs
- Adding a detection for Windows Event ID 1102 when the Security audit log is cleared
- Adding a detection for Windows Event ID 104 when other Windows logs are cleared
- Building a timeline showing suspicious PowerShell execution followed by log clearing
- Creating a higher-confidence correlation rule for suspicious PowerShell activity followed by `wevtutil.exe`
- Tuning the rule to reduce false positives from legitimate administrative maintenance
- Adding screenshots of the full alert investigation workflow
- Comparing process creation telemetry against native Windows log-clearing event IDs

---

## Portfolio Summary

This lab demonstrates a complete detection engineering workflow:

```text
Telemetry validation
        ↓
Attack behavior simulation
        ↓
KQL hunting
        ↓
Detection rule creation
        ↓
Alert validation
        ↓
SOC-style investigation
        ↓
MITRE ATT&CK mapping
        ↓
GitHub documentation
```

The final detection identified Windows Event Log clearing behavior using `wevtutil.exe` and successfully generated an Elastic Security alert. The lab also showed how parent process context, specifically PowerShell launching `wevtutil.exe`, can improve the investigation value of a detection.

This project strengthened my understanding of Windows process creation telemetry, command-line auditing, Elastic detection rules, and defense evasion detection mapped to MITRE ATT&CK T1070.001.

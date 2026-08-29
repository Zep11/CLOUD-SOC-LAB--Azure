# 🖥️ Endpoint Security Investigation

## 📌 Overview

This scenario focuses on investigating suspicious endpoint activity using **Microsoft Defender for Endpoint** and **Microsoft Sentinel**. Endpoint telemetry was analyzed to understand process execution, command-line activity, and relationships between processes.

---

## 🎯 Objective

- Detect suspicious endpoint activity
- Investigate process execution
- Analyze parent-child process relationships
- Review command-line activity
- Investigate device timelines
- Correlate endpoint alerts with Microsoft Sentinel

---

## 🛠️ Technologies Used

- Microsoft Defender for Endpoint
- Microsoft Sentinel
- Advanced Hunting
- KQL
- Device Timeline
- MITRE ATT&CK

---

## 🔎 Investigation Workflow

```text
Suspicious Endpoint Activity
          │
          ▼
Microsoft Defender for Endpoint
          │
          ▼
Process / Device Telemetry
          │
          ├── Process Execution
          ├── Parent Process
          ├── Command Line
          └── Device Timeline
          │
          ▼
Microsoft Sentinel Investigation
          │
          ▼
Incident Analysis
```

---

## 🧠 Key Investigation Areas

- Process name
- Process command line
- Parent process
- Child processes
- Device name
- User context
- Process execution timeline
- Related endpoint activity

---

## 🔍 Threat Hunting

Example Advanced Hunting query:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Investigation Area |
|---|---|
| Execution | Suspicious process execution |
| Discovery | System and process reconnaissance |
| Defense Evasion | Suspicious command execution |

---

## 📊 Outcome

The investigation demonstrated how endpoint telemetry can be used to reconstruct suspicious activity by analyzing processes, command lines, parent-child relationships, and device timelines.

---

## 📁 Contents

```text
03-Scenario-2-Endpoint-Detection
│
├── README.md
├── Screenshots
└── Incident-Report
```

---

## 📌 Project Status

🟢 **Completed**

This scenario successfully demonstrates endpoint detection and investigation using Microsoft Defender for Endpoint and Microsoft Sentinel.

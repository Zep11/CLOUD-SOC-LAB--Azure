# 🔐 Identity Security Investigation

## 📌 Overview

This scenario focuses on investigating suspicious authentication activity using **Microsoft Entra ID** and **Microsoft Sentinel**. The objective was to analyze identity-related security events, investigate the affected user, and determine whether suspicious login activity required further response.

---

## 🎯 Objective

- Monitor authentication activity
- Investigate failed and successful sign-ins
- Identify suspicious users and login patterns
- Analyze related security events in Microsoft Sentinel
- Document investigation findings

---

## 🛠️ Technologies Used

- Microsoft Entra ID
- Microsoft Sentinel
- Log Analytics Workspace
- KQL
- MITRE ATT&CK

---

## 🔎 Investigation Workflow

```text
Authentication Activity
        │
        ▼
Microsoft Entra ID Logs
        │
        ▼
Microsoft Sentinel
        │
        ▼
Security Investigation
        │
        ├── Failed Sign-ins
        ├── Successful Sign-ins
        ├── User Analysis
        └── Related Activity
        │
        ▼
Incident Findings
```

---

## 🧠 Key Investigation Areas

- Failed authentication attempts
- Successful authentication events
- User account involved
- Source IP analysis
- Login patterns
- Related Sentinel incidents
- Potential unauthorized access

---

## 🔍 Detection & Investigation

KQL queries were used to analyze identity telemetry and investigate suspicious authentication activity.

Example investigation focus:

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription
| order by TimeGenerated desc
```

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | Valid Accounts |
| Credential Access | Brute Force |
| Defense Evasion | Valid Account Abuse |

---

## 📊 Outcome

The scenario demonstrated how a SOC analyst can investigate identity-related security events by correlating authentication logs, user activity, source information, and Microsoft Sentinel alerts.

---

## 📁 Contents

```text
02-Scenario-1-Identity-Detection
│
├── README.md
├── Screenshots
└── Incident-Report
```

---

## 📌 Project Status

🟢 **Completed**

This scenario successfully demonstrates identity monitoring and security investigation using Microsoft Entra ID and Microsoft Sentinel.

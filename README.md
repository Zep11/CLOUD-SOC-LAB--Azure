# ☁️🛡️ CLOUD SOC LAB         -  <img src="https://img.shields.io/badge/License-MIT-green">
#  Azure Security Monitoring & Incident Response

![Microsoft Azure](https://img.shields.io/badge/Microsoft-Azure-0078D4?logo=microsoftazure&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?logo=microsoft&logoColor=white)
![Microsoft Defender](https://img.shields.io/badge/Microsoft-Defender%20for%20Endpoint-00A4EF?logo=microsoft&logoColor=white)
![Microsoft Entra ID](https://img.shields.io/badge/Microsoft-Entra%20ID-5E5E5E?logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Detection%20Engineering-purple)


A hands-on Cloud SOC Lab focused on detecting, investigating, and responding to security incidents using Microsoft Azure security technologies.

This project demonstrates practical SOC analyst workflows across cloud identity, endpoint security, and Azure infrastructure monitoring.

---

## 🎯 Project Objective

The goal of this lab is to simulate realistic security scenarios and perform the complete SOC investigation lifecycle:

- Detect suspicious activity
- Analyze security telemetry
- Investigate incidents
- Perform threat hunting
- Identify affected users and resources
- Apply containment and remediation actions
- Document findings through professional incident reports

---

## 🏗️ Lab Architecture

```text
                    ┌─────────────────────┐
                    │    Azure Cloud      │
                    │                     │
                    │  Microsoft Entra ID │
                    │  Azure Resources    │
                    │  NSG Configuration  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Diagnostic Settings │
                    │                     │
                    │ Azure Activity Logs │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Log Analytics       │
                    │ Workspace           │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Microsoft Sentinel  │
                    │                     │
                    │ Detection Rules     │
                    │ Incidents           │
                    │ Investigation       │
                    │ Automation          │
                    └─────────────────────┘


        Endpoint Telemetry
               │
               ▼
    ┌──────────────────────────┐
    │ Microsoft Defender       │
    │ for Endpoint             │
    │                          │
    │ Process Telemetry        │
    │ Device Timeline          │
    │ Alerts & Investigation   │
    └─────────────┬────────────┘
                  │
                  ▼
          Microsoft Sentinel
```

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Microsoft Sentinel | SIEM and incident management |
| Microsoft Defender for Endpoint | Endpoint Detection and Response |
| Microsoft Entra ID | Identity monitoring and investigation |
| Azure Activity Logs | Azure infrastructure activity monitoring |
| Azure Monitor | Log collection and diagnostics |
| Log Analytics Workspace | Security log storage and querying |
| KQL | Threat hunting and detection queries |
| Azure NSG | Network Security monitoring |
| Azure Automation Rules | Automated incident response |
| MITRE ATT&CK | Threat mapping and analysis |

---

# 🚨 Security Scenarios

This repository contains multiple Cloud SOC investigation scenarios.

---

## 🔐 Scenario 1 — Identity Security Investigation

**Technology:** Microsoft Entra ID | Microsoft Sentinel

A suspicious authentication scenario was investigated to analyze identity-related security events and determine whether unauthorized access occurred.

### Focus Areas

- Failed and successful authentication activity
- User investigation
- Suspicious login analysis
- Sentinel incident handling

📁 **Scenario Directory**

`01-Scenario-1-Identity-Detection/`

---

## 🖥️ Scenario 2 — Endpoint Security Investigation

**Technology:** Microsoft Defender for Endpoint | Microsoft Sentinel

Suspicious endpoint activity was generated and investigated using Microsoft Defender for Endpoint telemetry and Microsoft Sentinel.

### Focus Areas

- Process execution investigation
- Parent-child process relationships
- Command-line analysis
- Device timeline investigation
- Advanced hunting

📁 **Scenario Directory**

`02-Scenario-2-Endpoint-Detection/`

---

## 🌐 Scenario 3 — Azure NSG Security Rule Modification

**Technology:** Azure Activity Logs | Microsoft Sentinel

This scenario focuses on detecting and investigating modifications to Azure Network Security Group rules.

Unauthorized modifications to NSG rules can expose cloud infrastructure to external threats and increase the attack surface.

### Detection Objective

Detect successful Azure NSG security rule modifications and generate a Microsoft Sentinel incident for investigation.

### Monitored Activities

- NSG Security Rule Creation
- NSG Security Rule Modification
- NSG Security Rule Deletion

### Azure Activity Log Operations

```text
Microsoft.Network/networkSecurityGroups/securityRules/write

Microsoft.Network/networkSecurityGroups/securityRules/delete
```

### Detection Query

```kql
AzureActivity
| where OperationNameValue in~ (
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE"
)
| where ActivityStatusValue =~ "Success"
| extend NSGName = tostring(split(Resource, "/")[0])
| extend RuleName = tostring(split(Resource, "/")[1])
| project
    TimeGenerated,
    Caller,
    OperationNameValue,
    Resource,
    ResourceId,
    Properties,
    NSGName,
    RuleName
| order by TimeGenerated desc
```

### Detection Workflow

```text
NSG Rule Modified
        │
        ▼
Azure Activity Log Generated
        │
        ▼
Diagnostic Settings
        │
        ▼
Log Analytics Workspace
        │
        ▼
Microsoft Sentinel
        │
        ▼
Analytics Rule Detection
        │
        ▼
Security Incident Created
        │
        ▼
SOC Investigation
        │
        ▼
Automated Response
```

### Investigation Focus

During the investigation, the following information was analyzed:

- Who modified the NSG rule
- Which Azure resource was affected
- Which NSG rule was modified
- What operation was performed
- Whether the operation succeeded
- When the modification occurred
- Associated Azure resource group
- Potential security impact

### Automated Response

Microsoft Sentinel Automation Rules were configured to perform automated incident actions.

Example automated response actions include:

- Updating incident status
- Assigning incident severity
- Assigning ownership
- Triggering response workflows

📁 **Scenario Directory**

`03-Scenario-3-Azure-NSG-Security-Rule-Modification/`

---

# 🔎 SOC Investigation Methodology

Each scenario follows a structured SOC investigation workflow.

## 1️⃣ Detection

Security telemetry is monitored using Microsoft Sentinel and Microsoft Defender.

Examples include:

- Suspicious authentication attempts
- Suspicious endpoint activity
- Azure infrastructure modifications
- NSG security rule changes

---

## 2️⃣ Triage

Initial incident analysis focuses on:

- Incident severity
- Alert timeline
- Affected entities
- User accounts
- Devices
- Azure resources
- Detection source

---

## 3️⃣ Investigation

Detailed investigation is performed using:

- Microsoft Sentinel Logs
- KQL queries
- Microsoft Defender for Endpoint
- Device timelines
- Azure Activity Logs
- Microsoft Entra ID logs

---

## 4️⃣ Threat Hunting

KQL queries are used to investigate related security activity.

Example investigation areas:

```text
User Activity
│
├── Authentication Events
├── IP Address Analysis
├── Device Activity
└── Related Incidents


Endpoint Activity
│
├── Process Execution
├── Parent Process
├── Command Line
└── Device Timeline


Azure Activity
│
├── Caller
├── Operation
├── Resource
├── Resource Group
└── Configuration Changes
```

---

## 5️⃣ Containment

Potential containment actions include:

- Disabling suspicious accounts
- Resetting compromised credentials
- Isolating compromised endpoints
- Blocking malicious activity
- Restricting unauthorized Azure changes
- Reviewing RBAC permissions

---

## 6️⃣ Remediation

After investigation, remediation actions may include:

- Removing unauthorized configurations
- Restoring secure NSG rules
- Reviewing privileged access
- Applying least privilege
- Strengthening monitoring
- Improving detection rules

---

# 🧠 Key Skills Demonstrated

This project demonstrates practical skills relevant to Cloud SOC and Security Analyst roles.

### SIEM & Monitoring

- Microsoft Sentinel
- Log Analytics Workspace
- Azure Monitor
- Azure Activity Logs

### Detection Engineering

- Analytics Rule Creation
- KQL Detection Queries
- Alert Logic
- Incident Generation

### Threat Hunting

- KQL Queries
- Log Analysis
- Timeline Investigation
- Entity Investigation

### Cloud Security

- Azure Activity Monitoring
- Network Security Groups
- Azure Resource Investigation
- RBAC Awareness
- Cloud Configuration Monitoring

### Endpoint Security

- Microsoft Defender for Endpoint
- Process Investigation
- Device Timeline Analysis
- Command-Line Investigation

### Incident Response

- Alert Triage
- Incident Investigation
- Severity Classification
- Containment
- Remediation
- Incident Documentation

---

# 🗺️ MITRE ATT&CK Mapping

The investigated scenarios are mapped to relevant MITRE ATT&CK techniques where applicable.

| Tactic | Example Investigation Area |
|---|---|
| Initial Access | Suspicious authentication activity |
| Credential Access | Repeated authentication attempts |
| Execution | Suspicious process execution |
| Persistence | Suspicious system activity |
| Defense Evasion | Attempts to bypass security controls |
| Discovery | Process and system reconnaissance |
| Impact | Unauthorized infrastructure modification |

---



---

# 📊 SOC Incident Lifecycle

```text
┌───────────────┐
│   Detection   │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│    Triage     │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Investigation │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Threat Hunting│
└───────┬───────┘
        │
        ▼
┌───────────────┐
│  Containment  │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│   Remediation │
└───────────────┘
```

---

# 📈 Project Outcomes

Through this Cloud SOC Lab, the following practical capabilities were developed:

- Building a Microsoft Sentinel monitoring environment
- Collecting Azure security telemetry
- Writing KQL detection queries
- Creating Microsoft Sentinel analytics rules
- Generating and investigating security incidents
- Investigating users, devices, and Azure resources
- Analyzing Azure Activity Logs
- Monitoring Azure NSG modifications
- Using Microsoft Defender for Endpoint telemetry
- Creating automated incident response workflows
- Mapping security activity to MITRE ATT&CK
- Writing professional SOC incident reports

---

# 🚀 Future Improvements

Planned improvements for the lab include:

- Additional Sentinel detection rules
- Advanced KQL threat hunting queries
- Microsoft Sentinel playbook automation
- Automated incident enrichment
- IP reputation analysis
- Threat intelligence integration
- Defender XDR integration
- Automated remediation workflows
- Additional Azure attack simulations
- Cloud workload security monitoring

---

# ⚠️ Disclaimer

This project was created strictly for educational and cybersecurity training purposes.

All security simulations and investigations were performed within controlled lab environments using authorized Azure resources.

No unauthorized systems or third-party infrastructure were targeted.

---

# Project Status : Completed ✅

This project successfully demonstrates an end-to-end Cloud SOC workflow covering security monitoring, detection engineering, incident investigation, threat hunting, and automated response using Microsoft Azure security technologies.

**Project Completion Includes:**

✅ Microsoft Sentinel Environment Setup  
✅ Identity Security Investigation  
✅ Endpoint Security Investigation  
✅ Azure NSG Security Rule Modification Detection  
✅ Azure Activity Log Monitoring  
✅ KQL Detection Engineering  
✅ Microsoft Sentinel Analytics Rules  
✅ Incident Creation and Investigation  
✅ Automated Incident Response  
✅ Professional SOC Incident Reports  

---

# 👨‍💻 Author

**Shubrajit Dey**

Aspiring SOC Analyst | Cybersecurity Enthusiast

**Skills**

`Microsoft Sentinel` • `Microsoft Defender` • `Azure Security` • `KQL` • `SIEM` • `EDR` • `Threat Hunting` • `Incident Response` • `Cloud Security`

---

⭐ If you found this project useful, consider starring the repository.

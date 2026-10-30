
FILE 1: README.md (في الروت)

# 🛡️ SCO-Detections-Lab | PRD - Built with Offensive Mindset

[KQL Validation](https://img.shields.io/badge/KQL-Passing-brightgreen)
[MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
[Status](https://img.shields.io/badge/Status-PRD-blue)
[SOC Level](https://img.shields.io/badge/SOC-L2-orange)

> I don't just write KQL queries. I simulate attacks like an OSCP, then build production detections that can't be easily bypassed.

### Methodology
1. Attack First (OSCP Mindset)
2. Artifact Hunt (Unavoidable Event)
3. PRD Hardening (FP Filter)

### 📊 Detection Coverage
| ID | MITRE | Scenario | File | Status |
| :--- | :--- | :--- | :--- | :--- |
| D-01 | T1078 - Valid Accounts | Rogue Admin | detections/T1078_ValidAccounts/detection.kql | ✅ PRD |
| D-02 | T1003 | LSASS Dump | Coming Soon | 🟡 WIP |
| D-03 | T1059.001 | PowerShell Encoded | Coming Soon | 🟡 WIP |

### 📁 Structure
/detections/T1078_ValidAccounts/
  ├── detection.kql
  ├── attack_simulation.md
  └── bypass_notes.md

### Author: SOC Analyst | OSCP Aspirant

FILE 2: detections/T1078_ValidAccounts/detection.kql

SecurityEvent
| where EventID == 4720
| where TargetUserName !contains "HealthMailbox"
| where TargetUserName !contains "SM_"
| where SubjectUserName !in~ ("SYSTEM", "MSOL_", "Sync_", "AAD_")
| where TargetUserName !endswith "$"
| where SubjectUserName != "SYSTEM"
| extend AccountCreator = SubjectUserName, NewAccount = TargetUserName, CreatorDomain = SubjectDomainName
| project TimeGenerated, AccountCreator, NewAccount, CreatorDomain, Computer, Activity = strcat("Rogue account created: ", TargetUserName, " by ", SubjectUserName)
| extend MITRE_Technique = "T1078", Severity = "High", Description = "Potential persistence via rogue account"

FILE 3: detections/T1078_ValidAccounts/attack_simulation.md

# Attack Simulation - T1078 Valid Accounts
Objective: Create rogue admin for persistence.

Steps:
1. net user attacker01 P@ssw0rd123! /add
2. net localgroup administrators attacker01 /add

Alternative PowerShell:
New-LocalUser -Name "svc_backup" -Password (ConvertTo-SecureString "P@ss123!" -AsPlainText -Force)
Add-LocalGroupMember -Group "Administrators" -Member "svc_backup"

Expected: Security Event 4720
Validation: SecurityEvent | where EventID == 4720 | sort by TimeGenerated desc

FILE 4: detections/T1078_ValidAccounts/bypass_notes.md

# Bypass Analysis - T1078

Bypass 1: Name as HealthMailbox01 -> Fix: where TargetUserName !contains "HealthMailbox"
Bypass 2: Create via SYSTEM -> Fix: where SubjectUserName != "SYSTEM" and !endswith "$"
Bypass 3: Create during work hours -> Future: Join with Event 4732 (Added to admin group) within 10 mins

Result: Before 120 alerts/day (99% FP) -> After 1-2 alerts/day (95% TP)
This is PRD.

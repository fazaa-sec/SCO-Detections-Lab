# 🛡️ SOC Detections Lab - PRD Detections Built with Offensive Mindset

![KQL](https://img.shields.io/badge/KQL-Passing-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![PRD](https://img.shields.io/badge/Status-PRD-blue)
![SOC](https://img.shields.io/badge/Level-SOC_L2-orange)

> Junior SOC writes queries. L2 SOC builds detections that survive evasion. This repo is built with OSCP attack-first mindset.

### 🎯 Philosophy
**Attack → Artifact → Filter.** I simulate the attack as an attacker, find the unavoidable Windows Event, then filter 99% of False Positives.

### 📊 Detections
| ID | MITRE ATT&CK | Scenario | KQL | Evasion Fix | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| D-01 | T1078 - Valid Accounts | Rogue Admin Persistence | [detection.kql](Detections/T1078_ValidAccounts/detection.kql) | Filters HealthMailbox, SYSTEM, $ | ✅ PRD |

### 📁 Structure (L2 Standard)

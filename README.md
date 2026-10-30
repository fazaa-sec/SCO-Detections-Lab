# 🛡️ SOC-Detections | PRD - Built with Offensive Mindset

![KQL Validation](https://img.shields.io/badge/KQL-Passing-brightgreen)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Status](https://img.shields.io/badge/Status-PRD-blue)
![SOC Level](https://img.shields.io/badge/SOC-L2-orange)

> I don't just write KQL queries. I simulate attacks like an OSCP, then build production detections that can't be easily bypassed.

### Methodology: Offensive -> Defensive

1.  **Attack First (OSCP Mindset):** How would I exploit this in a real engagement?
2.  **Artifact Hunt:** What Windows Event is unavoidable even if attacker tries to evade?
3.  **PRD Hardening:** Filter False Positives that make Junior SOC rules useless.

### 📊 Detection Coverage

| ID | MITRE Technique | Attack Scenario | Detection File | Bypass Mitigation | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **D-01** | **T1078 - Valid Accounts** | Attacker creates a rogue admin account for persistence | [detection.kql](detections/T1078_ValidAccounts/detection.kql) | Filters `HealthMailbox`, `SYSTEM`, `Sync_*` service accounts | **✅ PRD** |
| **D-02** | **T1003 - Credential Dumping** | LSASS memory dump via Mimikatz | `detections/T1003_LSASS_Access/detection.kql` | Excludes AV / EDR processes | 🟡 In Lab |
| **D-03** | **T1059.001 - PowerShell** | Encoded PowerShell command execution | `detections/T1059_PowerShell/detection.kql` | - | 🟡 In Lab |

### 📁 Repository Structure (PRD Standard)

Each detection follows the L2 standard: Detection + Attack + Bypass.


### 🔬 Example: T1078 Detection Logic

**Junior Rule (Noisy):**
```kql
SecurityEvent | where EventID == 4720 // 100+ false positives / day
SecurityEvent
| where EventID == 4720
| where TargetUserName !contains "HealthMailbox"
| where SubjectUserName !in~ ("SYSTEM", "MSOL_", "Sync_")
| where TargetUserName !endswith "$"
# 1. Simulate the attack
Invoke-AtomicTest T1078 -TestNumbers 1

# 2. Wait 2-5 mins for log ingestion
# 3. Check Microsoft Sentinel > Incidents
# Expected: [High] Possible Rogue Admin Created
Paste it in your README and your repo will look like a real company's detection repo.

Done? Send me a screenshot of the repo and I'll give you the final check.

# Sentinel PRD - Detection Engineering Framework
![KQL Validation](https://img.shields.io/badge/Build-Passing-brightgreen) ![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red) ![OSCP Mindset](https://img.shields.io/badge/Mindset-Offensive%20%2B%20Defensive-blue) ![Status](https://img.shields.io/badge/Status-Production--Ready-orange)

> Offensive-Thinking, Defensive-Building. This is not a KQL collection, it's a Detection Engineering Framework built with attacker mindset.

## 📊 MITRE ATT&CK Coverage
| Tactic | Techniques Covered | Detections |
| :--- | :--- | :--- |
| Execution | T1059.001 | 1 |
| Impact | T1486 | 1 |
| Persistence | T1053.003 | 1 |
| **Total** | **3 Techniques** | **3 PRD Rules** |

---
## 🔥 Detections - Offensive vs Defensive

### [CRITICAL] T1059.001 - Encoded PowerShell Obfuscation

**1. OSCP / Red Team Mindset - How I Attack:**
As an attacker, I will never run `Invoke-Mimikatz` in clear text. I will use:
`powershell -enc <base64>` to bypass AV signature and AMSI string detection. I can also use `-EncodedCommand` with parent spoofing via `explorer.exe`.

**2. Bypass I Considered:**
Attacker can use `-WindowStyle Hidden` + shorten `-enc` to `-e` to evade simple string match. Also can use PowerShell 7 `pwsh.exe`.

**3. PRD Detection Logic & FP Reduction:**
```kql
// PRD Rule: T1059.001 - High Fidelity
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("-EncodedCommand", "-enc", "-e ", "IEX", "FromBase64String")
| where CommandLine !has "Microsoft\\Windows\\Defender" // FP Reduction: Exclude Defender scans
| extend Severity = "High", MITRE_Tactic = "Execution", MITRE_Technique_ID = "T1059.001"
| project TimeGenerated, Computer, Account, CommandLine, ParentProcess, Severity
// PRD Rule: T1486 - Ransomware Pattern + Shadow Copy Deletion
let RansomwareExt = dynamic([".enc", ".locked", ".crypt", ".ryk"]);
SysmonEvent
| where EventID in (11, 1)
| where TargetFilename has_any (RansomwareExt) or CommandLine has "vssadmin delete shadows"
| summarize FileCount=count(), Files=makeset(TargetFilename) by Computer, bin(TimeGenerated, 2m)
| where FileCount > 15
| extend Severity = "Critical", MITRE_Tactic = "Impact", MITRE_Technique_ID = "T1486"
// PRD Rule: T1053.003 - Cron Abuse
SysmonEvent
| where EventID == 1
| where ParentImage has "cron" or Process has "cron"
| where CommandLine has_any ("nc", "ncat", "bash -i", "/dev/tcp", "curl", "wget", "python -c")
| where CommandLine !has "/usr/bin/apt" // FP Reduction
| extend Severity = "High", MITRE_Tactic = "Persistence", MITRE_Technique_ID = "T1053.003"
/detections/T1059.001/ - detection.kql + attack_simulation.md + bypass_notes.md
/mitre/navigator_layer.json - MITRE Navigator Layer
/.github/workflows/kql-lint.yml - PRD CI/CD

*Focused on Offensive-informed Defense*
> **Disclaimer:** This repository is for educational and defensive purposes only (Blue Team / SOC Lab).

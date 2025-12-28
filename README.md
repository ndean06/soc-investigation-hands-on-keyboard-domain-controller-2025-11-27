# SOC Investigation: Hands-On Keyboard Activity on Domain Controller
**Date:** 2025-11-27  
**Tools:** Microsoft Defender XDR, Advanced Hunting  
**System:** Windows Domain Controller (MTS-DC)  

---

## Overview

This repository documents an investigation into **hands-on keyboard (HoK) activity** detected on a **Windows Domain Controller**. Microsoft Defender XDR identified **interactive administrator activity**, including remote logons, manual command execution, directory discovery, and execution of a suspicious file. Defender ultimately **disrupted the activity** before further impact was observed.

All findings in this investigation are based directly on **Defender XDR alerts and Advanced Hunting telemetry**, as shown in the collected screenshots.

---

## Incident Summary

- **Alert Type:** Hands-on keyboard activity  
- **Severity:** High  
- **Detection Source:** Microsoft Defender XDR  
- **Account Used:** Built-in Administrator  
- **Target:** Domain Controller  

The investigation confirmed that valid administrator credentials were used to remotely access the domain controller. The attacker then performed **interactive actions**, including command execution and Active Directory discovery, before attempting to run a suspicious executable. Defender detected the behavior and initiated **attack disruption**.

---

## Initial Access

Logon telemetry shows:
- Successful administrator logons to the domain controller
- External source IP addresses
- NTLM authentication
- Logon timing aligned with later interactive activity

These events confirm that **valid credentials** were used for initial access.

---

## Interactive (Hands-On Keyboard) Activity

Process events show:
- PowerShell launched interactively
- Native Windows utilities executed
- Commands run under an active administrator session

The timing and execution patterns indicate **human-driven activity**, not automated malware.

---

## Discovery Activity

After access was established, the attacker performed:
- Directory and account discovery
- LDAP-related queries
- Enumeration actions tied to the same admin session

This behavior is consistent with **Active Directory reconnaissance** following privileged access.

---

## Suspicious File Activity

File and process telemetry identified:
- A new executable written to disk
- Execution shortly after discovery activity
- Elevated execution context

The file was later flagged as suspicious by Defender.

---

## Detection and Disruption

Microsoft Defender XDR:
- Raised high-confidence alerts tied to interactive activity
- Detected the suspicious executable
- Triggered **attack disruption**

Based on available evidence:
- No persistence was confirmed
- No lateral movement beyond the domain controller was observed
- No data exfiltration was identified

---

## MITRE ATT&CK Mapping (Observed)

| Tactic | Technique |
|------|----------|
| Initial Access | Valid Accounts (T1078) |
| Execution | PowerShell (T1059.001) |
| Discovery | Account Discovery (T1087) |
| Discovery | LDAP Enumeration |
| Defense Evasion | Living-off-the-Land |
| Impact | Attack Disruption |

---

## Investigation Artifacts

- **Detailed investigation steps:**  
  👉 [Walkthrough](walkthrough.md)

- **Formal incident report:**  
  👉 [Investigation Report (PDF)](investigation-report/investigation-report.pdf)

---

## Evidence Highlights

Screenshots captured during the investigation show:
- Defender XDR incident overview identifying HoK activity
- Successful administrator logons from external IPs
- Interactive PowerShell and native tool execution
- Active Directory discovery activity
- Suspicious file creation and execution
- Defender attack disruption actions

All evidence is stored in the `/screenshots` directory using original filenames for traceability.

---

## Skills Demonstrated

- SOC alert triage using Defender XDR
- Identity and credential abuse analysis
- Detection of hands-on keyboard activity
- Active Directory security monitoring
- Correlation of logon, process, and file telemetry
- Clear SOC-style investigation documentation

---

## Repository Structure

```text
├── README.md
├── walkthrough.md
├── investigation-report/
│   ├── investigation-report.md
│   └── investigation-report.pdf
├── screenshots/
├── queries/
├── timeline/
└── mitre-mapping/

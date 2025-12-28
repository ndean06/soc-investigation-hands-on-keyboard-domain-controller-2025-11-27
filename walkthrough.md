# SOC Investigation Walkthrough  
## Hands-On Keyboard Activity on Domain Controller
**Date:** 2025-11-27  
**System:** Windows Domain Controller (MTS-DC)  
**Tools:** Microsoft Defender XDR, Advanced Hunting  

---

## Step 1 — Alert Triage

**Objective:** Determine whether the alert represents real attacker activity.

The investigation began with a **Microsoft Defender XDR incident** classified as **hands-on keyboard activity** involving a domain controller. The incident indicated interactive behavior rather than automated malware.

![Defender XDR incident overview identifying hands-on keyboard activity](screenshots/2025-11-27-mts-dc-compromise-96.png)

*Defender XDR incident overview identifying hands-on keyboard activity*

---

## Step 2 — Validate Authentication Activity

**Objective:** Confirm how access to the domain controller occurred.

Advanced Hunting logon telemetry showed:
- Successful administrator logons
- External source IP addresses
- NTLM-based authentication
- Logon events occurring shortly before interactive activity

These events confirmed that **valid administrator credentials** were used to access the system.

![Successful administrator logons from external IP addresses](screenshots/2025-11-27-mts-dc-compromise-95.png)

*Successful administrator logons from external IP addresses*

---

## Step 3 — Confirm Hands-On Keyboard (Interactive) Activity

**Objective:** Validate that the activity was human-driven.

Process telemetry showed:
- PowerShell launched interactively
- Native Windows tools executed
- Activity tied to active administrator sessions

The process chain and timing indicate **manual attacker interaction**, not automated execution.

![Interactive PowerShell and native command execution under administrator context](screenshots/2025-11-27-mts-dc-compromise-77.png)

*Interactive PowerShell and native command execution under administrator context*

---

## Step 4 — Identify Discovery and Enumeration Activity

**Objective:** Determine attacker intent after access.

Following initial access, Defender telemetry captured:
- Directory and account discovery
- LDAP-related activity
- Enumeration actions tied to the same administrator session

This behavior aligns with **Active Directory reconnaissance** commonly performed after privileged access is obtained.

![LDAP and directory discovery activity following administrator logon](screenshots/2025-11-27-mts-dc-compromise-91.png)

*LDAP and directory discovery activity following administrator logon*

---

## Step 5 — Detect Suspicious File Activity

**Objective:** Identify potential malware or attacker tooling.

File and process events showed:
- A previously unseen executable written to disk
- Execution shortly after discovery activity
- Elevated execution context

This file was later flagged as suspicious by Defender.

![Creation of a suspicious executable on the domain controller](screenshots/2025-11-27-mts-dc-compromise-90.png)

*Creation of a suspicious executable on the domain controller*

---

## Step 6 — Defender Detection and Attack Disruption

**Objective:** Confirm security control response and impact.

Microsoft Defender XDR:
- Generated high-confidence alerts
- Detected the suspicious executable
- Triggered **attack disruption**

This response interrupted the activity before further progression.

![Defender XDR incident graph showing attack disruption actions](screenshots/2025-11-27-mts-dc-compromise-99.png)

*Defender XDR incident graph showing attack disruption actions*

---

## Step 7 — Scope and Impact Review

**Objective:** Determine whether the attack spread or persisted.

Additional review showed:
- No confirmed persistence mechanisms
- No confirmed lateral movement beyond the domain controller
- No evidence of data exfiltration

Network telemetry during the timeframe showed expected outbound connections only.

![Network activity showing no confirmed malicious outbound traffic](screenshots/2025-11-27-mts-dc-compromise-88.png)

*Network activity showing no confirmed malicious outbound traffic*

---

## Walkthrough Summary

This walkthrough demonstrates:
- Validation of a Defender XDR alert
- Authentication analysis confirming credential abuse
- Identification of hands-on keyboard activity
- Detection of Active Directory reconnaissance
- Identification of suspicious file execution
- Verification of Defender attack disruption
- Scoping to confirm limited impact

➡️ **For conclusions and remediation recommendations, see the formal investigation report.**

📄 [Investigation Report (PDF)](investigation-report/investigation-report.pdf)

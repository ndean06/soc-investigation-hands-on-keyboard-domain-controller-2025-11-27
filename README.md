# MTS-DC Compromise – SOC Alert Investigation

## Overview
This repository documents a simulated SOC investigation involving a suspected domain controller compromise (`mts-dc.mts.local`) triggered by multiple Microsoft Defender XDR alerts.

The investigation focuses on:
- Brute force and password spray activity
- Successful NTLM network logons
- Hands-on-keyboard behavior
- Lateral movement attempts
- Process execution and file creation analysis

**Status:** Investigation in progress. Findings are subject to change as additional evidence is analyzed.

---

## Environment
- Platform: Microsoft Defender XDR
- Host: Windows Server 2022 (Domain Controller)
- Device: `mts-dc.mts.local`
- Accounts observed: `administrator`, others (TBD)

---

## Alerts Observed (Partial)
- Possible logon breach
- Password spray
- Hands-on keyboard attack
- Lateral movement via SMB/RPC
- Suspicious process execution
- Suspicious account manipulation

(Details documented in the investigation report.)

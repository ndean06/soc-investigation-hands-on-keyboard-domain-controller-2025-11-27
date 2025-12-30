# 2025-11-27 — Domain Controller Compromise Investigation

## Overview
This project documents a Security Operations Center (SOC) investigation into a
credential-based attack against a Windows Server 2022 domain controller.
The incident involved successful administrator authentication, confirmed
hands-on-keyboard access via RDP, post-compromise discovery, and attempted
malware deployment. The activity was detected and contained using Microsoft Defender.

---

## Incident Summary
- External attacker successfully authenticated using domain administrator credentials
- RemoteInteractive (RDP) access to the domain controller confirmed
- Post-compromise discovery and persistence attempts observed
- Malware execution and lateral movement attempts blocked
- Environment-wide scoping confirmed no additional assets were compromised

---

## Investigation Artifacts
- 📄 **SOC Walkthrough:** [`walkthrough.md`](walkthrough.md)  
  Step-by-step technical investigation with screenshots and analyst reasoning

- 📄 **Incident Report:** [`incident-report.md`](investigation-report/investigation-report.md)  
  Formal incident report including timeline, impact, scope, and recommendations

- 📸 **Screenshots:** [`/screenshots`](screenshots/)  
  Supporting evidence referenced throughout the investigation

---

## Tools & Telemetry Used
- Microsoft Defender for Endpoint
- Advanced Hunting (KQL)
- DeviceLogonEvents
- DeviceProcessEvents
- DeviceNetworkEvents

---

## Key Takeaways
- Credential-based attacks can escalate quickly to full domain controller compromise
- Distinguishing network logons from remote interactive logons is critical
- Hands-on-keyboard confirmation requires process execution correlation
- Environment-wide scoping is essential to validate containment

---

## Status
**Incident closed. Activity contained. No lateral spread observed.**


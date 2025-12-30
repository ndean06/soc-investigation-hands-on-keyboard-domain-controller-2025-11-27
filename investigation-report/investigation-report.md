# Incident Report

## 1. Report Title
**Hands-on-Keyboard Attack Against Domain Controller (mts-dc)**

---

## 2. Date of Report
**2025-11-27**

---

## 3. Reported By
**SOC Analyst – Dean the CyberSec Professional**

---

## 4. Severity Level
**High**

---

## 5. Summary of Findings
An external attacker successfully authenticated using the domain administrator account and established an RDP session to the domain controller `mts-dc.mts.local`. Following interactive access, the attacker performed domain discovery, attempted to deploy persistence and malicious tooling, and later attempted re-entry using additional attacker infrastructure. Endpoint security controls detected and blocked malware execution and lateral movement attempts. Environment-wide scoping confirmed the incident was contained to a single asset.

---

## 6. Investigation Timeline

| Time (UTC) | Event Description |
|-----------|------------------|
| 2025-11-26 23:53 | Successful network logon from external IP `80.64.19.57` (administrator) |
| 2025-11-27 04:24 | Successful RemoteInteractive (RDP) logon to domain controller |
| 2025-11-27 04:25 | Domain discovery command executed (`net.exe users /domain`) |
| 2025-11-27 06:07 | Malicious executable `RRcatEtz.exe` created |
| 2025-11-27 06:07 | Malicious Windows service created for persistence |
| 2025-11-27 06:08 | Masquerading `svchost.exe` detected and blocked by Defender |
| 2025-11-27 (later) | SMB lateral movement attempts blocked |
| 2025-11-27 (later) | Re-entry attempts from alternate IPs blocked |
| 2025-11-27 (end) | Environment-wide IOC scoping completed |

---

## 7. Who, What, When, Where, Why, How

**Who:**  
- External attacker using the `administrator` account  
- Affected system: `mts-dc.mts.local`

**What:**  
- Successful credential-based authentication and RDP access  
- Post-compromise discovery and persistence attempts

**When:**  
- 2025-11-26 23:53 UTC – 2025-11-27 (ongoing monitoring)

**Where:**  
- Domain Controller (`mts-dc.mts.local`, Windows Server 2022)

**Why:**  
- Likely initial access and domain reconnaissance following credential compromise

**How:**  
- Valid account abuse (administrator)  
- RDP for interactive access  
- Built-in tools (`net.exe`) and custom malware for persistence

---

## 8. MITRE ATT&CK Techniques

- **T1078** – Valid Accounts  
- **T1021.001** – Remote Services: RDP  
- **T1087** – Account Discovery  
- **T1059** – Command and Scripting Interpreter  
- **T1543.003** – Create or Modify System Process: Windows Service  
- **T1036** – Masquerading  

---

## 9. Impact Assessment

- Domain administrator credentials were compromised  
- Interactive access to the domain controller was achieved  
- No evidence of data exfiltration observed  
- No additional endpoints compromised  
- Lateral movement attempts were blocked

---

## 10. Recommendations / Next Steps

- Reset and rotate all privileged credentials  
- Restrict RDP access to domain controllers  
- Enforce stronger authentication controls for administrative accounts  
- Block identified malicious IP addresses
	- `80.64.19.57`
	- `2.57.121.20`
	- `93.123.109.245`
	- `202.53.6.68`
	-
- Add file hash to EDR blocklists:
	- `3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71`
	- `60b6d7664598e6a988d9389e6359838be966dfa54859d5cb1453cbc9b126ed7d`
- Continue monitoring for re-entry attempts

---

## 11. Attachments / Evidence

- Defender alert screenshots   
- `3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71`
- `60b6d7664598e6a988d9389e6359838be966dfa54859d5cb1453cbc9b126ed7d`
- Investigation walkthrough documentation  

---

## 12. Report Status
**Closed**

---

## 13. Reviewed By
**SOC Lead / Incident Response Team**  
*Date: 2025-11-27*

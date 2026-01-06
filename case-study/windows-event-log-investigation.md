# Windows Event Logs Investigation — Persistence & Evasion

**Platform:** Home Lab / Windows Server 2019
**Role:** SOC Analyst (Tier 1)
**Tools:** Windows Event Viewer, PowerShell
**MITRE ATT&CK:** T1070.001 (Indicator Removal), T1136.001 (Local Account)

---

### 🚨 Alert Summary
A high-severity alert triggered due to **Event ID 1102 (The audit log was cleared)** detected on a critical Windows server. Immediately following this, a new local user account was created and added to the Administrators group.

---

### 🔍 Initial Assessment
* **Alert Severity:** High
* **Alert Type:** Defense Evasion / Persistence
* **Affected System:** `FIN-SERVER-01` (Finance Department)
* **Potential Impact:** Loss of forensic visibility and unauthorized administrative access.

**Hypothesis:** An attacker has compromised a legitimate admin account, is attempting to hide their tracks (clearing logs), and is establishing persistence (creating a backdoor).

---

### 🕵️‍♂️ Investigation Steps

#### 1. Log Evasion Analysis (The "Smoke")
* Analyzed **Security Event Logs** focusing on system integrity events.
* **Findings:**
    * **Event ID 1102** observed at `14:02:15`.
    * **User Context:** The log clear was initiated by the user account `j.doe` (Legitimate Admin).
    * *Analyst Note:* Clearing event logs is rarely a standard administrative task and usually indicates a compromised account trying to hide previous actions.

#### 2. Account Creation Analysis (The "Fire")
* Checked for account activity immediately preceding or following the log clear.
* **Findings:**
    * **Event ID 4720 (A user account was created):** Detected at `14:05:30` (3 minutes after logs were cleared).
    * **Target Account:** `support_backup_svc` (Suspicious naming convention mimicking a service account).
    * **Event ID 4732 (A member was added to a security-enabled local group):** The user `support_backup_svc` was added to the **Administrators** group.

#### 3. Correlation
* The account `j.doe` was used to clear logs.
* Moments later, a new administrative account was created.
* No Change Request ticket existed for creating a new support account on this server.

---

### 📊 Findings
* **Confirmed Evasion:** Security logs were wiped to hide prior activity (likely initial access).
* **Confirmed Persistence:** A "backdoor" account (`support_backup_svc`) was created to maintain access if `j.doe` is discovered.
* **Technique Mapped:** Matches **MITRE T1070** (Indicator Removal) and **T1136** (Create Account).

---

### 🎯 Conclusion
This activity is a **True Positive**. A compromised administrative account (`j.doe`) was utilized to wipe forensic evidence and establish a rogue administrator account for persistence.

---

### 🛡️ Response & Recommendations
1.  **Isolate:** Disconnected `FIN-SERVER-01` from the network immediately.
2.  **Contain:** Disabled the compromised account `j.doe` and the rogue account `support_backup_svc`.
3.  **Remediate:** Initiated password resets for all domain admin accounts.
4.  **Forensics:** Escalated to Tier 2 for deep-dive forensics (checking PowerShell logs for command history regarding the initial compromise).

# Windows Event Logs Investigation — Finding Suspicious Activity

**Platform:** SOC Lab / Windows Endpoint
**Role:** SOC Analyst (Tier 1)
**Tools:** Windows Event Logs, SIEM
**MITRE ATT&CK:** T1059.001 – PowerShell Execution

---

## 🚨 Alert Summary
A SIEM alert was generated due to suspicious process execution involving PowerShell running encoded commands from a temporary directory.

---

## 🔍 Initial Assessment

- **Alert severity:** Medium
- **Alert type:** Suspicious host activity / Process Execution
- **Affected system:** `HR-WORKSTATION-04`
- **Potential impact:** Unauthorized command execution or malware download

The alert required log-level investigation to determine if this was an admin script or malicious activity.

---

## 🕵️‍♂️ Investigation Steps

### Event Log Analysis
- Reviewed **Windows Security Event Logs** for the timeframe of the alert.
- Focused on key Event IDs:
  - **4688** – Process Creation (identified the command line arguments).
  - **4624** – Successful Logon (identified the user `b.wayne`).

### Behavioral Analysis
- **Suspicious Process:** Identified `powershell.exe` launching with `-enc` (EncodedCommand) flags.
- **Path Analysis:** The process executed from `C:\Users\b.wayne\AppData\Local\Temp\`, which is a non-standard directory for administrative scripts.
- **Parent Process:** The parent process was `excel.exe`, indicating a potential phishing payload (Macro).

### Correlation
- Correlated the timestamp of the document opening with the PowerShell execution.
- No scheduled tasks or IT tickets justified this execution.

---

## 📊 Findings

- **Confirmed:** `powershell.exe` executed a Base64 encoded string.
- **Confirmed:** Execution originated from a user-writable Temp directory.
- **Mapping:** Behavior mapped to **MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)**.

---

## 🎯 Conclusion

The activity was classified as a **True Positive**. A macro-enabled document likely triggered a PowerShell downloader.

---

## 🛡️ Response & Recommendations

- **Escalation:** Escalated the incident for Tier 2 analysis (Forensics).
- **Isolation:** Recommended isolating `HR-WORKSTATION-04` from the network.
- **Policy:** Suggested reviewing Group Policy to block macro execution from internet-downloaded files.

---

## 💡 Skills Demonstrated

- Windows Event Log analysis (Event ID 4688)
- Command-line argument analysis
- Parent-Child process relationship mapping
- MITRE ATT&CK T1059 identification

# Threat Hunt Report: RDP Compromise and Post-Exploitation Activity

**Report ID:** INC-2025-RDP-COMPROMISE  
**Analyst:** Jordan Bowser  
**Incident Date:** 14 September 2025  
**Environment:** Microsoft Defender for Endpoint, Microsoft Sentinel  
**Affected Host:** flare  

---

## Scenario Overview

Suspicious authentication activity was identified on a cloud-hosted Windows virtual machine named `flare`. The activity suggested repeated failed RDP login attempts followed by a successful authentication from an external source.

The objective of this investigation was to determine how access was gained, what actions were performed on the host, and whether persistence or data exfiltration occurred. The investigation was conducted using Microsoft Defender for Endpoint Advanced Hunting and supporting telemetry, following a structured methodology aligned with the MITRE ATT&CK framework.

---

## Incident Summary

An external attacker gained access to the system via an RDP brute-force attack. After successfully authenticating, the attacker executed a malicious binary, established persistence using a scheduled task, modified Microsoft Defender settings to evade detection, and performed system reconnaissance.

The attacker then staged data into an archive file and initiated outbound communication to an external server. Evidence indicates an attempt to exfiltrate data over a non-standard port.

This represents a full intrusion chain from initial access through to attempted exfiltration.

---

## Key Findings

### Indicators of Compromise

| Type | Value |
|------|------|
| Attacker IP | 159.26.106.84 |
| Compromised Account | slflare |
| Host | flare |
| Malicious Binary | msupdate.exe |
| Execution Command | "msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1 |
| Scheduled Task | MicrosoftUpdateSync |
| Defender Exclusion | C:\Windows\Temp |
| Archive File | backup_sync.zip |
| C2 Server | 185.92.220.87 |
| Exfiltration Endpoint | 185.92.220.87:8081 |

---

## Investigation Details

### Initial Access: RDP Brute Force  
**MITRE Technique:** T1110.001

Multiple failed login attempts were observed from an external IP, followed by a successful authentication.

```kql
DeviceLogonEvents
| where DeviceName contains "flare"
| where ActionType == "LogonFailed"
| summarize FailedLoginCount = count() by RemoteIP
| sort by FailedLoginCount desc
```
Pivot to successful login:
```kql
DeviceLogonEvents  
| where DeviceName contains "flare"  
| where RemoteIP == "159.26.106.84"
```
Result: Successful login using account `slflare`.

---

### Execution: Malicious Binary

**MITRE Technique:** T1059.003

Process telemetry identified a suspicious binary executed shortly after login.
```kql
DeviceProcessEvents  
| where DeviceName contains "flare"  
| where AccountName == "slflare"  
| where IsProcessRemoteSession  
| project TimeGenerated, FileName, InitiatingProcessCommandLine  
| sort by TimeGenerated desc
```
Identified binary: `msupdate.exe`

Command used:
```powershell
"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1
```
---

### Persistence: Scheduled Task

**MITRE Technique:** T1053.005

A scheduled task was created to maintain persistence.
```kql
SecurityEvent  
| where EventSourceName == "Microsoft-Windows-Sysmon"  
| where EventID == 13  
| where EventData has "TaskCache"  
| project TimeGenerated, EventData
```
Result: `MicrosoftUpdateSync`

---

### Defense Evasion: Defender Modification

**MITRE Technique:** T1562.001

The attacker added a Defender exclusion:

C:\Windows\Temp

This allowed malicious files to execute without being scanned.

---

### Discovery: System Enumeration

**MITRE Technique:** T1082

The attacker performed system reconnaissance:
```powershell
"cmd.exe" /c systeminfo
```
Additional observed activity:
```powershell
"C:\Windows\system32\cmd.exe" /c "tasklist /svc"
```
---

### Collection: Data Staging

**MITRE Technique:** T1560.001

An archive file was created:

backup_sync.zip

---

### Command and Control

**MITRE Technique:** T1071.001

Outbound communication was observed to:

185.92.220.87

---

### Exfiltration Attempt

**MITRE Technique:** T1048.003

Outbound traffic to a non-standard port:

185.92.220.87:8081

---

## Attack Timeline

|Time (UTC)|Event|
|---|---|
|19:38:40|Brute-force activity begins|
|Shortly after|Successful RDP login|
|Minutes later|Malicious binary executed|
|Minutes later|Scheduled task created|
|Minutes later|Defender exclusion added|
|Minutes later|Discovery commands executed|
|Minutes later|Archive file created|
|Minutes later|C2 communication established|
|Minutes later|Exfiltration attempt observed|

---

## Impact Assessment

**Severity:** High

The attacker gained authenticated access, established persistence, modified security controls, and attempted data exfiltration. This indicates a significant compromise of the system.

---

## Conclusions

The attack originated from exposed RDP services and weak authentication controls. After gaining access, the attacker executed commands interactively, established persistence, and prepared data for exfiltration.

The use of scheduled tasks and Defender exclusions demonstrates deliberate efforts to maintain access and avoid detection.

While the activity appears limited to a single host, the techniques used could be applied elsewhere in the environment.

---

## Lessons Learned

### Key Gaps Identified

- RDP exposed to the internet without sufficient controls
- No account lockout or rate-limiting
- Limited monitoring of Defender configuration changes
- Insufficient visibility into scheduled task creation

---

## Recommendations

### Immediate Actions

- Disable or restrict external RDP access
- Reset credentials for the compromised account
- Remove scheduled task `MicrosoftUpdateSync`
- Remove Defender exclusion for `C:\Windows\Temp`
- Block attacker infrastructure (159.26.106.84, 185.92.220.87)

---

### Short-Term Improvements

- Enforce MFA for remote access
- Implement account lockout policies
- Enable alerting for Defender configuration changes
- Monitor scheduled task creation

---

### Long-Term Enhancements

- Implement Zero Trust architecture
- Expand detection coverage aligned to MITRE ATT&CK
- Centralise logging across systems
- Conduct regular threat hunting exercises

---

## Detection Opportunities
I recommend creating alerts based on the following queries:
### Brute Force Detection
```kql
DeviceLogonEvents  
| where ActionType == "LogonFailed"  
| summarize count() by RemoteIP  
| where count_ > 10
```
### Suspicious Process Execution
```kql
DeviceProcessEvents  
| where FileName endswith ".exe"  
| where InitiatingProcessCommandLine contains "ExecutionPolicy Bypass"
```
### Scheduled Task Creation
```kql
SecurityEvent  
| where EventID == 13  
| where EventData has "TaskCache"
```
---

## Final Notes

This investigation demonstrates a structured threat hunting approach, combining telemetry analysis, query development, and attack chain reconstruction. It reflects practical SOC workflows and highlights the importance of both detection capability and analytical reasoning.

# Investigation Notes — RDP Failed Logon Investigation

## 1. Investigation Objective

Investigate Windows failed authentication activity and determine whether the available evidence supports an RDP failed-logon or brute-force pattern.

The investigation focused on:

- Event ID `4625`
- Logon Type `10`
- Target account
- Source IP
- Workstation
- Authentication package
- Status
- SubStatus
- Repeated authentication attempts
- Event ID `4624` success

---

## 2. Temporary Account

A temporary account named `RDPBruteLab` was created.

```powershell
$Password = Read-Host "Enter temporary RDP test password" -AsSecureString
New-LocalUser -Name "RDPBruteLab" -Password $Password -Description "Temporary Elastic Lab 10 RDP test account"
```

The account was added to the Remote Desktop Users group:

```powershell
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "RDPBruteLab"
```

The account was verified:

```powershell
Get-LocalUser -Name "RDPBruteLab"
```

Observed:

```text
Name        Enabled Description
----        ------- -----------
RDPBruteLab True    Temporary Elastic Lab 10 RDP test account
```

Remote Desktop Users membership was verified:

```powershell
Get-LocalGroupMember -Group "Remote Desktop Users"
```

---

## 3. Account Policy

The local account policy was reviewed:

```powershell
net accounts
```

Relevant values:

```text
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
```

---

## 4. RDP Configuration

The initial RDP configuration was checked:

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections
```

Initial result:

```text
fDenyTSConnections : 1
```

RDP was temporarily enabled:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Port 3389 was checked:

```powershell
Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
```

No listener was observed in the captured output.

---

## 5. Remote Desktop Services

The Remote Desktop Services service was checked:

```powershell
Get-Service -Name TermService
```

Observed:

```text
Status   Name        DisplayName
------   ----        -----------
Running  TermService Remote Desktop Services
```

---

## 6. Failed-Logon Auditing

The initial audit configuration was checked:

```powershell
auditpol /get /subcategory:"Logon"
```

Initial state:

```text
Logon/Logoff
  Logon    No Auditing
```

Failure auditing was enabled:

```powershell
auditpol /set /subcategory:"Logon" /failure:enable
```

Verification:

```powershell
auditpol /get /subcategory:"Logon"
```

Result:

```text
Logon/Logoff
  Logon    Failure
```

---

## 7. Initial Event 4625 Search

The Windows Security log was checked:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

Initially, no Event ID `4625` events were present.

At this point, no suitable failed authentication had yet been generated after failed-logon auditing was enabled.

---

## 8. Controlled Failed Authentication

A controlled failed authentication was generated:

```powershell
net use \\localhost\IPC$ /user:.\RDPBruteLab WrongPassword123!
```

Windows returned:

```text
System error 1326 has occurred.

The user name or password is incorrect.
```

This generated Event ID `4625`.

---

## 9. Raw Event Analysis

The generated event was inspected from the Windows Security log.

Important fields:

```text
SubjectUserSid            S-1-0-0
SubjectUserName           -
SubjectDomainName         -
SubjectLogonId            0x0
TargetUserSid             S-1-0-0
TargetUserName            RDPBruteLab
TargetDomainName          .
Status                    0xc000006d
FailureReason             %%2313
SubStatus                 0xc000006a
LogonType                 3
LogonProcessName          NtLmSsp
AuthenticationPackageName NTLM
WorkstationName           DESKTOP-9MMM37V
TransmittedServices       -
LmPackageName             -
KeyLength                 0
ProcessId                 0x0
ProcessName               -
IpAddress                 ::1
IpPort                    64194
```

---

## 10. Logon Type Analysis

The event contained:

```text
LogonType: 3
```

Logon Type `3` represents network authentication.

The investigation was looking for:

```text
LogonType: 10
```

Logon Type `10` represents RemoteInteractive authentication and is relevant to RDP.

No Event ID `4625` with Logon Type `10` was observed.

The generated event was therefore treated as a network authentication failure.

---

## 11. Authentication Package

The event contained:

```text
AuthenticationPackageName: NTLM
```

The event therefore recorded NTLM authentication.

---

## 12. Failure Status

The event contained:

```text
Status:    0xc000006d
SubStatus: 0xc000006a
```

The SubStatus value was consistent with an incorrect password condition.

The authentication failure was therefore consistent with the intentionally supplied incorrect password.

---

## 13. Source Address

The raw Windows event contained:

```text
IpAddress: ::1
```

`::1` is the IPv6 loopback address.

The event therefore originated from the local system in the controlled test.

---

## 14. Elastic Agent Validation

Elastic Agent was verified in Fleet.

Observed:

```text
Host: DESKTOP-9MMM37V
Policy: Windows-SOC-Lab
Status: Healthy
Version: 9.5.4
```

The generated Event ID `4625` was successfully ingested into Elastic Security.

---

## 15. Elastic Query — Event ID 4625

```text
FROM logs-*
| WHERE event.code == "4625"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.AuthenticationPackageName, winlog.event_data.SubStatus
| SORT @timestamp DESC
```

The query returned Event ID `4625` documents.

---

## 16. Elastic Query — RDPBruteLab

```text
FROM logs-*
| WHERE event.code == "4625"
| WHERE winlog.event_data.TargetUserName == "RDPBruteLab"
| KEEP @timestamp, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.SubStatus, winlog.event_data.AuthenticationPackageName
| SORT @timestamp DESC
```

Observed:

```text
TargetUserName: RDPBruteLab
LogonType: 3
SubStatus: 0xc000006a
AuthenticationPackageName: NTLM
```

---

## 17. Elastic Query — RDP Logon Type 10

```text
FROM logs-*
| WHERE event.code == "4625"
| WHERE winlog.event_data.LogonType == "10"
| KEEP @timestamp, host.name, event.code, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.AuthenticationPackageName, winlog.event_data.SubStatus
| SORT @timestamp DESC
```

No matching RDP-specific failed-logon event was observed.

---

## 18. Failure Count by Target

```text
FROM logs-*
| WHERE event.code == "4625"
| STATS failure_count = COUNT(*) BY winlog.event_data.TargetUserName
| SORT failure_count DESC
```

Observed:

```text
RDPBruteLab    1
(null)         1
```

The null target value was not automatically treated as an additional attack.

---

## 19. Failure Count by Source IP

```text
FROM logs-*
| WHERE event.code == "4625"
| STATS failure_count = COUNT(*) BY winlog.event_data.IpAddress
| SORT failure_count DESC
```

Elastic returned null or empty source-IP values in the captured result.

The raw Windows event showed:

```text
IpAddress: ::1
```

The raw event was therefore used to validate the source address.

---

## 20. Source and Target Correlation

```text
FROM logs-*
| WHERE event.code == "4625"
| STATS attempts = COUNT(*) BY winlog.event_data.IpAddress, winlog.event_data.TargetUserName
| SORT attempts DESC
```

The Elastic result did not provide a clean source-IP-to-target correlation because the parsed source IP field was empty/null.

The raw event identified the source as:

```text
::1
```

---

## 21. Successful Authentication Search

```text
FROM logs-*
| WHERE event.code == "4624"
| WHERE winlog.event_data.TargetUserName == "RDPBruteLab"
| KEEP @timestamp, host.name, event.code, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.IpAddress
| SORT @timestamp DESC
```

No matching Event ID `4624` was observed for `RDPBruteLab` in the searched Elastic data.

---

## 22. Investigation Assessment

### Confirmed

- Event ID `4625` was generated.
- The target account was `RDPBruteLab`.
- The event had Logon Type `3`.
- NTLM was used.
- The raw event contained source address `::1`.
- The event was ingested into Elastic Security.
- No matching successful Event ID `4624` was observed.

### Not Demonstrated

- RDP Logon Type `10`.
- Repeated RDP authentication failures.
- Successful RDP authentication.
- Confirmed RDP brute-force activity.

---

## 23. Investigation Limitation

The lab was performed on a single Windows endpoint.

No separate RDP client was available.

The controlled authentication was therefore generated through SMB/IPC$ rather than an actual remote RDP session.

No automated password-guessing tools were used.

No synthetic Windows events were created.

The investigation was kept evidence-driven and limited to genuine telemetry generated during the lab.

---

## 24. Evidence Summary

```text
Event ID:                  4625
Target User:               RDPBruteLab
Logon Type:                3
Authentication Package:    NTLM
Workstation:               DESKTOP-9MMM37V
Source Address:            ::1
Status:                    0xc000006d
SubStatus:                 0xc000006a
```

The evidence supports a failed network authentication.

It does not support classifying the event as an RDP brute-force event.

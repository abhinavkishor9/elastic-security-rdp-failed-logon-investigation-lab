# Elastic Security — RDP Failed Logon Investigation Lab

## Overview

This lab investigates Windows failed authentication activity using Elastic Security and Windows Security Event ID `4625`.

The original investigation objective was to examine an RDP failed-logon or brute-force pattern by correlating:

- Event ID `4625`
- Logon Type `10`
- Source IP address
- Target account
- Repeated authentication failures
- Authentication package
- Failure status and substatus
- Successful Event ID `4624`

The lab was performed on a single Windows endpoint without a separate RDP client. Because of this limitation, a genuine remote RDP authentication sequence could not be reproduced.

Instead of using automated password-guessing tools or synthetic Windows events, a controlled failed network authentication was generated against a temporary account named `RDPBruteLab`.

The authentication attempt generated a genuine Windows Event ID `4625` and the event was successfully ingested into Elastic Security.

The observed event had:

- Target account: `RDPBruteLab`
- Logon Type: `3`
- Authentication Package: `NTLM`
- Workstation: `DESKTOP-9MMM37V`
- Source address: `::1`
- Status: `0xc000006d`
- SubStatus: `0xc000006a`

The evidence therefore represents a failed network authentication rather than an RDP authentication failure.

No Event ID `4625` with Logon Type `10` was observed, and no successful Event ID `4624` for `RDPBruteLab` was observed in the searched Elastic data.

---

## Objectives

- Create a temporary authentication test account.
- Add the account to the `Remote Desktop Users` group.
- Review the local account lockout policy.
- Review the Windows RDP configuration.
- Validate the Remote Desktop Services service.
- Enable Windows failed-logon auditing.
- Generate a controlled failed authentication.
- Confirm Event ID `4625` in the Windows Security log.
- Confirm Event ID `4625` ingestion into Elastic Security.
- Analyze the authentication Logon Type.
- Review the target account and source information.
- Analyze the authentication package and failure status.
- Search for RDP-specific Logon Type `10` events.
- Search for successful Event ID `4624` activity.
- Document telemetry and environment limitations.
- Clean up the temporary lab configuration.

---

## Scenario

A temporary local Windows account named `RDPBruteLab` was created for authentication testing.

The account was added to the `Remote Desktop Users` group because the original investigation objective was to examine RDP authentication telemetry.

During preparation, Windows failed-logon auditing was found to be disabled. Failure auditing was enabled before generating the test authentication.

A controlled failed authentication was then generated using:

```powershell
net use \\localhost\IPC$ /user:.\RDPBruteLab WrongPassword123!
```

Windows returned:

```text
System error 1326 has occurred.

The user name or password is incorrect.
```

This generated Event ID `4625`.

The resulting event was investigated locally and in Elastic Security to determine what type of authentication actually occurred.

---

## Environment

| Component | Configuration |
|---|---|
| Operating System | Windows 11 Pro |
| Host | `DESKTOP-9MMM37V` |
| Elastic Agent | `9.5.4` |
| Elastic Policy | `Windows-SOC-Lab` |
| SIEM | Elastic Security |
| Test Account | `RDPBruteLab` |
| Primary Event | Windows Event ID `4625` |
| RDP Service | `TermService` |
| RDP Client | No separate client |
| Authentication Test | SMB/IPC$ |

---

## Account Setup

The temporary account was created with:

```powershell
$Password = Read-Host "Enter temporary RDP test password" -AsSecureString
New-LocalUser -Name "RDPBruteLab" -Password $Password -Description "Temporary Elastic Lab 10 RDP test account"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "RDPBruteLab"
```

The account was verified with:

```powershell
Get-LocalUser -Name "RDPBruteLab"
```

Remote Desktop Users membership was verified with:

```powershell
Get-LocalGroupMember -Group "Remote Desktop Users"
```

---

## Account Policy

The local account policy was reviewed using:

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

## RDP Configuration

The initial RDP configuration was checked using:

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

The RDP listener was checked:

```powershell
Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
```

No listener was observed in the captured output.

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

## Failed-Logon Auditing

The initial audit policy showed:

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

## Controlled Authentication Failure

The following command generated the controlled authentication failure:

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

## Event ID 4625

The raw Windows event contained:

```text
TargetUserName              RDPBruteLab
TargetDomainName            .
Status                      0xc000006d
FailureReason               %%2313
SubStatus                   0xc000006a
LogonType                   3
LogonProcessName            NtLmSsp
AuthenticationPackageName   NTLM
WorkstationName             DESKTOP-9MMM37V
IpAddress                   ::1
IpPort                      64194
```

### Important Fields

| Field | Value |
|---|---|
| Event ID | `4625` |
| Target User | `RDPBruteLab` |
| Logon Type | `3` |
| Authentication | `NTLM` |
| Workstation | `DESKTOP-9MMM37V` |
| Source IP | `::1` |
| Status | `0xc000006d` |
| SubStatus | `0xc000006a` |

---

## Logon Type Analysis

The observed event contained:

```text
LogonType: 3
```

Logon Type `3` represents network authentication.

The RDP-specific Logon Type is:

```text
LogonType: 10
```

Logon Type `10` represents RemoteInteractive authentication and is relevant when investigating Windows RDP authentication.

No Event ID `4625` with Logon Type `10` was observed.

Therefore, the controlled event was classified as a failed network authentication rather than an RDP failed-logon event.

---

## Elastic Agent

Elastic Agent was verified in Fleet:

- Host: `DESKTOP-9MMM37V`
- Policy: `Windows-SOC-Lab`
- Status: `Healthy`
- Version: `9.5.4`

The Windows Event ID `4625` generated during the test was successfully ingested into Elastic Security.

---

## Elastic Investigation

### Search Event ID 4625

```text
FROM logs-*
| WHERE event.code == "4625"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.AuthenticationPackageName, winlog.event_data.SubStatus
| SORT @timestamp DESC
```

### Search for RDPBruteLab

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

### Search for RDP Logon Type 10

```text
FROM logs-*
| WHERE event.code == "4625"
| WHERE winlog.event_data.LogonType == "10"
| KEEP @timestamp, host.name, event.code, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.AuthenticationPackageName, winlog.event_data.SubStatus
| SORT @timestamp DESC
```

No matching RDP-specific failed-logon event was observed.

---

## Failure Count by Target

```text
FROM logs-*
| WHERE event.code == "4625"
| STATS failure_count = COUNT(*) BY winlog.event_data.TargetUserName
| SORT failure_count DESC
```

Observed groups included:

```text
RDPBruteLab    1
(null)         1
```

The null target value was not treated as evidence of another attack.

---

## Failure Count by Source IP

```text
FROM logs-*
| WHERE event.code == "4625"
| STATS failure_count = COUNT(*) BY winlog.event_data.IpAddress
| SORT failure_count DESC
```

The Elastic result showed null or empty source IP values.

The raw Windows event contained:

```text
IpAddress: ::1
```

The raw Windows event was therefore used to validate the source address.

---

## Successful Authentication Check

```text
FROM logs-*
| WHERE event.code == "4624"
| WHERE winlog.event_data.TargetUserName == "RDPBruteLab"
| KEEP @timestamp, host.name, event.code, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.IpAddress
| SORT @timestamp DESC
```

No matching Event ID `4624` was observed for `RDPBruteLab` in the searched Elastic data.

---

## Findings

### Confirmed

- Failed-logon auditing was enabled.
- A genuine Event ID `4625` was generated.
- The target account was `RDPBruteLab`.
- The observed Logon Type was `3`.
- NTLM was used.
- The raw Windows event showed source address `::1`.
- The event was successfully ingested into Elastic Security.
- No successful Event ID `4624` for `RDPBruteLab` was observed in the searched data.

### Not Observed

- Event ID `4625` with Logon Type `10`.
- Repeated RDP authentication failures.
- Successful RDP authentication.
- A confirmed RDP brute-force sequence.

---

## Limitations

The lab was performed on a single Windows endpoint without a separate RDP client.

The controlled authentication test therefore generated a network authentication event rather than a remote RDP authentication event.

No automated password-guessing tools were used.

No synthetic Windows events were created.

The investigation was intentionally limited to genuine telemetry generated during the lab.

---

## Cleanup

RDP was disabled:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

The temporary account was removed:

```powershell
Remove-LocalUser -Name "RDPBruteLab"
```

Verification:

```powershell
Get-LocalUser -Name "RDPBruteLab" -ErrorAction SilentlyContinue
```

The account no longer returned a result.

---

## Key Takeaway

An Event ID `4625` alone does not establish an RDP brute-force attack.

The authentication type must be validated.

The evidence collected in this lab showed:

```text
Event ID 4625
Target: RDPBruteLab
Logon Type: 3
Authentication: NTLM
Source: ::1
SubStatus: 0xc000006a
```

The evidence supports a failed network authentication.

No RDP-specific Logon Type `10` event was observed.

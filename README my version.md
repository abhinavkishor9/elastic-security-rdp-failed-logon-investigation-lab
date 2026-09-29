# elastic-security-rdp-failed-logon-investigation-lab
## Overview
RDP brute-force activity involves repeated authentication attempts against a Windows Remote Desktop service. From a SOC perspective, a single failed login is not automatically a brute-force attack. The investigation focuses on identifying a pattern of repeated failed authentications and determining whether the events share common characteristics.

The primary Windows Security event is:

4625 — An account failed to log on

For an RDP investigation, an important field is:

Logon Type 10 — RemoteInteractive

A potential RDP password-guessing pattern can therefore be represented as:

4625 Failed Logon
       ↓
Logon Type 10?
       ↓
Same Source?
       ↓
Same Account?
       ↓
Repeated Attempts?
       ↓
4624 Successful Logon?
       ↓
Timeline
       ↓
Evidence-Based Assessment

For example, if the telemetry contains:

05:45:01  4625  Logon Type 10  RDPBruteLab
05:45:04  4625  Logon Type 10  RDPBruteLab
05:45:07  4625  Logon Type 10  RDPBruteLab
05:45:10  4625  Logon Type 10  RDPBruteLab
05:45:15  4624  Logon Type 10  RDPBruteLab

the analyst can investigate the common source, target account, timestamps, authentication details, and whether a successful authentication followed the failures.

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

## Lab Objectives

- Understand how Windows records failed authentication activity through Security Event ID `4625`.
- Understand the difference between network authentication (`Logon Type 3`) and RemoteInteractive/RDP authentication (`Logon Type 10`).
- Configure Windows auditing to capture failed logon activity.
- Create a controlled authentication scenario using a temporary test account.
- Generate and capture a genuine failed authentication event without creating synthetic telemetry.
- Examine Event ID `4625` at the raw Windows event level.
- Analyze the target account, Logon Type, authentication package, source address, status, and substatus fields.
- Validate the ingestion of Windows Security events into Elastic Security.
- Use ES|QL to search, filter, and correlate failed authentication events.
- Investigate whether repeated authentication failures form a meaningful pattern.
- Search specifically for RDP-related failed authentication using Logon Type `10`.
- Check for a corresponding successful authentication event using Event ID `4624`.
- Compare raw Windows event fields with their parsed Elastic fields.
- Identify and document telemetry parsing or field-visibility limitations.
- Avoid classifying a failed authentication as RDP activity without supporting evidence.
- Apply an evidence-first investigation approach when the generated telemetry differs from the original scenario.
- Document environment limitations and distinguish confirmed findings from unsupported assumptions.
- Restore the test environment and remove temporary lab configuration after the investigation.

---

## Lab Scenario

A Windows endpoint is being monitored through Elastic Security for authentication-related activity. The investigation focuses on failed authentication attempts and whether the available telemetry can support an assessment of possible RDP brute-force activity.

A temporary local account named `RDPBruteLab` is created and added to the **Remote Desktop Users** group to provide a controlled test identity. Windows failed-logon auditing is enabled so that unsuccessful authentication attempts can be captured as Security Event ID `4625`.

The investigation then generates a controlled incorrect-password authentication attempt against the local system. The resulting Windows event is examined at both the raw Windows Security log level and after ingestion into Elastic Security.

The investigation focuses on the following evidence:

- Event ID `4625` and its authentication failure details.
- Target account associated with the failed authentication.
- `LogonType` and whether it represents network authentication or RDP.
- Authentication package and failure status/substatus.
- Source address and workstation information.
- Whether multiple failed attempts form a repeated authentication pattern.
- Whether any corresponding successful authentication event (`4624`) is observed.
- Whether Elastic Security preserves the relevant Windows event fields correctly.

The expected investigation question is:

> **Does the available telemetry provide sufficient evidence to classify the observed failed authentication activity as an RDP brute-force attempt?**

The lab intentionally does not fabricate RDP events or rely on automated password-guessing tools. If the generated event does not contain `LogonType 10`, it must be documented as the evidence shows rather than being classified as RDP activity.

The final assessment should distinguish between:

- **Confirmed:** facts directly supported by Windows or Elastic telemetry.
- **Plausible:** interpretations that may fit the activity but lack sufficient evidence.
- **Not established:** conclusions that cannot be supported by the available telemetry.

After the investigation, the temporary account and RDP-related configuration are removed so the Windows endpoint is returned to its previous state.

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

## MITRE ATT&CK Mapping

This lab focuses on authentication activity that can be relevant to credential-based access techniques. The observed telemetry is mapped only where the available evidence supports the relationship.

| ATT&CK Technique | Technique Name | Relevance to Lab |
|---|---|---|
| T1110 | Brute Force | The investigation examines failed authentication activity that could indicate repeated password-guessing attempts. The captured evidence does not establish a brute-force pattern by itself. |
| T1110.001 | Password Guessing | The controlled test uses an incorrect password to generate a genuine failed authentication event. This demonstrates the telemetry produced by an invalid credential attempt, but does not represent an actual attack campaign. |
| T1021.001 | Remote Services: Remote Desktop Protocol | RDP is the intended investigation context. However, the captured failed authentication event contains `LogonType 3`, not `LogonType 10`, so the event itself does not establish RDP authentication. |

### Evidence-Based Assessment

The lab demonstrates how authentication telemetry can be investigated against MITRE ATT&CK techniques without automatically assigning an attack classification.

The generated `4625` event confirms a failed authentication attempt, while the observed `LogonType 3` identifies it as network authentication. No captured evidence establishes a `LogonType 10` RDP authentication attempt or a repeated brute-force sequence.

Therefore, the ATT&CK mappings above represent the **investigation context and analytical relevance**, not confirmation that the endpoint experienced an RDP brute-force attack.

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


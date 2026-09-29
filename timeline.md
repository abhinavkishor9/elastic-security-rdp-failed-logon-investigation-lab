# Timeline — RDP Failed Logon Investigation

## Investigation Timeline

| Phase | Activity | Evidence | Result |
|---|---|---|---|
| Setup | Created temporary account | `RDPBruteLab` | Account created |
| Setup | Added account to Remote Desktop Users | Local group membership | Membership confirmed |
| Setup | Reviewed account policy | `net accounts` | Lockout threshold was `Never` |
| RDP Configuration | Checked RDP registry setting | `fDenyTSConnections` | RDP initially disabled |
| RDP Configuration | Enabled RDP temporarily | Registry + firewall | RDP configuration temporarily enabled |
| RDP Configuration | Checked port 3389 | `Get-NetTCPConnection` | No listener observed in captured output |
| Service Validation | Checked TermService | `Get-Service TermService` | Service running |
| Auditing | Checked Logon auditing | `auditpol` | Failure auditing initially disabled |
| Auditing | Enabled failed-logon auditing | `auditpol /set` | Failure auditing enabled |
| Authentication Test | Generated failed authentication | `net use \\localhost\IPC$` | Authentication failed |
| Event Generation | Windows generated Event ID 4625 | Security log | Failed authentication recorded |
| Event Analysis | Inspected raw 4625 | Windows Security event | Logon Type `3`, NTLM |
| Elastic Validation | Checked Elastic Agent | Fleet | Agent Healthy |
| Elastic Validation | Searched Event ID 4625 | ES\|QL | Event successfully ingested |
| Investigation | Filtered `RDPBruteLab` | ES\|QL | Failed event identified |
| Investigation | Checked Logon Type | ES\|QL | Logon Type `3` |
| Investigation | Searched Logon Type `10` | ES\|QL | No RDP-specific event observed |
| Investigation | Counted failures by target | ES\|QL | `RDPBruteLab` observed |
| Investigation | Checked source IP | Raw event + ES\|QL | Raw event showed `::1` |
| Investigation | Checked successful 4624 | ES\|QL | No matching success observed |
| Cleanup | Disabled RDP | Registry | RDP configuration restored |
| Cleanup | Disabled RDP firewall rules | Firewall | Rules restored |
| Cleanup | Removed test account | `Remove-LocalUser` | Account removed |

---

## Detailed Timeline

### Environment Setup

A temporary local account named `RDPBruteLab` was created.

The account was added to the `Remote Desktop Users` group.

The account was verified as enabled.

The local account policy was also reviewed.

Relevant configuration:

```text
Lockout threshold:                                    Never
Lockout duration:                                    30 minutes
Lockout observation window:                           30 minutes
Computer role:                                        WORKSTATION
```

---

### RDP Configuration

The initial RDP registry configuration was:

```text
fDenyTSConnections : 1
```

RDP was temporarily enabled:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

The Remote Desktop Services service was confirmed running.

Port 3389 was checked, but no listener was observed in the captured output.

---

### Failed-Logon Auditing

The initial audit configuration was:

```text
Logon/Logoff
  Logon    No Auditing
```

Failure auditing was enabled:

```powershell
auditpol /set /subcategory:"Logon" /failure:enable
```

The resulting configuration was:

```text
Logon/Logoff
  Logon    Failure
```

---

### 29-09-2026 06:50:32 — Controlled Failed Authentication

A controlled failed authentication was generated:

```powershell
net use \\localhost\IPC$ /user:.\RDPBruteLab WrongPassword123!
```

Windows returned:

```text
System error 1326 has occurred.

The user name or password is incorrect.
```

This generated Windows Event ID `4625`.

---

### 29-09-2026 06:50:32 — Raw Event Analysis

The generated event contained:

```text
TargetUserName              RDPBruteLab
Status                      0xc000006d
SubStatus                   0xc000006a
LogonType                   3
LogonProcessName            NtLmSsp
AuthenticationPackageName   NTLM
WorkstationName             DESKTOP-9MMM37V
IpAddress                   ::1
IpPort                      64194
```

The authentication was identified as Logon Type `3`, which represents network authentication.

---

### Elastic Ingestion

Elastic Agent was confirmed healthy on:

```text
Host: DESKTOP-9MMM37V
Policy: Windows-SOC-Lab
Version: 9.5.4
```

The Event ID `4625` was successfully ingested into Elastic Security.

---

### Elastic Investigation

The generated event was located using:

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

### RDP-Specific Search

The investigation searched for Event ID `4625` with Logon Type `10`:

```text
FROM logs-*
| WHERE event.code == "4625"
| WHERE winlog.event_data.LogonType == "10"
```

No matching event was observed.

The available evidence therefore did not demonstrate an RDP authentication failure.

---

### Successful Authentication Search

The investigation searched for a successful authentication for `RDPBruteLab`:

```text
FROM logs-*
| WHERE event.code == "4624"
| WHERE winlog.event_data.TargetUserName == "RDPBruteLab"
```

No matching Event ID `4624` was observed in the searched Elastic data.

---

### Additional 4625 Event

A second Event ID `4625` was visible in the Windows Security log at:

```text
29-09-2026 06:59:36
```

The captured investigation did not extract the detailed fields for this event.

It was therefore not used to infer a specific target account, Logon Type, source IP, or attack pattern.

This distinction was maintained to avoid assigning unsupported details to the event.

---

### Cleanup

RDP was disabled:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
```

The Remote Desktop firewall rules were disabled:

```powershell
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

No account was returned.

---

## Evidence Summary

### Observed Event

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

### Not Observed

```text
Event ID 4625 with Logon Type 10
Repeated RDP authentication failures
Successful RDP authentication
Confirmed RDP brute-force sequence
```

---

## Investigation Flow

```text
Environment Setup
        |
        v
Temporary Account
        |
        v
RDP Configuration
        |
        v
Audit Policy
        |
        v
Controlled Failed Authentication
        |
        v
Windows Event 4625
        |
        v
Elastic Ingestion
        |
        v
Logon Type Analysis
        |
        v
RDP Logon Type 10 Search
        |
        v
4624 Success Check
        |
        v
Evidence-Based Assessment
        |
        v
Cleanup
```

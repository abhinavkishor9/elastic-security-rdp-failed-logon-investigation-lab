# Timeline

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


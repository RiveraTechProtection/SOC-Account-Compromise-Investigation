# Suspicious Account Compromise Investigation
### Splunk | Windows Security Logs | SOC Incident Response

**Analyst:** Marcos Rivera  
**Portfolio:** Rivera Tech Protection  
**Project Type:** Simulated SOC Investigation

## Project Overview

This case study investigates a simulated password-spraying campaign that progressed into suspected administrator account compromise, host discovery, persistence, privilege escalation, and access to sensitive payroll information.

The investigation demonstrates Tier 1 SOC analysis, Windows Security Event correlation, Splunk Search Processing Language (SPL), threat identification, and incident escalation.

> **Lab Disclaimer:** This is a simulated training investigation using fictional events and infrastructure. Findings are based on the supplied scenario evidence.

## Objectives

- Identify suspicious authentication patterns.
- Analyze Windows Security Events.
- Correlate user, host, and network activity.
- Reconstruct an attack timeline.
- Identify behaviors consistent with MITRE ATT&CK.
- Distinguish confirmed findings from hypotheses.
- Develop evidence-based escalation recommendations.

## Tools and Skills

- Splunk Search Processing Language (SPL)
- Windows Security Event Logs
- Security Information and Event Management (SIEM)
- Incident Triage and Escalation
- MITRE ATT&CK
- Threat Detection and Log Correlation

## Investigation

### Phase 1: Suspicious Authentication Activity

The initial alert identified multiple failed authentication attempts originating from `185.44.10.9` between 14:01 and 14:05.

The source attempted authentication against several accounts, including `admin`, `jsmith`, and `payroll`.

At 14:06, the `admin` account successfully authenticated from the same source.

**SPL query from the case study:**

```spl
status=failure
| stats count by src_ip
| where count > 2
| sort - count
| table src_ip count
```

**Assessment:** The pattern was consistent with password spraying. The successful administrator authentication warranted further investigation.

### Phase 2: Post-Login Discovery

Windows Security Event IDs 4624 and 4688 showed a successful administrator login followed by process execution.

Observed activity included:

- `powershell.exe`
- `whoami.exe`
- `net user`
- `net localgroup administrators`

**Assessment:** This sequence suggested account and privilege discovery following the suspicious login.

### Phase 3: Persistence and Privilege Escalation

Further investigation identified:

- **Event ID 4720:** Creation of a new account named `svc_support`.
- **Event ID 4732:** Addition of `svc_support` to the local Administrators group.
- **Event ID 4624:** Successful authentication by `svc_support` from the suspicious source IP.

**Assessment:** These events provided strong evidence of persistence and privilege escalation within the simulated incident.

### Phase 4: Sensitive Data Access

The privileged `svc_support` account accessed and exported:

`C:\Finance\employee_payroll.xlsx`

Shortly afterward, the host initiated an outbound HTTPS connection to `203.0.113.88` on port 443.

**Assessment:** Sensitive file access and export were confirmed within the scenario. However, the available evidence did not establish that the file was transmitted externally.

Possible exfiltration therefore remained **suspected, not confirmed**.

## Consolidated Attack Timeline

| Time | Observed Activity |

| 14:01–14:05 | Multiple failed authentication attempts |
| 14:06 | Administrator login succeeds |
| 14:07–14:10 | PowerShell and account discovery |
| 14:12 | New account `svc_support` created |
| 14:13 | New account added to Administrators |
| 14:14 | Privileged account authenticates |
| 14:17–14:18 | Sensitive payroll file accessed and exported |
| 14:19 | Outbound HTTPS connection |
| 14:21 | Session ends |

## MITRE ATT&CK Behavioral Analysis

| Tactic | Observed Behavior |
|---|---|
| Discovery | User and administrator enumeration |
| Persistence | Creation of a new account |
| Privilege Escalation | Addition to local Administrators group |
| Collection / Exfiltration Concern | Sensitive file export and subsequent outbound connection |

## Incident Escalation Recommendation

The simulated incident warranted immediate escalation to Tier 2 SOC analysts or incident response personnel.

Recommended next steps:

1. Preserve relevant logs and the complete attack timeline.
2. Investigate the compromised administrator session.
3. Examine all activity associated with `svc_support`.
4. Review additional hosts for related suspicious activity.
5. Analyze outbound network and proxy telemetry.
6. Follow organizational containment procedures.

## Key Takeaways

This investigation strengthened my ability to:

- Interpret Windows authentication and process events.
- Identify suspicious login behavior.
- Correlate evidence across multiple log sources.
- Recognize persistence and privilege-escalation techniques.
- Communicate incident findings using structured escalation notes.
- Avoid unsupported conclusions when evidence is incomplete.

## Conclusion

This simulated investigation demonstrates a Tier 1 SOC workflow from initial alert triage through incident escalation.

The evidence supports suspected password spraying followed by privileged account compromise, discovery, persistence, privilege escalation, and sensitive data access.

Possible data exfiltration was identified as a concern requiring additional evidence.

**Prepared by Marcos Rivera | Rivera Tech Protection**

# SOC Lab: Windows Authentication Attack Detection & Triage

## Incident Title
Simulated Brute Force Authentication Attempt Resulting in Account Lockout

## Environment
- Windows Server 2019 Domain Controller (DC01)  
- Windows 10 Domain-Joined Client (WIN10-CLIENT)  
- Splunk Enterprise (Ubuntu VM)  
- Windows Event Logs collected via Universal Forwarder

## Objective
Simulate and investigate repeated failed authentication attempts within a Windows Active Directory environment using Splunk Enterprise as a SIEM. Document detection, investigation, and remediation workflow in a SOC-style format.

## Enviroment
- Domain Controller: Windows Server 2019 (DC01)
- Domain Client: Windows 10 (WIN10-CLIENT)
- SIEM: Splunk Enterprise (Ubuntu 22.04 VM)
- Domain: corp.local
- Log Forwarding: Splunk Universal Forwarder (port 9997)
- Logs Collected:
   Windows Security Logs, System Logs

## Incident Summary
Multiple failed authentication attempts were generated against domain user jdoe from a domain-joined workstation. Repeated failures triggered the domain account lockout policy. The activity was detected and investigated using Splunk queries.

## Alert Source
Windows Security Event Logs ingested into Splunk Enterprise via Universal Forwarder.

## Investigation Steps

---

**Query Used:**

```
index=* EventCode=4625 TargetUserName=jdoe
```

Reviewed repeated failed authentication attempts, timestamps, host, and logon type.

---

### Account Lockout Confirmation (Event ID 4740)

**Query Used:**

```
index=* EventCode=4740
```

Confirmed domain account lockout occurred after repeated failed attempts.

---

### Successful Logon Review (Event ID 4624)

**Query Used:**

```
index=* EventCode=4624 TargetUserName=jdoe
```

Reviewed successful authentication events to verify no unauthorized login occurred following lockout.

---

### Event Correlation

**Query Used:**

```
index=* (EventCode=4625 OR EventCode=4740) | stats count by TargetUserName, host, EventCode
```

Correlated failed logon attempts with account lockout events to validate attack pattern.

## Findings / Assessment
- Activity consistent with repeated authentication failures originating from a single domain-joined host.
- Multiple Event ID 4625 entries observed.
- Account lockout confirmed via Event ID 4740.
- No evidence of lateral movement.
- No suspicious successful authentication events detected.
Risk Level (Lab Environment): Low – Controlled Simulation
In production, similar behavior could indicate password spraying or brute-force activity.

## Detection Engineering

---

### Objective

Develop detection logic to identify repeated failed authentication attempts consistent with brute-force behavior.

---

### Detection Query – Threshold Based

```
index=* EventCode=4625 | stats count by TargetUserName, host | where count > 5
```

**Purpose:**

Identifies user accounts experiencing more than five failed login attempts, which may indicate credential abuse or brute-force attempts.

---

### Detection Query – Time Window Correlation

```
index=* EventCode=4625 | bin _time span=5m | stats count by _time, TargetUserName, host | where count > 5
```

**Purpose:**

Detects repeated failed authentication attempts within a 5-minute window to reduce false positives from isolated mistyped passwords.

## Validation
- Simulated repeated failed login attempts from WIN10-CLIENT.
- Confirmed detection query returned expected results.
- Verified account lockout (Event ID 4740) occurred as expected.

## Response & Remediation
- Account unlocked.
- Password reset performed.
- Incident documented.
- Detection logic validated for effectiveness. 

## Screenshots / Evidence
1. Failed logons (4625): ![Failed Logons](01_failed_logons_4625.png)
2. Account lockout (4740): ![Account Lockout](02_account_lockout_4740.png)
3. Correlated events stats: ![Event Correlation](03_event_correlation_stats.png)

## Lessons Learned
- Validated log ingestion and visibility into Windows Security Events.
- Demonstrated SOC-style workflow: detection → investigation → correlation → risk assessment → remediation.
- Practiced developing basic threshold-based detection logic.

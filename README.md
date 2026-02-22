# SOC Lab: Windows Authentication Attack Detection & Triage

## Incident Title
Simulated Brute Force Authentication Attempt Resulting in Account Lockout

## Environment
- Windows Server 2019 Domain Controller (DC01)  
- Windows 10 Domain-Joined Client (WIN10-CLIENT)  
- Splunk Enterprise (Ubuntu VM)  
- Windows Event Logs collected via Universal Forwarder  

## Incident Summary
Detected multiple failed authentication attempts against a domain user (`jdoe`) resulting in account lockout.

## Alert Source
Windows Security Event Logs ingested into Splunk.

## Investigation Steps
1. Queried Event ID 4625 to identify failed login attempts for `Account_Name=jdoe`.  
2. Verified timestamps and host to find repeated authentication failures.  
3. Confirmed account lockout with Event ID 4740.  
4. Correlated failed login events and lockout in a stats query for analysis.  
5. No suspicious successful logins (Event ID 4624) detected after account lockout.  

## Findings / Assessment
- Activity consistent with a brute-force authentication attempt from a single host.  
- No lateral movement or unauthorized access observed.  

## Response & Remediation
- Account unlocked and password reset.  
- Event documented and monitoring rules validated.  

## Screenshots / Evidence
1. Failed logons (4625): ![Failed Logons](01_failed_logons_4625.png)
2. Account lockout (4740): ![Account Lockout](02_account_lockout_4740.png)
3. Correlated events stats: ![Event Correlation](03_event_correlation_stats.png)

## Lessons Learned
- Validated account lockout thresholds and log monitoring.  
- Demonstrated ability to detect, investigate, and document suspicious authentication activity using a SIEM.
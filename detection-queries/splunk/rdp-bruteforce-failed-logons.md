# RDP Brute Force — Failed Logons Followed by Success

**MITRE Technique**: T1110 — Brute Force
**Detects**: high volume of failed authentication attempts across multiple accounts from a single source, followed by a success.
**Source hunt**: [rdp-bruteforce-c2-persistence](../../hunts/rdp-bruteforce-c2-persistence/README.md)

```spl
index="mydfir_soc" sourcetype="winevent:security" EventCode IN (4625) |stats count by user

index="mydfir_soc" sourcetype="winevent:security" EventCode IN (4624) user="ryan.adams" 172.16.0.184 |table _time src_ip Elevated_Token Logon_type EventCode Logon_ID

index="mydfir_soc" sourcetype="sysmon" EventCode=3 | stats count by src_ip, DestinationIp, DestinationPort, Image | where count > 20 | sort - count
```

# Internal Host DNS Resolution — Domain Controller Reconnaissance

**MITRE Technique**: T1018 — Remote System Discovery
**Detects**: an untrusted process resolving/querying an internal domain controller, suggesting reconnaissance ahead of lateral movement.
**Source hunt**: [rdp-bruteforce-c2-persistence](../../hunts/rdp-bruteforce-c2-persistence/README.md)

```spl
index="mydfir_soc" sourcetype="sysmon" source="sysmon.csv" 172.16.0.7 python.exe |table Image QueryName QueryResults User Computer
```

# Unsigned Binary Execution from a User-Writable Path

**MITRE Technique**: T1204.002 — User Execution: Malicious File (also used to observe the resulting C2 traffic, T1071 — Application Layer Protocol)
**Detects**: process creation and network connections for a binary running from a non-standard, user-writable directory — same telemetry covers both the execution event and its outbound C2 connection.
**Source hunt**: [rdp-bruteforce-c2-persistence](../../hunts/rdp-bruteforce-c2-persistence/README.md)

```spl
index="mydfir_soc" sourcetype="sysmon" source="sysmon.csv" python EventID IN (7,1,3) |table _time EventID src_ip dest_ip ProcessId Image ImageLoaded Hashes Signed Signature SignatureStatus
```

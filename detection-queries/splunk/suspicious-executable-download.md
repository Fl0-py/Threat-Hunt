# Executable Downloaded from External Host

**MITRE Technique**: T1105 — Ingress Tool Transfer
**Detects**: an executable file transferred from an external IP via an HTTP download.
**Source hunt**: [rdp-bruteforce-c2-persistence](../../hunts/rdp-bruteforce-c2-persistence/README.md)

```spl
index="mydfir_soc" sourcetype="suricata" alert_signature="*" Download

index="mydfir_soc" sourcetype="Sysmon" source="sysmon.csv" EventCode=11 python.exe
```

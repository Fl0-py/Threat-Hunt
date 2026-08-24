# Scheduled Task Creation via PowerShell/schtasks

**MITRE Technique**: T1053.005 — Scheduled Task
**Detects**: a scheduled task created via `schtasks.exe`, especially one running under `SYSTEM` and pointed at a binary outside standard install paths.
**Source hunt**: [rdp-bruteforce-c2-persistence](../../hunts/rdp-bruteforce-c2-persistence/README.md)

```spl
index="mydfir_soc" sourcetype="winevent:powershell" source="powershell.csv" schtasks |table ScriptBlock_ID _time EventCode Message
```

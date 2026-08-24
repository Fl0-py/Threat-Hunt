# Windows Defender Real-Time Protection Disabled

**MITRE Technique**: T1562.001 — Impair Defenses
**Detects**: Defender real-time protection being turned off (EventCode 5001) — no legitimate reason to occur outside a maintenance window.
**Source hunt**: [rdp-bruteforce-c2-persistence](../../hunts/rdp-bruteforce-c2-persistence/README.md)

```spl
index="mydfir_soc" sourcetype="WinEvent:Defender" source="defender.csv" | table _time raw
```

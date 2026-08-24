# Detection Queries

Reusable detection queries, organized by SIEM/query language. Populated either by hand between hunts, or
extracted from a published hunt's kill-chain table once it's documented.

## splunk/

| Query | MITRE Technique | From hunt |
|---|---|---|
| [rdp-bruteforce-failed-logons](splunk/rdp-bruteforce-failed-logons.md) | T1110 | [rdp-bruteforce-c2-persistence](../hunts/rdp-bruteforce-c2-persistence/README.md) |
| [defender-realtime-protection-disabled](splunk/defender-realtime-protection-disabled.md) | T1562.001 | [rdp-bruteforce-c2-persistence](../hunts/rdp-bruteforce-c2-persistence/README.md) |
| [suspicious-executable-download](splunk/suspicious-executable-download.md) | T1105 | [rdp-bruteforce-c2-persistence](../hunts/rdp-bruteforce-c2-persistence/README.md) |
| [unsigned-binary-execution-user-writable-path](splunk/unsigned-binary-execution-user-writable-path.md) | T1204.002 / T1071 | [rdp-bruteforce-c2-persistence](../hunts/rdp-bruteforce-c2-persistence/README.md) |
| [internal-host-dns-recon](splunk/internal-host-dns-recon.md) | T1018 | [rdp-bruteforce-c2-persistence](../hunts/rdp-bruteforce-c2-persistence/README.md) |
| [scheduled-task-creation-via-powershell](splunk/scheduled-task-creation-via-powershell.md) | T1053.005 | [rdp-bruteforce-c2-persistence](../hunts/rdp-bruteforce-c2-persistence/README.md) |

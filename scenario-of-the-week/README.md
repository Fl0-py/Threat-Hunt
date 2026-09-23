# Scenario of the Week

This folder is a pedagogical challenge journal, not a forensic report: each entry takes a SOC alert scenario
through my initial response, an unfiltered expert review of that response — conducted by Claude (Anthropic),
acting as a senior SOC coach — my own reflection on the gaps found, and a revised response after integrating the
critique. The value here is the visible progression — the reasoning, the mistakes, and how they get corrected —
not a polished write-up that hides the learning process.

## Index

| # | Scenario | Summary |
|---|---|---|
| 1 | [vendor-email-compromise-wire-fraud](scenario-of-the-week-1-vendor-email-compromise-wire-fraud.md) | An AP clerk pays a $184,000 invoice to fraudulent banking details after a hijacked vendor email thread, despite the sender domain matching exactly — business email compromise |
| 2 | [unauthorized-anydesk-installation-service-account](scenario-of-the-week-2-unauthorized-anydesk-installation-service-account.md) | A silent AnyDesk install runs under a service account (`svc-confluence`) on an internal host |
| 3 | [potential-privilege-escalation-regsvr32-dll-execution-system](scenario-of-the-week-3-potential-privilege-escalation-regsvr32-dll-execution-system.md) | A suspicious DLL is executed via `regsvr32` under the SYSTEM account |
| 4 | [internal-port-scan-detected-netscan-exe](scenario-of-the-week-4-internal-port-scan-detected-netscan-exe.md) | `netscan.exe` sweeps an internal `/24` network range from a server, running under the administrator account |
| 5 | [impossible-travel-sign-in-detected](scenario-of-the-week-5-impossible-travel-sign-in-detected.md) | Two Microsoft 365 sign-ins for the same user, 15 minutes apart, from geographically incompatible locations — Conditional Access flagged the session but authentication still succeeded |
| 6 | [ssh-brute-force-activity-detected](scenario-of-the-week-6-ssh-brute-force-activity-detected.md) | Over 500 failed SSH login attempts against `administrator` from a single external IP in under 10 minutes |
| 7 | [potentially-malicious-url-click-detected](scenario-of-the-week-7-potentially-malicious-url-click-detected.md) | A user clicks a link to a PaaS-hosted domain structured like an auto-generated phishing kit |
| 8 | [endpoint-file-downloaded-via-wget](scenario-of-the-week-8-endpoint-file-downloaded-via-wget.md) | A file is pulled from an S3 bucket URL to a Linux host via `wget` under a user account |
| 9 | [accounting-credential-phishing](scenario-of-the-week-9-accounting-credential-phishing.md) | An Accounting user clicks a fake "IT security upgrade" link and enters their password on a page that fails to load |

# Hunts

This folder collects the threat hunts I've conducted as part of building my SOC analyst portfolio. Each
write-up demonstrates my investigation and analysis capability end to end — scoping, evidence-backed kill-chain
reconstruction, and hardening recommendations tied to the gaps actually found — not just the final verdict.

## Index

| # | Hunt | Summary |
|---|---|---|
| 1 | [rdp-bruteforce-c2-persistence](rdp-bruteforce-c2-persistence/README.md) | RDP brute force → Defender tampering → malicious payload download → C2 → domain controller reconnaissance → scheduled task persistence (MyDFIR SOC Community exercise, host FRONTDESK-PC1) |
| 2 | [advance-fee-fraud-email-analysis](advance-fee-fraud-email-analysis/README.md) | Raw header and OSINT analysis of an advance-fee fraud email impersonating US Treasury officials — SPF/DKIM/DMARC failure, spoofed domain, unverified relay hostname (MyDFIR "First Email Analysis" lab) |

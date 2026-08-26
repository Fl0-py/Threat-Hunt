# Scenario of the Week 3 — Potential Privilege Escalation: regsvr32 DLL Execution (SYSTEM)

## 🎬 Scenario

```
Alert: MYDFIR-ALRT-0001
Alert Name: Potential Privilege Escalation: regsvr32 DLL Execution (SYSTEM)
Date/Time: 2025-08-15 04:25:01 UTC
Device: conf-west02.internal.local
User: SYSTEM
File: nbjlop.dll
Command Line: regsvr32 nbjlop.dll
```

A suspicious DLL was executed with regsvr32 under SYSTEM.

## 🧭 Guided Questions

- What's your gut telling you and how would you confirm it?
- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
First reflex on receiving the alert: take stock of the information available. Not knowing `regsvr32` going in,
I take the time to look it up first. `regsvr32.exe` is a native Windows utility used to register or unregister
DLLs and ActiveX/COM controls by updating the corresponding Windows Registry entries. From a security
standpoint, it's a significant risk because it's a Microsoft-signed binary, which attackers can abuse to load
malicious COM scriptlets (`.sct` files) or DLLs.

With that in mind, I organize the information into context, anomaly, and priority data: **context** — alert
raised on 2025-08-15 at 04:25:01 UTC on `conf-west02.internal.local`, for a DLL load via `regsvr32 nbjlop.dll`,
run by the `SYSTEM` account; **anomaly** — unknown `nbjlop` DLL, executed outside the usual activity window;
**priority** — the `nbjlop.dll` library and the command that loaded it.

Before starting the investigation, I set a true-positive and a false-positive hypothesis: (1) ATT&CK T1218.010
— a threat successfully ran a malicious DLL via the SYSTEM profile; (2) this is a legitimate IT action. To
confirm, I'll contact IT to validate (or rule out) legitimacy, before digging further into the library and the
events around its load via `regsvr32.exe`. I set a graduated IR response threshold based on the investigation
outcome: legitimate → close the ticket; not recognized → targeted network block on the source; lateral
movement, persistence, or exfiltration demonstrated → full isolation.

**What questions would you ask?**
What is the target's function? Is there an IT-scheduled task involving regsvr32? Are there unusual
inbound/outbound network connections around the target? Where was this DLL loaded from, and where does it come
from? What's its hash? What process launched the abused binary? What processes ran upstream and downstream of
the DLL load? What are the authentication logs around the SYSTEM profile? How did the SYSTEM profile launch the
binary?

**What would you investigate and in what order?**
First reflex: preserve data volatility (network connections, then process state, then memory, then disk, then
logs) before moving to analysis. Then review network connections for anything out of the ordinary; if
suspicious IPs/domains/URLs surface, run an OSINT reputation check that could support a targeted network block
on the source. Then focus on the DLL: extract the load path via Sysmon Event ID 7, extract the hash for an
OSINT reputation lookup (threat actor attribution), and check the signature to assess the DLL's legitimacy.
Next, confirm the full parent chain of the `regsvr32.exe` process itself via Sysmon EID 1 — `ParentImage`,
`ParentProcessId`, `CommandLine`, `User`, `LogonId`, `IntegrityLevel` — plus the hash/signature of `regsvr32.exe`
itself, and inspect downstream processes for signs of LOLBin abuse (PowerShell, cmd, …). Then pivot around the
SYSTEM profile to identify how system privileges were assigned, via Windows Event ID 4624/4672, and how the
binary was launched (scheduled task, token abuse, misconfiguration, …). Continue with a search for persistence
activity — processes launched after the command, scheduled tasks, registry persistence, COM hijacking. Finally,
for scoping: search for the `nbjlop.dll` hash across other machines in the organization, and for other IOCs
(IP, URL, domain, …), to surface other forms of the attack and locate the initial access vector (email,
quishing, …).

**Who would you communicate with and when?**
First, notify the team that I'm taking the alert, and check for any other alert that could be correlated
(impossible travel, privilege escalation, a phishing link email, …). At minute 0 of triage, I secure the
volatility axis per RFC 3227, before moving to IT contact. If nobody is available, I check the back logs on
hand for any trace of a scheduled task. If a task exists, or IT confirms the action, I close the ticket. If no
clear legitimate action is identified, I request a targeted network block on the source; if persistence or
another threat action is confirmed, I request full isolation, then extraction of `nbjlop.dll` for malware
analysis, then pivot to `regsvr32` executions across the environment and add a detection rule for `regsvr32`
with unusual DLL paths.

## 🧠 Expert Review

The single most consequential gap is that the true-positive hypothesis conflates two verdicts that should stay
separate. "ATT&CK T1218.010 — a threat successfully ran a malicious DLL via the SYSTEM profile" treats
technique confirmation and privilege escalation as one and the same. T1218.010 (Signed Binary Proxy Execution:
Regsvr32) documents an execution/defense-evasion mechanism — it says nothing about how the SYSTEM context was
obtained. A misconfigured scheduled task that happens to launch `regsvr32` is not privilege escalation at all:
the process was already running in a privileged context by construction, and the attacker exploited an
existing execution path rather than elevating anything. Token abuse, by contrast, is genuine escalation
(`T1134` — Access Token Manipulation, tactic `TA0004`). These are two different incident verdicts with two
different remediation targets — hardening a scheduled task versus hunting for a live token-abuse mechanism —
and the investigation plan's step on "how system privileges were assigned" (`4624`/`4672`, the parent chain)
is exactly the discriminator needed, but the initial hypothesis is written as if T1218.010 confirmation were
already the full verdict.

Second, and this is a repeat of a pattern already flagged on a prior scenario (vendor email compromise): the
plan secures the volatility axis under RFC 3227 and only then moves to IT contact — "at minute 0... before
moving to IT contact." These are two independent actions with no dependency on each other's outcome, and
sequencing them costs response time for no benefit; both should start at minute 0.

Two smaller precision points. The response never explicitly places T1218.010 on the ATT&CK two-axis model —
worth stating outright that using a trusted signed binary to blend into normal activity and evade an
application-control check is a Stealth-axis behavior, not Defense Impairment (the v19.1 split), since it never
actively disables or tampers with a defense mechanism. And `ParentProcessId` is listed among the Sysmon EID 1
fields to pull for the `regsvr32.exe` parent chain without noting that it's spoofable via
`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` — a process can freely declare its own parent at creation time.
`LogonId`, listed right alongside it, is the field that actually corroborates the chain independently, because
it's assigned by the LSA at authentication time and ties directly back to Windows EID 4624/4672 — a layer the
attacker's process-creation call doesn't control.

What holds up well: the command-line syntax (`regsvr32 nbjlop.dll`, no `/i:URL` flag) is correctly read as the
local `DllRegisterServer` load path — the mechanism documented in Qakbot and Emotet activity — rather than the
disk-less "Squiblydoo" remote-scriptlet variant, which needs `/i:` and wasn't invoked here. The RFC 3227
volatility ordering, the specificity of the data sources named throughout (Sysmon EID 1/7, Windows EID
4624/4672, hash and signature checks rather than vague "analyze the logs" language), and the graduated
containment thresholds (no "if confirmed as a threat" hand-waving) are all solid and didn't need correction.

## 🪞 Reflection

Two operational reflexes to carry forward, not a factual correction. First: naming an ATT&CK execution
technique as confirmed is not the same as confirming how a privileged context was reached, and collapsing the
two into a single hypothesis hides which of several very different remediation paths actually applies — a
technique ID answers "how was this executed," not "how was this privilege obtained," and both questions need
their own hypothesis when the alert's own framing is about escalation. Second: securing volatile evidence and
reaching out to a stakeholder are independent actions the moment neither depends on the other's outcome, and
sequencing them instead of running them in parallel is now a repeat pattern across two separate scenarios —
worth treating as a standing checklist item ("what runs in parallel at minute 0") rather than something to
catch case by case.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
Same first reflex: take stock of the information available, look up `regsvr32` (native Windows utility for
registering/unregistering DLLs and ActiveX/COM controls via the Registry; a significant risk given its status
as a Microsoft-signed binary, abusable to load malicious COM scriptlets or DLLs), and organize the information
into context, anomaly, and priority data — alert on `conf-west02.internal.local`, `regsvr32 nbjlop.dll` run by
`SYSTEM` on 2025-08-15 at 04:25:01 UTC; unknown DLL outside the usual activity window; the `nbjlop.dll` library
and its command line as the priority.

The hypothesis structure changes here: rather than one true-positive hypothesis fusing execution and
escalation, two ATT&CK entries are carried in parallel against the same false-positive hypothesis (legitimate
IT action) — `TA0004`, a threat gained higher-level permissions on the SYSTEM profile (genuine privilege
escalation), and `T1218.010`, a threat ran a malicious DLL following a possible privilege escalation on the
SYSTEM profile (the execution/defense-evasion technique itself, with escalation status still undetermined). To
confirm, I'll contact IT to validate or rule out legitimacy before digging further into the library and the
events around its load via `regsvr32.exe`. Same graduated IR response threshold: legitimate → close the
ticket; not recognized → targeted network block on the source; lateral movement, persistence, or exfiltration
demonstrated → full isolation.

**What questions would you ask?** Unchanged.

**What would you investigate and in what order?** Unchanged.

**Who would you communicate with and when?** One change: at minute 0 of triage, the RFC 3227 volatility axis is
secured *while simultaneously* initiating IT contact, rather than one after the other. If nobody is available
on the IT side, back logs are checked for a scheduled-task trace. Legitimate action confirmed (by IT or a
matching scheduled task) → close the ticket. No clear legitimate action identified → targeted network block on
the source. Persistence or other threat activity confirmed → full isolation, extraction of `nbjlop.dll` for
malware analysis, pivot to `regsvr32` executions environment-wide, and a new detection rule for `regsvr32` with
unusual DLL paths.

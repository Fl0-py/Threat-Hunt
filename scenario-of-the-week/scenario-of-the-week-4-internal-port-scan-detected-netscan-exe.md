# Scenario of the Week 4 — Internal Port Scan Detected (netscan.exe)

## 🎬 Scenario

```
Alert: MYDFIR-ALRT-0002
Alert Name: Internal Port Scan Detected
Date/Time: 2025-08-20 06:18:35 UTC
Device: Vuln-srv.internal.local
User: administrator
File: netscan.exe
Network: 192.168.1.0/24
```

The alert "Internal Port Scan Detected" was triggered after `netscan.exe` executed on `Vuln-srv.internal.local`.
The process was observed scanning the internal network range of `192.168.1.0/24`.

## 🧭 Guided Questions

- What's your gut telling you and how would you confirm it?
- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
First reflex on receiving the alert: take stock of the information available. Not knowing `netscan.exe` going
in, I take the time to look it up. `netscan.exe` is a legitimate portable executable for network administration
— it scans IP addresses, detects open ports, file shares, and active services, giving full visibility into
connected devices and their configuration. From a security standpoint, attackers use it as a scanner during the
reconnaissance/network-mapping phase to find entry points before an intrusion. In addition, malware can
sometimes masquerade under the name `netscan.exe` to hide its activity.

With that in mind, I organize the information into context, anomaly, and priority data:

- **Context** — alert `Internal Port Scan detected` raised on 2025-08-20 at 06:18:35 UTC, from device
  `Vuln-srv.internal.local`, run by user `administrator` via `netscan.exe`, targeting the `192.168.1.0/24` range.
- **Anomaly** — a scan from an internal server outside business hours, run under an `administrator` profile,
  across a network range.
- **Priority** — the device and the user who initiated the scan.

Before starting the investigation, I set contradictory (true/false positive) hypotheses:

1. ATT&CK T1046 — adversaries may attempt to get a listing of services running on remote hosts and local
   network infrastructure devices, including those that may be vulnerable to remote software exploitation.
2. ATT&CK TA0004 — adversaries gain higher-level permissions on a system or network.
3. A legitimate scan initiated by the organization, which seems likely given the `Vuln-srv` mention in the
   server name.

To confirm, I'll contact IT to validate (or rule out) the task's legitimacy, before digging further into the
activity on the device and the `administrator` profile that initiated the scan. I set a graduated IR response
threshold based on the investigation outcome: legitimate → close the ticket; not recognized → targeted network
block on the source; lateral movement, persistence, or exfiltration demonstrated → full isolation of the source
and associated targets.

**What questions would you ask?**
Was a legitimate network scan task carried out by IT? What devices/services exist on the `192.168.1.0/24` range?
What is the device's role within the organization? What is the parent/child chain associated with the launch of
`netscan.exe`? Are there suspicious commands or parent/child relationships within the alert's time window? What
do the authentication logs around the `administrator` profile look like? How did the profile launch the binary?

**What would you investigate and in what order?**
First reflex: preserve data volatility (network connections, then process state, then memory, then disk, then
logs) before moving to analysis. In parallel, I initiate contact with IT. Depending on their response/
availability, I review network connections for anything out of the ordinary regarding the device on the scanned
range; if suspicious IPs/domains/URLs surface, I run an OSINT reputation check that could support a targeted
network block on the source. Then I focus on the device and `netscan.exe` via Sysmon Event ID 1 — Process
creation, to get the hash, the image (executable path), command line, ParentImage/CommandLine (parent process
context), and signature. My goal is to confirm (or rule out) the use of `netscan.exe` and where it was launched
from, which could surface anomalous behavior. Then I look up the process GUID and examine the parent/child
process ID to follow the process chain and determine how this .exe was spawned, and whether there are signs of
LOLBins after execution.

Then I pivot around the `administrator` profile by analyzing the login history and identifying how system
privileges were assigned, and from where and when the `administrator` account logged in, using Windows Event ID
4624/4672. I push the analysis further by looking for persistence activity — processes launched after the
command, scheduled tasks, registry persistence, COM hijacking — before scoping more broadly for any lateral
movement activity.

**Who would you communicate with and when?**
I'd start by letting my team know I'm taking the alert, and checking for any other alert that could be
correlated (lateral movement, a phishing email, privilege escalation…). At minute 0 of triage, I secure the
volatility axis of the investigation per RFC 3227, before moving to IT contact. If nobody is available, I check
the back logs/emails on hand to determine whether a trace of a scheduled task exists. If a task exists, or IT
confirms the action, I close the ticket. If no clear legitimate action is identified, I request a targeted
network block on the source; and if lateral movement, persistence, or another threat action is confirmed, I
request full isolation for further investigation.

## 🧠 Expert Review

The most consequential framing error is hypothesis 2: "ATT&CK TA0004 — adversaries gain higher-level
permissions." TA0004 names an entire tactic, not a technique, and pairing it with T1046 puts two different kinds
of ATT&CK objects on the same level. More importantly, nothing in the alert evidences an escalation mechanism —
the only thing cited in support is that the account running the scan already holds administrator rights. That's
a precondition inherited from before this alert, not evidence that an escalation happened as part of the
observed action. A port scan run with admin rights is a discovery action executed from an already-privileged
context; it says nothing by itself about how that context was reached. If an escalation angle matters here, it
belongs to *how* the `administrator` account obtained or is using its privileges around this time window — a
token abuse, a group membership change, a misconfiguration — investigated downstream via `4624`/`4672`, not
inferred upfront from who happened to run the command.

Second, the "legitimate scan" hypothesis leans on the server's name, `Vuln-srv`, as if it were evidence of
legitimacy. It's a surface signal exactly like a valid code-signing certificate — suggestive, and just as easy
for an attacker to ignore, since renaming a compromised pivot host is not something an intruder has any reason
to do. Treating a naming convention as making an outcome "likely" needs to be replaced with an independently
verifiable criterion: direct IT contact, a change ticket, or a scheduled-task baseline for this host.

Third, the anomaly block asserts the scan happened "outside business hours" from a bare UTC timestamp, with no
stated organizational timezone and no known working hours. That's an unverified claim presented as a fact — the
alert alone cannot support it.

Fourth, the investigation plan states the volatility axis should be secured "before moving to analysis," and
the same before/after framing around IT contact resurfaces, nearly verbatim, in both the investigation plan and
the communication plan. Volatile-evidence preservation and stakeholder outreach are independent actions the
moment neither depends on the other's result, and gating one behind the other costs response time for nothing
in return. This is a repeat of a pattern already flagged twice on a prior scenario (regsvr32 DLL execution) —
worth treating as a standing "what runs in parallel at minute 0" habit rather than a case-by-case catch.

Fifth, the plan names `ParentProcessId` alongside the parent/child chain as if a clean-looking chain settles the
question of legitimacy. `ParentProcessId` is declared by a process at its own creation via
`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, so it's attacker-controllable and proves nothing alone. The field that
actually corroborates the chain independently is `SubjectLogonId`: it's assigned by the LSA at authentication
time, appears on both the process-creation event and the `4624`/`4672` logon events, and lets the process chain
be tied to one specific `administrator` session — which matters here since that account can have several
sessions open at once.

Sixth, the RFC 3227 order names "then memory" but the plan never puts memory to use — a stated intention that's
never operationalized. Given the plan's own hypothesis 3 (malware masquerading under the `netscan.exe` name),
the concrete use of memory here is a direct comparison between the in-memory image hash and the on-disk file
hash, which is the only way to surface process hollowing or injection that a disk-only hash check would miss.

What holds up well: `netscan.exe`'s dual-use nature — legitimate admin tool, adversary recon tool, and a name
malware sometimes borrows — is correctly worked out before any hypothesis is written, which is exactly the right
first move on an unfamiliar binary. The graduated containment thresholds (close / targeted block / full
isolation) never collapse into a vague "if confirmed as a threat." And the data sources named throughout —
Sysmon Event ID 1 fields, Windows Event ID 4624/4672 — are concrete and specific rather than a generic "analyze
the logs."

## 🪞 Reflection

Five operational reflexes to carry forward:

1. The privilege level an account already holds is context, not evidence that a privilege-escalation technique
   occurred in the action being investigated — a tactic needs a mechanism behind it, not just an actor who
   happens to already be privileged.
2. A hostname or naming convention is a surface legitimacy signal exactly like a code-signing certificate, and
   needs to be replaced by an independently verifiable criterion — IT contact, change ticket, scheduled-task
   baseline — before a hypothesis gets called "likely."
3. No timing claim ("outside business hours," "anomalous timestamp") counts as a fact without the
   organization's actual timezone and working hours behind it.
4. Volatile-evidence preservation and stakeholder communication are independent from minute 0 whenever neither
   depends on the other's outcome — this is now a third occurrence of the same sequencing mistake across two
   different scenarios, which makes it a standing checklist item rather than something to catch case by case.
5. `ParentProcessId` is attacker-controllable at process creation; `SubjectLogonId` is the field that survives,
   because it's assigned by the LSA at authentication and ties directly into the identity layer (`4624`/`4672`)
   — that's the correct pivot for any process-to-identity correlation, not `ProcessId` or a clean-looking parent
   chain alone.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
Same first reflex: take stock of the information available, look up `netscan.exe` (a legitimate portable
network-administration executable — IP/port/share/service scanning — also used by attackers for reconnaissance,
and a name malware sometimes masquerades under), and organize the information into context, anomaly, and
priority data:

- **Context** — alert `Internal Port Scan detected` on `Vuln-srv.internal.local`, `netscan.exe` run by
  `administrator` against `192.168.1.0/24` on 2025-08-20 at 06:18:35 UTC.
- **Anomaly** — a network scan from an internal server, run under the `administrator` profile.
- **Priority** — the scan's status (still active or not?), and the device and user that initiated it.

The hypothesis structure changes here:

1. ATT&CK T1046 — network service discovery.
2. A legitimate scan initiated by the organization, to be confirmed via direct IT contact, a change ticket, or
   a scheduled-task baseline — not inferred from the server's name alone.

To confirm this, I'll work to establish the task's legitimacy via IT contact or a search through available
backlogs/emails, in parallel with digging further into the activity on the device and the `administrator`
profile that initiated the scan. Same graduated IR response threshold, with one addition: legitimate → close
the ticket; not directly recognized as legitimate → targeted network block on the source; lateral movement,
persistence, privilege escalation, or exfiltration demonstrated → full isolation of the source and associated
targets.

**What questions would you ask?** Unchanged.

**What would you investigate and in what order?**
My first reflex is to determine whether the scan is still active, and to preserve the investigation's volatile
axis (network connections, process state, memory, disk, and logs). I confirm `netscan.exe` by comparing the
in-memory image hash against the on-disk file hash, to surface a potential mismatch. In parallel, I initiate
contact with IT to confirm the process's legitimacy, and push the analysis of network connections tied to the
scanned range, looking for suspicious IPs/domains/URLs on which I can run OSINT/reputation checks.

Then I focus on the device and `netscan.exe` via Sysmon Event ID 1 — Process creation, to get the Image
(executable path), CommandLine, and ParentImage/CommandLine (parent process context). My goal is to confirm
`netscan.exe`'s launch directory, which could surface anomalous behavior. Then I look up the process GUID and
examine the `SubjectLogonId` of the parent/child process to follow the process chain, determine how this .exe
was spawned, check for signs of LOLBins after execution, and tie it back to the `administrator` logon. I then
pivot around the profile and Windows Event ID 4624/4672 to understand where and when the `administrator` account
logged in, and how system privileges were granted. I push the analysis further by looking for persistence
activity — processes launched after the command, scheduled tasks, registry persistence, COM hijacking — before
scoping more broadly for any lateral movement activity, or the creation of a results file generated by
`netscan.exe`.

**Who would you communicate with and when?**
I'd start by letting my team know I'm taking the alert, and checking for any other alert that could be
correlated (lateral movement, a phishing email, privilege escalation…). At minute 0 of triage, I secure the
volatility axis of the investigation per RFC 3227, initiating contact with IT in parallel. If nobody is
available, I check the back logs/emails on hand to determine whether a trace of a scheduled task exists. If a
task exists, or IT confirms the action, I close the ticket. If no clear legitimate action is identified, I
request a targeted network block on the source; and if persistence or another threat action is confirmed, I
request full isolation for further investigation.

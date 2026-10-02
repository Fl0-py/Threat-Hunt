# Scenario of the Week 7 — Potentially Malicious URL Click Detected

**Published:** 2026-09-09

## 🎬 Scenario

```
Alert: MYDFIR-ALRT-0005
Alert Name: Potentially Malicious URL Click Detected
User: Emily.Wong@fakecompany.ca
Device: PC-3
URL: bdo-online-customer-2d525-0813[.]pages[.]dev
Time Detected: 2025-09-14 14:37 UTC
```

A URL click was recorded from `PC-3` by the user `Emily.Wong@fakecompany.ca`.

## 🧭 Guided Questions

- What's your gut telling you and how would you confirm it?
- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
My first reflex is to organize the information using the context / anomaly / priority triptych:

- **Context** — the user `Emily.Wong@fakecompany.ca` clicked the URL `bdo-online-customer-2d525-0813[.]pages[.]dev`
  from the device `PC-3` at `2025-09-14 14:37 UTC`.
- **Anomaly** — the URL itself, `bdo-online-customer-2d525-0813[.]pages[.]dev`.
- **Priority** — the user `Emily.Wong@fakecompany.ca` and the device `PC-3`.

Before starting the investigation, I set hypotheses that could either prove a false positive or confirm the
alert:

1. ATT&CK T1204.001 — User Execution: Malicious Link: an adversary may rely on a user clicking a malicious link
   in order to gain execution, subjecting users to social engineering to get them to click a link that leads to
   code execution.
2. Detection based on an inaccurate or stale domain reputation, a dynamically generated URL that structurally
   resembles a phishing pattern, or a click on a link from a legitimate email sent by a frequently-impersonated
   platform.

To confirm this quickly, I'd contact the user to understand where the link came from and why she clicked it,
while scanning the link for reputation in parallel. I set the following graduated response scale:

- False positive confirmed → close the ticket.
- URL scan flagged as malicious, outbound connection to an untrusted domain/IP, a file download, or subsequent
  child execution by a LOLBin → targeted network block on the source, session revocation, and a deeper
  investigation.
- Lateral movement, persistence, or exfiltration demonstrated → full isolation of the source and associated
  targets, and incident response triggered.

To close out the qualification, I look at the volatility axis to prioritize actions — from my perspective, it
centers on the network connections and the user's device.

**What questions would you ask?**
What is the result of the scan? What is the user's recent activity? How did the user get access to the link?
Why did she need to click it? Are there any outbound connections to an untrusted domain/IP from the device? Was
any data exfiltrated? Was a file downloaded? Were there any dialog boxes or installation prompts? Was there
subsequent child execution by a LOLBin? Were persistence mechanisms deployed? Was lateral movement observed? Did
anyone else receive the link?

**What would you investigate and in what order?**
My first reflex is to preserve the volatility axis identified above, following RFC 3227 best current practice
(network connections → process state → memory → disk) to secure the data/evidence. In parallel, I check the
reputation of `bdo-online-customer-2d525-0813.pages.dev` with a tool like urlscan.io. Then I contact the user for
more context, to understand what she needed the link for and how she received it. If the use of the link is
confirmed legitimate, I close the ticket. Otherwise, I push the analysis further by checking whether anything was
downloaded, installed, or triggered a dialog box interaction. I also note the channel through which the link was
delivered, for a scoping exercise across the organization to anticipate other clicks.

For the deep-dive, assuming a Windows machine, I start with Sysmon Event ID 3 (Network Connection) to surface
outbound network connections, and Sysmon Event ID 22 (DNSEvent) for the domain's DNS resolution right
before/during the click, to get the resolved IP address and cross-check it against proxy/firewall logs if
available. I also look for outbound connections carrying an abnormal data volume toward an external IP/domain or
an unapproved cloud service, and note traffic toward other internal hosts on SMB (445), WinRM (5985/5986), RDP
(3389), and WMI (135) as a possible sign of lateral movement.

I then check whether a file was downloaded via Sysmon Event ID 11 (FileCreate), looking for a new file in
`%USERPROFILE%\Downloads` or elsewhere. Right after, I look at Sysmon Event ID 1 (Process Create) for the launch
of an installer (`setup.exe`, `msiexec.exe`, or any signed/unsigned binary) spawned from the downloaded file, and
Sysmon Event ID 7 (Image Loaded) to identify DLLs loaded during installation, looking for DLL side-loading. I
follow up with Sysmon Event ID 1 again, this time with the downloaded file or the browser as the parent of a
LOLBin (`mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `powershell.exe`, `wscript.exe`...), looking for the classic
click → drop → execution pivot.

I then move to persistence, checking any registry modification via Sysmon Event ID 13 (Registry Value Set),
service creation via Security Event ID 4697 or System Event ID 7045 (Service Control Manager), scheduled task
creation via Security Event ID 4698, and the startup folder. Finally, I check Security Event ID 4624 to surface a
connection from `PC-3` to another host/server (Logon type 3, network, or type 10, RemoteInteractive), or evidence
of account compromise.

Once the incident is resolved, for the post-incident phase, I would recommend:

- User awareness training.
- Automatic URL scanning in emails or other communication channels.
- Blocking at the moment of the click.

**Who would you communicate with and when?**
I notify my team that I'm taking ownership of the alert and ask them to check the alert queue for potential
correlation with new or older alerts. I then contact the user to get more context, measure the impact of the
click, and identify the delivery channel of the link. Once I have the channel, I don't wait to escalate it to
the IT Helpdesk to contain the threat both on the user's device and across the organization. I inform my SOC
manager as soon as an element triggers a short-term containment. If the situation escalates, I bring in the IR
response manager, management, and legal in case sensitive data was exfiltrated.

## 🧠 Expert Review

The most consequential gap is a contradiction between the gut-feeling answer and the investigation plan: the
gut-feeling section states the user will be contacted "while scanning the link in parallel," but the
investigation plan then sequences it instead — "I check the reputation of the domain via a tool like urlscan.io.
Then I contact the user for more context." Contacting the user carries no volatility pressure of its own;
sequencing it behind a reputation scan gains nothing and risks losing context if she takes further action or
closes her laptop in the meantime. Why does the plan revert to a sequential order one paragraph after stating
the intent was parallel?

Second, "preserving the volatility axis" is named as the first reflex, citing RFC 3227's order (network
connections → process state → memory → disk), but nothing in the plan says what that capture actually consists
of on `PC-3` — no tool, no command, nothing distinguishing a live capture of currently-active state from the
retrospective Sysmon/Security Event Log review that follows. Those two things aren't equivalent: once an event
is written to Sysmon or the Security channel, it's already persisted and isn't going anywhere, whereas the
current network connections, running process list, and memory content on `PC-3` change or disappear the longer
the response takes. Naming the framework isn't the same as operationalizing it — what specifically would be
captured, and with what?

Third, Security Event ID 4624 is checked at the very end of the plan, in isolation, to surface "a connection
from `PC-3` to another host/server... or evidence of account compromise" — with no link back to the process
chain built earlier in the same plan (Sysmon Event ID 1 for the dropped installer, then again for a LOLBin child
process). A process lineage alone doesn't prove which logon session it belongs to — `ParentProcessId` is
spoofable — so treating process creation and logon events as two independent checks leaves open whether the
observed activity actually maps to Emily Wong's own session rather than another session active on the same
host. What field would tie the two together?

Fourth, the three post-incident measures — user awareness, automatic URL scanning, and click-time blocking — are
named as intentions rather than mechanisms, and the second one has a structural weakness worth naming directly:
reputation-based scanning, whether at delivery or at click time, checks a URL against a list of already-known-bad
domains. A domain registered and weaponized the same day it's clicked, like this one, simply hasn't accumulated
a bad reputation yet by the time either check runs — and attackers commonly serve a benign page to known scanner
IPs/user-agents while serving the malicious payload to the real click (cloaking), which specifically defeats
click-time rewriting. Naming "scan the URL" as a control doesn't address either gap.

Fifth, the intermediate containment tier calls for a "targeted network block on the source" without specifying
at what layer — an EDR/firewall-level block that severs command-and-control traffic while leaving `PC-3` running
is forensically very different from isolating or powering off the host, and only one of those preserves the
volatile state the plan opened by promising to protect.

What holds up well: two competing hypotheses (malicious link vs. false positive) are stated upfront in ACH form
rather than defaulting to an assumed threat, and the deep-dive names exact, specific telemetry throughout —
precise Sysmon/Security Event IDs, exact registry and file paths, and lateral-movement ports (SMB 445, WinRM
5985/5986, RDP 3389, WMI 135) — rather than a vague "check the network." The graduated containment scale is
criteria-based (a flagged URL, an untrusted outbound connection, a dropped file, or LOLBin execution — versus
demonstrated lateral movement/persistence/exfiltration) rather than an undefined "if confirmed malicious." And
checking Sysmon Event ID 7 (Image Loaded) for DLL side-loading, rather than trusting the installer's Authenticode
signature alone, is exactly the right instinct — Authenticode validates the signed binary, not the DLLs it loads
at runtime.

## 🪞 Reflection

1. A legitimacy-axis action (contacting the user) and a volatility-axis action (live capture) that don't depend
   on each other's outcome should never be written in sequence just because they're described one after the
   other. "Parallel" means no task waits on another's result — not that both happen at the exact same instant;
   for a single analyst, the execution order is a matter of convenience, not of methodology.
2. Naming a best practice (RFC 3227) isn't the same as operationalizing it. A concrete tool has to be attached to
   it — EDR live response (CrowdStrike Falcon RTR, Microsoft Defender for Endpoint Live Response, SentinelOne:
   `netstat`, `ps`, a `runscript`/`getfile` action for a memory capture) or, without EDR, PowerShell remoting
   (`Invoke-Command`, `Get-NetTCPConnection`, `Get-Process`) with the caveat that opening the remote session
   itself creates a new process on the target. This stays theoretical until it's actually practiced.
3. A correlation field like `SubjectLogonId` only does its job once the data it's meant to correlate has already
   been retrieved — sequencing it before the process chain it validates defeats the point.
4. A preventive control deserves the same scrutiny as an investigative step: before naming one, ask what data it
   actually relies on and how quickly that data goes stale relative to the attacker's own timeline — a
   reputation-based check is only as fast as the reputation database behind it, and a same-day domain outruns it
   by design.
5. Identifying which network log fields carry real ROI is still a developing skill — the habit to build is
   asking, for every log source pulled, what concrete data it returns and how it will actually be used, instead
   of listing event IDs without a plan for their output.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
Same triptych and hypotheses as above. The graduated response scale is tightened on the middle tier: a URL
flagged malicious, an outbound connection to an untrusted domain/IP, a file download, or subsequent child
execution by a LOLBin now triggers session revocation, account lockout/password change, and a targeted network
block on the source — specifically at the EDR/firewall layer, cutting command-and-control traffic without
touching the state of the machine, rather than an isolation or shutdown that would destroy volatile evidence
before it's captured.

**What questions would you ask?** Unchanged.

**What would you investigate and in what order?**
My first reflex is still preserving the volatility axis following RFC 3227 (network connections → process state
→ memory → disk), but this time tied to actual tooling: in an EDR environment (CrowdStrike Falcon RTR, Microsoft
Defender for Endpoint Live Response, SentinelOne), I use an interactive remote session exposing `netstat`/`ps`
commands and a `runscript`/`getfile` action to push a memory-capture tool and retrieve it. Without EDR, the
equivalent is PowerShell remoting (`Invoke-Command`, `Enter-PSSession`) with `Get-NetTCPConnection` and
`Get-Process` — keeping in mind that opening a remote PowerShell session itself spawns a new process on the
target machine, slightly altering the state it's meant to preserve. In parallel, I check the reputation of
`bdo-online-customer-2d525-0813.pages.dev` via a tool like urlscan.io while contacting the user for more context
— what she needed the link for and how she received it. If the use of the link is confirmed legitimate, I close
the ticket. Otherwise, I push the analysis further, checking whether anything was downloaded, installed, or
triggered a dialog interaction, and I note the delivery channel for a scoping exercise across the organization.

For the deep-dive, I start with Sysmon Event ID 3 (Network Connection) and Event ID 22 (DNSEvent) to surface
outbound connections and check whether `PC-3` contacts other domains after the initial click — beaconing toward
infrastructure different from the phishing page itself. I also watch for an abnormal outbound data volume toward
an external IP/domain or unapproved cloud service, and note traffic toward other internal hosts on SMB (445),
WinRM (5985/5986), RDP (3389), and WMI (135) for possible lateral movement.

I then check whether a file was downloaded via Sysmon Event ID 11 (FileCreate) in `%USERPROFILE%\Downloads` or
elsewhere, followed by Sysmon Event ID 1 (Process Create) for the launch of an installer (`setup.exe`,
`msiexec.exe`, or any signed/unsigned binary) from that file, and Sysmon Event ID 7 (Image Loaded) to catch DLL
side-loading during installation. I follow with Sysmon Event ID 1 again, this time with the downloaded file or
the browser as the parent of a LOLBin (`mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `powershell.exe`,
`wscript.exe`...), looking for the classic click → drop → execution pivot. With the process chain established, I
check Security Event ID 4624 (Logon type 3 or type 10) for a connection from `PC-3` to another host/server, and
pull the `SubjectLogonId` field to explicitly tie that process chain to a specific logon session — protecting
against a spoofed `ParentProcessId` and confirming whether the activity actually belongs to Emily Wong's own
session.

I then move to persistence: registry modification via Sysmon Event ID 13 (Registry Value Set), service creation
via Security Event ID 4697 or System Event ID 7045 (Service Control Manager), scheduled task creation via
Security Event ID 4698, and the startup folder.

**Who would you communicate with and when?** Unchanged.

Once the incident is handled and the post-incident phase starts, I would recommend:

- Targeted, measured awareness: simulated phishing campaigns with click-rate tracking before/after, and
  individual follow-up with repeat clickers (including Emily Wong), rather than a generic annual training
  session.
- Domain-age filtering (newly registered domains): block or flag domains registered within the last 30 days at
  the DNS/proxy layer — catches disposable infrastructure without depending on an already-established
  reputation.
- Remote browser isolation for free PaaS hosting platforms: treat subdomains like `*.pages.dev`, `*.web.app`,
  `*.netlify.app`, `*.herokuapp.com` as a high-risk category, rendered inside an isolated cloud container rather
  than directly on the endpoint.
- Post-click behavioral detection: turn the mapped chain (URL opened → outbound connection → file dropped) into
  a Sigma/EDR rule to catch a similar incident earlier next time, rather than relying solely on upfront
  prevention.

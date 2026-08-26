# Scenario of the Week 2 — Unauthorized AnyDesk Installation via a Service Account

## 🎬 Scenario

Alert: MYDFIR-ALRT-0000
Alert Name: Unauthorized Remote Tool Installation
Device: `app-east01.internal.local`
User: `svc-confluence`
File: `AnyDesk.exe`
Command Line: `AnyDesk.exe --install --silent --password P@ssword1`

## 🧭 Guided Questions

- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?
- What's your gut telling you and how would you confirm it?

## 📝 First Response

**What's your gut telling you and how would you confirm it?** I sort the information as follows :

Context: user `svc-confluence` runs `AnyDesk.exe --install --silent --password P@ssword1`, installing the tool
on device `app-east01.internal.local`.
What's abnormal: `AnyDesk.exe` itself (if it's not part of the baseline), the `--install --silent` flags, and
the fact that `svc-confluence` is the one running it.
What to prioritize: the volatility of the data, both before and after the command ran.As an analyst, I'd check 
whether there's another ticket I can link this to, searching for `AnyDesk.exe` and this exact command line, plus
any ticket about active network connections involving `AnyDesk.exe`. The `.exe` extension implies a Microsoft/Windows 
environment.
How could this be a false positive? A legitimate installation performed by IT, or a user operating under the
`svc-confluence` profile. How could this be a true positive? An illegitimate installation by an external
threat actor aiming to take control of an organizational resource. If the threat is real, I'd place this under 
Initial Access — T1133 (External Remote Services) combined with Valid Accounts (T1078) for the `svc-confluence` user.
We could also be looking at lateral movement (T1021) or command and control (T1219).
My instinct is to quickly settle the legitimacy of AnyDesk and/or a planned intervention, to rule out a false
positive fast, before investigating the events in the alert's time window for new elements confirming the
threat hypothesis.

**What questions would you ask?** Is AnyDesk a known, commonly used application within the organization? What's the criticality/role of this
machine within the organization? Is there an active connection via AnyDesk right now? Is any IT action planned
involving AnyDesk? Who has access to the `svc-confluence` profile? What are its permissions? What do the
authentication logs around this profile show? What was `svc-confluence`'s behavior before and after the alert
(time window +/- 2h)?

**What would you investigate and in what order?** Before diving into execution, I map out the volatility and legitimacy axes to prioritize my actions.
On volatility: I need to prioritize preserving data around the `svc-confluence` profile — authentication logs,
command/process launch logs, file creation/modification — and network data that could reveal a C2-type
connection.
On legitimacy: I check AnyDesk's prevalence, evaluate the target's criticality, look at the surrounding
alerts/logs (especially network activity or LOLBins like `cmd`, PowerShell, `wmic`, or `rundll32`), and surface
any potential activity around the `svc-confluence` profile that falls outside this service account's normal
scope.
In terms of action: at minute 0, I verify AnyDesk's prevalence against the baseline while, in parallel,
requesting information from IT. Without waiting for IT's answer, I move to securing volatile data (Windows
logs, authentication, Sysmon, network logs), and I take the opportunity to check network logs to rule out any
C2 activity at first glance.
I then move to analyzing logs over a wider time window, surfacing any potential discovery, lateral movement, or
persistence activity (checking persistence registry keys, scheduled task creation, or startup folder entries).
I then pivot to the profile itself and try to determine the logon type, the source IP if available, or observe
its activity.

**Who would you communicate with and when?** I start by notifying my team that I'm taking ownership of the ticket 
and checking for any correlated alert. I then contact IT with questions about AnyDesk's legitimacy. If, after analysis,
the threat is confirmed, with the help of IT and IR: I isolate the host. I reset `svc-confluence`'s password and revoke 
all associated sessions/tokens. I remediate by uninstalling AnyDesk and any other persistent behavior. I then hand the
host back to the user.

## 🧠 Expert Review

The most consequential issue is a technique attributed before the underlying mechanism is verified. Placing
this under Initial Access — T1133 (External Remote Services) — misreads what T1133 actually describes: an
attacker using a remote access service that already exists and is legitimate within the organization to get
in, not an attacker installing a brand-new remote access tool after already obtaining command execution. The
fact that `svc-confluence` is the one running the install command means execution access was already achieved
upstream — AnyDesk is not the door, it's what gets carried in once the door is already open. The mechanism
that actually fits the observable is T1219 (Remote Access Software), used here for persistence and follow-on
access, not initial entry. The real initial-access vector is still unknown and needs its own line of
investigation.

That leads directly to the second gap: the investigation plan never reaches the one data source capable of
answering the initial-access question. Windows authentication logs and Sysmon can confirm whether
`svc-confluence`'s process lineage looks abnormal, but they cannot show *how* that account came to be executing
commands in the first place. Given the account name, Confluence's own application logs (Tomcat/Catalina) are
the only source that could surface an exploitation attempt — a suspicious HTTP request, an encoded payload, a
webshell artifact — and confirm or rule out a public-facing RCE (T1190) as the true entry point. Without that
source, every downstream conclusion about lateral movement or persistence stays disconnected from how the
attacker actually got in.

Third, the containment trigger — "if, after analysis, the threat is confirmed" — is exactly the kind of
formulation that should be avoided: it isn't a threshold, it's a restatement of the decision itself. A workable
criterion has to name concrete, checkable signals (an active AnyDesk network connection, a LOLBin spawned after
install, an abnormal logon type) rather than deferring to an unspecified moment of certainty.

Fourth, the response frames containment as binary — either monitor or isolate the host outright. For a host
that may be tied to a production Confluence instance, that binary skips a middle tier that a modern EDR
actually offers: a targeted network block of the AnyDesk channel specifically (via EDR or proxy/firewall,
targeting known AnyDesk relay infrastructure) preserves the business function while cutting the suspected
control channel, and can be the first move when confidence is medium-to-high on a critical asset — full
isolation reserved for confirmed lateral movement or exfiltration.

Fifth, the volatility ordering groups authentication logs, Sysmon, and network logs together as one category
to secure, without following RFC 3227's actual order: active network connections, then process state, then
memory, then disk, and only then logs. Live network connections and process memory disappear far faster than a
log file sitting on disk, and the concrete commands run first should reflect that difference.

Sixth, the closing line — investigating "to confirm the threat hypothesis" — leans toward confirmation rather
than testing both hypotheses that were correctly laid out earlier (legitimate IT install vs. external threat).
Given a documented tendency to default toward the malicious hypothesis when the legitimate baseline is
unfamiliar, this is worth naming explicitly rather than treating as incidental phrasing.

What holds up well: the volatility and legitimacy axes are run in parallel from the very first draft, not
sequenced — exactly the discipline that's easiest to get wrong under alert pressure. The competing-hypothesis
framing (legitimate IT action vs. external compromise) is stated explicitly and up front, not treated as an
afterthought. And the instinct not to jump straight to isolation, deciding instead to settle prevalence and
legitimacy first, is the right posture — it just needs the concrete criteria and the middle containment tier to
back it up.

## 🪞 Reflection

Technique attribution has to wait for a verified mechanism — the account executing a command tells you
execution was already achieved, not where the attacker got in; conflating "who ran the install" with "how they
got here" is the specific trap to name. A containment decision needs the one data source that resolves the
open question before anything else — for an alert tied to a named application, that application's own logs
outrank the OS-level telemetry for answering "how did this start." A containment trigger phrased as "if the
threat is confirmed" isn't a threshold — it has to name the concrete signal (an active connection, a specific
logon type, a LOLBin spawned post-install) that flips the decision. Containment itself is not binary: for a
critical asset, a targeted network block sits between monitoring and full isolation, and should be the default
first move once confidence is medium-to-high, isolation reserved for confirmed lateral movement or
exfiltration. Volatility ordering follows RFC 3227 specifically — network connections, then process state,
then memory, then disk, then logs — not "everything that might disappear" treated as one undifferentiated
bucket. And closing an answer with language oriented toward confirming a hypothesis, rather than testing it
against the alternative, is a recurring pattern worth catching in the moment, not just in hindsight.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
The pattern — a service account silently installing a remote access tool with a hardcoded password — still
points toward a compromise, but I'm treating that as a hypothesis to test against a legitimate-install
alternative, not something to build the investigation around confirming. If real, this sits under Persistence
and Command and Control — T1219 (Remote Access Software) — not Initial Access: `svc-confluence` already running
the install command means execution access was obtained upstream, most likely through a Confluence
vulnerability (T1190, Exploit Public-Facing Application), which only Confluence's own application logs can
confirm or rule out. I'd confirm by resolving legitimacy first (prevalence, planned IT action) and, in
parallel, checking whether `svc-confluence`'s logon type and process lineage are consistent with a service
account or show signs of an already-established foothold.

**What questions would you ask?**
Same starting set — AnyDesk's prevalence in the baseline, the host's criticality, any active AnyDesk
connection, any planned IT action, `svc-confluence`'s access and permissions — plus a specific one: what do
Confluence's own application logs show around the alert window, and does the process lineage for the AnyDesk
install trace back to Confluence's own process (`java`/`tomcat`) or to an intermediate shell (`cmd`,
`powershell`) that would push the point of entry further back in time?

**What would you investigate and in what order?**
Volatility, in RFC 3227 order: active network connections, then process state, then memory, then disk, then
application/system/security logs — not all of these treated as one undifferentiated bucket. Legitimacy, run in
parallel: AnyDesk prevalence, host criticality, LOLBin activity (`cmd`, PowerShell, `wmic`, `rundll32`) after
the install, anomalous `svc-confluence` behavior.

At minute 0: verify prevalence against the baseline while requesting IT input in parallel, without waiting on
that answer to start securing volatile data (active connections, process state, memory) and doing a first-pass
check of network logs for a C2 pattern.

Then, over a widened time window: discovery, lateral movement, and persistence indicators (Run keys, scheduled
tasks, startup folder).

Then pivot to the identity itself: `svc-confluence`'s logon type on the relevant EID 4624 (type 5/3 expected
for a service account, type 2/10 anomalous), and the parent process of the AnyDesk install via Sysmon EID 1,
correlated through `SubjectLogonId` between EID 4688 and EID 4624/4672 — never taking process lineage alone as
proof, since `ParentProcessId` can be spoofed.

Finally, Confluence's own application logs (Tomcat/Catalina) over the same window, specifically to surface an
exploitation attempt that Windows-side telemetry can't show — this is the step that actually answers how
`svc-confluence` came to be running commands in the first place.

**Who would you communicate with and when?**
Same starting sequence — team notification and correlated-alert check, then IT on AnyDesk's legitimacy — with
one addition: Confluence's business/application owner is notified and consulted before any containment action,
not after, given that owner's context on the host's criticality directly shapes which containment tier applies.

If an active AnyDesk network connection is confirmed, AND either AnyDesk is absent from the legitimate baseline
or IT confirms no planned task — with IT, IR, and the business owner already looped in — containment is
graduated rather than binary: a targeted network block of the AnyDesk channel (EDR or proxy/firewall, against
known AnyDesk relay infrastructure) is the first move on a critical asset, preserving the Confluence service
while cutting the suspected control channel. Full network isolation is reserved for a confirmed signal of
lateral movement or active exfiltration. In parallel, regardless of the containment tier chosen:
`svc-confluence`'s password is reset and its active sessions/tokens revoked, once confirmed this isn't required
for Confluence's own startup. Once remediated (AnyDesk uninstalled, persistence removed), the host is handed
back to the user.

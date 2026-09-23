# Scenario of the Week 9 — Accounting Credential Phishing

**Published:** 2026-09-23

## 🎬 Scenario

```
A user in Accounting reported a suspicious email they received this morning. The email claimed to be from IT
asking them to verify their credentials due to a "security upgrade." The user admits they clicked the link and
entered their password, but say the page just spun and never loaded. They closed the tab and moved on with
their day.
```

## 🧭 Guided Questions

- What's your gut telling you and how would you confirm it?
- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
I start by organizing the alert information using the context / anomaly / priority triptych:

- **Context** — an email was received by Accounting this morning, containing a link the user clicked.
- **Anomaly** — a request to verify credentials due to a "security upgrade."
- **Priority** — the user clicked the link and shared their credentials.

I then set hypotheses to determine the alert's status, true or false positive:

1. ATT&CK T1566 — Phishing: an email impersonating IT, containing a malicious link, as part of a credential
   harvesting campaign.
2. A legitimate request following an organizational update.

To verify these quickly, I contact the helpdesk/IT point of contact to validate or invalidate this "security
update," while in parallel analyzing the URL and identity/endpoint activity to check for a true positive. Before
starting the investigation, I set the following escalation process:

1. False positive confirmed: communicate with the user and close the ticket with supporting evidence/context.
2. Identity/endpoint activity suspicious: containment of the profile with account block and session revocation,
   followed by a scope analysis and deeper investigation/remediation action.
3. Lateral movement, persistence, or exfiltration demonstrated: full isolation of the source and associated
   targets, and a crisis cell is triggered.

Finally, I set the alert's volatility axis for prioritization on the email, the account status for the account
whose credentials leaked, and the network connections/user device logs.

**What questions would you ask?**
Is there a legitimate intervention planned? What exact credentials were shared? What is the age and reputation
of the link/sender domain? What is the identity activity after the user shared their credentials? Did the user
download anything? Are there any abnormal connections or suspicious processes on the user's device? Was the
user's mailbox modified? Were any inbox rules created? Were any mail flow rules created/modified? Did mailbox
permissions change? Who else in the organization received this email? Did anyone else click and/or share their
credentials?

**What would you investigate and in what order?**
Assuming an EDR and Windows/Microsoft 365 environment, my first reflex will be:

- Collecting endpoint data following RFC 3227 (network connections → process state → memory → disk), using an
  interactive remote session exposing `netstat`/`ps` commands and a `runscript`/`getfile` action to push a
  memory-capture tool and retrieve it.
- Securing the `.eml` file by contacting the user.

In parallel, I initiate contact with the helpdesk/IT point of contact to determine the legitimacy of the
request, using the response latency to scan the URL on VirusTotal/URLscan and check Event ID 4624 and the
sign-in logs after the click to determine whether a connection and MFA were completed. I want to first surface
connections outside the usual context (impossible travel, unknown IP address, unusual logon type, different user
agent) to confirm the account's status (threat connected/not connected, active/inactive connection). If a
suspicious connection is confirmed, I initiate step 2 of the incident response with a scope of the threat across
the organization, to find out who else received the email and clicked the link, in order to quarantine them and
limit the scope/impact of the threat.

For the deep-dive analysis, I start with Sysmon Event ID 3 (Network Connection) to surface outbound network
connections, and Sysmon Event ID 22 (DNSEvent) for the domain's DNS resolution right before/during the click, to
get the resolved IP address and cross-check it against proxy/firewall logs if available. I then run an OSINT
analysis (IP, domain reputation, creation date, geolocation) and correlate it with the suspicious connection's IP
in the Source Network Address field of Event ID 4624. I also look for outbound connections carrying an abnormal
data volume toward an external IP/domain or an unapproved cloud service, and note traffic toward other internal
hosts on SMB (445), WinRM (5985/5986), RDP (3389), and WMI (135) as a possible sign of lateral movement. I then
push the analysis further by checking whether a file was downloaded via Sysmon Event ID 11 (FileCreate), looking
for a new file in `%USERPROFILE%\Downloads` or elsewhere. Right after, I look at Sysmon Event ID 1 (Process
Create) and Event ID 4688 to observe process creations after the click, to surface abnormalities via commands or
suspicious activity. If an abnormality is detected, I perform endpoint data collection following the principles
of RFC 3227 (process state → memory → disk) via a `runscript`/`getfile` action to push a memory-capture tool and
retrieve it. I then perform a parent-child
analysis with GUID (encoded command, parent-children) coupled to the `SubjectLogonId` retrieved from Event ID
4624 (with the IP of interest), to build the complete process tree tied to the threat. If a malicious
process/command is identified, I then move to persistence: checking any registry modification via Sysmon Event
ID 13 (Registry Value Set), service creation via Security Event ID 4697 or System
Event ID 7045 (Service Control Manager), scheduled task creation via Security Event ID 4698, and the startup
folder. Beyond endpoint persistence, I also analyze the mailbox, determining whether an email was added to a
forwarding list or a secondary mailbox was added using `Set-Mailbox`. I check whether new unwanted rules were
added via `New-InboxRule`, whether sender/recipient routes were modified or an SMTP was recently added via
`New-TransportRule`, whether permissions changed via `Add-MailboxFolderPermission`, `Add-MailboxPermission`,
`Set-MailboxFolderPermission`, and finally whether any emails were deleted, accessed, or sent from the IP of
interest. Finally, I use the IP of interest to scope the threat's activity, surfacing other Event ID 4624
(success) entries with the same source IP on other accounts, or 4625 (failure) entries with the same IP showing
failed spray/bruteforce attempts. I then widen the scope to firewall/proxy logs to see whether the IP
communicated with other internal hosts, in order to widen the perimeter to address in the incident response.

On the post-incident and continuous-improvement side, depending on the organization's needs:

- Understand why the phishing email passed the anti-spam/anti-phishing filters.
- Targeted, measured awareness: simulated phishing campaigns with click-rate tracking before/after, and
  individual follow-up with repeat clickers (including Emily Wong), rather than a generic annual training
  session.
- Domain-age filtering (newly registered domains): block or flag domains registered within the last 30 days at
  the DNS/proxy layer — catches disposable infrastructure without depending on an already-established
  reputation.
- Safe Links / URL rewriting at the mail gateway level: rewrites links to scan them at click time, not just at
  delivery (blocks kits that only activate the phishing payload after delivery).
- Conditional Access / risk-based sign-in (Entra ID Identity Protection): block or force MFA re-verification on
  "atypical risk" connections (new geolocation, new device) — this would have limited the impact even if the
  password was stolen.

**Who would you communicate with and when?**
I notify my team that I'm taking ownership of the alert and ask them to check the alert queue for potential
correlation with new or older alerts. I then contact the user to secure the `.eml` file and get more context. I
contact IT in parallel for confirmation and initiation of the response phase. If the login is confirmed with no
legitimate reason, with the help of the helpdesk and the identity team, I block the IP, lock the account, revoke
sessions/tokens, reset the password, and do a targeted network block on the user's device if needed, before
deeper investigation. If data forwarding, persistence, or other activity is confirmed, I trigger a full incident
response plan with a crisis cell, with escalation to management and, if sensitive data was accessed or
exfiltrated, to legal.

## 🧠 Expert Review

The most consequential gap is a proportionality problem: memory acquisition (`runscript`/`getfile`) is named as
the "first reflex," on the same footing as a lightweight `netstat`/`ps` triage, before anything on the endpoint
has actually been observed. At this stage the alert has demonstrated nothing beyond a credential-harvesting page
that failed to load — no dropped file, no abnormal process. A full memory capture is not a two-command,
negligible-cost action: it means deploying an imaging tool over EDR live response, dumping potentially several
gigabytes of RAM, and retrieving it, with real I/O load and a visible footprint on the endpoint. This is the same
pattern already seen on the Impossible Travel scenario (Scenario 5): RFC 3227's endpoint volatility order applied
by default to an alert that has not yet established an endpoint component. What specific endpoint observable —
short of "identity activity looks suspicious" — should be required before memory acquisition is triggered?

Second, the escalation tier "Identity/endpoint activity suspect" is a label, not a threshold. The plan lists
several signals (impossible travel, unknown IP, unusual logon type, different user agent) without saying whether
any single one of them is sufficient on its own to trigger account block and session revocation, or whether some
require corroboration before acting. A downloaded file and an unusual user agent are not the same strength of
evidence — treating them as interchangeable inputs into the same containment trigger risks both over-reacting on
weak signals and under-reacting when a strong one appears alongside noise.

Third, the mailbox persistence check — forwarding rules, secondary mailboxes, inbox rules, transport rules,
folder/mailbox permissions — never extends to the two persistence mechanisms most directly tied to a stolen
password: a newly registered MFA method and a newly consented OAuth application. Both let an attacker retain
access to the account independently of whether the password is later reset, and neither is covered anywhere in
the plan.

Fourth, the plan waits on the helpdesk to determine legitimacy without naming the fastest, free, and
independent check available in the meantime: the email's own SPF/DKIM/DMARC authentication results (and
Return-Path/originating MTA), which would immediately indicate whether the message was actually sent through a
domain authorized to send as IT — resolving the true/false-positive hypothesis in seconds rather than waiting
on a human reply.

Finally, on a smaller but still relevant point: the `netstat`/`ps` commands are written into the plan without
naming which tool exposes them; on a Windows/M365 environment, `ps` is not a native command — worth naming the
actual EDR live-response tool (e.g., CrowdStrike Falcon RTR, which does unify command names across platforms)
rather than leaving an unexplained cross-platform syntax in an investigation plan.

What holds up well: two competing hypotheses (phishing vs. legitimate request) are stated explicitly in ACH form
before any investigation starts, rather than defaulting to an assumed threat. The deep-dive names precise,
specific telemetry throughout — exact Sysmon/Security Event IDs, exact Exchange cmdlets for mailbox tampering,
and the `SubjectLogonId` field correctly used to tie a process chain back to a specific logon session rather than
trusting `ParentProcessId` alone. The three-tier escalation structure, moving from false positive to containment
to full crisis response, is the right shape even where its middle tier needs sharper thresholds.

## 🪞 Reflection

1. Before applying RFC 3227's volatility order by reflex, separate the cost tiers explicitly: a lightweight
   process/network triage is near-free and can run immediately, but full memory acquisition is expensive and
   disruptive — it should be gated on an actual endpoint observable (an unexpected file drop or process/command
   launch), not triggered by identity suspicion alone or by habit.
2. A containment threshold needs a stated weight per signal, not just a list. Some signals (a downloaded file,
   impossible travel, a known-bad IP reputation) are strong enough to trigger containment alone; others (an
   unfamiliar user agent, an unusual geolocation) need to be corroborated with a second signal before acting.
3. Identity-based compromise investigations need a systematic check for identity persistence, not just mailbox
   rules: newly registered MFA methods and newly consented OAuth applications are at least as relevant as
   forwarding rules, and are easy to miss if "persistence" is only associated with the endpoint side of an
   incident.
4. When a verification channel is slow (waiting on a human at the helpdesk), always look for the fastest
   independent check available in parallel — email header authentication (SPF/DKIM/DMARC) resolves a
   spoofed-sender hypothesis in seconds and shouldn't be skipped in favor of waiting.
5. Never write a command into an investigation plan without knowing what it actually does on the target
   platform. `ps`/`netstat` happened to be correct here because CrowdStrike Falcon RTR unifies command names
   across operating systems — but that was confirmed after the fact, not verified before writing the plan.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
Same triptych and hypotheses as above. The escalation process is sharpened on tier 2: "Identity/endpoint
activity suspect" is now split into strong signals that trigger containment on their own — a downloaded file,
impossible travel, a bad IP reputation, or an uncontrolled outbound connection — and weak signals that require
corroboration with another signal before acting — an unknown IP address, an unusual logon type, or a different
user agent. The volatility axis is also extended: beyond the email and the leaked-credential account status, it
now explicitly includes the sign-in logs and the attacker's ability to establish identity-side persistence.

**What questions would you ask?** Unchanged.

**What would you investigate and in what order?**
Assuming an EDR and Windows/Microsoft 365 environment, my first reflex is securing the data via RFC 3227:
exporting the Microsoft 365 sign-in logs, and securing the `.eml` file by contacting the user. In parallel, I
initiate contact with the helpdesk/IT point of contact to determine the legitimacy of the request, using the
response latency to check the email's SPF/DKIM/DMARC authentication results and scan the URL on
VirusTotal/URLscan. I check Event ID 4624 and the sign-in logs after the click to determine whether a connection
and MFA were completed, prioritizing connections outside the usual context (impossible travel, unknown IP
address, unusual logon type, different user agent) to confirm the account's status. If a suspicious connection is
confirmed, I initiate step 2 of the incident response with an organization-wide scope to find out who else
received the email and clicked the link, to quarantine them and limit the threat's impact.

For the deep-dive, I start with Sysmon Event ID 3 (Network Connection) for outbound connections and Event ID 22
(DNSEvent) for the domain's DNS resolution at the time of the click, cross-checked against proxy/firewall logs.
I run an OSINT analysis (IP, domain reputation, creation date, geolocation) correlated with the suspicious
connection's IP in Event ID 4624's Source Network Address field, and watch for abnormal outbound data volume or
traffic toward other internal hosts on SMB (445), WinRM (5985/5986), RDP (3389), and WMI (135) as a sign of
lateral movement. I check whether a file was downloaded via Sysmon Event ID 11 (FileCreate), then look at Sysmon
Event ID 1 (Process Create) and Event ID 4688 for process creations after the click. If an anomaly is detected at
either of these two steps, I move to endpoint data collection using CrowdStrike Falcon RTR — an interactive
remote session exposing `netstat`/`ps` commands, and a `runscript`/`getfile` action to push a memory-capture tool
and retrieve it, following RFC 3227 (network connections → process state → memory → disk). I then perform a
parent-child analysis with the process GUID and command line, coupled to the `SubjectLogonId` retrieved from
Event ID 4624, to build the complete process tree tied to the threat. If a malicious process/command is
identified, I move to persistence: registry modification (Sysmon Event ID 13), service creation (Security Event
ID 4697 / System Event ID 7045), scheduled task creation (Security Event ID 4698), and the startup folder.

Beyond endpoint persistence, I analyze the mailbox: additions to a forwarding list or a secondary mailbox
(`Set-Mailbox`), new inbox rules (`New-InboxRule`), modified sender/recipient routes or a recently added SMTP
connector (`New-TransportRule`), permission changes (`Add-MailboxFolderPermission`, `Add-MailboxPermission`,
`Set-MailboxFolderPermission`), and any emails deleted, accessed, or sent from the IP of interest. I then check
the account's audit logs for an added or modified MFA factor, a change to forwarding/delegation rules, a recent
password change, or a newly consented OAuth application, followed by the Microsoft 365 activity logs: on
SharePoint/OneDrive, mass downloads and external shares; on Teams, outbound messages; and OAuth application
consents for any persistence attempt.

Finally, I use the IP of interest to scope the threat across the organization: other successful Event ID 4624
entries on the same source IP against other accounts, or 4625 failures on the same IP showing failed
spray/bruteforce attempts, then widen to firewall/proxy logs to check whether the IP communicated with other
internal hosts.

Once the incident is resolved, for the post-incident phase, I would recommend:

- Understanding why the phishing email passed the anti-spam/anti-phishing filters.
- Targeted, measured awareness: simulated phishing campaigns with click-rate tracking before/after, and
  individual follow-up with repeat clickers, rather than a generic annual training session.
- Domain-age filtering (newly registered domains): block or flag domains registered within the last 30 days at
  the DNS/proxy layer — catches disposable infrastructure without depending on an already-established
  reputation.
- Safe Links / URL rewriting at the mail gateway level: scan links at click time, not just at delivery — blocks
  kits that only activate the phishing payload after delivery.
- Conditional Access / risk-based sign-in (Entra ID Identity Protection): block or force MFA re-verification on
  atypical-risk connections (new geolocation, new device) — this would limit the impact even if the password was
  stolen.

**Who would you communicate with and when?** Unchanged.

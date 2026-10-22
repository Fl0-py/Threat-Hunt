# Scenario of the Week 13 — Service Account Authenticating to an Unusual File Server

**Published:** 2026-10-22

## 🎬 Scenario

```
A service account used by an internal application just authenticated to a file server it has never accessed
before. The login happened at 11:43 PM on a Saturday. Normally, this account only communicates with the database
server.
```

## 🧭 Guided Questions

- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?
- What's your gut telling you and how would you confirm it?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
I start by organizing the alert information using the context / anomaly / priority triptych:

- **Context** — on a Saturday evening at 11:43 PM, a service account used by an internal application authenticated
  to a file server instead of the usual database server.
- **Anomaly** — `authenticated to a file server it has never accessed before`, `Normally, this account only
  communicates with the database server`, `service account used by an internal application`, `11:43 PM on a
  Saturday`. The anomaly is the unusual behavior of a service account compared to its defined business scope (an
  action on a file server rather than the database) and to its known history, in an off-hours context.
- **Priority** — the activity linked to this service account and the files exposed on the file server.

I then set hypotheses on two main axes to segment the analysis:

1. **False positive** — the authentication is legitimate and could be explained by the deployment of a new
   application process, the use of a rarely used feature, a server migration or modification, an application
   update or restart, or the use of the account by another legitimate application or script.
2. **True positive** — a threat is present through the service account, either by direct exploitation via the
   application or by exploitation of the service account's identity.

To determine the status, a quick win is to identify the initiator of the authentication, from which source, and
through which process. This lets me split the analysis into two branches from the start:

1. **Parent from the application** — directs the analysis toward the application, where I need to decide between
   a legitimate and a non-legitimate application job.
2. **Parent outside the application** — directs the analysis toward the identity, where I need to decide on the
   legitimacy of the process or the compromise of the service account.

Before starting the investigation, I set the 3 calibrated response levels and the conditions that trigger them:

1. **Level 1** — the service account's action is confirmed as legitimate: I close the ticket with a summary and
   the conclusion of the analysis, then escalate the alert to my manager to start a possible effort to evolve the
   detection rule to fit the business need.
2. **Level 2** — defined on two axes:
   - *Parent from the application* — if the parent/action is illegitimate, after securing the data and validating
     the action with the application owner, I request a targeted network block of the application server, then
     eradicate the threat by removing the mechanism or persistence, fixing the vulnerability, and resetting the
     account.
   - *Parent outside the application* — if the parent/action is illegitimate, after securing the data and
     validating the action with the application owner, I request a targeted network block of the source machine,
     then eradicate the threat by resetting the account with a purge of the associated sessions/authentication
     tickets, removing the persistence, and fixing the vulnerability.
3. **Level 3** — lateral movement, exfiltration, or suspicion of a wider AD compromise (Golden Ticket or several
   accounts): I launch a crisis cell to respond to the threat in a collective and coordinated way.

Finally, I set the alert's volatility axis around the following critical evidence:

- The application server's memory, where a mechanism leaving no trace on disk (injection, DLL, direct
  exploitation) and the account's cached credentials can be found.
- The network logs of the SMB sessions active on the file server, which can show what is open right now and from
  which machine the threat operates.
- The file server's access logs, as proof of what was consulted or copied.
- The application server and database logs, to show what triggered the action.

Given the delay between the event and the handling of the alert, my first reflex is to verify and secure what
was forwarded to the SIEM, export immediately what remains locally, and document and report any missing evidence.
If an ongoing connection is detected, level 2 is triggered directly, with a contact to the application owner to
confirm that the connection is illegitimate.

In terms of impact, the priority is to determine the sensitivity of the files on the file server and to identify
the actions performed on them (consultation, copy, exfiltration...).

**What questions would you ask?**
Which network, file server, application server and database logs are available to me? Is a network communication
initiated from the service account ongoing? Were files accessed, copied, exfiltrated? What is the confidentiality
level of the files potentially exposed? Which parent initiated this authentication process? Was it launched
outside the application, or through it? Were other connections from this account to other hosts observed? Was
any lateral movement observed?

**What would you investigate and in what order?**
In a Windows environment, after checking what is available to me and securing what was forwarded to the SIEM, I
remotely check, without an interactive session, whether an SMB connection through the service account is active
in real time from the file server, with
`Get-SmbSession -ClientUserName "DOMAIN\<account name>"` complemented by
`Get-SmbOpenFile -CimSession <FILESRV> -ClientUserName "DOMAIN\<account>"`. If a connection is ongoing, I
directly launch a memory acquisition of the application server and secure, if not already done, the network logs,
the file server access logs and the application server logs. If no connection is ongoing, I secure the network
logs, the file server access logs and the application server logs.

Once the volatility axis is handled, I analyze the access logs to bring to light what was consulted, copied or
downloaded, and I determine the nature of the exposed data and the impact on the organization. For this I use
events `5140` and `5145`, filtered on the service account, to get the associated IP, the share opened, the
file/object name, and whether access was granted or denied, through the key field `Accesses` / `Access Mask`,
which indicates the nature of the action:

| Access                     | Mask      | Interpretation                       |
| -------------------------- | --------- | ------------------------------------ |
| `ReadData`                 | 0x1       | Content read                         |
| `WriteData` / `AppendData` | 0x2 / 0x4 | Write or modification                |
| `DELETE`                   | 0x10000   | Deletion                             |
| `ReadAttributes` alone     | 0x80      | Simple listing, no content read      |

For exfiltration, I cross-check this information with the outbound network flows of the source machine
(firewalls, proxy, NetFlow), focusing on abnormal volumes. I correlate the analysis with the EDR logs of the
source machine, looking for archive creation or traces of transfer tools.

Once the state of the data is defined, I confirm the criticality of the exposed data by contacting the business
owner, who can confirm the impact. Depending on the criticality and the type of data (credentials or personal
data), I trigger level 3 of the response plan, with a communication to the DPO without delay if personal data is
involved.

I then move to the authentication analysis, whose goal is to determine from which source and through which
process this action was launched. I start from the file server's `4624` log, which gives me `IpAddress`, the
exact timestamp and the authentication type. On the application server, I use Sysmon 3 with the IP address as a
pivot to retrieve the `ProcessGuid` of the network connection to the file server's IP. On the source machine, I
then pivot on Sysmon 1 or event ID `4688` using the `ProcessGuid` to obtain the executable path `Image`, the full
`CommandLine`, the immediate parent `ParentImage`, the `User` and the `ParentProcessGuid`. I then walk up the tree
to a known process. Once the process is known, I contact the application owner and the application's technical
referent to validate its legitimacy. Depending on their feedback, I can then launch the response plan defined
during the qualification step, according to the status of the action (legitimate / non-legitimate) and the source
(application / outside the application).

For the post-incident phase:

1. Rotation of all exposed secrets and verification that the eradication is complete.
2. Verification of the fix's effectiveness (scan or test); if not available, compensating measures (WAF rule,
   disabling the vulnerable function...).
3. Reinforced monitoring for 30 to 90 days, with a watchlist built from service accounts or leaked credentials.
4. Documentation of the handling and response to the alert, with playbook updates.
5. Threat hunt with the IOCs found and according to the observed TTPs (other service accounts contacting unusual
   servers, application processes launching shells, outbound connections from servers to the Internet...), going
   back in time.

For improvement:

1. For a false positive, evolve the alert so that it fits the business need while limiting the attack surface as
   much as possible.
2. Set up an alert on illegitimate parent processes and abnormal outbound volumes, followed by a detection test
   through simulation (purple team).
3. Harden the service account: gMSA, least privilege (access to the only share needed), interactive logons
   forbidden by GPO.
4. Network segmentation: block SMB and Internet access if the application does not need it.
5. Vulnerability testing cycle: regular scans, application tests (SAST/DAST), pentest, and a patch management
   process with deadlines according to criticality.

**Who would you communicate with and when?**
1. At the start of the alert handling: my manager and the team, to say that I am taking ownership of this
   high-impact alert and to watch for other alerts to correlate.
2. If suspicious data is involved: the business owner of the data for the impact, the DPO if the data is personal
   data, and the IAM / AD team if credentials are involved.
3. Once the parent process is identified: the application owner and the application's technical referent if the
   source is the application, for validation. If a true positive is confirmed, escalation to the helpdesk, the
   identity team and AppSec if an application vulnerability needs to be fixed.
4. If level 3 of the response is reached: the organization's management and the incident response manager.

## 🧠 Expert Review

The most consequential gap is in the identity branch. The First Response treats "exploitation of the service
account's identity" as a single hypothesis, with a single containment: reset the account and purge the associated
sessions and tickets. Yet one observable, a successful network logon (`4624`, logon type 3) by this account,
can come from three different mechanisms. Someone may know the password, obtained for instance by Kerberoasting
(T1558.003) or from a leak in a configuration file or script. Someone may hold only the NTLM hash, extracted from
the memory of the machine where the service runs, and replay it (Pass-the-Hash, T1550.002). Or someone may hold a
Kerberos ticket without the secret, stolen or forged, and replay it (Pass-the-Ticket, T1550.003). They leave
different traces: the authentication package of the `4624` (Kerberos or NTLM, `NtLmSsp`) compared with the
account's usual one, and whether the domain controller logged a matching `4768` / `4769`. They also call for
different responses, and the plan mentions the Golden Ticket only as a level 3 trigger. Which field of the `4624`,
and which event on the DC, would let you tell these three mechanisms apart, and would a single reset treat all of
them?

Second, the response and the impact both depend on assumptions the plan does not state. A reset with a purge of
tickets does not cut access already granted: a Kerberos ticket already issued remains valid until it expires
(10 hours by default for a TGT, renewable up to 7 days), and changing the password does not invalidate it. The KDC
keeps no list of issued tickets that could be revoked over a time window. What reduces the exposure is disabling
the account (which blocks new tickets), closing the open SMB sessions on the file server (`Close-SmbSession`,
`Close-SmbOpenFile`), and, when a forged ticket is suspected, resetting `krbtgt` twice, which is the level 3
scenario. `klist purge` only empties the local cache of the machine where it is run. For a stolen hash, the
rotation only holds if the machine the hash was extracted from is contained first; otherwise the new hash is
extracted again. The same logic applies to the impact: the plan rests on events `5140` and `5145`, but `5145` is
only produced if the "Detailed File Share" audit is enabled, `5140` only identifies the share and not the files,
and `4663` requires an audit rule (SACL) on the objects. The plan does not say what is left if none of these
exist. What can you still state about what was read or copied in that case, and what do you write as the limit of
the investigation?

Finally, on technical precision, the authentication chain pairs events and fields that do not match. The pivot
toward event `4688` is stated with the `ProcessGuid`, a field Security event `4688` does not have; it carries
`NewProcessId` (in hexadecimal) and `SubjectLogonId`, which ties the process to its logon session. The
`ProcessGuid` obtained from Sysmon Event ID 3 leads to Sysmon Event ID 1 (process creation), which is where
`CommandLine`, `ParentImage` and `ParentProcessGuid` live. A pivot on the IP address alone returns every SMB
connection toward the file server in the time window; the `4624` also records `IpPort`, which matches the
`SourcePort` of Sysmon 3 and isolates one specific connection. Why is an IP-only pivot not enough to identify the
process, and which identifier carries you from Sysmon 3 to event `4688`?

What holds up well: the context / anomaly / priority triptych is anchored on quoted elements of the alert, the two
hypotheses are explicit, and the quick win (initiator, source, process) splits the analysis into two branches
with a distinct next step for each. The response plan has three levels with a stated condition for each, and the
level 3 criteria (lateral movement, exfiltration, wider AD compromise) are concrete. The volatility axis names the
evidence, orders the actions, and uses commands that do not require an interactive session on the target. The
`Access Mask` table is accurate, and the impact is determined before the authentication analysis. The
communication plan includes the business owner, the DPO and the IAM team, and the post-incident and improvement
sections are specific to a service account (gMSA, least privilege, interactive logon denial).

## 🪞 Reflection

1. Name the mechanism families before choosing the remediation. A single observable (a successful logon by the
   account) can come from a known password, a replayed NTLM hash or a replayed Kerberos ticket, and each calls for
   a different action. The distinguishing evidence is the authentication package of the `4624` against the
   account's baseline, and the presence or absence of a matching `4768` / `4769` on the domain controller.
2. A reset and a ticket purge do not cut access that was already granted. Always state the residual window (the
   lifetime of tickets already issued) and the levers that shrink it: disable the account, close the open SMB
   sessions, and contain the source machine before rotating a secret that was extracted from it.
3. Check what the evidence chain really provides before relying on it. Before counting on `5145` or `4663`, find
   out whether the audit exists; if not, switch to a degraded analysis on the source's network and endpoint
   activity, and bound the impact by what the account's rights allow rather than claim what was read.
4. Pivot exactly. Each event has its own fields, and two events are linked only through identifiers they both
   carry: `IpPort` of the `4624` with `SourcePort` of Sysmon 3, `ProcessGuid` toward Sysmon 1, `ProcessId` with
   `NewProcessId` (hexadecimal) for `4688`. Never write an event / field pairing into a plan without knowing what
   it contains.
5. Areas still to consolidate: Kerberos and NTLM authentication traces, field-level knowledge of Sysmon and
   Security events, and the post-incident and improvement blocks, where I leaned on research more than on a
   template of my own.
6. On the method: the modular blocks held up (qualification, tiered response, volatility, and the new impact
   block), and the investigation felt simpler because the decisions were already set upstream. The exercise is
   still costly: the method is in construction, not yet saving time.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
The triptych, the quick win and the volatility axis are unchanged, with three changes:

- Before launching the investigation chain, I check whether a change ticket or a planned intervention explains
  the activity.
- The true-positive hypothesis on the identity side is split into three families, which I separate by the
  authentication package of the `4624` against the account's baseline and by what the domain controller logged
  just before:

  1. **Known password** (Kerberoasting, T1558.003, or a leak). The `4624` shows Kerberos, and a consistent
     `4768` then `4769` exists on the DC.
  2. **NTLM hash** taken from the LSASS memory of the machine where the service runs (Pass-the-Hash,
     T1550.002). The `4624` shows NTLM (`NtLmSsp`), with no prior `4768` / `4769` for the account.
  3. **Ticket** stolen or forged (Pass-the-Ticket, T1550.003). The `4624` shows Kerberos, but the DC has no
     matching `4768` / `4769`, or one issued to another machine.

- The account treatment in level 2 depends on the family. A ticket already issued stays valid until it expires,
  so a password change alone never cuts it:

  1. **Password** — close the open sessions, change the password, then find how it leaked.
  2. **Hash** — contain and eradicate the machine the hash was taken from first, then rotate the secret, which
     changes the hash.
  3. **Ticket** — disable the account for the ticket's validity period, close the open SMB sessions and block the
     source on the network (or deny the share temporarily), then change the secret before re-enabling the
     account. The application owner is warned beforehand, because disabling a service account stops the
     legitimate application.

**What questions would you ask?** Unchanged.

**What would you investigate and in what order?**
Two changes in the volatility step and the authentication analysis, and one in the impact step:

- The memory acquisition targets the source of the connection, read from `ClientComputerName` / the IP of the
  SMB session or from the `IpAddress` of the `4624`, rather than the application server by default.
- The authentication analysis starts from the `4624` of the file server (`IpAddress`, `IpPort`, timestamp,
  authentication package). On the source machine, Sysmon 3 is matched on `SourceIp` + `SourcePort` (`IpPort`) and
  the timestamp, which gives the `ProcessGuid` and `ProcessId` of the connection. Sysmon 1, through the
  `ProcessGuid`, then gives `Image`, `CommandLine`, `ParentImage`, `ParentProcessGuid` and `User`; without Sysmon,
  event `4688` is reached through `ProcessId` and `NewProcessId` (hexadecimal), and its `SubjectLogonId` ties the
  process to its logon session.
- The impact step relies on `5140` (share opened), on `4663` where an audit rule exists, on the network volume of
  SMB, and on file creation on the source machine (Sysmon 11). If neither `5145` nor `4663` is enabled, I cannot
  prove what was read: I switch to a degraded analysis, focused on the network activity and endpoint activity of
  the source, and I bound the impact by what the account's rights allow, as a worst case.

The rest of the investigation, the post-incident phase and the improvement actions are unchanged.

**Who would you communicate with and when?** Unchanged.

# Scenario of the Week 12 — DLP Alert: Client List Sent to a Personal Gmail

**Published:** 2026-10-16

## 🎬 Scenario

```
DLP flagged an outbound email from a Sales employee to a personal Gmail address. The email contained an
attachment named "Q4_Client_List.xlsx." The employee has been with the company for three years with no prior
incidents.
```

## 🧭 Guided Questions

- What's your gut telling you and how would you confirm it?
- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
On reading the alert, I don't recognize the notion of DLP. So I take a moment to ask myself why DLP is an
important notion and how it connects to the field of cybersecurity.

DLP, or Data Loss Prevention, is a set of methods that protect an organization's sensitive information (personal
data, intellectual property, trade secrets…) against accidental or malicious leaks, while ensuring regulatory
compliance (GDPR, HIPAA, PCI-DSS). The DLP tools can be classified as follows:

- Network: email or web traffic
- Endpoint: the workstation (USB, copy-paste, printing)
- Cloud: activity and data in SaaS/Cloud

With this in mind, I organize the context and perspective of the alert around the context / anomaly / priority
triptych:

- **Context** — a network DLP identified an email flow containing the document `Q4_Client_List.xlsx` between a
  Sales employee with a clean record over three years and a personal Gmail address.
- **Anomaly** — a file containing a client list for the organization's Q4 transferred to a personal address. This
  type of document is strategic for the organization, and sending it to a personal address is an anomaly from the
  start.
- **Priority** — the exfiltrated file and the activity/behavior of the Sales employee within the company.

Before moving to the analysis, I set hypotheses on two axes to determine the alert's status:

1. **False positive** — the employee's activity is legitimate despite the alert. This could be explained by the
   employee wanting to work from home on a personal computer, or by sending to an email address considered
   personal but legitimate (consultant, partner, supplier).
2. **True positive** — the employee's activity is illegitimate. This could be explained by an intent of revenge
   against the organization, a possible preparation to leave, the resale of data to a competitor or another
   illegitimate actor, or an external threat's ongoing attack at the exfiltration stage.

To prove this, a quick win would be to determine whether there are other alerts or suspicious events, whether the
destination is legitimate, and finally whether the action is consistent with the employee's role/history (the
last 30 days of activity and the management/HR context).

Before starting the investigation, I set the tiers and conditions to trigger a response calibrated to the moment:

- **Tier 1** — if the action is confirmed as legitimate, I report to the employee's manager and close the ticket,
  which captures the analysis with the description of the actions taken and the conclusion. I report the alert to
  my own manager to start a possible evolution of the DLP configuration or a business awareness effort on the
  organization's security policy.
- **Tier 2**, on two axes:
  - *External threat axis* — if persistence, exfiltration mechanisms or identity compromise are detected, I
    start preserving evidence and revoke the profile's current sessions with a password reset / refresh token
    reset, and a targeted network block of the endpoint if needed. I then remove the attacker's persistence and
    analyze the scope of the threat to bring other compromises to light and handle them.
  - *Insider threat axis* — if the action is suspicious (action outside the employee's scope, context confirmed
    by the manager/HR, or a destination not confirmed as trusted), with legal's agreement I place the employee's
    account/endpoint under enhanced monitoring for in-depth analysis over a given time window (for example the
    last 30 days).
- **Tier 3** — if the action is validated as an internal threat, I escalate to HR, legal and management to
  validate the suspension of the account and, through legal, to obtain the deletion of the data on the Gmail side
  and on personal media. In parallel, I start the forensic capture to preserve the evidence before any session
  revocation, account suspension or device isolation, following the collective decision.

On volatility, my first axis is a possible ongoing or repeated exfiltration while the alert is being handled, and
my second axis is evidence that is still present but erasable, or short-retention logs on the endpoint.

**What questions would you ask?**
Are there correlated alerts or other EDR telemetry on this user, their identity or their devices? Which address
was the email sent to? Where and how was the email sent? Is the email still in the Sent Items? What is the body of
the message? Are there signs of persistence on the mailbox? What do the authentication logs look like? Were other
emails sent to this address, or to other suspicious ones? What is the context around this employee? Which
sensitive resources did the employee access? Is there a sign of another exfiltration channel?

**What would you investigate and in what order?**
My first reflex is to launch preservation actions that are invisible to the user and require no interaction or
validation. I place the mailbox on litigation hold to keep its content despite deletions, and I copy the email and
the attachment from quarantine or from the DLP incident.

To decide the means to deploy and the order of actions to handle the alert's volatility, I need to separate the
two hypotheses, insider threat or external threat, through quick, low-intrusion checks. For this I use the quick
wins defined in the framing step, keeping in mind that if a sign of an active attack shows up right away, I go
straight to preservation and containment without finishing the quick wins.

I look at the user's DLP alert history for recurrence. I read the body of the message and the recipient address to
see whether it matches the employee, and whether there is a history in the Message Trace. I then query Entra ID
Protection to analyze the profile's sign-ins, looking for impossible travel, unfamiliar sign-ins and a suspicious
IP, and Defender for Office 365 to check whether a phishing email was received/clicked over the last 90 days. I
then look in Defender for Cloud Apps for massive downloads/exports from SharePoint, OneDrive or the CRM. I look for
any trace of an OAuth consent given to a third-party application able to send emails, and I identify suspicious
mailbox rules as well as activity from unusual IPs (to correlate with the previous step). I inspect the
workstation's EDR for malware, infostealers (session cookie theft), remote access tools, connections to suspicious
IPs or domains, but also a copy to USB or an upload to a personal cloud. I then pivot around the email by
analyzing the `Send` events in the UAL to get the `ClientIP` and `ClientInfoString`/AppId and compare them to the
employee's habits, for example Outlook desktop on the usual workstation versus OWA/Graph from an unknown IP. I
inspect the Sent Items to see whether the email is still there or has been deleted. Finally, I analyze the
business context with the manager and HR, determining whether the action is consistent with the employee's role
and whether there is other information to know (notice period, conflict…).

Once these steps are done, I should have a better view of the alert's volatility:

- External threat: the attacker's active session and the ongoing exfiltration. The priority is to preserve the
  volatile data around the attacker's active session and to stop the ongoing exfiltration.
- Internal threat: the Sent Items, local copies and endpoint logs. The priority is rather to pursue the analysis
  discreetly, collecting data from the most to the least volatile.

Depending on the result, I trigger the response associated with the tier defined in the framing. In both cases, I
run a global scoping across the organization using the IOCs and other information found during the analysis, to
determine what was compromised and start a dedicated response plan.

For the post-incident phase, I make sure of:

- Writing an incident report with the timestamped chronology, the root cause with evidence and actions taken, the
  impact and the associated recommendations.
- Starting a reflection on the MTTD / MTTR indicators, on what worked well and what blocked.

For recommendations, depending on the case:

- False positive: a business need that is poorly covered, which may require setting up a legitimate way to do it,
  switching the DLP to an advisory mode for the user (policy tip), or raising awareness in the teams.
- External compromise: reinforce the MFA policy, conditional access, automatic forwarding to external addresses,
  restrict OAuth consents and raise phishing awareness.
- Insider: reinforced and supervised monitoring of employees serving notice, with an HR → SOC information
  circuit, reinforced least privilege, sensitivity labels (encryption of sensitive files, which stay unreadable
  even once they leave) and DLP in blocking mode toward webmail domains (gmail.com, outlook.com…) and USB transfer
  for files classified as confidential.

**Who would you communicate with and when?**

1. At the start of the alert handling: my manager and the team, to tell them I am taking ownership of this
   high-impact alert and to watch for other alerts to correlate.
2. When context is needed or an insider is suspected: HR and the legal department, before the employee's manager,
   to escalate the incident, gather the business context and obtain the validations/authorizations for the
   response plan.
3. If a true positive is confirmed: the DPO for personal data, notification of the CISO and launch of the
   response plan.
4. Containment decision: the helpdesk and the identity team for the containment actions on the user's endpoint
   and account. I then contact the DPO, since a client list is probably personal data to be handled as part of
   the incident.
5. After containment or closure: the employee (if the action was legitimate) and the manager, for explanation,
   remediation and deletion of the data.

## 🧠 Expert Review

The first point is vocabulary, and what it hides. The plan calls the legitimate case a "false positive", but the
DLP detected something real: a client list left the organization for a mailbox the organization does not control.
The detection is correct, the usage may be legitimate, the policy is violated: this is a benign true positive. The
distinction matters because Tier 1 closes the ticket and informs the manager, and nothing addresses the data that
now sits in a personal Gmail, even when the intent was harmless. The remedy is reachable but bounded: the employee
deletes the message, empties the Gmail trash (a deleted message stays recoverable for 30 days), removes the copies
on the phone and in the downloads, and confirms in a written, timestamped attestation. That control stays
declarative, since the organization cannot verify the content of a personal account. In the insider case the
limit is harder: the plan asks legal to obtain the deletion of the data on the Gmail side, but a third party
cannot obtain access to or deletion of a private account's content from the provider without a legal procedure.
The realistic lever is legal action and HR measures, not a support ticket.

Second, the order of the checks. The investigation lists about ten verifications grouped by data source (the
Microsoft security consoles first, then the mailbox, then the endpoint), when the question was which check settles
the competing hypotheses fastest and at the lowest cost. The `Send` event in the UAL does it in one query:
`ClientInfoString` tells which client sent the email (Outlook desktop, OWA, REST/Graph, EWS, ActiveSync) and
`ClientIP` from where, to be compared with the employee's habits. In the plan it comes after the sign-in analysis,
Defender for Office 365 and Defender for Cloud Apps, which are heavier and mostly build evidence. Two checks are
missing from the front of the list: the status of the DLP action itself (blocked, quarantined or delivered), which
changes the whole severity, and the endpoint EDR. The EDR belongs among the quick checks because a usual client
and a usual IP do not exclude compromise: an infostealer or a remote access tool on the employee's workstation
would send from Outlook desktop on the usual IP and produce a log identical to a benign send. Only the EDR
excludes that case. A decision table would also help: usual client and IP, unknown client or IP, never-seen
recipient, each pointing to a branch. One detail: the device name is not in the `Send` event, it is in the Entra
sign-in logs.

Third, the trigger criteria for Tier 2. "If the action is suspicious" is not a threshold: a colleague could not
apply it without asking. Observable criteria are needed, each with its source: other sensitive emails sent to the
same address before the alert (a technical signal, for example the information type or sensitivity label in the
DLP), access to data outside the employee's rights (SharePoint/CRM audit), and a tense business context confirmed
by the manager or HR (a human source, to name). The same applies to the benign/insider split, which no technical
data settles: it takes the recipient, the content and the context.

Fourth, a policy violation is not a data breach. The DPO step is tied to "if a true positive is confirmed", which
makes it depend on the employee's intent. But the qualification of a personal data breach (GDPR art. 4(12), an
unauthorized disclosure of personal data) does not depend on intent: a delivered email carrying a client list to
a mailbox the organization does not control must reach the DPO even when the usage is benign. The SOC does not
qualify the breach, the DPO does; the SOC brings the facts: delivered or not, recipient, nature and volume of the
data (individuals or companies), known opening or forwarding, chronology, measures taken. The natural trigger is
the confirmation that the email was delivered and left the organization. The 72-hour notification delay starts
when the organization becomes aware of the breach, which is why the DPO should be told early.

What holds up well: the reflex to discover the notion of DLP and tie it to the field before answering, and the
triptych built from it. Preservation comes first and is invisible to the user (litigation hold, copy of the email
from quarantine), before any interaction. The tiers separate an external axis from an insider axis, require
legal's agreement before monitoring, and put the forensic capture before any revocation or isolation. Volatility
is thought per hypothesis rather than as one list. HR and legal come before the employee's manager, and the
recommendations are specific to each case.

## 🪞 Reflection

1. The notion of DLP was new to me, and the lack of background slowed my answer. Naming the case precisely (a
   benign true positive rather than a false positive) came only through the review, and it changed what the plan
   owed the data left behind.
2. I justified the volatility level and the means that go with it, which I want to keep: the means follow from
   the hypothesis (external session to preserve and stop, versus Sent Items and endpoint logs to collect
   discreetly).
3. Each tier now carries explicit trigger criteria and an explanation of why, which my previous scenarios did not
   have. A tier without an observable trigger is a decision left to feeling.
4. I still struggle to prioritize and to separate the quick wins that settle the hypotheses from the checks that
   build evidence. The reflex to build is to rank by discriminating power and cost, and to ask of each check what
   it would change in the branch I take.
5. A policy violation and a data breach are two questions: the second belongs to the DPO, and the SOC's job is to
   hand over the facts early.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
The DLP definition, the triptych and the quick wins are unchanged. Changes:

- The hypotheses are renamed and reframed:
  - **Benign true positive** — the employee's activity is legitimate despite the alert: working from home on a
    personal computer, or sending to an address considered personal but legitimate (consultant, partner,
    supplier). The DLP detection is correct, but the policy is violated and the data stays out of the
    organization's control.
  - **True positive** — the employee's activity is illegitimate: revenge, preparation to leave, resale of data, or
    an external threat's ongoing attack at the exfiltration stage.
- **Tier 1** — if the action is confirmed as legitimate, I report to the employee's manager and I help the employee
  delete the message, empty the Gmail trash and delete the copies on their phone and downloads, with a written,
  timestamped attestation, before closing the ticket, which captures the analysis with the actions taken and the
  conclusion. I report the alert to my own manager to start a possible evolution of the DLP configuration or a
  business awareness effort.
- **Tier 2, insider threat axis** — if other sensitive emails were sent to the same address before the alert, if
  access to data outside the employee's rights is detected, or if a tense context is confirmed by the manager or
  HR, then with legal's agreement I place the account/endpoint under enhanced monitoring for in-depth analysis over
  a given time window (for example the last 30 days). The external threat axis is unchanged.
- **Tier 3** — if the action is validated as an internal threat, I escalate to HR, legal and management to
  validate the suspension of the account and to initiate the HR measures. In parallel, I start the forensic
  capture before any session revocation, account suspension or device isolation, following the collective
  decision.

The volatility axes are unchanged.

**What questions would you ask?** Unchanged.

**What would you investigate and in what order?**
My first reflex is to launch preservation actions that are invisible to the user and require no interaction or
validation. I place the mailbox on litigation hold to keep its content despite deletions, and I copy the email and
the attachment from quarantine or from the DLP incident.

To decide the means to deploy and the order of actions to handle the alert's volatility, I need to separate the
two hypotheses, insider threat or external threat, through quick, low-intrusion checks. My priority is to
determine the status of the DLP action (blocked, quarantined, delivered) and the user's DLP history. I then look
at how the email was sent through the `Send` events in the UAL and the `ClientIP` and `ClientInfoString`/AppId
fields, to bring unusual behavior to light. I then analyze the body of the message and the recipient address to
see whether it matches the employee, and whether there is a history in the Message Trace. Finally, I analyze the
workstation's EDR through light telemetry, looking for malware, infostealers (session cookie theft), remote access
tools, connections to suspicious IPs or domains, but also a copy to USB or an upload to a personal cloud.

In parallel, I extract the Entra ID Protection logs to analyze the profile's sign-ins (impossible travel,
unfamiliar sign-in, suspicious IP) and I use Defender for Office 365 to check whether a phishing email was
received/clicked over the last 90 days. I then look in Defender for Cloud Apps for massive downloads/exports from
SharePoint, OneDrive or the CRM. I look for any trace of an OAuth consent given to a third-party application able
to send emails, and I identify suspicious mailbox rules as well as activity from unusual IPs (to correlate with
the previous step). I inspect the Sent Items to see whether the email is still there or has been deleted. Finally,
I analyze the business context with the manager and HR, determining whether the action is consistent with the
employee's role and whether there is other information to know (notice period, conflict…).

To help the analysis, I set this decision table:

- **Case 1** (usual client and IP): benign, insider or external, to correlate with the EDR.
- **Case 2** (unknown client or IP): benign or external, even insider outside the workstation; to corroborate with
  the sign-ins, a new mailbox rule, a new MFA factor or an OAuth consent.
- **Case 3** (never-seen recipient): settled by the three facts below.

The three facts that separate benign from insider: (1) the recipient (the employee's address or a third party),
(2) the content (consistent with their role, their usual volume and their access), (3) the context (manager and
HR: notice period, conflict, remote work authorized or not).

Once these steps are done, I should have a better view of the alert's volatility, unchanged from before
(external threat: the attacker's active session and ongoing exfiltration; internal threat: Sent Items, local
copies and endpoint logs). The rest (scoping across the organization, post-incident phase) is unchanged. The
recommendations are unchanged, except that the first case is now named "benign true positive" instead of "false
positive".

**Who would you communicate with and when?**

1. At the start of the alert handling: my manager and the team, to tell them I am taking ownership of this
   high-impact alert and to watch for other alerts to correlate.
2. When context is needed or an insider is suspected: HR and the legal department, before the employee's manager,
   to escalate the incident, gather the business context and obtain the validations/authorizations for the
   response plan.
3. If a true positive is confirmed: the DPO for personal data, as soon as the email is confirmed delivered and
   outside the organization, with the recipient, the nature and volume of the data (individuals or companies),
   known opening or forwarding, the chronology and the measures taken; then notification of the CISO and launch
   of the response plan.
4. Containment decision: the helpdesk and the identity team for the containment actions on the user's endpoint
   and account.
5. After containment or closure: the employee (if the action was legitimate) and the manager, for explanation,
   remediation and deletion of the data.

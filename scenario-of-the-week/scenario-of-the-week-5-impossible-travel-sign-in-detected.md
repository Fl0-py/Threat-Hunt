# Scenario of the Week 5 — Impossible Travel Sign-In Detected

## 🎬 Scenario

```
Alert Name: Impossible Travel Sign-In Detected
User: George.Matthews@fakecompany.ca
IP Address: 197.228.6.18 → 142.113.48.49
Time Detected: 2025-08-29 15:24 UTC
```

Within a 15-minute window, the user account George.Matthews signed into Microsoft 365 from two geographically
distant locations that are not physically possible to travel between. Conditional Access flagged the session,
but authentication was still successful.

## 🧭 Guided Questions

- What's your gut telling you and how would you confirm it?
- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
My first reflex is to break the alert down and organize the information into context, anomaly, and priority
data:

- **Context** — on 2025-08-29 15:24 UTC, `George.Matthews@fakecompany.ca` authenticated successfully to
  Microsoft 365 from IP `197.228.6.18` then `142.113.48.49`, two geographically distant locations that cannot
  be physically reconciled within the observed timeframe.
- **Anomaly** — two geographically distant locations physically impossible to link within that timeframe, with
  successful authentication on both.
- **Priority** — successful authentication, account and IP tied directly to the user.

Before starting any investigation, I set contradictory (true/false positive) hypotheses:

1. ATT&CK T1078 — Valid Accounts: an adversary may obtain and abuse credentials of an existing account for
   initial access, persistence, privilege escalation, or defense evasion.
2. A legitimate sign-in explainable by business travel, VPN use, or a network misconfiguration.

To settle this, I'll reach out to the user and IT to confirm or rule out a false positive, in parallel with an
IP reputation check and an authentication log review, to surface a possible real threat. I set a graduated IR
response threshold based on the investigation's outcome:

- False positive confirmed → close the ticket.
- Valid account compromise confirmed → lock the account, revoke sessions/tokens, and reset the password.
- Data forwarding, persistence, or exfiltration → trigger a full incident response.

**What questions would you ask?**
What is George Matthews' position within the organization? Is the connection still active? What is the exact
trigger condition for this alert? Does the user use a VPN? Is he traveling? Are the proxy and load balancer
correctly configured? What is the source IP's reputation? What do the authentication logs show in the 15-minute
window around the alert? Did MFA succeed? What activity followed the suspicious sign-in? Is this the first time
this IP has appeared?

**What would you investigate and in what order?**
My priority is to find out whether the connection is still active and what George Matthews' exact role is
within the organization. I contact him and IT to get context on the connection, the alert, and the network
setup, in parallel with preserving the volatility of network, cloud, and endpoint logs around the source IP and
the profile. If logs are available, I check firewall/proxy logs to see whether the user's device actually
changed location, whether this is the first time this IP shows up over a 30-day window, and whether it has
authenticated against other accounts.

If that's the case, I move to IP reputation analysis to identify the owning ASN/organization, then to the
authentication logs. I start with the sign-in logs for both connections, comparing user agents (browser/OS),
Device IDs and their compliance status (enrolled/unknown), the MFA method used per connection
(satisfied/bypassed), the Conditional Access result (flagged but allowed), the client application used
(Outlook, web browser, legacy ActiveSync, Graph API...), and the Session ID/Correlation ID to link the two
connections. I then move to the audit logs to spot account changes — an added or modified MFA factor, a change
to forwarding/delegation rules, a recent password change, or a newly added OAuth application. Then I review
Microsoft 365 activity logs: on Exchange Online, forwarding/redirect rule creation (`New-InboxRule`,
`Set-Mailbox -ForwardingSmtpAddress`), mass mailbox access, searches for sensitive keywords ("password",
"invoice", "wire transfer"); on SharePoint/OneDrive, mass downloads and newly created external shares; on
Teams, outbound messages (often used for lateral phishing post-compromise); and application OAuth consents
(`Consent to application`) for any persistence attempt.

**Who would you communicate with and when?**
I'd start by letting my team know I'm taking the alert, and checking whether other alerts could be correlated
(phishing email, privilege escalation, data exfiltration...). At minute 0 of triage, I secure the
investigation's volatility axis per RFC 3227, get a quick win on proxy/firewall logs, then contact IT and the
user. If the alert is confirmed as a false positive, I close the ticket; if impossible travel is confirmed, I
contact the identity/IAM team for an account lockout, a full revocation of active sessions and other tokens,
before changing the password. If data forwarding, persistence, or exfiltration is confirmed, I trigger a full
incident response plan with escalation to management and, potentially, legal.

## 🧠 Expert Review

The most consequential error is citing RFC 3227's volatility order (network connections → process state →
memory → disk) as the guiding framework for securing evidence, when there is no endpoint anywhere in this
scenario — the entire telemetry surface is Entra ID / Exchange Online / SharePoint / Teams. That endpoint
forensics framework doesn't transpose mechanically to SaaS. The actual perishable resource in a cloud-only
investigation is the default sign-in log retention window (7 days on Entra ID's free tier without export to a
SIEM/Log Analytics workspace) and the persistence actions an active adversary can still take while you wait —
a new forwarding rule, a newly registered MFA method, a new OAuth consent. That's the real time pressure here,
not a session "ending."

Second, the question "did MFA succeed?" is a yes/no question standing in front of at least five distinct
mechanisms that all produce the same observable ("Conditional Access flagged the session, but authentication
still succeeded") — legacy authentication bypassing MFA outright, a stolen session/refresh token replayed
without ever triggering a fresh MFA prompt, a legitimate user approving a push in an MFA-fatigue attack, or a
socially-engineered approval. The plan already names the one field that can discriminate between them — the
Session ID/Correlation ID — but places it last in the sign-in log review instead of first, and never asks what
a shared correlation ID between the two connections would actually mean mechanically versus two fully
independent authentications.

Third, IP/ASN reputation is named as an action ("IP reputation analysis," "which ASN/organization it belongs
to") without stating what would be looked for or how it would change the hypothesis — a violation of
operational specificity, naming an intention rather than an action. A live lookup on both source IPs during
this review returned AS37457 (Telkom SA, Gauteng/Centurion, South Africa) for `197.228.6.18` and AS577 (Bell
Canada, Québec/Montréal) for `142.113.48.49`. Neither belongs to a commercial VPN or hosting ASN — both are
ordinary residential/business ISP space. Since `fakecompany.ca` is a Canadian organization, the Bell Canada leg
is mundane; it's the Telkom SA leg that needs explaining. That distinction matters operationally: an attacker
routing through a $5 commercial VPN lands on a detectable, blockable hosting ASN, while a residential ISP
origin means either a genuine local user or, if malicious, a residential proxy network specifically chosen to
blend in and evade IP-reputation heuristics — a materially different, costlier adversary capability with
different containment implications.

Fourth, the investigation order gates the sign-in log pull behind IP reputation ("if that's the case [new IP],
I move to IP reputation, then to authentication logs"), even though nothing about pulling sign-in logs — MFA
method, Conditional Access result, Device ID, Correlation ID — depends on the IP reputation result. That log
pull is a zero-cost, immediate win that belongs in parallel with, not gated behind, the ASN check.

Fifth, the containment thresholds list "block the IP" as the default response to confirmed compromise without
any link back to the ASN finding above — a static IP block has close to zero value against infrastructure that
can rotate, and real value against a fixed hosting/VPN address. The threshold needs to be conditioned on what
the ASN lookup actually reveals about the adversary's infrastructure, not applied uniformly.

Sixth, the plan treats a firewall/proxy log pull as a "quick win" for confirming the device's real location
without first checking whether that traffic even transits the corporate perimeter — Microsoft's own guidance
favors direct/optimized routing for Microsoft 365 traffic, which for a large share of remote and mobile
endpoints means it never touches an on-prem proxy at all. Querying a log source before confirming it has any
chance of containing the answer risks either wasted effort or, worse, reading "nothing found" as a clean
signal when the source structurally never saw the traffic.

What holds up well: the context/anomaly/priority breakdown is sound, the two competing hypotheses (T1078 vs.
legitimate travel/VPN/misconfiguration) are stated without collapsing into premature attribution — nowhere does
the language jump to "we are facing a threat" before the evidence supports it — and the sign-in log field list
(Device ID and compliance, MFA method per connection, Conditional Access result, client application) is exactly
the right level of granularity from the first pass. The Microsoft 365 activity log coverage (Exchange, SharePoint/
OneDrive, Teams, OAuth consents) is also broad and relevant without needing correction.

## 🪞 Reflection

Six operational reflexes to carry forward:

1. RFC 3227's volatility order doesn't transpose to a cloud/identity investigation by default — check that a
   preservation framework actually matches the instrumented layer (endpoint vs. identity/SaaS) before citing
   it.
2. A corporate firewall/proxy log is only a "quick win" if the traffic in question actually transits that
   perimeter — verify the routing architecture (forced tunneling vs. direct/optimized SaaS routing) before
   relying on the source.
3. The Session ID/Correlation ID belongs at the top of sign-in log analysis, not the bottom — it's the field
   that actually links (or rules out a link between) two connections, which every other field comparison
   depends on.
4. A binary "did MFA succeed?" doesn't discriminate between an attacker replaying a stolen session and an
   attacker who owns a valid MFA factor on the account — the real question is which mechanism produced the
   successful authentication, and each mechanism demands a different remediation.
5. Naming a data source ("IP reputation," "ASN/organization") isn't the same as naming why it's being pulled —
   the ASN lookup is what should calibrate the adversary's capability and, downstream, whether a containment
   action like a static IP block has any teeth.
6. A containment threshold shouldn't be uniform across adversary infrastructure types — it needs a stated
   fallback (tightened Conditional Access, compliant/hybrid-joined device requirement, blocked legacy auth,
   Identity Protection risk-based sign-in) for when the primary control (IP block) is assessed as ineffective.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
Same first reflex — context, anomaly, and priority data:

- **Context** — on 2025-08-29 15:24 UTC, `George.Matthews@fakecompany.ca` authenticated successfully to
  Microsoft 365 from IP `197.228.6.18` then `142.113.48.49`, two geographically distant locations that cannot
  be physically reconciled within the observed timeframe.
- **Anomaly** — two geographically distant locations physically impossible to link within that timeframe, with
  successful authentication on both.
- **Priority** — successful authentication, account and IP tied directly to the user.

Same contradictory hypotheses going in:

1. ATT&CK T1078 — Valid Accounts.
2. A legitimate sign-in explainable by business travel, VPN use, or a network misconfiguration.

To settle this, I reach out to the user and IT in parallel with an IP reputation check and an authentication
log review. The graduated response threshold now branches on the sign-in log findings rather than staying
uniform: false positive confirmed → close the ticket; valid account compromise confirmed → depending on what
the Microsoft 365 sign-in logs show, block the IP, lock the account, revoke sessions/tokens, reset MFA, or
change the password; data forwarding, persistence, or exfiltration → trigger a full incident response.

**What questions would you ask?** One change: "Did MFA succeed?" becomes "What MFA methods were used per
connection?" — the rest of the list is unchanged.

**What would you investigate and in what order?**
My priority is still to find out whether the connection is active and what George Matthews' exact role is. I
contact him and IT for context, in parallel with exporting the Microsoft 365 logs for analysis — not waiting on
that export, since it's what secures the investigation against the retention window and against persistence
actions an active adversary could still add. I then move to IP/ASN reputation analysis to determine the
organization behind each source IP (commercial VPN, hosting provider, or ordinary residential/business ISP),
specifically to calibrate the adversary's capability and adapt the defense posture accordingly. I continue with
the authentication log review, starting with the Session ID/Correlation ID to link the two connections, then
comparing user agents (browser/OS), Device IDs and their compliance status, the MFA method used per connection
(satisfied/bypassed), the Conditional Access result, and the client application used (Outlook, web browser,
legacy ActiveSync, Graph API...). I then move to the audit logs for account changes — an added or modified MFA
factor, a change to forwarding/delegation rules, a recent password change, or a newly added OAuth application —
followed by the Microsoft 365 activity logs: on Exchange Online, forwarding/redirect rule creation
(`New-InboxRule`, `Set-Mailbox -ForwardingSmtpAddress`), mass mailbox access, sensitive-keyword searches; on
SharePoint/OneDrive, mass downloads and external shares; on Teams, outbound messages; and OAuth application
consents for any persistence attempt. I close with a scope pass pivoting on the source IP to see whether it
appears in older logs or against other accounts.

**Who would you communicate with and when?**
I'd start by letting my team know I'm taking the alert, and checking whether other alerts could be correlated.
At minute 0 of triage, I secure the investigation's volatility axis by exporting the Microsoft 365 logs,
coordinating with the cloud team, while contacting IT and the user tied to the profile. If the alert is
confirmed as a false positive, I close the ticket; if impossible travel is confirmed, my response now depends
on the sign-in logs. If the Correlation ID shows a session token replayed across both IPs — a session theft
mechanism closer to T1557 (Adversary-in-the-Middle) combined with T1550.004 (Use Alternate Authentication
Material: Web Session Cookie) than to T1078 alone — I ask the identity team to revoke sessions/tokens first,
then change the password. If instead the two are independent authentications, I prioritize an MFA reset and an
audit of registered methods to understand how the attacker obtained a valid MFA factor on the account. I block
the IP based on what the ASN lookup shows about the threat's infrastructure, and if that proves ineffective, I
request a tighter Conditional Access policy instead — a compliant/hybrid-joined device requirement, blocked
legacy auth, tightened named locations, or Identity Protection's risk-based sign-in rather than a static IP.
If data forwarding, persistence, or other activity is confirmed, I trigger a full incident response plan with
escalation to management and, if sensitive data was accessed or exfiltrated, to legal.

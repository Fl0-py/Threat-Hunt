# Scenario of the Week 1 — Vendor Email Compromise and Wire Fraud

## 🎬 Scenario

```
An AP clerk calls the SOC at 2:10 PM about a payment she processed that morning. No alert fired. The previous
week, a vendor emailed to say their banking details had changed and sent updated remittance instructions on
the vendor's usual letterhead. The email arrived on the existing thread, quoting the last three messages about
an outstanding invoice.

She replied with a question and got an answer within the hour, then updated the vendor record. That morning
she paid the invoice — $184,000. At lunch, the real vendor called asking why it was still outstanding. She had
already checked the sender address and it matches the vendor's domain exactly, character for character.

```
## 🧭 Guided Questions

- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?
- What's your gut telling you and how would you confirm it?

## 📝 First Response

**What questions would you ask?**
What data is available in the mail server/header logs? Does the bank-detail change process followed here match
the organization's established procedure? What legitimate reasons could explain the funds not arriving at the
destination account (processing delays)? What banking details and instructions were actually communicated in
the conversation? Is there any urgency or pressure language in the message? Was the change request itself
legitimate? Did other employees receive emails from this vendor after last week?

**What would you investigate and in what order?**
First, collect and secure every available trace on the organization's side — the original email with full
headers and server logs — with investigation, insurance, and a possible legal process in mind. Then analyze the
week-old exchange in detail, specifically the clerk's question and the reply received within the hour, looking
for a shift in tone, phrasing, or behavior suggesting a different party on the other end. Then review the SPF,
DKIM, and DMARC records to validate use of the vendor's infrastructure, check the sender IP, and check
Return-Path/Reply-To consistency, looking for any technical contradiction or an alternative compromise
hypothesis beyond VEC. Finally, scope the incident by checking whether other employees received messages from
the same vendor mailbox.

**Who would you communicate with and when?**
First reflex: notify the SOC manager for coordination and the finance department to immediately request a
funds hold/recall from the issuing bank — better to escalate a false positive than risk not recovering the
money. Then the AP clerk (exact email details) and her manager (freeze further payments, confirm whether the
bank-detail change process followed matches normal procedure). Then the vendor, over a secure and historically
validated phone line, to verbally validate the change and formally alert them to a suspected mailbox
compromise. Then the email security/helpdesk team, to search for messages from that exact address since last
week and quarantine, once suspicion is confirmed, anything from that mailbox.

**What's your gut telling you and how would you confirm it?**
The email arrived on the existing thread, quoting the last three messages, from a sender address matching the
vendor's domain exactly, and a wire transfer that never arrived — this pattern points to an ongoing Vendor
Email Compromise (VEC). A false positive remains possible: banking processing delay (holidays, bank closure
depending on the vendor's country), a reconciliation error on the vendor's accounting side, or miscommunicated
information. To confirm, validate that the email genuinely originates from the vendor's infrastructure and
that the bank-detail change is legitimate, using the conversation context and header/server logs, then contact
the vendor directly on a secure, historically validated line to confirm legitimacy and the banking details. The
money has already left the organization's account, and every minute counts to recover it before it disappears.

## 🧠 Expert Review

The response is structurally sound but misses the most consequential distinction in this case: this is not a
preventive check ahead of a payment, it is a confirmed fraud with a dated, quantified funds-out event —
$184,000 already left the account. The volatility axis here is the money, not the mailbox, and a wire
recall has a success window measured in hours, not days, closing faster the longer the receiving bank has had
the funds. Yet the investigation plan still reads as a qualification sequence — header analysis, then behavior
analysis, then scoping — with no first action that runs in parallel with an immediate call to the issuing bank.
Keeping the four guided questions as four separate lists, rather than a single chronological sequence, is what
hides this: the correct actions are present, but nothing in the text establishes that the bank call and the
evidence-gathering happen at the same time rather than one after the other.

A second, more serious issue is a misplaced trust in email authentication. The sender address matches the
vendor's domain exactly, character for character — not spoofing, not a lookalike domain. In a "clean" VEC where
the vendor's real mailbox is compromised, SPF passes because the mail genuinely leaves an authorized server,
DKIM passes because it is signed with the real private key, and DMARC aligns because From and Return-Path point
to the same legitimate domain. These checks passing tells us essentially nothing about the legitimacy of the
banking instruction itself. The one control with real evidentiary value — a voice callback on a historically
validated number — is correctly identified but placed at the end of the chain rather than treated as the
reference proof it should be.

A third gap concerns the mid-week exchange itself: the reply received within the hour to the clerk's
clarifying question is never investigated on its own merits — for a break in writing style compared to prior
certified-legitimate exchanges, for a reply that carefully avoids proposing a voice confirmation, or that
insists on keeping everything in writing (a "man-in-the-mailbox" pattern consistent with active post-compromise
monitoring, often via a forwarding rule or repeated manual checking).

Fourth, vendor-side remediation is under-specified: contacting the vendor cannot stop at "is the change
legitimate" — their IT/security team needs to check sign-in logs for anomalies (impossible travel, a new
device, legacy auth bypassing MFA), any recently created inbox/forwarding rules, and any OAuth app grants on
their tenant. Without that, "informing the vendor of a compromise" is a hollow phrase — informing them of what,
with what evidence, asking them to check exactly what?

Fifth, before drawing conclusions about the vendor's mailbox, the AP clerk's own mailbox deserves a check too —
in principle, a malicious internal forwarding rule intercepting correspondence with this vendor would change
the incident's scope entirely (internal account compromise with BEC as a consequence, rather than external
VEC). In this specific case, that hypothesis is weaker than it first appears: an internal forwarding rule alone
cannot explain how the fraudulent email authenticated as coming from the vendor's exact domain — that requires
access to the vendor's own infrastructure, which by itself also explains how the attacker had enough context
about the outstanding invoice to reply credibly within the hour. The hypothesis is correctly deprioritized on
that basis, but deprioritizing it is not the same as skipping verification: a quick check of the AP clerk's own
inbox rules and recent sign-ins costs very little and closes the alternative definitively rather than leaving
it as an untested assumption. Separately, the claim that the sender address "matches exactly" comes from the AP
clerk, not a security professional, based on a visual read of the email client — a homoglyph or punycode domain
can render identically to the eye. That claim needs an independent, byte-level check of the raw headers before
being treated as an established fact.

What holds up well and should not get lost in the critique: freezing other payments to this vendor, the
SPF/DKIM/DMARC check as an action in itself (the error is in the interpretation, not in performing it), the
Return-Path/Reply-To comparison, the voice callback on a historically validated line, and the finance/legal
coordination for a regulatory report.

## 🪞 Reflection

The core lesson from this pass is methodological, not factual: keeping the four guided questions as four
separate answer blocks hides parallelism that must be made explicit. When the volatility axis and the
legitimacy axis both apply, the first move is not to answer the questions in order but to ask "what runs at
the same time" before writing anything down. A second lesson concerns technical authentication controls:
passing SPF/DKIM/DMARC provides no signal about the legitimacy of a human instruction once the attacker
controls the vendor's real infrastructure — treating a green result as progress toward a legitimacy conclusion
is the specific cognitive trap to name explicitly, not just avoid by accident. Third, competing-hypothesis
discipline does not require two hypotheses to be equally probable — it requires that a hypothesis not be
dropped without being falsified at low cost, even when the evidence already points strongly toward a single
explanation. Fourth, a non-expert's visual confirmation of a technical detail (an exact domain match) is a
claim to independently verify at the byte level, not a fact to build an investigation on.

## 🔁 Revised Response

**Track A — financial volatility (does not depend on any other conclusion):** immediate contact with the
issuing bank to initiate a wire recall (SWIFT MT192 or the equivalent local rail), launched at the same time as
notifying the SOC manager and the finance department for response coordination and to begin the regulatory
reporting process.

**Track B — evidence and context (runs in parallel with Track A, never blocking it):** export and preserve the
original email with full headers before any remediation action that could make it disappear (quarantine,
deletion); contact the AP clerk to reconstruct the exact context of last week's exchange and freeze any other
pending payment to this vendor; run a quick, low-cost check of the AP clerk's own inbox rules and recent
sign-ins to close the internal-compromise hypothesis rather than leaving it unverified.

**Supporting analysis, blocking neither track:** review SPF/DKIM/DMARC, Return-Path/Reply-To consistency, and
sender IP history — useful for the case file and for catching a technical anomaly, but not treated as evidence
of legitimacy given that the vendor's own infrastructure is the likely source. Review the mid-week exchange
itself for a style break or signs of active mailbox monitoring.

**Vendor contact, positioned as the reference proof rather than a final step:** once Track B context is in
hand, call the vendor on a secure, historically validated line (never a number supplied in the exchange under
review) to verbally confirm the legitimacy of the bank-detail change and formally notify them of a suspected
mailbox compromise, with a specific list of checks to hand them: sign-in logs for anomalies (impossible travel,
new device, legacy auth bypassing MFA), recently created inbox/forwarding rules, and OAuth app grants on their
tenant.

**Scoping:** search for all emails sent by this vendor mailbox to the organization since last week, to identify
other targeted employees and any compromise indicator unrelated to the initial bank-detail request. Quarantine
new messages from this mailbox once suspicion is confirmed — after evidence export, never before.

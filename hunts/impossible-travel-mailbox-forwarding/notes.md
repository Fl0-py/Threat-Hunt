# Investigation Notes & Methodology

Personal notes on how I actually worked through this hunt — the real chronology, the mistakes I made and
corrected along the way, and the methodology I'm building for future identity investigations. The polished
findings live in [`README.md`](README.md); this file is the process behind it. The raw lab data is not
republished here (it belongs to the course), so there is no raw-data file next to this one.

## Investigation Timeline

1. **Lab setup and integrity checks.** Treated the setup as a small project of its own
   (framing, sizing, parameters, application), reusing the method of my AD 2.0 project. Verified the SHA256 of the
   lab archive with `Get-FileHash`, built an Ubuntu Server 22.04.5 VM under VMware (4 vCPU / 8 GB / 160 GB),
   verified the ISO hash, installed Splunk Enterprise 10.6.0.5 (checked with `sha512sum`; hit a `dpkg` lock error
   and a 404 caused by a mistyped version in the download URL), opened port 8000, set the profile timezone to GMT
   so `_time` reads in UTC (the lab asks for the login time in UTC), then installed the lab app.

   *Learned:* establish the chain of custody and a reproducible setup before reading any data. Done in
   30-minute slots before work, without a step-by-step video, because the AD 2.0 method carried over.

2. **Framing and definitions.** `index="cloud"` returned 242 events across three sources
   (126 / 99 / 17). I took the time to list the sources with their time bounds and volumes, inventory the fields
   source by source, and write my own definitions (interactive versus non-interactive sign-ins, impossible
   travel, unfamiliar sign-in) with the conditions that would prove each. Then a query plan, the real fields of
   each sign-in source, a list without duplicates, and a corrected list of fields worth checking for an anomaly.

   *Learned:* at first I felt overwhelmed by the logs: I did not know what they represented or in which order to
   treat them. Defining an objective and hypotheses, and putting on the table what was within reach before
   querying, is what removed that feeling.

3. **Interactive sign-ins.** A first table of the 17 interactive sign-ins showed three IP
   addresses and two accounts. I swapped a profile and an IP in my own notes and corrected it myself.
   Looked up the meaning of the error codes `50072` (MFA enrollment required), `50140` (the "stay signed in"
   prompt) and `0` (success) on the official error page. AbuseIPDB showed that the log geolocation was wrong for
   the reference IPs (California in the logs, Vancouver in AbuseIPDB) and that the Singapore IP was a hosting
   provider. Authentication details showed a correct password then an MFA step that never succeeded. Tested three
   hypotheses on the "claim in the token" lines with the correlation and request identifiers and the user agent.
   Answered the first three lab questions: the account `jchan`, the Singapore login, and its time in UTC.

   *Learned:* the gap between the first request (20:46:37) and the first success (20:46:42) matters when
   answering a question about time, and my first estimate of the travel time (about 10 minutes) was wrong: it is
   13 min 5 s. I also spent a long stretch on MFA details I only partly master, which pulled me away from the
   six questions until I stepped back.

4. **Non-interactive sign-ins.** Read the 126 non-interactive lines. Each interactive success is
   followed 1 to 5 seconds later by a burst of token requests, in every series, legitimate or not, so the pattern
   itself proves nothing. For the Singapore IP, the 54 lines fall into six phases (a start-up burst, a second
   burst after a new interactive success, periodic Graph calls).

   *Learned:* non-interactive sign-ins show access and tokens, not actions. The actions are in the audit log.

5. **Audit log.** The 99 audit events mix two families (Exchange and Azure AD), and the IP is
   stored in three different fields. From the Singapore IP: 34 events, an inbox rule and a mailbox-level SMTP
   forward, drafts created and deleted, then a fraudulent bank-account message. A pivot on its `InternetMessageId`
   led to the `\Finance` folder of a colleague, `schan`, who replied with a signed attachment. I first concluded
   there was no trace of that reply, because I had not opened page 2 of the Splunk results.

   *Learned:* open every page of the results before concluding on an absence.

6. **Response plan, question 6.** Escalate to incident response with a crisis cell including
   finance, preserve the logs before any change, then four parallel strands (identity, fraud, post-incident, data
   leak), an interview of `schan`, and the DPO for the leak. I rewrote the first version of this answer after
   finding the reply of `schan`.

7. **Method and grind map.** From my notes I extracted a two-step method (framing, then
   investigation) and built an identity investigation grind map, exported as an SVG after fixing typos and adding
   the verdict states under the deduction step.

## What I Got Wrong (and Fixed) During the Audit

I used the reference IP `181.214.153.165` as the "normal" location without any OSINT lookup, even though the log
geolocation was already shown wrong for `181.214.153.176`. The impossible travel needs both endpoints.

> **✅ Fixed:** run an OSINT lookup on every baseline IP and write its date next to the result.

The sign-in logs raised an impossible travel; they did not prove a compromise. The discriminating evidence was in
the audit log (an inbox rule and an SMTP forward created from the suspicious IP, compared with the Vancouver
session that only read mail and replied to a thread). The lab tells me to ignore the VPN, so the "legitimate user
behind a VPN" hypothesis is excluded by the lab premise, not by an observation.

> **✅ Fixed:** write both statements separately, and name the observation that separates the competing hypotheses before concluding.

I treated `MailItemsAccessed` as "delivered but never opened" and expected network logs to show the forwarded
messages. In fact it records access to mailbox items, and an Exchange Online forward happens inside the Microsoft
service, so the source is the Exchange message trace, which the lab does not provide. I also called the leak
"confirmed" before settling on "probable": the forward was active when `schan` replied, but two inferences stack
(the reply was addressed to `jchan`, and the forward processed it).

> **✅ Fixed:** keep the configuration of the forward (confirmed) and the exit of messages (not observed) as two statements, with a three-level scale (confirmed, probable, possible).

Two query effects were only caught by comparing totals. The IP appears in different audit fields depending on the
event (`ClientIP`, `ClientIPAddress`, `ActorIpAddress`), and `stats count by` silently drops the events where a
grouped field is empty: my first IP inventory returned 88 events instead of 99. While taking the final
screenshots, a statement in my draft ("the MFA step failed on the 8 `50072` lines from Singapore") also turned out
to be wrong: there are 8 such lines in the whole data set and 4 from Singapore.

> **✅ Fixed:** after every `stats`, add up the counts, merge fields with `coalesce` and use `fillnull` before `stats ... by`; check each number against the export before writing it.

Four terms were imprecise in my notes: an inbox rule called a transport rule, an internal mail propagation called
lateral movement, an account without registered MFA called an MFA bypass, and `MailItemsAccessed`. Each changed
the conclusion that followed.

> **✅ Fixed:** define a mechanism from the official documentation before writing its name.

On the other side, I pushed back when the audit suggested I was missing a detection query: the lab asks for
transformation queries, not a detection rule, and the queries I had already built answered that.

## My Investigation Framework (Identity, V0.4)

Built at the end of this hunt from what I actually did.

1. **Framing.** Define the objective, write the hypotheses with the conditions that would prove them, then list
   what is available: sources, time bounds, volumes, fields and error codes. Note the organizational questions that
   would matter in a real environment (log retention, access, ability to handle the data, level of abstraction,
   network scope).
2. **Investigation.** A loop between extraction (queries on the sources) and deduction (a verdict on each
   hypothesis: confirmed, refuted or inconclusive). Qualification follows: scope, impact and OSINT. A question bank
   per theme (connection, privilege, persistence, scope, OSINT) feeds the queries.

Still to add: a map of the identity theory behind this one (authentication flows, tokens and sessions, MFA, roles
and consents, persistence), so the method rests on understanding of identity itself and not only on handling an
alert, and a branch for the response plan, which I left out of the map on purpose because it went beyond the lab.

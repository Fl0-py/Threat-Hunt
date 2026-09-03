# Investigation Notes & Methodology

Personal notes on how I actually worked through this hunt — the real chronology, the mistakes I made and
corrected along the way, and the methodology I'm building for future email investigations. The polished
findings live in [`README.md`](README.md); this file is the process behind it.

## Investigation Timeline

1. **Integrity check.** Downloaded `First_Email.zip`, verified its SHA256 with `Get-FileHash` in PowerShell
   against the lab statement. Extracted `First_Email.eml`, verified its hash the same way.

   *Learned:* start every investigation by establishing chain-of-custody on the evidence itself, before
   reading a single byte of content — a habit worth keeping even when it feels like a formality on a lab file.

2. **First pass on the headers (Notepad++).** Pulled `Message-ID` and `Date` first, to anchor a timeline. Then
   asked: does it pass SPF/DKIM/DMARC, and who's the true sender? Compared `Authentication-Results`,
   `Reply-To`, and `From` — found `From` (`sasktel.net`) diverging from `Reply-To` (a Gmail address), and SPF
   `softfail` with DKIM/DMARC both failing. Concluded this was a threat until proven otherwise.

   *Learned:* `Authentication-Results` is where the mail server's own SPF/DKIM/DMARC verdict lives — I don't
   need to recompute it myself, just read and interpret it. And the `Received` chain is literally the list of
   servers the message hopped through between sender and recipient — each hop adds one entry.

3. **Content review.** Checked for an attachment first, since one would change my priority toward scope/impact
   instead of reputation work. Single `Content-Type: text/html` confirmed none. Read the subject and body:
   a classic advance-fee ("419") scam impersonating US Treasury officials. No embedded links, only email
   addresses. `To: Undisclosed recipients:` confirmed mass BCC delivery — decided to set organizational scoping
   aside, since this is a lab artifact with no real environment to scope.

   *Learned:* a single top-level `Content-Type` (no `multipart` structure) is enough to rule out an attachment
   without opening anything else. `To: Undisclosed recipients:` is a recognizable signature of mass BCC
   delivery, not a targeted send.

4. **OSINT round 1 — the mail server's domain (`yobow.cn`).** DNS checker: A record → Tencent Cloud (Beijing);
   MX → Tencent QQ Mail; NS → Alibaba Cloud. WHOIS: registered 2014-07-18. Read this (at the time) as
   "confirmed China-based sending infrastructure."

   *Learned (incompletely — corrected later, see below):* at this point I treated the domain named in the
   last `Received` header I'd captured as equivalent to a verified fact, without checking whether its own DNS
   records (A/MX here) actually matched the IP I was investigating.

5. **OSINT round 2 — the sender IP (`183.56.179.169`).** AbuseIPDB: 9 reports, 8 sources, ISP CHINANET
   Guangdong, Usage Type "Fixed Line ISP", one report explicitly tagged "Nigerian 419 Phishing Email Spam"
   (2023-11-11). Read the "Open Proxy" tag + "Fixed Line ISP" as arguing *against* a VPN.

   *Learned:* AbuseIPDB's category tags are user-submitted and unverified individually (like "Open Proxy"
   here) — they're context, not proof on their own. The "Usage Type" field (Fixed Line ISP vs Data
   Center/Hosting) is the more reliable signal for a VPN/hosting question.

6. **OSINT round 3 — the impersonated domain (`sasktel.net`).** WHOIS: registered 2000-04-05, real registrar
   (Webnames.ca). DNS TXT: a real SPF record (doesn't include the sending IP) and a real DMARC policy exist —
   confirming this domain is a legitimate victim of spoofing, not the attacker's infrastructure.

   *Learned:* don't stop at the message's own SPF verdict — go check the impersonated domain's actual
   published SPF/DMARC records. That's what turns "the header says softfail" into "the sending IP is
   provably outside the domain's own authorized range."

7. **OSINT round 4 — phishing history.** VirusTotal on `yobow.cn`: 0/92, currently serving an unrelated Chinese
   business site.

   *Learned (incompletely — corrected later, see below):* I read this as "no phishing history," without
   noticing I was checking today's reputation to answer a question about 2023.

8. **Answered the lab's 16 guided questions + bonus**, then went into audit with Claude — see below for what
   changed.

## What I Got Wrong (and Fixed) During the Audit

I initially wrote "confirmed China-based sending infrastructure" for `yobow.cn` — treating a hostname
(`mail.yobow.cn`, self-declared in a `Received` header) as equivalent to a verified fact. Pushed to check it, I
reopened the full `.eml` and pulled the *complete* `Received` chain, not just the last hop I'd captured. The
chain shows Microsoft's own gateway (`DM6NAM04FT068.mail.protection.outlook.com`) recording the connection from
`mail.yobow.cn (183.56.179.169)` — a real, reliable pairing since it's logged by the *recipient's*
infrastructure, not self-declared by the sender. But a PTR lookup on `183.56.179.169` returned nothing, and
`yobow.cn`'s own A/MX records point to entirely different infrastructure (Tencent). Corrected conclusion:
`183.56.179.169` is the verified artifact; `mail.yobow.cn` is a hostname claim with no DNS corroboration behind
it. **Lesson: always pull the full `Received` chain before attributing infrastructure, not just the header you
happened to capture first.**

I answered the bonus VPN question "yes," citing the same AbuseIPDB "Fixed Line ISP" field I'd used a day earlier
to argue "probably not a VPN." Caught the contradiction, restored the original (correct) reasoning: "Fixed Line
ISP" argues against a commercial VPN, not for one. **Lesson: re-read what I already concluded before writing a
final answer — don't let the write-up drift from the actual analysis.**

I kept `yobow.cn` as the answer to "root domain of the mail server," which is fine, but added an explicit
caveat that the link is unverified by DNS rather than stating it flatly. **Lesson: it's fine to keep an
uncertain data point if it's what the evidence literally shows — just say plainly that it's uncertain.**

I answered "has this domain been involved in phishing before" using VirusTotal checked *today*, on a domain
that's clearly been repurposed since 2023. That doesn't answer a question about 2023. The historically
relevant data was already in front of me: AbuseIPDB's reports on `183.56.179.169` are dated Nov–Dec 2023 —
contemporary with the email. **Lesson: match the artifact and the time window to the actual question being
asked — a clean reputation check today says nothing about three years ago, and website content and mail
infrastructure are different layers of the same domain.**

## My Investigation Framework (v1)

Four phases I used here and want to keep using on future hunts:

1. **First reflex** — get `Date`/`Message-ID` to anchor a timeline, check SPF/DKIM/DMARC, determine the true
   sender by comparing `From`/`Reply-To`/`Return-Path`.
2. **Content** — attachment present? (changes priority toward scope/impact). Read subject/body for social
   engineering markers and embedded links. Identify every recipient/contact address.
3. **Impact/scope** — did the recipient reply, click, or download? Who else received it, who else
   interacted, is this the first occurrence of this sender? Branch into graduated response:
   - First occurrence → block sender, quarantine associated emails.
   - User replied (no click/credentials) → user awareness/context, block sender.
   - User clicked a link or shared credentials → full incident: lockout, password reset, session
     invalidation.
4. **Reputation** — does the claimed sending domain have real MX records? Reputation and creation date of the
   domain found in `From`/`Return-Path`/`Reply-To`. Reputation of the mail server closest to the sender
   *chronologically* — i.e. the earliest hop in the `Received` chain, not the first one read top-down.

Still to add: a branch for "attachment opened/executed" (not applicable here — no attachment on this case).

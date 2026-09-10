# Investigation Notes & Methodology

Personal notes on how I actually worked through this hunt — the real chronology, the mistakes I made and
corrected along the way, and the methodology I'm building for future email investigations. The polished
findings live in [`README.md`](README.md); this file is the process behind it.

## Investigation Timeline

1. **Integrity check.** Downloaded `Second_Email.zip`, verified its SHA256 with `Get-FileHash` in PowerShell
   against the two reference hashes supplied with the archive. Extracted `Second_Email.eml`, verified its hash
   the same way.

   *Learned:* start every investigation by establishing chain-of-custody before reading a single byte of
   content — same reflex as the previous hunt, confirmed worth keeping.

2. **First pass on the headers (Notepad++).** Pulled `Message-ID`, `Date`, and the `ARC-Authentication-Results`
   closest to `i=1` — SPF/DKIM/DMARC all `pass` on `comunidadeduar.com.ar`. Compared `From`, `Reply-To` (absent),
   and `Return-Path` — all consistent with the declared domain. Concluded the mail was "technically legitimate"
   and moved to content analysis.

   *Learned (incompletely — corrected later, see below):* first real exposure to ARC (Authenticated Received
   Chain) — didn't know the concept going in. Scoped my attention to `i=1` alone, reasoning that would be
   "closest to the sender," and read the domain/IP found at that hop as the sender's own infrastructure.

3. **Content-Type / MIME analysis.** Found a `multipart/mixed` structure with two parts: a primary `text/html`
   body and a second part declared `text/html` but named and dispositioned as `Detailsdisable-262340.pdf`.
   Decoded the base64 payload — HTML, not a PDF (no `%PDF-` signature) — confirming the attachment was fake, and
   reproducing the same Amazon phishing content as the primary body, with unresolved template placeholders in
   both parts.

   *Learned:* a `Content-Type` that doesn't match the file extension in `name=`/`filename=` is a strong
   deception signal, confirmed rather than assumed by actually decoding the payload.

4. **Subject, body, and embedded URL.** Subject and body built entirely on authority/urgency bias ("account
   locked," "24 hours," "any locked account will be deleted"). The embedded link pointed to a Google Apps
   Script endpoint (`script.google.com/macros/s/.../exec`) rather than any Amazon domain — scanned via urlscan.io
   and Cloudflare Radar (nothing conclusive), then VirusTotal (1/91 vendors, "Criminal IP" → Phishing).
   Hypothesized the link served a credential/banking-details form — not confirmed, the endpoint returned 404 at
   scan time.

   *Learned:* a domain mismatch between the claimed brand (Amazon) and the actual link destination is worth
   flagging even before any reputation lookup — the inconsistency itself is the signal.

5. **Reputation round.** WHOIS/DNS on `comunidadeduar.com.ar` (registered 2013, Argentina), blacklist checks on
   both the domain's A record and the sender IP `40.107.215.98` (both listed on 3 lists), AbuseIPDB on both IPs.
   Noted the ISP on `40.107.215.98` as "Microsoft Corporation" without yet drawing the conclusion that this
   meant shared infrastructure rather than a dedicated attacker asset.

   *Learned (incompletely — corrected later, see below):* ran this as a single end-of-investigation block
   rather than triggering each lookup as the artifact emerged earlier in the analysis.

6. **Self-review before the formal audit.** Before handing this off, went back over the whole investigation and
   flagged, on my own, several issues later confirmed in the audit: likely mixed up internal vs. external
   infrastructure at step 2, never checked the `sender-ip` field directly, and reputation analysis probably
   shouldn't be its own late-stage block. Concluded the mail as phishing, to be deleted, with generic
   organizational next steps (SIEM search by subject, password reset/session revocation for anyone who clicked).

   *Learned:* catching my own errors before the audit is worth doing deliberately, not just leaving correction
   entirely to the external review — most of what surfaced here was confirmed as real issues, not false alarms.

## What I Got Wrong (and Fixed) During the Audit

I wrote "technically legitimate" after step 2 based on SPF/DKIM/DMARC alone. Pushed on what that phrase actually
meant, I could defend the *intent* — I'd already moved straight to content analysis, treating it as a checkpoint
rather than a verdict — but the distinction lived only in my head, not on paper. **Fixed:** write the checkpoint
explicitly every time: "authentication technically valid for the declared domain, does not establish sender
legitimacy" — keeping the technical (authentication) and logical (context/content) legitimacy layers visibly
separate, not just mentally separate.

I'd scoped my attention to ARC hop `i=1` as "closest to the sender," then later found the actual `sender-ip`
value sitting in the `i=2` block — which looked contradictory until I reconstructed the *entire* `Received`
chain, hop by hop, instead of trusting a single header. Several apparent "external" hops
(`TYZPR02MB6656.apcprd02.prod.outlook.com` talking to itself over `fe80::` link-local IPv6, then to
`TYZPR02MB6854` over an internal `2603:1096:...` datacenter range) turned out to be entirely internal to
Microsoft's own mailbox transport. The real external boundary was several hops further down:
`APC01-SG2-obe.outbound.protection.outlook.com (40.107.215.98)`. The hostname alone gave it away — Microsoft's
own shared Exchange Online Protection *outbound* relay pool, used by every M365 tenant, not infrastructure
dedicated to this sender. **Fixed:** there is no dedicated "sender IP" to chase when mail is sent via M365 — the
domain/tenant is the only attribution anchor that means anything.

That reframing pushed me to look harder at `comunidadeduar.com.ar` itself instead of the IP. A Google search
turned up "Comunidad Educativa.ar," an active-looking school-management platform tied to a real Argentine school
(Escuela Nacional Ernesto Sabato / UNICEN) — but I hadn't tested the competing explanation before landing on
"compromised legitimate infrastructure." Forced to name it explicitly: either a real, hijacked educational
tenant (H1), or a domain purpose-registered from the start with an educational-sounding name as a cover (H2).
Claude independently checked the Wayback Machine and found a snapshot from 2025-03-19 returning HTTP 200,
corroborating H1 as the better-supported hypothesis — but not a certainty, so it stays phrased as a probability
in the write-up, not a fact.

I didn't understand why "noreply@Quick Response" as a `From` display name was deceptive until it was explained:
most mail clients show only the display name, never the real address underneath, unless you go looking for it —
so the fake "noreply@"-shaped name does the actual work of making the sender look automated and legitimate,
while the real address (`nuthostsrl.SaintU74045Walker@comunidadeduar.com.ar`) stays hidden. I'd only ever looked
at this in raw Notepad++ text, never at how it would actually render for a real recipient. **Fixed:** pair raw
`.eml` inspection with a rendered view (a real mail client, or a safe preview) whenever a finding depends on
how something displays, not just what the header literally says.

## My Investigation Framework (v2)

Updated from the version I used on the previous hunt — same four phases, with this hunt's corrections folded in
directly rather than left as a separate list.

1. **First reflex** — get `Date`/`Message-ID` to anchor a timeline. Locate the `sender-ip` field *before*
   picking any `Received`/ARC hop as "closest to the sender." Then reconstruct the *complete* `Received` chain,
   top to bottom, checking on each hop: is the address link-local/internal-datacenter/public, and does the
   hostname on both sides of `from`/`by` stay inside the same provider (internal hop) or cross into something
   else (the real boundary)? Only then read SPF/DKIM/DMARC — and log the result as an authentication checkpoint
   ("technically valid for the declared domain"), not a legitimacy verdict.
2. **Content** — attachment present? Check the *declared* `Content-Type` against the file extension in
   `name=`/`filename=`; if they disagree, decode and confirm rather than assume. Read subject/body for social
   engineering markers and embedded links; flag any mismatch between the claimed brand and the actual link
   destination immediately, before any reputation lookup. Identify every recipient/contact address.
3. **Reputation — continuous, not a phase.** Fire a lookup (ISP/ASN/blacklist/WHOIS) the moment a new IP,
   domain, or hash surfaces during steps 1–2, on the spot. Before treating any IP as attacker infrastructure,
   check whether its hostname/ASN identifies it as a shared cloud/SaaS provider pool (Microsoft, Google, AWS,
   etc.) — if so, reports against that IP are diluted noise, not a signal about this specific sender; the
   domain/tenant becomes the only attribution anchor worth pursuing.
4. **Impact/scope** — did the recipient reply, click, or download? Who else received it, who else interacted,
   is this the first occurrence of this sender? When the sending domain's status is ambiguous (real
   organization vs. a domain built purely as a cover identity), name both hypotheses explicitly and gather
   evidence to discriminate before picking one. Branch into graduated response:
   - First occurrence → block sender, quarantine associated emails.
   - User replied (no click/credentials) → user awareness/context, block sender.
   - User clicked a link or shared credentials → full incident: lockout, password reset, session
     invalidation.

Still to add: a branch for reconciling conflicting-looking authentication data across multiple ARC hops when a
message crosses more than one organization's ARC-sealing infrastructure (only saw a single-organization,
two-hop case here — `d=microsoft.com` on both `i=1` and `i=2`).

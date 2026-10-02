# Scenario of the Week 10 — Stolen Laptop (VP Customer Success)

**Published:** 2026-10-02

## 🎬 Scenario

```
You receive an email from a client saying "A VP in Customer Success had their work laptop stolen while
they were on vacation. Not sure what we should be doing here. Please advise."
```

## 🧭 Guided Questions

- What's your gut telling you and how would you confirm it?
- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
I start by organizing the alert information using the context / anomaly / priority triptych:

- **Context** — a high-profile user (a VP in Customer Success) had their work laptop stolen outside the
  organization's premises, while on vacation, and no action has been taken since.
- **Anomaly** — laptop stolen on vacation.
- **Priority** — the circumstances of the theft, the laptop, and the VP in Customer Success profile.

Once the triptych is set, I set aside the false/true positive reflection and directly define the alert's
volatility axis and propose a response plan, because in my view the event is a confirmed security incident, so no
condition is needed to trigger the response. In my view, the volatile elements of the alert are the laptop's
state (active/inactive) together with its associated identity, and the data stored on the laptop. For the
incident response, I follow this sequence:

1. Securing the identity
2. Securing the endpoint
3. Impact analysis and governance
4. Lessons learned and improvement

**What questions would you ask?**
Where? When? How did the theft happen? Were other items stolen? What was the laptop's status when it disappeared
(locked, unlocked, sleeping)? Is the device managed through an MDM (mobile device management) or an EDR? Is the
device online? Is there any credential-type information directly available to the threat (post-it, sticky note)?
Is MFA in place for this profile? Which devices are registered for MFA? Are the devices involved still under
control? Is the disk encrypted with BitLocker? Is BitLocker in TPM-only mode or TPM + PIN? Is a BIOS/UEFI password
enabled? Have there been any suspicious authentications since the theft? What are the VP's access and
privileges? Does the laptop have VPN access or installed certificates? Does the VP use a password manager, and is
its vault synchronized on the device? Is any sensitive customer or employee information (GDPR) stored locally on
the laptop?

**What would you investigate and in what order?**
For this alert I am not trying to investigate, but to respond directly to the incident, with the goal of limiting
the scope and impact of the threat on the organization. Using the volatility axis defined during qualification,
my first reflex is to contact the user to get as much context as possible about the theft, in parallel with
checking the device's status (online/offline) in the EDR (search by hostname/user, `last seen` + IP fields) or via
the Entra ID sign-in logs (interactive/non-interactive user sign-ins), and to secure the identity side: revoking
sessions/tokens via Entra with `Revoke-MgUserSignInSession`, locking the profile/changing the password, marking
the device as non-compliant in Entra via `Update-MgDevice -DeviceId <objectId> -AccountEnabled:$false` so that
Conditional Access blocks it, and finally checking disk encryption and whether the recovery key is properly
escrowed. If the device is online, I isolate the host, set up an alert on reconnection through the EDR to capture
the exact time, IP address, approximate geolocation and telemetry, and export the EDR timeline to keep a trace of
what happened on the host before and after the theft. Once isolation is done, I lock the laptop via the MDM and
launch a wipe (or not) after collegial validation by the organization. If the device is offline, I issue the EDR
isolation commands to queue them for execution at reconnection, as with the MDM actions. Finally, I mark the
device as lost/stolen in the MDM (geolocation, lock) and block its certificate in the NAC. I then move on to
impact analysis and governance, analyzing activity within the organization using the time of the theft and pivot
data such as the Device ID, User-Agent and session ID gathered during the first reflex. I check VPN connections
and logs (established sessions, internal resources reached, transferred volume), mailbox connections with
creation of forwarding or deletion rules, sent mails, mailbox accessed, downloaded attachments, and the Entra
audit logs (new MFA method, OAuth consent, password change as persistence), and I widen beyond Microsoft to CRM
and SaaS logs (report exports, customer lists, access to sensitive accounts). I then hold a meeting with legal and
top management to present the impact of the theft and measure the potential exposure, which depends on what is
stored on the device, what the account could reach, and the sensitivity of the data.

For the post-incident phase, I make sure of:

- Confirmation of eradication: sessions and tokens revoked, MFA re-enrolled, certificates revoked, secrets stored
  on the device (API keys, SSH) regenerated, BitLocker key rotated if it may have been exposed.
- Fate of the device: wipe, or retention for the police. Declare the device stolen in the MDM and remove it from
  the inventory.
- Reinforced monitoring: keep a watchlist (hostname, MAC, certificate, account) for a few weeks to detect a late
  reconnection.
- Documentation: timeline, exported evidence (EDR, Entra, Purview), decisions taken and their justification,
  final qualification.
- Legal: police report, DPO opinion, notification of the government authority and customers if personal data was
  compromised, entry in the breach register.
- Lessons learned: a blameless meeting covering what worked, what was missing, with actions and owners.

For recommendations, depending on the client's maturity:

- **Endpoint**
  1. BitLocker TPM + PIN on all mobile devices, with escrow verified through a compliance report.
  2. BIOS/UEFI password, USB boot disabled, Secure Boot and DMA protection enabled, all managed through MDM.
  3. 100% of the fleet enrolled in MDM and EDR: an unmanaged device is a blind spot.
  4. Lost/stolen mode documented and tested in the MDM.
- **Identity**
  1. Conditional Access: compliant and managed device required for sensitive applications.
  2. Short session lifetimes for at-risk profiles (executives on the move) and Token Protection where available.
  3. Phishing-resistant MFA (FIDO2, Windows Hello) for privileged profiles.
  4. Least privilege: review the rights of the VP and similar profiles.
- **Detection**
  1. Create a "stolen device" use case: a watchlist fed by the ticket, with a high-priority alert on any event
     (EDR, authentication, VPN, DHCP, NAC) tied to the device.
  2. Retention: if logs were missing, extend retention and ingest the missing sources (VPN, NAC, SaaS, Purview
     audit).
  3. Automate with a SOAR: session revocation and EDR isolation triggered in one click from the ticket, instead
     of ten manual actions.
- **Data**
  1. Limit local data: folder redirection to OneDrive, ban CRM exports on the device, DLP.
  2. Data classification, to know within minutes whether the device held anything sensitive.
- **Process and people**
  1. A clear theft/loss procedure, with a reporting channel reachable 24/7. The delay between the theft and the
     report conditions everything else.
  2. Awareness for traveling executives: never leave the device unattended, no post-its, report immediately.
  3. A tabletop exercise on this scenario once or twice a year.

**Who would you communicate with and when?**
I start by communicating with my SOC manager to report that a VP's laptop was stolen and that I am taking
ownership. I then communicate with the VP Customer Success to gather as much information as possible about the
theft and to define the priority in the action plan and the scope (possible multi-device or credential leak). In
parallel, I contact the helpdesk to initiate the identity and endpoint response. Finally, I involve legal and
governance for impact analysis, countermeasures, and post-incident/continuous improvement activities.

## 🧠 Expert Review

The most consequential gap is in the qualification step. The First Response states that the event is "a confirmed
security incident, so no condition is needed to trigger the response." What is confirmed is the theft of an
asset, and only on the client's word; compromise of the identity or the data is not confirmed. Yet the plan's own
question list is made of conditions: disk encryption, TPM-only versus TPM + PIN, MFA status, lock state at the
time of theft, suspicious authentications since. The two positions pull against each other, and the plan never
says which answer moves the response from one level to the next. What observable, in the answers to those
questions, turns "a stolen asset" into "a compromised identity"?

Second, the order of the identity block. Session and token revocation, password change and device disabling are
listed first; the export of the EDR timeline and the sign-in logs comes afterwards, partly inside the
online-device branch. Sign-in log retention is finite, and revocation changes what the account looks like in
those logs from that point on. Evidence that documents what the attacker did before containment should be
secured before, or at the same time as, the containment actions.

Third, the plan lists around fifteen actions, but only one is explicitly marked as needing a decision from
someone else: the wipe, "after collegial validation by the organization." Nothing separates the actions the SOC
can take as an immediate reflex (revoking sessions, disabling the device, isolating it) from the ones that need
the client's approval (wipe, police report, GDPR notification). In a client-facing engagement, that line is what
the reader actually needs in order to act on the plan, and it also makes explicit who is authorized to decide
what.

Finally, on a smaller point: `Update-MgDevice -DeviceId <objectId> -AccountEnabled:$false` is described as
"marking the device as non-compliant." It does something different: it disables the device object in Entra.
Compliance is evaluated by Intune from policies and cannot be forced to "non-compliant" with a single command.
The command itself is a valid lever, but the description attached to it does not match what it does.

What holds up well: the volatility axis is identified correctly (device state and identity, then data), and the
four-phase sequence follows from it. The initial question list is specific and targeted, notably TPM-only versus
TPM + PIN, whether the password manager vault is synchronized on the device, and VPN access and installed
certificates. The online/offline split is handled properly, including the fact that EDR and MDM actions queue and
only execute at the next reconnection. The wipe is left as a collegial decision rather than a reflex, which is
the right call for an irreversible action, and the post-incident and recommendation sections are complete and
tied to the maturity of the client.

## 🪞 Reflection

1. A theft confirms the loss of an asset, not a compromise. The qualification should name the observable that
   makes the incident evolve into a compromise: a successful authentication from the stolen device's context,
   with or without MFA. The response level follows that observable, not the theft alone.
2. Secure the evidence before, or together with, the containment actions: export the EDR timeline and sign-in
   logs first, because retention is finite and revocation changes what the logs show afterwards.
3. State explicitly which actions are reflexes that need no approval (revoke sessions/tokens, disable the
   device, isolate) and which are decisions that need validation (wipe, police report, notification). A plan
   that does not draw that line stays a statement of intent rather than something someone can execute.
4. Do not write a command into a plan without checking what it does. Copying commands or field names from an AI
   assistant works, but it is not understanding: the `AccountEnabled:$false` example shows a valid command
   attached to the wrong description.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
Same triptych as above. The qualification is sharpened: the event is a security incident that becomes a
compromise as soon as an authentication succeeds, with or without MFA, instead of being treated as a confirmed
compromise by default. The volatility axis and the four-phase sequence are unchanged.

**What questions would you ask?** Unchanged.

**What would you investigate and in what order?**
For this alert I am not trying to investigate, but to respond directly to the incident, with the goal of limiting
the scope and impact of the threat on the organization. Using the volatility axis defined during qualification,
my first reflex (after notifying my manager that I am taking ownership of the alert) is to contact the user to
get as much context as possible about the theft, in parallel with checking the device's status (online/offline)
in the EDR (search by hostname/user, `last seen` + IP fields) or by securing the Entra ID sign-in logs
(interactive/non-interactive user sign-ins), and to secure the identity side: exporting the EDR timeline, then
revoking sessions/tokens via Entra with `Revoke-MgUserSignInSession`, locking the profile/changing the password,
disabling the device in Entra via `Update-MgDevice -DeviceId <objectId> -AccountEnabled:$false` so that
Conditional Access blocks it, and finally checking disk encryption and whether the recovery key is properly
escrowed. If the device is online, I isolate the host, set up an alert on reconnection through the EDR to capture
the exact time, IP address, approximate geolocation and telemetry, and export the EDR timeline to keep a trace of
what happened on the host before and after the theft. Once isolation is done, I lock the laptop via the MDM and
launch a wipe (or not) after collegial validation by the organization. If the device is offline, I issue the EDR
isolation commands to queue them for execution at reconnection, as with the MDM actions. Finally, I mark the
device as lost/stolen in the MDM (geolocation, lock) and block its certificate in the NAC. I then move on to
impact analysis and governance, analyzing activity within the organization using the time of the theft and pivot
data such as the Device ID, User-Agent and session ID gathered during the first reflex. I check VPN connections
and logs (established sessions, internal resources reached, transferred volume), mailbox connections with
creation of forwarding or deletion rules, sent mails, mailbox accessed, downloaded attachments, and the Entra
audit logs (new MFA method, OAuth consent, password change as persistence), and I widen beyond Microsoft to CRM
and SaaS logs (report exports, customer lists, access to sensitive accounts). I then hold a meeting with legal and
top management to present the impact of the theft and measure the potential exposure, which depends on what is
stored on the device, what the account could reach, and the sensitivity of the data.

The post-incident phase and the recommendations by client maturity are unchanged.

**Who would you communicate with and when?**
One change: I notify my SOC manager before taking ownership of the alert, and the rest of the sequence (VP,
helpdesk, then legal and governance) is unchanged.

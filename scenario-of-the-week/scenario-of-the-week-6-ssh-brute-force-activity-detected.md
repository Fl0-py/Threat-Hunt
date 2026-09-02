# Scenario of the Week 6 — SSH Brute Force Activity Detected

## 🎬 Scenario

```
Alert: MYDFIR-ALRT-0004
Alert Name: Identity – SSH Brute Force Activity Detected
User: administrator
Source IP: 213.171.21.75
Target Host: LNX-WEB01
Time Detected: 2025-09-07 02:11 UTC
Failed Attempts: 500+ ~10 minutes
```

Within a 10-minute period, more than 500 failed SSH login attempts were recorded against the `administrator`
account from a single external IP address.

## 🧭 Guided Questions

- What's your gut telling you and how would you confirm it?
- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
My first reflex on receiving this alert is to get familiar with the available data. Not knowing exactly what the
SSH protocol involves, I dig into it. SSH (Secure Shell) is fundamental in IT because it's the standard for
secure remote administration, replacing obsolete protocols like Telnet that transmitted data in clear text. It
allows executing commands, managing files, and configuring networks without being physically present at the
machine. It encrypts all communication between a client and a server, guaranteeing confidentiality, integrity,
and authentication of sessions. SSH is a prime target for brute-force attacks, where malicious actors use
automated tools to guess credentials in order to take control of servers.

With that context, I organize the information from the alert using the context / anomaly / priority triptych:

- **Context** — on 2025-09-07 at 02:11 UTC, IP `213.171.21.75` made 500+ failed login attempts in ~10 minutes
  against the `administrator` account on `LNX-WEB01` (Linux).
- **Anomaly** — 500+ failed attempts in ~10 minutes on the `administrator` account.
- **Priority** — the `administrator` account, `213.171.21.75`, and `LNX-WEB01`.

Before starting the investigation, I set contradictory hypotheses that could either prove a false alarm or
confirm a real threat:

1. ATT&CK T1110 — Brute Force: adversaries may use brute-force techniques to gain access to accounts when
   passwords are unknown.
2. An automated script/scheduled task using stale credentials, an expired/out-of-sync SSH key, or another
   network misconfiguration.

To confirm this, as a quick win I'd check whether the source IP is known/"legitimate" for the organization and
whether there's been a recent password change on the `administrator` account, in parallel with reviewing the
account's activity within the alert's time window. I set a graduated incident response based on the analysis
results:

- False positive confirmed → close the ticket.
- Successful login within the alert's time window → lock the account, revoke sessions/tokens, reset the
  password, and a targeted network block on `LNX-WEB01`, for a deeper investigation into initial access and
  post-exploitation activity.
- Lateral movement, persistence, or exfiltration demonstrated → full isolation of the source and associated
  targets, and incident response triggered.

Finally, I look at the alert's volatility axis to help prioritize actions. For me, volatility mainly revolves
around the `administrator` account's status (compromised or not) and, consequently, the data tied to
`LNX-WEB01` based on its availability.

**What questions would you ask?**
Did a valid login occur within the incident's time window? What was the MFA result on a successful login, and
how was it completed or bypassed? Is the source IP `213.171.21.75` known within the organization? Is there an
active SSH connection from that source IP? What is the IP's reputation and geolocation? Is there an outbound
connection from `LNX-WEB01` to an external IP? What process did SSH spawn on `LNX-WEB01`? Was a file downloaded?
Were persistence mechanisms deployed? Was lateral movement observed? Was there a recent password or SSH key
change? Is there an automated script/scheduled task running with stale credentials?

**What would you investigate and in what order?**
My first reflex is to check the authentication logs (`/var/log/auth.log`) for an accepted connection, a
validated MFA, and an open session. If that's the case, I check whether the connection is still active before
moving to log collection following RFC 3227 (active network connections first, then registers, CPU cache, RAM,
network/process state, temporary filesystems, disk, remote/monitoring logs, physical configuration and network
topology, and archival media, based on availability).

In parallel with this volatility-axis action, I initiate contact with IT and search available databases
(tickets, emails, past tickets, knowledge base…) for traces of a legitimate action. I check whether the IP is
known, whether a password-change/network-configuration operation was initiated, or whether another alert exists
for the same IP tied to a legitimate explanation. I check the IP's reputation and determine its geolocation for
more context.

If a legitimate action is confirmed, I close the ticket; otherwise, I request account lockout, session/token
revocation, password reset, and a targeted network block on `LNX-WEB01` before moving to a deeper analysis. I
observe active connections using `netstat`, supplemented by firewall logs (if available) for history. I then
look at what process SSH spawned, building the process tree (`pstree`) to look for a child process that
shouldn't be there (a `curl`, `wget`, `nc`, an unknown script, a binary in `/tmp`). I follow up on persistence
mechanisms (user and system cron jobs via `crontab`, SSH keys added to `/home/admin/.ssh/authorized_keys` or
`/root/.ssh/authorized_keys`, users created or modified in `/etc/passwd`, suspicious systemd services in
`/etc/systemd/system/`, and files modified recently within the alert's time window). Finally, I finish by
checking for potential lateral movement, scoping the source IP's use elsewhere in the environment, or privilege
escalation. If any of the above is demonstrated, I request full isolation of the source and associated targets,
and escalate the incident to IR management.

**Who would you communicate with and when?**
I start by notifying my team that I'm taking ownership of the ticket, and checking for any correlated alerts.
At minute 0, I secure the investigation's volatility axis by saving and checking the authentication logs. I
contact IT in parallel with questions about SSH and a possible change/misconfiguration. If the login is
confirmed with no legitimate reason, with the help of the helpdesk and the identity team, I block the IP, lock
the account, revoke sessions/tokens, reset the password, and do a targeted network block on `LNX-WEB01` for a
deeper investigation. If data forwarding, persistence, or other activity is confirmed, I trigger a full
incident response plan with escalation to management and, if sensitive data was accessed or exfiltrated, to
legal.

## 🧠 Expert Review

The most consequential gap is that confirming a successful login is stated as an intention — "check
`/var/log/auth.log` for an accepted connection, a validated MFA, and an open session" — without naming an actual
field or command to do it with. That specificity only surfaced once pushed on directly, and even then needed a
second pass: the first version, `grep "Accepted" /var/log/auth.log`, matches any successful login in the file,
including a legitimate admin session with nothing to do with this brute-force campaign. Scoping it to
`grep "Accepted" /var/log/auth.log | grep "213.171.21.75"` is what actually ties the result to the source under
investigation rather than to "some successful login exists in this file."

Second, IP reputation and geolocation are named as an action to take — "I check the IP's reputation and
determine its geolocation for more context" — but the plan never follows through on it or ties the result back
to the two competing hypotheses. A live lookup on `213.171.21.75` returns AS56694, "LLC Smart Ape," Moscow,
Russia — a small AS tied to a leased/hosting-style entity rather than a residential ISP. That distinction
matters: dedicated or rented infrastructure is a materially different signal from a consumer connection when
weighing an external attacker against an internal misconfiguration. Critically, that data point alone doesn't
close hypothesis 2 (stale credentials/misconfigured script) — an ASN with no obvious tie to the organization
only becomes a closed hypothesis once it's paired with independent confirmation from IT or the internal baseline
that no legitimate relationship (vendor, contractor) exists with that infrastructure.

Third, the plan stops at containment and doesn't extend into post-incident remediation — once the incident is
closed, nothing addresses what let the attempt volume reach the alert threshold in the first place: a
privileged, password-authenticable account reachable from the entire internet.

What holds up well: the volatility axis (`auth.log` → active-connection check → RFC 3227 collection) and the
legitimacy axis (IT contact, tickets, knowledge base) are run in parallel from the very first draft, with
containment gated behind both — never sequenced, and evidence acquisition never subordinated to a remediation
action. Two competing hypotheses (external brute force vs. internal misconfiguration) are stated upfront without
premature attribution, and the graduated containment thresholds are concrete and criteria-based (a successful
login inside the alert window, then demonstrated lateral movement/persistence/exfiltration) rather than a vague
"if confirmed as a threat." The forensic detail throughout — exact log paths, `pstree` for child-process
anomalies, exact `authorized_keys` paths — stays concrete rather than generic.

## 🪞 Reflection

1. IP reputation, geolocation, and ASN ownership type have to actually be looked up and correlated during the
   investigation, not just named as a planned action — the type of infrastructure behind a source IP (dedicated
   or leased hosting vs. a residential ISP) materially shifts the relative likelihood between an external threat
   actor and an internal misconfiguration.
2. A single piece of corroborating evidence doesn't close a competing hypothesis by itself. ASN/infrastructure
   type supports ruling out an internal misconfiguration, but the hypothesis only closes once that's paired with
   the independent confirmation it was gathered to support — here, IT or the internal baseline confirming no
   legitimate tie to that infrastructure.
3. Whenever a detection or confirmation method is stated, name the actual field or command, scoped to the source
   and time window under investigation, rather than the source/goal alone — `grep "Accepted"` only becomes
   meaningful once it's filtered to the IP and window actually being investigated.
4. Post-incident remediation should become a default closing move on every incident response plan, not an
   afterthought added only when asked — and it should target the underlying condition an alert measured (here: a
   privileged, password-authenticable account reachable from the entire internet), not just the volume the alert
   flagged.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?** Unchanged.

**What questions would you ask?** Unchanged.

**What would you investigate and in what order?**
Same first reflex: check `/var/log/auth.log` for an accepted connection, a validated MFA, and an open session,
scoped to the source under investigation with `grep "Accepted" /var/log/auth.log | grep "213.171.21.75"`; if
found, check whether the connection is still active before moving to RFC 3227 log collection (active network
connections first, then registers, CPU cache, RAM, network/process state, temporary filesystems, disk,
remote/monitoring logs, physical configuration and network topology, and archival media, based on availability).

In parallel with this volatility-axis action, I initiate contact with IT and search available databases
(tickets, emails, past tickets, knowledge base…) for traces of a legitimate action, check whether the IP is
known, whether a password-change/network-configuration operation was initiated, or whether another alert exists
for the same IP tied to a legitimate explanation. I check the IP's reputation and geolocation, and pull its ASN:
`AS56694`, "LLC Smart Ape," Moscow, Russia. An "LLC" entity name tied to a small AS for an address generating
500+ SSH attempts in 10 minutes points to potentially leased infrastructure — this condition still has to be
verified with IT/the internal baseline before it can close hypothesis 2.

If a legitimate action is confirmed, I close the ticket; otherwise, I request account lockout, session/token
revocation, password reset, and a targeted network block on `LNX-WEB01` before moving to a deeper analysis. I
observe active connections using `netstat`, supplemented by firewall logs (if available) for history. I then
look at what process SSH spawned, building the process tree (`pstree`) to look for a child process that
shouldn't be there (a `curl`, `wget`, `nc`, an unknown script, a binary in `/tmp`). I follow up on persistence
mechanisms — user and system cron jobs via `crontab`, SSH keys added to `/home/admin/.ssh/authorized_keys` or
`/root/.ssh/authorized_keys`, users created or modified in `/etc/passwd`, suspicious systemd services in
`/etc/systemd/system/`, and files modified recently within the alert's time window. Finally, I check for potential
lateral movement, scoping the source IP's use elsewhere in the environment, or privilege escalation. If any of
the above is demonstrated, I request full isolation of the source and associated targets, and escalate the
incident to IR management.

**Who would you communicate with and when?**
I start by notifying my team that I'm taking ownership of the ticket, and checking for any correlated alerts.
At minute 0, I secure the investigation's volatility axis by saving and checking the authentication logs. I
contact IT in parallel with questions about SSH and a possible change/misconfiguration. If the login is
confirmed with no legitimate reason, with the help of the helpdesk and the identity team, I block the IP, lock
the account, revoke sessions/tokens, reset the password, and do a targeted network block on `LNX-WEB01` for a
deeper investigation. If data forwarding, persistence, or other activity is confirmed, I trigger a full
incident response plan with escalation to management and, if sensitive data was accessed or exfiltrated, to
legal.

Once the incident is handled and the post-incident phase starts, I would recommend:

- Changing only the SSH authentication method — password vs. an SSH key pair (a private key held only by the
  legitimate user, a public key deposited on the server) — not the encryption of the connection itself.
- Moving away from generic, well-known account names like `administrator` in favor of dedicated, named accounts.
- Putting a bastion host/VPN in place so the server isn't directly exposed on SSH to every IP on the internet.
- Adding network segmentation: only ports `80`/`443` open for HTTP/HTTPS, with SSH reachable only through
  VPN/bastion.
- Putting an IP management/blocking policy in place for excessive attempts in a short window (threshold to be
  defined).

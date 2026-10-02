# Scenario of the Week 8 — Endpoint File Downloaded via wget

**Published:** 2026-09-16

## 🎬 Scenario

```
Alert: MYDFIR-ALRT-0006
Alert Name: Endpoint – File Downloaded via wget
User: baskin.robbins@fakecompany.ca
Host: LNX-DEV01
URL: hxxps://s3.amazonaws[.]com/artifacts/tool.tar.gz
Time Detected: 2025-09-20 08:42 UTC
File Path: /tmp/tool.tar.gz
```

A file was downloaded to `LNX-DEV01` via `wget` under the `baskin.robbins` account. The file `tool.tar.gz` was
saved to `/tmp/`.

## 🧭 Guided Questions

- What's your gut telling you and how would you confirm it?
- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
Before sorting the information using the context / anomaly / priority triptych, I look into what "File Downloaded
via wget" actually involves. `wget` is fundamental in IT: a non-interactive, robust, scriptable command-line tool
for downloading files and mirroring sites over HTTP, HTTPS, and FTP. It's essential for administrators to back up
data, verify site integrity, and test service availability — but its non-interactive nature and popularity also
make it a tool attackers can abuse to download and execute malicious code remotely, without any user interaction.

- **Context** — the file `tool.tar.gz` was downloaded via `wget` to `/tmp/` by `baskin.robbins@fakecompany.ca` on
  `LNX-DEV01` at `2025-09-20 08:42 UTC`, from `https://s3.amazonaws[.]com/artifacts/tool.tar.gz`.
- **Anomaly** — the user `baskin.robbins@fakecompany.ca`, the use of `wget`, the file path `/tmp/tool.tar.gz`,
  and the URL itself.
- **Priority** — the URL, the file path `/tmp/tool.tar.gz`, and the user `baskin.robbins@fakecompany.ca`.

I then set hypotheses to determine the alert's final status — true or false positive:

1. ATT&CK T1105 — Ingress Tool Transfer: adversaries may transfer tools or other files from an external system
   into a compromised environment, copying them from an adversary-controlled system through the C2 channel or an
   alternate protocol such as `wget` on Linux.
2. `wget` usage as part of a legitimate admin action, a deployment, or an automation pipeline.

To confirm the status quickly, I check the IT backlog and contact the Adminsys or DevOps team to validate the
legitimacy of the download on this DEV machine. In parallel, I scan the URL and submit the file's hash to a
threat intel platform for a reputation check, while verifying the coherence between the file type and its
extension. Before starting the investigation, I set the following escalation levels:

1. False positive confirmed → close the ticket.
2. URL scan flags the link as malicious, `wget` usage not confirmed by IT, hash flagged as malicious, or a
   mismatch between file type and extension → lock the profile/change the password, revoke associated sessions,
   and a targeted network block on the source at the EDR/firewall level.
3. Lateral movement, persistence, or exfiltration demonstrated → full isolation of the source and associated
   targets, and incident response triggered.

Finally, I set the volatility axis to prioritize around the endpoint/network data on `LNX-DEV01`.

**What questions would you ask?**
What is the role of the user and the device? Is there a legitimate IT reason explaining the use of `wget`? What
is the reputation of the URL and the hash of the downloaded file? What is the file's actual type? What is the
network activity around `LNX-DEV01`? What is the parent-child process chain around `wget`? Was the archive
decompressed? Was a binary related to the `.tar` launched? Were persistence mechanisms deployed? Was privilege
escalation observed? Was lateral movement observed?

**What would you investigate and in what order?**
My first reflex is to secure the volatility axis of the investigation following RFC 3227 best practice on Linux,
with the overall goal of freezing the system's state and preserving evidence integrity before any analysis or
interpretation. After creating a dedicated evidence folder, I run the following actions:

1. Suspect file integrity: `sha256sum /tmp/tool.tar.gz > hash_original.txt`, to freeze the file's cryptographic
   fingerprint.
2. Volatile state capture: `ps auxf > ps_auxf.txt` for the full process state; `ss -tulpn > ss_state.txt` for
   socket state; `cat /proc/net/arp > arp_cache.txt` for the kernel's ARP cache before it expires; `lsof >
   lsof_full.txt` for a raw, complete capture of every file open by every process.
3. Physical memory: `insmod lime.ko "path=/mnt/evidence/mem.lime format=lime"` for a full raw dump of physical
   RAM before any reboot or action that could erase it.
4. Temporary directories: `ls -laR /tmp /dev/shm > tmp_shm_listing.txt` for a raw, complete inventory of these
   directories.
5. Disk metadata of the file and its location: `stat /tmp/tool.tar.gz > stat_archive.txt`, to freeze timestamps
   (atime/mtime/ctime) and permissions before a later action modifies the atime.
6. System logs: `journalctl --since "2h ago" > journal_export_2h.txt` to export the relevant log window in full,
   and `ausearch -ts recent > audit_export.txt 2>&1` to export all recent audit events.

Once the volatility axis is secured, I move to establishing the organizational context by determining the role of
the user and their device. I try to find out whether the use of `wget` is consistent with the machine/user, and
whether maintenance activity was planned on this machine, by checking the backlog and other communication
channels available to me. In parallel, I scan the URL and submit the hash of `tool.tar.gz` to a CTI platform. I
also take the opportunity to quickly check the current connection state on the machine via `ss -tulpn`, looking
for any unusual remote port, any process that shouldn't have a network connection, or a remote IP that's
geographically/contextually inconsistent. Based on the results of the actions above, I follow the established
response plan.

If I need to push the analysis further, I check the audit logs for how `wget` was spawned via `ausearch -x wget
-i`, to retrieve the `ppid` (parent process ID), letting me trace back to the `SYSCALL` event corresponding to
that process's launch, along with its own name (`comm=`) and binary path (`exe=`) — letting me understand how it
was launched and pivot the analysis around this new element to get closer to the initial access. I then determine
the file's actual type via `file suspicious.tar.gz`, to detect any type-masquerading attempt. If that's the case,
I trigger level 2 of the response; otherwise, I list the contents of `tool.tar.gz` without extracting via `tar
tzvf tool.tar.gz.evidence`, and check whether a binary from the archive is currently running (`ps auxf | grep
<binary_name>`) or was launched, via the audit logs (`ausearch -x <binary_path_or_name> -i`). If a binary was
launched, I look for the potential consequences of that launch against the cyber kill chain:

- **Persistence** — crontabs (`cat /var/spool/cron/crontabs/* 2>/dev/null`, `cat /etc/crontab /etc/cron.d/*
  2>/dev/null`, `crontab -l -u brobbins`); recently created/modified systemd services (`find /etc/systemd/system
  /lib/systemd/system -newer /tmp/tool.tar.gz -type f`, `systemctl list-units --type=service --state=running`);
  shell startup files (`cat ~/.bashrc ~/.profile ~/.bash_profile /etc/profile.d/*.sh 2>/dev/null`); added SSH keys
  (`find / -name "authorized_keys" -newer /tmp/tool.tar.gz 2>/dev/null`, `cat ~/.ssh/authorized_keys`); recently
  loaded kernel modules (`lsmod`, `dmesg | grep -i "module\|insmod"`).
- **Privilege escalation** — recently set SUID/SGID binaries (`find / -perm -4000 -newer /tmp/tool.tar.gz
  2>/dev/null`); sudoers modifications (`stat /etc/sudoers /etc/sudoers.d/* 2>/dev/null`); suspicious failed
  authentication or su/sudo attempts (`grep -i "sudo\|su:" /var/log/auth.log 2>/dev/null`, `journalctl
  _COMM=sudo --since ...`).
- **Lateral movement** — outbound SSH connections initiated from this system (`ss -tanp | grep :22`, `grep -i
  "ssh" ~/.bash_history 2>/dev/null`); the ARP cache for recently contacted machines (`cat /proc/net/arp`).

Based on the results, I activate the corresponding response level defined at the start of the case. I close out
the investigation with an organization-wide scoping exercise, using the hash of `tool.tar.gz` to determine
whether it's present on other machines in the organization.

**Who would you communicate with and when?**
I'd start by notifying my team that I'm taking ownership of the alert, and ask them to check the queue for
potential correlation with new or older alerts. I try to contact the user, Adminsys, or DevOps to confirm the
legitimacy of the `wget` usage on the machine in question. If the scans or other quick checks confirm the threat,
I don't wait to escalate it to the IT Helpdesk to contain the threat both on the user's device and across the
organization. I inform my SOC manager as soon as an element triggers a short-term containment. If the situation
escalates, I bring in the IR response manager, management, and legal in case sensitive data was exfiltrated.

For post-incident and continuous improvement, depending on the organization's needs, I would propose:

1. Mounting `/tmp` as `noexec,nosuid`: directly breaks the pattern seen in this incident (extraction + execution
   from a temporary directory).
2. Egress filtering: map the destinations/ports legitimately required (internal repositories, DNS, updates) and
   block everything else by default — significantly reduces the C2/exfiltration window.
3. Restricting `wget`/`curl` (and other download tools) to admin/service accounts.

## 🧠 Expert Review

The most consequential gap sits underneath the ATT&CK T1105 hypothesis itself: `wget` is explicitly named as
non-interactive, meaning its execution requires a deliberate invocation — so if T1105 is correct, a
command-execution foothold on this account already existed before 08:42 UTC. Nothing in the investigation plan
actually goes looking for that foothold. The plan jumps straight from identifying how `wget` was spawned
(`ppid`/`comm`/`exe` via `ausearch -x wget -i`) into persistence, privilege escalation, and lateral movement
checks — all of which are consequences of an already-established compromise, not evidence of how one started. The
very same `ausearch -x wget -i` record already being pulled for `ppid`/`comm`/`exe` also carries the `auid`
(login UID, set once at authentication and unaffected by any later `su`/`sudo`) and `ses` (session ID) fields —
exactly what's needed to pivot into the authentication logs and recover the source IP, auth method, and timestamp
of the session that actually launched this. Why trace the process lineage of `wget` without also tracing the
login session behind it, especially when the data is already in hand?

Second, the plan states the intent to secure the volatility axis first, then move to organizational context —
"once the volatility axis is secured, I move to establishing the organizational context." Contacting
Adminsys/DevOps and checking the IT backlog carry no volatility pressure of their own; nothing requires the
technical capture to finish before that outreach starts. Sequencing them wastes the time it takes to get a reply
from another team, time during which the technical capture could already be running. Why not launch both at
once?

Third, the very first action in the volatility capture is `sha256sum /tmp/tool.tar.gz` — which opens and reads
the file's content, updating its access time — immediately ahead of `stat /tmp/tool.tar.gz`, a step justified
explicitly as needed "before a later action modifies the atime." The plan destroys the exact timestamp it says
it's trying to preserve, in the very step before the one meant to preserve it. Which of the two should run first,
and why doesn't `stat` carry the same risk as `sha256sum`?

Fourth, every disk-based artifact — including `tool.tar.gz` itself — is treated as inherently low-priority under
RFC 3227's volatility order (network → process → memory → disk), on the unstated assumption that `/tmp` is
persistent disk storage. On many modern Linux distributions, `/tmp` is mounted as `tmpfs` — RAM-backed, gone on
reboot or unmount — which would put this exact file in the same volatility tier as the process/memory state the
plan is racing to capture, not at the bottom of the list. What would confirm which case applies here, and where
would that check belong in the sequence?

Fifth, the persistence check scopes `crontab -l -u brobbins` to a specific local account name that appears
nowhere in the alert — the alert only provides `baskin.robbins@fakecompany.ca`. Nothing in the plan establishes
that this is the same account, or how the two identities map to each other, before crontab, `authorized_keys`,
and shell startup files are all scoped to it.

What holds up well: two competing hypotheses are set explicitly in ACH form (T1105 vs. a legitimate
admin/deployment action) rather than defaulting to an assumed threat, and the escalation scale is criteria-based
throughout — a flagged URL, an unconfirmed `wget` use, a flagged hash, or a type/extension mismatch, versus
demonstrated lateral movement/persistence/exfiltration — rather than an undefined "if confirmed malicious."
Forensic acquisition is also correctly placed ahead of any containment action across the whole plan, and the
deep-dive names exact, specific commands and log sources throughout (`ausearch`, `journalctl`, precise file
paths) rather than a vague "check the logs."

## 🪞 Reflection

1. Before attributing a technique, check what it presupposes as already true. `wget`'s non-interactive nature
   means T1105 as a hypothesis requires a pre-existing foothold on the account — the investigation has to go find
   that foothold (via `auid`/`ses`, pivoting into the authentication logs), not stop at the consequences that
   come after it.
2. A legitimacy-axis action and a volatility-axis action that don't depend on each other's outcome should never
   be written in sequence just because they're described one after the other. This isn't a new lesson for me —
   it's a pattern that keeps recurring across scenarios, and it needs to become a written habit, not a fix
   applied after the fact each time.
3. Any action that reads a file's content will update its access time — order matters when a later step in the
   same plan is explicitly meant to capture that same timestamp for evidentiary purposes.
4. A generic label like "disk artifact, therefore low priority" hides an assumption that needs checking first —
   a path like `/tmp` isn't automatically persistent storage, and confirming the actual filesystem type can
   change where an artifact sits in the volatility order entirely.
5. A correlation or scoping value (a username, in this case) is only usable once it's been verified against the
   actual identity involved, not assumed or invented as a placeholder.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?** Unchanged.

**What questions would you ask?** Unchanged.

**What would you investigate and in what order?**
My first reflex is still to secure the volatility axis following RFC 3227 on Linux, with the same overall goal of
freezing the system's state and preserving evidence integrity before any analysis. After creating a dedicated
evidence folder, and depending on the mount type of `/tmp` determined via `findmnt /tmp` (if `tmpfs`, treat it
with the same fragility as memory state), I run the following actions:

1. Disk metadata of the file and its location: `stat /tmp/tool.tar.gz > stat_archive.txt`, to freeze timestamps
   (atime/mtime/ctime) and permissions before a later action modifies the atime.
2. Suspect file integrity: `sha256sum /tmp/tool.tar.gz > hash_original.txt`, to freeze the file's cryptographic
   fingerprint.
3. Volatile state capture: `ps auxf > ps_auxf.txt` for the full process state; `ss -tulpn > ss_state.txt` for
   socket state; `cat /proc/net/arp > arp_cache.txt` for the kernel's ARP cache before it expires; `lsof >
   lsof_full.txt` for a raw, complete capture of every file open by every process.
4. Physical memory: `insmod lime.ko "path=/mnt/evidence/mem.lime format=lime"` for a full raw dump of physical
   RAM before any reboot or action that could erase it.
5. Temporary directories: `ls -laR /tmp /dev/shm > tmp_shm_listing.txt` for a raw, complete inventory of these
   directories.
6. System logs: `journalctl --since "2h ago" > journal_export_2h.txt` to export the relevant log window in full,
   and `ausearch -ts recent > audit_export.txt 2>&1` to export all recent audit events.

In parallel, I start contacting the identified stakeholders to establish the organizational context — the role of
the user and their device, whether the use of `wget` is consistent with the machine/user, and whether maintenance
activity was planned on this machine. If I get no response, I check the backlog and other communication channels
available to me. I scan the URL and submit the hash of `tool.tar.gz` to a CTI platform, and take the opportunity
to quickly check the current connection state via `ss -tulpn`, looking for any unusual remote port, any process
that shouldn't have a network connection, or a remote IP that's geographically/contextually inconsistent. Based
on the results of the actions above, I follow the established response plan.

If I need to push the analysis further, I check the audit logs for how `wget` was spawned via `ausearch -x wget
-i`, to retrieve the `ppid` (parent process ID), letting me trace back to the `SYSCALL` event corresponding to
that process's launch, along with its own name (`comm=`) and binary path (`exe=`). In the same record, I also
pull `auid`/`ses` (session ID) to trace back to the originating login session in the authentication logs — source
IP, auth method, and timestamp, to compare against the `wget` at 08:42 UTC. This is what lets me understand how
`wget` was launched and pivot the analysis toward initial access, instead of stopping at the download itself.

I then determine the file's actual type via `file tool.tar.gz`, to detect any type-masquerading attempt. If
that's the case, I trigger level 2 of the response; otherwise, I list the contents of `tool.tar.gz` without
extracting via `tar tzvf tool.tar.gz`, and check whether a binary from the archive is currently running (`ps auxf
| grep <binary_name>`) or was launched, via the audit logs (`ausearch -x <binary_path_or_name> -i`). If a binary
was launched, I look for the potential consequences of that launch against the cyber kill chain:

- **Persistence** — crontabs (`cat /var/spool/cron/crontabs/* 2>/dev/null`, `cat /etc/crontab /etc/cron.d/*
  2>/dev/null`, `crontab -l -u <verified account>`), with the account name verified against the correspondence
  between `baskin.robbins@fakecompany.ca` and the real OS account via the `auid` field in `ausearch -x wget -i`,
  rather than assumed; recently created/modified systemd services (`find /etc/systemd/system
  /lib/systemd/system -newer /tmp/tool.tar.gz -type f`, `systemctl list-units --type=service --state=running`);
  shell startup files (`cat ~/.bashrc ~/.profile ~/.bash_profile /etc/profile.d/*.sh 2>/dev/null`); added SSH keys
  (`find / -name "authorized_keys" -newer /tmp/tool.tar.gz 2>/dev/null`, `cat ~/.ssh/authorized_keys`); recently
  loaded kernel modules (`lsmod`, `dmesg | grep -i "module\|insmod"`).
- **Privilege escalation** — recently set SUID/SGID binaries (`find / -perm -4000 -newer /tmp/tool.tar.gz
  2>/dev/null`); sudoers modifications (`stat /etc/sudoers /etc/sudoers.d/* 2>/dev/null`); suspicious failed
  authentication or su/sudo attempts (`grep -i "sudo\|su:" /var/log/auth.log 2>/dev/null`, `journalctl
  _COMM=sudo --since ...`).
- **Lateral movement** — outbound SSH connections initiated from this system (`ss -tanp | grep :22`, `grep -i
  "ssh" ~/.bash_history 2>/dev/null`); the ARP cache for recently contacted machines (`cat /proc/net/arp`).

Based on the results, I activate the corresponding response level defined at the start of the case. I close out
the investigation with an organization-wide scoping exercise, using the hash of `tool.tar.gz` to determine
whether it's present on other machines in the organization.

**Who would you communicate with and when?** Unchanged.

For post-incident and continuous improvement, depending on the organization's needs, I would propose:

1. Mounting `/tmp` as `noexec,nosuid`: directly breaks the pattern seen in this incident (extraction + execution
   from a temporary directory).
2. Egress filtering: map the destinations/ports legitimately required (internal repositories, DNS, updates) and
   block everything else by default — significantly reduces the C2/exfiltration window.
3. Restricting `wget`/`curl` (and other download tools) to admin/service accounts.

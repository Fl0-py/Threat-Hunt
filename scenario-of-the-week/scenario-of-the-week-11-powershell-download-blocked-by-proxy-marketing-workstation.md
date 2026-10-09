# Scenario of the Week 11 — PowerShell Download Blocked by the Proxy (Marketing Workstation)

**Published:** 2026-10-09

## 🎬 Scenario

```
An EDR flagged a PowerShell process on a workstation in Marketing. The alert says the process attempted to
download a file from an external URL, but the connection was blocked by the proxy. The user claims they were
just browsing the web and didn't notice anything unusual.
```

## 🧭 Guided Questions

- What questions would you ask?
- What would you investigate and in what order?
- Who would you communicate with and when?
- What's your gut telling you and how would you confirm it?

## 📝 First Response

**What's your gut telling you and how would you confirm it?**
I start by organizing the alert information using the context / anomaly / priority triptych:

- **Context** — a PowerShell process attempted to download a file from an external URL on a workstation in
  Marketing. The connection was blocked by the proxy. The user claims they were just browsing the web and didn't
  notice anything unusual.
- **Anomaly** — the EDR signal of the PowerShell process and the connection blocked by the proxy, compared to the
  user's claim that they didn't notice anything unusual.
- **Priority** — the PowerShell process, to determine how it was triggered, and the endpoint, to bring other forms
  of threat to light.

I then set hypotheses to determine the alert's status. A download attempt through a PowerShell process means we are
upstream of the web browser, and that we should look locally for what launched the process:

1. **False positive** — a legitimate tool, an administration script, a legitimate Office macro or business add-in.
2. **True positive** — a click on a link or attachment, a malicious document launching PowerShell, a threat
   already in place, or ClickFix / fake CAPTCHA (the web page pushes the user to paste a command into Win+R or a
   terminal; the user is then the origin of the execution without realizing it, which fits "I was just
   browsing").

In both cases, the conditions that will quickly settle the question are the user's actions and the process tree:
I need to identify what the user did and how `powershell.exe` was launched.

Before starting the investigation, I set the following escalation process:

1. Parent-child consistent, clear command, known script, URL/file validated after review: close the ticket, update
   the alerts, and block the proxy so this false positive no longer comes up.
2. PowerShell launch confirmed through a click on a malicious link/attachment, or a macro not identified by the
   organization: targeted network block of the endpoint and deeper analysis.
3. Outbound connection to an untrusted domain/IP, lateral movement, persistence, or exfiltration demonstrated: full
   isolation of the source and associated targets, and a crisis cell is set up.

Finally, I set the alert's volatility axis mainly around endpoint telemetry and network connections. The priority
is to preserve the process tree and the command line of `powershell.exe`, the active network connections, the DNS
cache, the PowerShell history in memory / logs, and if needed the memory image (RAM).

**What questions would you ask?**
What exactly did the user do on their workstation? By what, or whom, and how was the PowerShell process launched?
What is the command that initiated the download? Were other commands launched within the alert's time window
(before/after)? Are there signs of persistence on the machine? Are there signs of lateral movement? Of identity
compromise? Why did the proxy block the URL? What is the associated domain/IP? What are their reputation and
creation date? What was supposed to be downloaded?

**What would you investigate and in what order?**
My first reflex is to secure the volatile side of the alert, following the RFC 3227 good practice adapted to the
context:

- Process tree and command line:
  `Get-CimInstance Win32_Process | Select ProcessId, ParentProcessId, Name, CommandLine, CreationDate, ExecutablePath | Export-Csv E:\evid\processes.csv -NoTypeInformation`
- If the process is alive, a targeted dump of the suspect process, spotting the active PIDs with
  `Get-Process powershell,pwsh -ErrorAction SilentlyContinue | Select Id,StartTime,Path`, then
  `.\procdump64.exe -accepteula -ma <PID> E:\evid\ps_<PID>.dmp` and
  `Get-FileHash E:\evid\ps_<PID>.dmp -Algorithm SHA256`.
- Active connections tied to the owning process:
  `Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime | Export-Csv E:\evid\netconns.csv -NoTypeInformation`
- DNS cache, ARP, routes: `Get-DnsClientCache | Export-Csv E:\evid\dnscache.csv -NoTypeInformation`,
  `arp -a > E:\evid\arp.txt`, `route print > E:\evid\routes.txt`.
- Raw PowerShell logs and console history:

```powershell
# Export raw logs (preserves everything for off-machine analysis)
wevtutil epl "Microsoft-Windows-PowerShell/Operational" "out\ps_operational.evtx"
wevtutil epl "Windows PowerShell" "out\ps_classic.evtx"
wevtutil epl Security "out\security.evtx"
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "out\sysmon.evtx"   # if present
# Console history of the user concerned
Copy-Item "C:\Users\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" $out
# Quick read: executed scripts (4104) and PowerShell process creations (4688)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddHours(-24)} | Select TimeCreated, Message
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-24)} | Where-Object { $_.Message -match 'powershell' } | Select TimeCreated, Message
```

If the parent process is suspect, the command line is obfuscated/encoded, or I suspect fileless activity or
injection, I dump the RAM with WinPmem (`.\winpmem_mini_x64.exe E:\evid\ram.raw`, then
`Get-FileHash E:\evid\ram.raw -Algorithm SHA256`).

In parallel with securing the data, I contact the user to get more context about their activity on the endpoint.
I want to know what exactly they did, which could quickly point to a click on a link/attachment, the opening of a
malicious document, or a ClickFix / fake CAPTCHA. To confirm, I check Sysmon Event ID 1 for this process to
retrieve the parent and learn how it was launched, using the `ParentImage` and `ParentCommandLine` fields. I
retrieve the security context through `User` and `LogonId`, and note `ProcessGuid` and `ParentProcessGuid` to walk
up the whole tree. If the parent-child relationship is consistent and the commands are clear, I ask the user and
the organization's IT whether the action is valid and compliant with the security policy. If the job is confirmed
as legitimate, I document it and close the ticket, and I go to my manager to start a cost/benefit discussion about
evolving the alert. If a script launch by an unvalidated parent is confirmed, I start the targeted network block
of the endpoint and the deeper analysis before moving to tier 3.

I then look at the content of the executed script and determine whether the write succeeded despite the proxy
block, using the 4104 log (PowerShell/Operational) and the following fields:

- `DownloadString`: downloaded code is executed without touching the disk, with the URL.
- `DownloadFile`: file downloaded to disk, with the URL and the destination path, and a possible artifact to
  search for and hash for scanning and reputation analysis.
- `Invoke-WebRequest`: for the user-agent headers.
- `FromBase64String`: decodes to find a potential payload or URL.

If a file was downloaded, I retrieve its hash/path and check whether it spawned other processes. I also identify
all children of `powershell.exe` using `ParentImage=PowerShell` or a `ParentProcessGuid` equal to the
`ProcessGuid` found earlier. I then check for file creation by PowerShell around the time of the alert using
Sysmon 11 to note the path and hash, and Sysmon 7 to identify loaded DLLs. I follow with Sysmon 1, using `Image`
matching the path/hash to see whether the file was executed, and `ParentImage` to see whether it spawned children.

I then move to persistence, checking registry modifications via Sysmon Event ID 13 (Registry Value Set), service
creation via Security Event ID 4697 or System Event ID 7045 (Service Control Manager), scheduled task creation via
Security Event ID 4698, and the startup folder. I then check lateral movement in three layers:

- **Network**: Sysmon 3, to look for connections from the Marketing workstation to other internal hosts over
  protocols such as SMB, RPC/DCOM, WinRM, RDP or SSH.
- **Authentication**: 4624/4648/4672 for successful logons, repeated failures, logons with explicit credentials,
  or admin account use. If a suspicious authentication is identified, I add a dedicated identity step to the
  response plan.
- **Execution on the target**: service execution, WMI, WinRM or scheduled task.

Next I check the volume and destination of potential outbound data through the web proxy, as well as unusual
protocols (FTP, SFTP, SMB or RDP to the Internet, non-standard ports).

Finally, I pivot on the URL blocked by the proxy. I retrieve the domain and IP to determine the domain creation age
and what is behind the IP (bulletproof host or cheap VPS, other domains on the same IP). I use this to scope the
threat in the organization by looking for the domain (and its subdomains) and the IP in the proxy logs, DNS logs
or Sysmon 22. If new domains or IPs are found, I add them to the IOC list and block them. If an additional
workstation is impacted, I trigger tier 3 of the response plan and widen the scope to treat every workstation.

For the post-incident phase, I make sure of:

- Confirmation of eradication: all endpoints handled with persistence removed (scheduled tasks, Run keys, WMI,
  services) and a clean EDR re-scan. All exposed credentials handled with account resets (password, revoked
  sessions, tokens).
- Recovery: restoration or reinstallation of the workstations, validation before returning to production, and
  lifting of temporary measures (blocks, locked accounts).
- Correction: the entry vector/vulnerability fixed (patch, mail rule, macro blocking).
- Blocking: IOCs (domain, IP, hash) blocked, with a retro-hunt that no longer returns anything new.
- Evidence retention: retention period, secure storage, chain of custody for legal or insurance procedures.
- Communication: a closing message to stakeholders (management, business, the user concerned).
- Documentation: timeline, exported evidence, decisions taken and their justification, final qualification, and
  feeding the internal threat intel platform.
- Legal: police report, DPO opinion, notification of the government authority and customers if personal data was
  compromised, entry in the breach register.
- Reinforced monitoring: keep a watchlist of the impacted devices to detect suspicious behavior (connections to
  the IOCs, `powershell.exe` with suspicious command lines, new scheduled tasks, off-hours connections, unusual
  authentications of the accounts concerned), with a duration and an exit criterion.
- Lessons learned: a blameless meeting covering what worked, what was missing, with actions and owners.

For recommendations:

- Targeted awareness for Marketing: contractor links and attachments, fake CAPTCHAs (ClickFix), copy-pasting
  commands.
- ASR (Attack Surface Reduction) rules: block child process creation by Office, obfuscated scripts, and
  executable content coming from email.
- Constrained Language Mode or WDAC / AppLocker for non-technical workstations.
- A list of contractors and tools validated by Marketing (domains, applications).

**Who would you communicate with and when?**
I start by communicating with my SOC team to say that I am taking ownership of the alert and to check whether
alerts can be correlated. I then communicate with the user to collect as much information and context as possible
for my analysis. In parallel, I contact the helpdesk / IT organization for confirmation and initiation of the
response phase. If the script launch is confirmed as suspicious, I coordinate with the different stakeholders
(Incident Response manager, infrastructure and identity teams) for the response, and with top management and legal
for communication and the non-IT response.

## 🧠 Expert Review

The most consequential gap is in the volatility step. The First Response opens its evidence collection with a
snapshot of a live system: `Get-CimInstance Win32_Process`, active connections, DNS cache, then a `procdump` of any
running PowerShell. The alert, however, is a download attempt that the proxy blocked. A one-liner of that kind
typically runs and exits within seconds, and by the time an analyst acts, minutes or hours have gone by. What is
actually volatile here is the command line and the outbound-connection telemetry, held in EDR retention and in
local event logs, not a process that most likely no longer exists. The dump has the same weakness: its only
condition is "the process is alive", which says nothing about whether it is suspicious, and
`Get-Process powershell,pwsh` lists every PowerShell instance rather than the one the alert points to. A benign
interactive session would be dumped as readily as the one that matters. The RAM capture, by contrast, is gated on
concrete observables (suspect parent, obfuscated command line, suspicion of fileless activity or injection). What
observable, a process identifier, a parent, a command line, should authorize the process dump, and why does it
deserve a lower bar than the memory image? Related: the EDR alert already carries the process tree, the parent and
the command line, so the first gesture is to read it before touching the endpoint.

Second, "parent-child consistent" is the pivot of the whole plan, and it is never defined. Which parents justify
containment? `explorer.exe` is both what a user launching PowerShell by hand produces and where the Win+R dialog of
a ClickFix runs, so the parent alone separates nothing. It takes the command line to separate the two (hidden
window, policy bypass, encoded content, a download cradle with `iex`, `iwr`, `DownloadString`, a plain URL). In
this scenario the alert already shows a download from an external URL, which makes an `explorer.exe` parent
combined with that command a serious ClickFix candidate. The parent is also spoofable, so it never decides alone.
What would the process tree and command line look like if this were a legitimate administration script, versus a
ClickFix?

Third, the escalation tiers. Tier 3 fires on "outbound connection to an untrusted domain/IP", but the alert itself
is an attempt toward an untrusted URL, so the condition is true at minute zero and the plan would escalate to full
isolation immediately. The plan does not say what separates an attempt that the proxy refused from a connection
that was established. Tier 3 also fuses two different decisions: isolating a host, a technical action triggered by
an indicator on the endpoint (second stage executed, persistence, lateral movement), and setting up a crisis cell,
an organizational decision triggered by scope (several hosts, identity or privileged-account compromise,
exfiltration, legal exposure). What observable triggers each one?

Finally, on technical precision. The plan leans almost entirely on Sysmon (Event IDs 1, 3, 7, 11, 13, 22), yet the
raw-log export itself says "if present". Security 4688 only carries the command line if process-creation command
line auditing is enabled, and 4104 only exists if Script Block Logging is enabled. The plan neither checks which of
these sources actually exist and are centralized nor says what to do when they do not. Also, `DownloadString` is
described as "executed without touching the disk". `DownloadString` only downloads text; what executes it is
`Invoke-Expression` / `iex`, typically in the form `IEX (New-Object Net.WebClient).DownloadString('...')`. With the
proxy refusing the request, nothing came back to execute.

What holds up well: the ClickFix hypothesis is raised and explicitly tied to the user's statement, and the
condition that settles the alert (the user's actions and the process tree) is correctly identified. The plan names
precise sources and fields (Sysmon `ParentImage`, `ParentProcessGuid`, 4104 keywords, 4697/7045/4698 for
persistence) rather than intentions. The lateral movement check is structured in three layers (network,
authentication, execution on the target). Contacting the user is done in parallel with securing the data, not
after. The post-incident phase is complete, and the recommendations (ASR rules, Constrained Language Mode,
targeted awareness) are specific to the vector.

## 🪞 Reflection

1. Before collecting anything, ask which logs are already centralized and protected (EDR, SIEM), and put the
   priority on the ones that are not, here the raw endpoint logs. The first reflex is to read what is already at
   hand, not to run commands on the machine.
2. A process dump needs an activation condition and an order relative to the containment. Here, blocking first
   costs nothing because the proxy had already blocked the download; if the process were in active communication
   with a C2, the order would be reversed and the dump would come first.
3. State why a parent is suspect rather than listing names. An Office application (`WINWORD.EXE`, `EXCEL.EXE`,
   `POWERPNT.EXE`), `wscript.exe`, `cscript.exe`, `mshta.exe` or a browser as the parent of PowerShell is abnormal
   on a Marketing workstation on its own. An ambiguous parent (`explorer.exe`, a terminal) needs a second
   indicator, such as the command line.
4. Separate the technical response (host isolation, on an endpoint indicator) from the organizational response
   (crisis cell, on scope and impact), each with its own observable trigger instead of one fused tier.
5. Do not rely on a single telemetry source. The plan depended almost entirely on Sysmon; the improvement axis is
   to know the alternative sources and to adapt to what the real context provides.
6. Areas still to consolidate: how parent processes work (when they are suspect, when they are less so), the dump
   (when, at which point, and what influences it), and ordering the steps of a response plan according to the real
   context of the alert.

## 🔁 Revised Response

**What's your gut telling you and how would you confirm it?**
The triptych and the two hypotheses are unchanged. Two changes:

- The escalation process now has four tiers, with the technical response separated from the organizational one:

  1. Parent-child consistent, clear command, known script, URL/file validated after review: close the ticket and
     update the alerts so this false positive no longer comes up. (The proxy block is dropped from this branch: a
     proxy block belongs to the post-incident IOC blocking of a confirmed malicious case.)
  2. PowerShell launch confirmed through a click on a malicious link/attachment, or a macro not identified by the
     organization: targeted network block of the endpoint and deeper analysis.
  3. Lateral movement, persistence, or exfiltration demonstrated on the endpoint: full isolation of the source and
     associated targets.
  4. Several workstations affected, identity or privileged-account compromise, data exfiltration, or business
     and legal impact (personal data): a crisis cell is set up.

- The volatility axis is now mainly endpoint telemetry and network connections, but the priority is to preserve
  and secure the logs that are not centralized and have a short retention time.

**What questions would you ask?**
One change: a first question is added — which logs are centralized/archived/accessible, and for how long? The
rest is unchanged.

**What would you investigate and in what order?**
My first reflex is to read the alert and the process tree in the EDR console, check the SIEM coverage, and then
secure the local logs by exporting the raw logs and the console history:

```powershell
# Export raw logs (preserves everything for off-machine analysis)
wevtutil epl "Microsoft-Windows-PowerShell/Operational" "out\ps_operational.evtx"
wevtutil epl "Windows PowerShell" "out\ps_classic.evtx"
wevtutil epl Security "out\security.evtx"
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "out\sysmon.evtx"   # if present
# Console history of the user concerned
Copy-Item "C:\Users\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" $out
```

In parallel with securing the data, I contact the user for context on their activity (link or attachment click,
malicious document, ClickFix / fake CAPTCHA). To confirm, I check Sysmon Event ID 1 for the process: `ParentImage`
and `ParentCommandLine` to learn how it was launched, `User` and `LogonId` for the security context, and
`ProcessGuid` and `ParentProcessGuid` to walk up the tree. If the parent-child relationship is consistent and the
commands are clear, I ask the user and IT whether the action is valid and compliant with the security policy; if
the job is legitimate, I document it, close the ticket, and go to my manager to discuss evolving the alert.

Otherwise, the parent is suspect when:

1. The parent is suspect on its own, because a Marketing workstation has almost no legitimate reason to produce
   it: an Office parent (`WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`), even behind an intermediate (`cmd.exe`,
   `wscript.exe` or `mshta.exe`); a `wscript.exe`, `cscript.exe` or `mshta.exe` parent; or a browser
   (`chrome.exe`, `msedge.exe`).
2. The parent is ambiguous — `explorer.exe` (it also launches a hand-opened PowerShell) or a terminal
   (`cmd.exe`, `WindowsTerminal.exe`) — but is tied to a command line that shows a hidden window, a policy bypass,
   encoded content, `iex` / `iwr` / `irm` / `DownloadString`, or a plain URL.

In that case I move to tier 2 of the response plan and start the deeper analysis. The EDR network block preserves
the memory, and since the connection is already blocked by the proxy, containing first loses nothing; if the
process were in active communication with a C2, it would be the reverse: dump first, then block. Using the PID
analyzed earlier, I check whether the process is still running with
`Get-Process powershell,pwsh -ErrorAction SilentlyContinue | Select Id,StartTime,Path`; if so, I take a targeted
dump with `.\procdump64.exe -accepteula -ma <PID> E:\evid\ps_<PID>.dmp` and hash it with `Get-FileHash`.

I then look at the content of the executed script in the 4104 log (PowerShell/Operational) with the following
fields:

- `DownloadString`: associated with `iex`, to look for a command that downloads code and executes it directly in
  memory.
- `DownloadFile`: file downloaded to disk, with the URL and the destination path, and a possible artifact to
  search for and hash for scanning and reputation analysis.
- `Invoke-WebRequest`: for the user-agent headers.
- `FromBase64String`: decodes to find a potential payload or URL.

The rest of the investigation (file downloaded, children of `powershell.exe`, persistence, lateral movement in
three layers, outbound data, pivot on the blocked URL and scoping) is unchanged. The final step now reads: if an
additional workstation is impacted, I trigger the last tier of the response plan and widen the scope to treat every
workstation. The post-incident phase and the recommendations are unchanged.

**Who would you communicate with and when?** Unchanged.

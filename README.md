# Active Directory Home Lab with Splunk SIEM and SOAR Automation

I built a small Active Directory network in VirtualBox, attacked it two ways (password brute force, then Kerberoasting), wrote Splunk detections that caught both attacks on real event data, hardened the account I targeted, and set up an automated alerting/response workflow with Shuffle SOAR.

Started from MYDFIR's *Active Directory Project 2.0* series, then I extended it with a second attack stage, two of my own detections, an encryption hardening test, and a reworked response workflow (more on that in [What I added](#what-i-added-beyond-the-tutorial)).

---

## Results at a glance

| What | Outcome |
|---|---|
| Brute-force detection (Event 4625) | ✅ Fired on real failed RDP logins |
| Unauthorized logon detection (Event 4624) | ✅ Fired on the attacker's successful login |
| Kerberoasting detection (Event 4769) | ✅ Isolated the attacker's RC4 ticket request from normal traffic |
| Kerberoasting attack | ✅ Service ticket dumped and password cracked |
| RC4 → AES hardening | ✅ Account now issues AES tickets only, the same cracking tool could no longer process the ticket |
| Shuffle SOAR workflow | ✅ Ran end to end (Slack + email), ⚠️ alert messages don't include incident details yet |
| IP-block response script | ✅ Works when run manually, ⚠️ Splunk-triggered version blocked by a platform permission issue |
| Account disable | ⚠️ Manual analyst step (cloud SOAR couldn't reach the domain controller) |

**Skills shown:** Active Directory administration, Splunk SPL, Sysmon, Windows event analysis, detection tuning, Kerberos attacks and hardening, SOAR workflow design, Windows OpenSSH, troubleshooting.

---

## Environment

Everything runs locally in VirtualBox on a NAT Network (`192.168.10.0/24`).

| VM | Role | IP | OS / Specs |
|---|---|---|---|
| AD-DC02 | Domain controller (`mydifr.local`) | 192.168.10.10 | Windows Server 2022, 4 GB RAM |
| AD-WIN10 | Domain-joined workstation | 192.168.10.100 | Windows 10 Pro, 6 GB RAM |
| Splunk-SVR | SIEM | 192.168.10.6 | Ubuntu Server 24.04, 6 GB RAM |
| Kali | Attacker | 192.168.10.101 (static) | Kali rolling |

**Logging:** Splunk Universal Forwarder on both Windows machines sends Security, System, and Application logs plus Sysmon (SwiftOnSecurity config) to the `mydifr-ad` index.

**Accounts:** `jsmith` is the standard domain user I targeted with brute force, `svc-sql` is the service account I targeted with Kerberoasting, and `localadmin` is the local admin I used for machine-level config. Every password in this writeup is lab-only.

> The domain is spelled `mydifr.local` instead of `mydfir.local` because I typo'd it during DC promotion. I kept it instead of demoting and re-promoting, and kept everything after that consistent with the typo.

---

## Attack chain

```
Brute force (T1110)            →  jsmith's password recovered
        ↓
Kerberoasting (T1558.003)      →  jsmith's access used to steal and crack svc-sql's password
```

I chained these on purpose instead of building two separate demos. Real compromises usually escalate from initial access into further credential theft, so I wanted the lab to actually show that.

---

## Detections

I tested all three queries against real attack data, and I checked every field name by expanding a real captured event first. That turned out to matter a lot, see [Lessons learned](#lessons-learned).

### 1. Unauthorized successful logon (Event 4624)

```spl
index=mydifr-ad EventCode=4624
(Source_Network_Address=* AND Source_Network_Address!="-"
 AND NOT (Source_Network_Address="192.168.10.10" OR Source_Network_Address="192.168.10.100"))
| stats count by _time, ComputerName, Source_Network_Address, user, Logon_Type
```

The base tutorial flagged public IPs, but my lab is fully internal, so I used an allowlist of the two legitimate hosts instead. Anything logging in successfully from outside that list gets flagged.

### 2. Brute force within a time window (Event 4625)

```spl
index=mydifr-ad EventCode=4625 LogName=Security
| sort 0 _time
| streamstats time_window=90s count as recent_failures by user, src_ip
| where recent_failures >= 5
```

I used a rolling window so this separates fast tool-driven guessing from slow background noise, like an old cached password retrying every few hours.

- `sort 0 _time` is needed because `streamstats` requires oldest-first order, and Splunk returns newest-first by default.
- I set the threshold to `>= 5` because my test only generated exactly 5 failures, so `> 5` would never have fired.
- 90 seconds fit my manual test (5 attempts spread over 51 seconds). Against a real automated tool I'd tighten this to around 10 seconds.

### 3. Kerberoasting (Event 4769)

```spl
index=mydifr-ad EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="krbtgt" Service_Name!="*$"
| stats count dc(Service_Name) as unique_services by Account_Name, Client_Address
| where count >= 1
```

Modern domains normally negotiate AES (`0x12`) for Kerberos tickets, so a request for an RC4 (`0x17`) ticket against a real service account, not a machine account, stands out as a Kerberoasting signature.

I left the threshold at 1 because that's what I tested (one targeted service account). In production I'd bump it to 3+ distinct services, so it catches one account roasting a bunch of SPNs instead of flagging a single normal request.

![4769 detection result showing jsmith requesting an RC4 ticket for svc-sql from 192.168.10.101](images/4769-detection-query-result.png)

---

## Attack walkthrough

### Phase 1: Brute force over RDP

I started with Hydra's RDP module. It found the password, but **it didn't generate any Windows logon events** (I checked Event Viewer directly to confirm). That module is marked experimental, and it looks like it's validating credentials without completing a full logon.

So I switched to manual `xfreerdp` connections instead, which do generate real events:

```bash
xfreerdp /v:192.168.10.100 /u:jsmith /p:'<password>' /cert:ignore
```

Five wrong passwords gave me five 4625 events, and the correct password gave me one 4624 event (Logon Type 10, from 192.168.10.101). **Both detections fired.**

Getting RDP to even accept a login took two extra steps first: enabling Remote Desktop (which I had to do as `localadmin`, since `jsmith` doesn't have the rights), then adding `jsmith` to the local Remote Desktop Users group.

### Phase 2: Kerberoasting

**Setup.** I created a service account with a password that never expires and registered a fake SQL Server SPN on it, the way real service accounts often get set up in the wild:

```powershell
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" -AccountPassword (ConvertTo-SecureString "SuperSecretSvcPass123!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
setspn -A MSSQLSvc/sqlserver.mydifr.local:1433 svc-sql
```

![Creating svc-sql and registering its SPN on the domain controller](images/kerberoast-svc-account-spn-setup.png)

**Attack.** Using `jsmith`'s stolen credentials, I ran Impacket to request a service ticket for every SPN-bearing account:

```bash
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py mydifr.local/jsmith:'Winter2025!' -dc-ip 192.168.10.10 -request -outputfile svc-sql-hash.txt
```

The ticket came back as `$krb5tgs$23$...`. That `23` means RC4 encryption, which is crackable offline.

![GetUserSPNs output showing the RC4 ($23$) ticket hash](images/kerberoast-rc4-hash-dump.png)

**Cracking.** hashcat's GPU mode wasn't available in the VM, and once I installed its CPU-only OpenCL runtime (POCL), it was way too slow to be practical. So I switched to John the Ripper, which handles this natively on CPU:

```bash
john --format=krb5tgs --wordlist=<wordlist> svc-sql-hash.txt
```

Cracked instantly against a targeted wordlist.

![John the Ripper cracking the RC4 ticket](images/john-cracked-rc4-hash.png)

### Phase 3: Hardening (RC4 → AES)

I locked the service account down to AES only:

```powershell
Set-ADUser -Identity svc-sql -KerberosEncryptionType AES128,AES256
```

`msDS-SupportedEncryptionTypes` came back as `24` (AES128 + AES256), confirming RC4 was gone.

![Applying AES-only encryption and verifying msDS-SupportedEncryptionTypes = 24](images/aes-hardening-applied.png)

When I reran the exact same attack, the ticket came back as `$krb5tgs$18$` (AES256) instead of `$23$` (RC4). John, using the same wordlist that already had the real password in it, returned **"No password hashes loaded"**, so it couldn't even process the AES ticket.

**What this actually proves (and what it doesn't):** the hardening worked, and the account only hands out AES tickets now. The specific command I used before (John in RC4 mode) just can't touch an AES ticket. That shows my tool no longer works against it, not that AES is unbreakable. I never ran an actual AES-capable cracking attempt to test that part.

![AES ($18$) ticket and John's "No password hashes loaded"](images/aes-hash-and-failed-crack.png)

---

## Automated response (SOAR)

Splunk alerts trigger a Shuffle workflow over a webhook. I gave each alert a different response level based on how risky it'd be to automate.

### Unauthorized logon → notify and ask for approval

```
Splunk alert → Shuffle webhook → Slack (#alerts)
                                    ├── FYI email to the account holder
                                    └── Approval email asking the SOC analyst to review and disable the account
```

**Original plan:** once the analyst approves, Shuffle disables the account over LDAP on its own.

**What actually happened:** Shuffle's cloud service only allows outgoing HTTP/HTTPS. I tested an LDAP connection through a working ngrok tunnel and the tunnel never registered a single connection. So instead, the analyst disables the account manually (`Disable-ADAccount -Identity jsmith`). The approval step stayed exactly the same, only who actually flips the switch changed.

**Known gap:** the Slack and email notifications show up, but the account, source IP, and time fields are blank. I never wired the template to Shuffle's runtime variables. This is a real operational gap since the analyst needs those details to act on it, and it's the next thing I want to fix.

### Brute force → block the attacker's IP

I wrote a script on the Splunk server (`ip_ban.sh`) that SSHes into the workstation with a key and adds a Windows Firewall rule to block the attacker's IP.

- **Working:** running it manually created and then removed a real block rule, confirmed with `Get-NetFirewallRule`.
- **Blocked:** when Splunk's "Run a script" alert action triggers it automatically, it fails (exit code 1). Splunk's internal logs (`index=_internal ip_ban`) showed me the results file sits in a `root`-only directory the `splunk` user can't read. This alert action is marked deprecated by Splunk itself, so instead of loosening permissions on Splunk's own internal folders, I just documented it. The real fix is a packaged custom alert action.

### Kerberoasting → manual investigation only

No automated response here. Auto-rotating a service account's password could break a live service that's still using the old one, so I left that call to a human.

---

## Design decisions

- **Account disable needs approval, IP block doesn't.** Disabling the wrong account locks a real employee out of everything. Blocking an IP is lower stakes and easy to reverse in this lab, where every IP maps to one attacker machine. In production, a shared or NAT'd IP could belong to a bunch of legitimate users, so that step would need more thought.
- **I notify the account holder in parallel, not as a gate.** Waiting on them first would slow down containment, and their inbox might already be compromised.
- **Hardening and detection are kept separate.** Detection reacts after something already happened. Removing RC4 just gets rid of the weaker option, Kerberoasting is still technically possible against an AES-only account, it just can't get cracked the same way anymore.
- **I documented limits instead of forcing workarounds.** For both the Shuffle and Splunk blockers, I wrote up the root cause and the actual production fix instead of hacking around a platform restriction.

---

## What I added beyond the tutorial

- A second attack stage (Kerberoasting), plus the RC4 to AES before/after test
- Two detections I built myself: the time-windowed brute-force alert and the Kerberoasting alert
- An allowlist-based logon detection that actually fits a fully internal network
- Sysmon on both Windows hosts
- A local VirtualBox build with a dedicated Kali attacker instead of a cloud VM
- An IP-block response built on the Splunk side instead of through SOAR
- Slack Incoming Webhooks instead of Shuffle's Slack app, since its OAuth kept failing

---

## Lessons learned

**Check Splunk field names against a real event, every single time.** The source IP field had a different name depending on the event type: `Source_Network_Address` (4624), `src_ip` (4625), and `Client_Address` (4769, where `IpAddress` turned out to be blank). A wrong field name just quietly returns zero results with no error. This ate more of my debugging time than anything else in the project.

**Check the basics before assuming something complex broke.**
- After sitting in a saved state for a while, the VM clocks drifted by about 4 hours, which silently broke alert scheduling. Fixed it with `timedatectl set-ntp true`.
- An alert fired every minute for 20 minutes straight with zero effect because I'd left the Shuffle webhook trigger set to "stopped."
- Kali could ping IPs fine but couldn't resolve hostnames because `/etc/resolv.conf` had no nameserver in it.
- Kali's DHCP lease collided with Splunk's static IP, so I just gave Kali a static one.

**A few Windows things that aren't obvious:**
- RDP needs both the feature turned on and the user added to the Remote Desktop Users group.
- Windows OpenSSH reads admin keys from `C:\ProgramData\ssh\administrators_authorized_keys`, not the user's `.ssh` folder, and it'll silently ignore the file if the permissions are too open.

**Tools don't always do what you'd expect.** Hydra's RDP module found the password but never logged anything. hashcat couldn't run without a GPU, so I switched to John.

---

## Future work

- Fill in the Slack and email templates with real incident details
- Rebuild the IP block as a proper packaged Splunk custom alert action
- Correlate the brute-force and successful-logon alerts into one higher-confidence alert
- Self-host Shuffle inside the lab so it can actually reach the domain controller
- Add detections for lateral movement, PowerShell abuse, and pass-the-ticket
- Figure out a safe, service-aware way to auto-rotate service account passwords

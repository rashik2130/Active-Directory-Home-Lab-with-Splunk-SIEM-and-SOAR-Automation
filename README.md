# Full Project Writeup — AD Home Lab with Splunk SIEM and SOAR Automation

> **Note on this document:** Sections marked **[PLANNED — NOT YET VERIFIED]** describe intended behavior that has been designed and built but not yet executed against the real environment. These will be replaced with actual results, screenshots, and any corrections once testing is complete. Nothing under those markers should be read as a claimed outcome.

---

## 1. Executive Summary

This project simulates a small enterprise Active Directory environment, then layers detection engineering and automated incident response on top of it. The scenario: a domain account is compromised via brute force, the compromise is detected by a custom SIEM pipeline, and a tiered response — partly automated, partly human-approved — contains it. A second attack stage (Kerberoasting) is chained onto the first to demonstrate a realistic multi-step compromise rather than an isolated technique.

Base reference: MYDFIR's "Active Directory Project 2.0" tutorial series, extended with several original additions (Section 8).

---

## 2. Environment

Built entirely on local VirtualBox (not cloud-hosted), on a NAT Network named `AD-Project` (`192.168.10.0/24`).

| VM | Role | IP | Specs |
|---|---|---|---|
| AD-DC02 | Domain Controller (`mydifr.local`) | 192.168.10.10 | Windows Server 2022, 4096MB RAM, 2 CPU |
| AD-WIN10 | Domain-joined workstation | 192.168.10.100 | Windows 10 Pro, 6144MB RAM, 2 CPU |
| Splunk-SVR | SIEM | 192.168.10.6 | Ubuntu Server 24.04 LTS, 6144MB RAM, 2 CPU |
| Kali Linux | Attacker | DHCP | Kali rolling, default image |

Each Windows VM and Splunk-SVR has a second NIC on plain NAT for host internet access and port-forwarding, kept separate from the internal lab network — meaning the host machine cannot directly reach `192.168.10.0/24` addresses without explicit port forwarding.

Domain user of interest: `mydifr\jsmith`.

---

## 3. Build Process

1. All four VMs built and networked; connectivity verified via ping across the NAT Network.
2. AD DS installed on AD-DC02; promoted to domain controller for `mydifr.local`.
3. AD-WIN10 domain-joined; `jsmith` login confirmed.
4. Splunk Enterprise installed on Splunk-SVR; index `mydifr-ad` created; receiving port 9997 configured.
5. Splunk Universal Forwarder installed on both Windows VMs, configured to forward Security/System/Application Windows Event Logs plus Sysmon telemetry to Splunk-SVR.
6. Sysmon (SwiftOnSecurity configuration) installed on both Windows machines for enhanced telemetry beyond native Windows logging.
7. Ingestion confirmed for both hosts in Splunk Web.

**Notable build issue:** a typo (`mydifr.local` instead of the intended `mydfir.local`) occurred during AD DS promotion and was deliberately kept rather than corrected via demote/re-promote, since that path had already produced errors. All subsequent configuration (index name, base DN, etc.) is intentionally consistent with the typo'd spelling.

---

## 4. Detection Engineering

Three alerts, each targeting a distinct stage of the attack chain (Section 6), tuned to reduce false positives specific to this lab's fully-internal topology.

### 4.1 — Unauthorized Successful Logon (Event ID 4624)

```spl
index=mydifr-ad EventCode=4624
(source_network_address=* AND source_network_address!="-"
 AND NOT (source_network_address="192.168.10.10" OR source_network_address="192.168.10.100"))
| stats count by _time, ComputerName, source_network_address, user, Logon_Type
```

Unlike the base tutorial (which relied on a public/private IP split), this environment is fully internal, so "unauthorized" is defined via an allowlist of the two legitimate hosts (the DC and the workstation) rather than a geographic/network boundary.

### 4.2 — Brute-Force Threshold, Time-Windowed (Event ID 4625)

```spl
index=mydifr-ad EventCode=4625
| streamstats time_window=10s count as recent_failures by Account_Name, src_ip
| where recent_failures > 5
```

A rolling time window was chosen over a flat count specifically to distinguish tool-speed brute-forcing (many attempts in seconds) from slower, non-malicious noise such as a stale cached credential retrying periodically over hours.

**[TO VERIFY]:** whether 4625 events populate `src_ip` or `source_network_address` in this environment — confirm against real event data before finalizing.

### 4.3 — Kerberoasting Detection (Event ID 4769)

```spl
index=mydifr-ad EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="krbtgt" Service_Name!="*$"
| stats count dc(Service_Name) as unique_services by Account_Name, IpAddress
| where count > 3
```

Flags RC4-encrypted service ticket requests (the weaker, more easily-cracked encryption type) from an account requesting tickets across multiple distinct services in a short window — the behavioral signature of an SPN-enumeration tool rather than normal usage.

---

## 5. Attack Simulation Methodology

### Phase 1 — Brute Force (T1110)

**[PLANNED — NOT YET VERIFIED]**

From Kali, Hydra is run against the `jsmith` account over RDP, targeting AD-WIN10. RDP is deliberately enabled on the target (disabled by default on Windows) and a wordlist including the account's real password is used, to guarantee a demonstrable success rather than relying on chance. Expected result: alert 4.2 fires on the failed attempts, alert 4.1 fires on the eventual successful login.

### Phase 2 — Kerberoasting (T1558.003)

**[PLANNED — NOT YET VERIFIED]**

Prerequisite: a dedicated service account is created on AD-DC02 with a registered SPN (`setspn -A service/name serviceaccount`), since Kerberoasting specifically targets service accounts rather than regular user accounts like `jsmith`.

Using the credentials obtained in Phase 1, Impacket's `GetUserSPNs.py` (pre-installed on Kali) is run against the domain, authenticated as `jsmith`, to enumerate and request a service ticket for the target service account. Expected result: alert 4.3 fires; the returned ticket is RC4-encrypted (`0x17`).

### Phase 3 — Encryption Hardening Demonstration

**[PLANNED — NOT YET VERIFIED]**

The target service account's `msDS-SupportedEncryptionTypes` attribute is set to AES-only. Phase 2 is repeated identically. Expected result: the returned ticket is now AES-encrypted (`0x12`); a real crack attempt (hashcat/John) against each ticket is compared for feasibility, illustrating the practical security gain from disabling RC4 — expected to be dramatically slower or infeasible in a reasonable timeframe for the AES version, versus a fast/feasible crack for the RC4 version if a weak password was used.

**Note for this section once complete:** state actual crack time/attempts-per-second observed, not just "it was slower" — a concrete number is more credible than a qualitative claim.

---

## 6. Attack Chain

```
T1110 (Brute Force) → jsmith credentials compromised
        ↓
T1558.003 (Kerberoasting) → service account ticket obtained using compromised jsmith session
```

This structure was chosen deliberately over building two disconnected detection demos — it reflects how a real compromise typically escalates from initial access to further credential harvesting, rather than presenting isolated techniques.

---

## 7. Automated Response (SOAR)

Built in Shuffle (cloud-hosted, [shuffler.io](https://shuffler.io)), triggered by Splunk webhook alert actions.

### 7.1 — High-Confidence Path (Alert 4.1)

```
Splunk webhook → Slack notification (#alerts)
                     ↓
        ┌────────────┴────────────┐
        ↓                         ↓
  SOC analyst email          Account-holder
  approval (yes/no)          notification
        ↓                    (informational
   [if yes]                   only, no gate)
        ↓
  Disable jsmith via LDAP (Active Directory app)
        ↓
  Verify userAccountControl reflects ACCOUNTDISABLE
        ↓
        ┌──────────┴──────────┐
        ↓                     ↓
  Confirmation email    Slack confirmation
```

**[TO VERIFY]:** full end-to-end execution against the live DC — LDAP connection (server, port 389, domain, base DN `CN=Users,DC=mydifr,DC=local`) is configured but not yet tested for actual reachability/authentication, since Shuffle's cloud infrastructure cannot reach the internal `192.168.10.0/24` network without a tunnel (ngrok or similar) established first.

### 7.2 — Lower-Confidence Path (Alert 4.2)

**[PLANNED — NOT YET BUILT]**

Implemented as a native Splunk alert action rather than routed through Shuffle, since Splunk-SVR already sits on the same internal network as the target (no tunnel required) and Shuffle has no native SSH/WinRM connector. A local script on Splunk-SVR SSHes into AD-WIN10 and runs `New-NetFirewallRule` to block the offending source IP — automatically, with no human approval gate, since the action is reversible and low-impact.

### 7.3 — Kerberoasting Path (Alert 4.3)

No automated response. Flagged explicitly for manual investigation — automatically rotating a service account's password risks breaking a live service still referencing the old credential elsewhere, which is a judgment call better made by a human with context on that specific service.

---

## 8. Design Decisions & Trade-offs

**Why account-disable requires approval but IP-ban doesn't:** disabling an account is high-impact and disruptive if wrong (a real employee loses access to everything instantly); blocking an IP is low-impact and fully reversible. The response speed/false-positive-cost trade-off is resolved differently for each, rather than applying one blanket automation policy.

**Why the account-holder notification is parallel, not sequential:** notifying the account holder as a *gate* before response would both slow down containment and risk notifying a potentially-compromised inbox. Notification and containment happen independently.

**Why Kerberoasting has no automated remediation:** the "correct" fix (service account password rotation) has a failure mode worse than the vulnerability itself if done carelessly (breaking the live service), so it's deliberately left to human judgment rather than automated for the sake of completeness.

**Why RC4 hardening is framed as a separate control from detection:** detection reacts to something that already happened; disabling RC4 removes the vulnerable option before an attacker can exploit it at all. Documenting both together shows the difference between reactive and preventive controls rather than relying on detection alone.

---

## 9. Deltas Beyond the Base Tutorial

- Local VirtualBox build instead of a cloud-hosted VM (Vultr)
- Dedicated, persistent Kali attacker VM instead of a "VPN from another machine" approach
- Sysmon deployed on both Windows hosts in addition to native Windows Security logging
- A second, independently-designed detection alert (windowed brute-force threshold) not present in the base tutorial
- Slack integration via native Incoming Webhooks rather than Shuffle's built-in Slack OAuth app (see Section 10)
- A full second attack stage (Kerberoasting) chained onto the original brute-force scenario, including a before/after RC4-to-AES hardening demonstration
- IP-ban response implemented as a native Splunk alert action rather than forced through the SOAR platform, once it became clear the SOAR path would require exposing internal infrastructure to the public internet purely to satisfy the platform

---

## 10. Notable Issues Encountered

- Shuffle's built-in Slack OAuth integration failed with an "invalid permissions requested" error, reproducible regardless of which Slack workspace was targeted. Resolved by using Slack's native Incoming Webhooks feature with a generic HTTP POST node instead of Shuffle's dedicated Slack app.
- Shuffle's shared/reusable "Authentication" credential object proved unreliable when linked across multiple Active Directory nodes referencing the same connection — the link would silently break. Resolved by configuring connection credentials directly on each individual node instead.
- Shuffle trigger nodes (webhooks) can only connect to exactly one downstream node — branching to multiple parallel paths must happen one step later, off a regular action node.
- No native SSH/WinRM integration exists in Shuffle's app store; combined with Shuffle's cloud infrastructure being unable to reach the internal lab network without a tunnel, this led to keeping the IP-ban response entirely within Splunk rather than Shuffle.

---

## 11. Results

**[TO BE COMPLETED]** — fill in with actual outcomes once testing is done:

- [ ] Alert 4.1 fired on real brute-force success — screenshot
- [ ] Alert 4.2 fired on real brute-force attempts — screenshot
- [ ] Alert 4.3 fired on real Kerberoasting attempt — screenshot
- [ ] Shuffle Branch 1 executed end-to-end successfully — screenshot of Slack thread + disabled account
- [ ] IP-ban script executed successfully — screenshot of blocked connection attempt
- [ ] RC4 vs AES crack-time comparison — actual numbers

---

## 12. Lessons Learned / Future Work

- Automate the Kerberoasting → service-account-rotation response once a safe, service-aware method is designed
- Extend detection coverage beyond RDP-based brute force (e.g., lateral movement, PowerShell abuse, pass-the-ticket)
- Correlate the brute-force and successful-logon alerts into a single higher-confidence combined signal (rapid failures immediately followed by a success from the same account/IP)
- Consider self-hosting Shuffle within the lab network to avoid the tunnel dependency entirely for future SOAR integrations

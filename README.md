# Full Project Writeup — AD Home Lab with Splunk SIEM and SOAR Automation

> **Note on this document:** Sections marked **[PLANNED — NOT YET VERIFIED]** describe intended behavior that has been designed and built but not yet executed against the real environment. Sections marked **[VERIFIED]** have been run against the real environment and reflect actual observed results, including real debugging.

---

## 1. Executive Summary

This project simulates a small enterprise Active Directory environment, then layers detection engineering and automated incident response on top of it. The scenario: a domain account is compromised via brute force, the compromise is detected by a custom SIEM pipeline, and a tiered response — partly automated, partly human-approved — contains it. A second attack stage (Kerberoasting) is chained onto the first to demonstrate a realistic multi-step compromise rather than an isolated technique.

Base reference: MYDFIR's "Active Directory Project 2.0" tutorial series, extended with several original additions (Section 9), and with several real infrastructure limitations discovered and worked around during build (Section 10).

---

## 2. Environment

Built entirely on local VirtualBox (not cloud-hosted), on a NAT Network named `AD-Project` (`192.168.10.0/24`).

| VM | Role | IP | Specs |
|---|---|---|---|
| AD-DC02 | Domain Controller (`mydifr.local`) | 192.168.10.10 | Windows Server 2022, 4096MB RAM, 2 CPU |
| AD-WIN10 | Domain-joined workstation | 192.168.10.100 | Windows 10 Pro, 6144MB RAM, 2 CPU |
| Splunk-SVR | SIEM | 192.168.10.6 | Ubuntu Server 24.04 LTS, 6144MB RAM, 2 CPU |
| Kali Linux | Attacker | **192.168.10.101 (static)** | Kali rolling, default image |

Each Windows VM and Splunk-SVR has a second NIC on plain NAT for host internet access and port-forwarding, kept separate from the internal lab network — meaning the host machine cannot directly reach `192.168.10.0/24` addresses without explicit port forwarding.

Domain user of interest: `mydifr\jsmith` (password: `Winter2025!`). AD-WIN10 also has a local admin account, `localadmin`, used for machine-level configuration (e.g. enabling Remote Desktop) that jsmith doesn't have rights to perform.

**[VERIFIED]** Kali initially relied on DHCP and was assigned `192.168.10.6` — an IP collision with Splunk-SVR's static address. Resolved by manually configuring Kali with a static IP (`192.168.10.101`) outside the DHCP-assigned range.

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

**[VERIFIED] VM clock drift after saved-state pauses.** Both AD-DC02 and Splunk-SVR developed significant system clock drift (Splunk-SVR was off by ~4 hours) after sitting in VirtualBox's saved-state for an extended period between sessions. This silently broke Splunk's alert scheduling. Fixed via `sudo timedatectl set-ntp true` on Splunk-SVR followed by `sudo /opt/splunk/bin/splunk restart --run-as-root`. **Lesson for future sessions:** always verify VM clocks after resuming from a long saved-state before trusting any timestamp-dependent behavior (alert scheduling, event correlation, screenshots).

---

## 4. Detection Engineering

Three alerts, each targeting a distinct stage of the attack chain (Section 6), tuned to reduce false positives specific to this lab's fully-internal topology.

### 4.1 — Unauthorized Successful Logon (Event ID 4624) — [VERIFIED]

```spl
index=mydifr-ad EventCode=4624
(Source_Network_Address=* AND Source_Network_Address!="-"
 AND NOT (Source_Network_Address="192.168.10.10" OR Source_Network_Address="192.168.10.100"))
| stats count by _time, ComputerName, Source_Network_Address, user, Logon_Type
```

Unlike the base tutorial (which relied on a public/private IP split), this environment is fully internal, so "unauthorized" is defined via an allowlist of the two legitimate hosts (the DC and the workstation) rather than a geographic/network boundary.

**Field-name correction:** the field is `Source_Network_Address` (capitalized, underscored — matching Windows' raw XML field naming) — not the lowercase `source_network_address` originally assumed. This was silently causing the query to return zero results despite matching events genuinely existing in the index. Confirmed by manually expanding a real event's full field list in Splunk rather than trusting an assumed name. **This is inconsistent across event types** — see 4.2 below, where the lowercase form turned out to be correct.

### 4.2 — Brute-Force Threshold, Time-Windowed (Event ID 4625) — [VERIFIED]

```spl
index=mydifr-ad EventCode=4625 LogName=Security
| sort 0 _time
| streamstats time_window=90s count as recent_failures by user, src_ip
| where recent_failures >= 5
```

A rolling time window was chosen over a flat count specifically to distinguish tool-speed brute-forcing (many attempts in seconds) from slower, non-malicious noise such as a stale cached credential retrying periodically over hours.

**Field name:** unlike 4624, the lowercase `src_ip` field is correct here — Splunk's Windows TA generates a CIM-normalized lowercase field for 4625 events that it does not consistently generate for 4624. **Verified by expanding a real 4625 event's full field list**, rather than assuming consistency with the 4624 fix.

**Two additional real bugs found and fixed:**
- `streamstats` with `time_window` requires events in ascending chronological order. Splunk's default result order is newest-first, which silently breaks the trailing-window calculation. Fixed by adding `| sort 0 _time` before the `streamstats` line.
- With exactly 5 real failed attempts generated during testing, `where recent_failures > 5` can mathematically never trigger (it requires a 6th attempt to exceed 5). Corrected to `>= 5`.

**Window sizing note:** `time_window=90s` was tuned against real observed data — 5 manually-generated failed login attempts (see Section 5, Phase 1) spanned a full 51 seconds due to the manual pace of triggering each one individually. A production deployment tuned against genuine automated brute-force tooling (which operates on the order of seconds, not tens of seconds) would likely use a much tighter window, closer to the original `10s` design intent.

### 4.3 — Kerberoasting Detection (Event ID 4769) — [PLANNED — NOT YET VERIFIED]

```spl
index=mydifr-ad EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="krbtgt" Service_Name!="*$"
| stats count dc(Service_Name) as unique_services by Account_Name, IpAddress
| where count > 3
```

Flags RC4-encrypted service ticket requests (the weaker, more easily-cracked encryption type) from an account requesting tickets across multiple distinct services in a short window — the behavioral signature of an SPN-enumeration tool rather than normal usage.

**[TO VERIFY]:** given that both other queries in this project turned out to have incorrect field-name assumptions (`Source_Network_Address` vs. `source_network_address`, and inconsistent capitalization between event types), this query's field names should NOT be trusted until checked against a real captured 4769 event the same way the other two were corrected.

---

## 5. Attack Simulation Methodology

### Phase 1 — Brute Force (T1110) — [VERIFIED, with a real tooling substitution]

**Original plan:** run Hydra from Kali against jsmith over RDP.

**What actually happened:** Hydra's RDP module (explicitly labeled "experimental" by Hydra itself) successfully identified the correct password (`jsmith:Winter2025!`) but **did not generate a corresponding Windows Security event**. Investigation (checking Event Viewer directly on AD-WIN10, bypassing Splunk entirely) confirmed zero 4624/4625 events were logged for the time window Hydra ran in, despite Hydra reporting a valid password found. This appears to be a known limitation where Hydra's RDP module validates credentials at a lower protocol layer without completing a full interactive logon session that Windows would log.

**Workaround used:** manual `xfreerdp` connections instead, which do complete a full RDP handshake and reliably generate real Windows Security events:

```
xfreerdp /v:192.168.10.100 /u:jsmith /p:'<password>' /cert:ignore
```

Five wrong passwords were attempted this way (generating 5 real 4625 events, timestamps spanning 51 seconds), followed by the correct password (generating one real 4624 event, Logon Type 10, `Source_Network_Address: 192.168.10.101`).

**Two additional real prerequisites discovered before RDP would accept any login at all:**
- Remote Desktop is disabled by default on Windows 10 and had to be manually enabled (Settings → System → Remote Desktop) — this specifically required being logged in as the local `localadmin` account, since jsmith (a standard domain user) does not have rights to change this system setting.
- Even with RDP enabled, jsmith's login was rejected with "account not active for remote desktop" until explicitly added to the local Remote Desktop Users group: `net localgroup "Remote Desktop Users" mydifr\jsmith /add`. Enabling RDP does not, by itself, authorize any given user to use it.

**Result:** Alert 4.2 (brute-force threshold) fired correctly on the 5 manual failures; Alert 4.1 (unauthorized successful logon) fired correctly on the final successful login.

### Phase 2 — Kerberoasting (T1558.003) — [PLANNED — NOT YET BUILT]

Prerequisite: a dedicated service account is created on AD-DC02 with a registered SPN (`setspn -A service/name serviceaccount`), since Kerberoasting specifically targets service accounts rather than regular user accounts like `jsmith`.

Using the credentials obtained in Phase 1, Impacket's `GetUserSPNs.py` (pre-installed on Kali) is run against the domain, authenticated as `jsmith`, to enumerate and request a service ticket for the target service account. Expected result: alert 4.3 fires; the returned ticket is RC4-encrypted (`0x17`).

### Phase 3 — Encryption Hardening Demonstration — [PLANNED — NOT YET BUILT]

The target service account's `msDS-SupportedEncryptionTypes` attribute is set to AES-only. Phase 2 is repeated identically. Expected result: the returned ticket is now AES-encrypted (`0x12`); a real crack attempt (hashcat/John) against each ticket is compared for feasibility, illustrating the practical security gain from disabling RC4.

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

### 7.1 — High-Confidence Path (Alert 4.1) — [VERIFIED end-to-end, with one known cosmetic issue]

**Original design (as planned):**
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

**What actually shipped, and why it changed:** the automated LDAP disable/verify/confirmation steps were removed from this workflow. Testing (an LDAP connection attempt from Shuffle to the DC through a verified-working ngrok TCP tunnel) confirmed Shuffle's cloud execution environment blocks outbound raw TCP connections on arbitrary ports — the connection attempt timed out with zero connections ever registered on the tunnel, meaning Shuffle's servers never even attempted the call. Shuffle's cloud sandbox appears to permit HTTP/HTTPS egress only (which is why the Slack webhook integration works fine).

**Revised, actually-implemented design:**
```
Splunk webhook → Http node (posts to Slack via Incoming Webhook) → branches into:
  (a) FYI email to account holder (jsmith), no approval gate
  (b) SOC Approval email — asks the analyst to manually review and disable
      the account in Active Directory, then reply once done (dead-end node;
      no further automation)
```

The human-approval gate central to the original design is preserved — the SOC analyst is still the sole authority to disable the account — only the *executor* of the actual disable action changed from Shuffle (blocked) to the human analyst (works).

**Two additional real bugs found before this fired correctly:**
- The webhook trigger node itself was never switched from its default "stopped" state to "started." Splunk fired its scheduled alert correctly, every minute, for over 20 minutes with zero visible effect, because the receiving webhook simply wasn't listening. This was an oversight carried over from initial build, not a configuration error — worth double-checking on any Shuffle webhook trigger before assuming a pipeline is broken.
- Slack Incoming Webhooks were used instead of Shuffle's native Slack app after the native app's OAuth flow repeatedly failed with an "invalid permissions requested" error, reproducible across different Slack workspaces — apparently an issue with Shuffle's registered Slack OAuth app itself, not a user-side misconfiguration.

**Known remaining cosmetic issue, not yet fixed:** the Slack/email message body template uses static placeholder text (e.g. "Source IP: ") that was never wired to Shuffle's actual runtime-variable syntax referencing the real webhook payload fields. The first confirmed live-fire of this pipeline produced a correctly-triggered but content-blank notification. This does not affect the pipeline's functional correctness (detection, routing, and delivery all worked) — only the informational content of the message itself.

### 7.2 — Lower-Confidence Path (Alert 4.2) — [PLANNED — NOT YET BUILT]

Implemented as a native Splunk alert action rather than routed through Shuffle, since Splunk-SVR already sits on the same internal network as the target (no tunnel required) and Shuffle has no native SSH/WinRM connector — the same sandbox limitation discovered in 7.1 applies here too. A local script on Splunk-SVR will SSH into AD-WIN10 and run `New-NetFirewallRule` to block the offending source IP — automatically, with no human approval gate, since the action is reversible and low-impact. Not yet built; requires enabling OpenSSH on AD-WIN10 and setting up key-based SSH auth from Splunk-SVR first.

### 7.3 — Kerberoasting Path (Alert 4.3)

No automated response. Flagged explicitly for manual investigation — automatically rotating a service account's password risks breaking a live service still referencing the old credential elsewhere, which is a judgment call better made by a human with context on that specific service.

---

## 8. Design Decisions & Trade-offs

**Why account-disable requires approval but IP-ban doesn't:** disabling an account is high-impact and disruptive if wrong (a real employee loses access to everything instantly); blocking an IP is low-impact and fully reversible. The response speed/false-positive-cost trade-off is resolved differently for each, rather than applying one blanket automation policy.

**Why the account-holder notification is parallel, not sequential:** notifying the account holder as a *gate* before response would both slow down containment and risk notifying a potentially-compromised inbox. Notification and containment happen independently.

**Why Kerberoasting has no automated remediation:** the "correct" fix (service account password rotation) has a failure mode worse than the vulnerability itself if done carelessly (breaking the live service), so it's deliberately left to human judgment rather than automated for the sake of completeness.

**Why RC4 hardening is framed as a separate control from detection:** detection reacts to something that already happened; disabling RC4 removes the vulnerable option before an attacker can exploit it at all. Documenting both together shows the difference between reactive and preventive controls rather than relying on detection alone.

**Why the account-disable action is human-executed rather than platform-automated:** this wasn't the original plan — it's a direct consequence of discovering that Shuffle's cloud execution sandbox restricts outbound traffic to HTTP/HTTPS only. Rather than working around the restriction (e.g. self-hosting Shuffle, or building a custom local relay service purely to route around a platform limitation), the simpler and arguably more defensible choice was made: keep the human-approval gate exactly where it already was, and have the same human execute the approved action directly. This mirrors a real consideration in SOAR tooling selection — cloud-hosted SOAR platforms are not always able to reach fully air-gapped or internally-isolated infrastructure, and response architecture needs to account for that rather than assume unlimited platform reach.

---

## 9. Deltas Beyond the Base Tutorial

- Local VirtualBox build instead of a cloud-hosted VM (Vultr)
- Dedicated, persistent Kali attacker VM instead of a "VPN from another machine" approach
- Sysmon deployed on both Windows hosts in addition to native Windows Security logging
- A second, independently-designed detection alert (windowed brute-force threshold) not present in the base tutorial
- Slack integration via native Incoming Webhooks rather than Shuffle's built-in Slack OAuth app (see Section 10)
- A full second attack stage (Kerberoasting) chained onto the original brute-force scenario, including a before/after RC4-to-AES hardening demonstration
- IP-ban response designed as a native Splunk alert action rather than forced through the SOAR platform, once it became clear the SOAR path would require exposing internal infrastructure to the public internet purely to satisfy the platform
- Account-disable automation was scoped back from full LDAP automation to a human-executed action with an automated approval workflow, after discovering a genuine platform limitation (Section 7.1) — an honest architectural adjustment made mid-build rather than a shortcut

---

## 10. Notable Issues Encountered

This section intentionally documents real debugging, not just the finished result — the process of finding and fixing these is itself part of the demonstrated skill set.

- **Shuffle's built-in Slack OAuth integration failed** with an "invalid permissions requested" error, reproducible regardless of which Slack workspace was targeted. Resolved by using Slack's native Incoming Webhooks feature with a generic HTTP POST node instead of Shuffle's dedicated Slack app.
- **Shuffle's shared/reusable "Authentication" credential object proved unreliable** when linked across multiple Active Directory nodes referencing the same connection — the link would silently break. Resolved by configuring connection credentials directly on each individual node instead.
- **Shuffle trigger nodes (webhooks) can only connect to exactly one downstream node** — branching to multiple parallel paths must happen one step later, off a regular action node.
- **Shuffle's cloud execution sandbox blocks outbound raw TCP** on arbitrary ports (confirmed via an LDAP connection attempt through a verified-working ngrok tunnel, which timed out with zero connections ever registered on the tunnel side). Only HTTP/HTTPS egress appears to be permitted. This is the direct cause of the Section 7.1 and 7.2 architecture changes.
- **ngrok's free tier requires payment-card identity verification** (explicitly not charged) before allowing any TCP tunnel — an unexpected wall encountered mid-session that cost significant time before being resolved.
- **A VM network adapter correctly configured in VirtualBox's settings can still fail to obtain a DHCP address** — Kali's adapter was correctly attached to the right NAT Network but received no IPv4 address at all; root cause traced to the NAT Network's DHCP pool independently assigning an already-in-use static address (a collision with Splunk-SVR) rather than a client-side misconfiguration. Resolved with a manually-assigned static IP outside the DHCP range.
- **Windows RDP has two independent gates, not one:** enabling the Remote Desktop feature itself, and separately authorizing a specific user account via the local "Remote Desktop Users" group. A correct password and an enabled RDP service are not sufficient on their own.
- **Hydra's RDP module (labeled experimental by the tool itself) does not reliably generate complete Windows authentication events**, despite correctly identifying valid credentials — likely validating only at a lower protocol layer than a full interactive session. Verified failed events required switching to manual `xfreerdp` connections instead.
- **Splunk field names are fully case-sensitive and inconsistently capitalized across different Windows Event IDs** even within the same TA — `Source_Network_Address` (4624) vs. `src_ip` (4625) for conceptually the same data. A query that looks syntactically correct can silently return zero results indefinitely if the assumed field name doesn't match Splunk's actual extraction for that specific event type. The only reliable fix is manually expanding a real captured event and checking its exact extracted field list before trusting any field name in a new query.
- **`streamstats time_window` requires ascending chronological sort order** to calculate a trailing window correctly; Splunk's default newest-first result order silently breaks this.
- **VM system clocks drift significantly during extended VirtualBox saved-state periods**, which can silently break time-dependent Splunk behavior (alert scheduling, in this case) without any explicit error — worth checking directly (`date` / `timedatectl`) any time a VM resumes after a long pause, rather than assuming the clock is correct.
- **A fully correct, firing alert produces no visible effect if its downstream webhook trigger was never switched from "stopped" to "started."** Both this and the field-name issues above cost significant debugging time before being isolated — each required directly inspecting raw data (a real event's field list, a tunnel's connection counter, a webhook's own start/stop state) rather than assuming the configuration was correct and searching for a different cause.

---

## 11. Results

- [x] **Alert 4.1 (unauthorized successful logon) fired on a real, manually-generated attack** — confirmed via Splunk's Triggered Alerts history.
- [x] **Alert 4.2 (brute-force threshold) fired on real, manually-generated failed attempts** — confirmed via Splunk's Triggered Alerts history.
- [ ] Alert 4.3 (Kerberoasting) fired on real data — not yet attempted.
- [x] **Shuffle pipeline executed end-to-end automatically**, with zero manual intervention beyond starting the webhook trigger — Slack notification and email both fired for real. **Known caveat:** message body content was blank due to an unwired runtime-variable template (Section 7.1); the pipeline's routing and delivery were correct, the content was not yet populated.
- [ ] Manual AD account disable performed and screenshotted, matching the SOC Approval flow's design.
- [ ] IP-ban script executed successfully — not yet built.
- [ ] RC4 vs AES crack-time comparison — not yet attempted.

*(Screenshots to be inserted: Splunk Triggered Alerts list, Kali terminal output from the xfreerdp attack sequence, the blank-but-triggered Slack message, the eventual fixed Slack message once the variable-mapping issue is resolved.)*

---

## 12. Lessons Learned / Future Work

- Automate the Kerberoasting → service-account-rotation response once a safe, service-aware method is designed.
- Extend detection coverage beyond RDP-based brute force (e.g., lateral movement, PowerShell abuse, pass-the-ticket).
- Correlate the brute-force and successful-logon alerts into a single higher-confidence combined signal (rapid failures immediately followed by a success from the same account/IP).
- Consider self-hosting Shuffle within the lab network to avoid both the cloud sandbox's TCP restriction and the tunnel dependency entirely for future SOAR integrations.
- **Never trust an assumed Splunk field name — always verify against a real captured event first.** This single lesson, learned the hard way across two separate queries, was the single largest source of debugging time in this project.
- **Always verify VM clock accuracy after any extended saved-state pause**, before debugging anything else that depends on timing or scheduling.
- Fix the Shuffle message-body variable mapping so notifications carry real incident data rather than a correctly-triggered-but-empty template.

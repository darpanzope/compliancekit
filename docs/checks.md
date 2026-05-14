# Check catalog

<!--
  AUTO-GENERATED FILE -- DO NOT EDIT BY HAND.
  Regenerate with: make docs
  Source of truth: internal/checks/**/*.go (the core.Check vars).
-->

This catalog is generated from the live registry on each release. At the current revision, compliancekit ships **20 checks** across the providers below.

Each check below has:

- A stable **ID** (the string CI gates and waiver files reference).
- A **severity** in {`critical`, `high`, `medium`, `low`, `info`}.
- A list of **framework controls** it maps to (SOC 2 TSC, ISO 27001:2022 Annex A, CIS Controls v8).
- A **description** of the underlying concern.
- A copy-pastable **remediation** for the typical hosting setup.

To inspect a single check from the CLI: `compliancekit checks show <id>`.

## By provider

| Provider | Checks |
|---|---:|
| `digitalocean` | 5 |
| `linux` | 15 |
| **total** | **20** |

## By severity

| Severity | Checks |
|---|---:|
| `high` | 8 |
| `medium` | 6 |
| `low` | 6 |

## digitalocean

### `do-droplet-backups-disabled`

**Droplet backups must be enabled** &middot; severity `medium` &middot; service `droplets` &middot; resource `digitalocean.droplet`

DigitalOcean droplet backups take a weekly snapshot used to recover from incidents, ransomware, or accidental deletion. SOC 2 CC6.6 and CIS Controls v8 11.2 both require some form of backup capability for production data.

_Remediation:_

> Enable backups for the droplet via 'doctl compute droplet-action enable-backups <id>' or set 'backups: true' in your Terraform digitalocean_droplet resource.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.5.30` | ICT Readiness for Business Continuity |
| `iso27001` | `A.8.13` | Information Backup |
| `soc2` | `A1.2` | Availability - Backup and Recovery |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `backup`, `recovery`

---

### `do-droplet-no-firewall`

**Public-IP droplets must have at least one firewall attached** &middot; severity `high` &middot; service `droplets` &middot; resource `digitalocean.droplet`

A droplet exposed to the internet via a public IPv4 address with no firewall has every listening port reachable from anywhere. Cloud-native compliance frameworks treat this as a critical control gap: SOC 2 CC6.6 (logical access controls), CIS Controls v8 4.4 (network filtering), and ISO 27001 A.8.21 all require restricted network access for production resources.

_Remediation:_

> Create a DigitalOcean Cloud Firewall and attach it: 'doctl compute firewall create --name web-fw --inbound-rules "protocol:tcp,ports:443,sources:address:0.0.0.0/0" --droplet-ids <id>'. In Terraform, use the digitalocean_firewall resource and set droplet_ids on it.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `cross-resource`, `exposure`, `network`

---

### `do-droplet-no-tags`

**Droplets should carry attribution tags** &middot; severity `low` &middot; service `droplets` &middot; resource `digitalocean.droplet`

Tags are how DigitalOcean resources are grouped for firewall membership, cost attribution, and operational queries. A droplet without any tags is effectively orphaned: incidents are harder to triage, costs harder to allocate, and bulk operations harder to scope. SOC 2 CC1.4 and CIS Controls v8 1.1 both expect inventory attribution.

_Remediation:_

> Add at least one tag identifying environment and owner: 'doctl compute droplet tag <id> --tag-name prod' or set 'tags' in your Terraform digitalocean_droplet resource.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of Information and Other Associated Assets |
| `soc2` | `CC1.4` | Commitment to Competence |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `attribution`, `inventory`

---

### `do-droplet-old-image`

**Droplet base image should be less than one year old** &middot; severity `medium` &middot; service `droplets` &middot; resource `digitalocean.droplet`

A droplet running an image older than one year is likely missing patches for vulnerabilities disclosed since the image was built. Rebuilding from a current image (or rotating the droplet) is the cleanest mitigation. SOC 2 CC7.1 and CIS Controls v8 7.5 both require a documented patch cadence.

_Remediation:_

> Rebuild the droplet from a current image ('doctl compute droplet-action rebuild <id> --image ubuntu-22-04-x64') or rotate it via an updated Terraform digitalocean_droplet block.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.5` | Perform Automated Vulnerability Scans of Internal Enterprise Assets |
| `iso27001` | `A.8.19` | Installation of Software on Operational Systems |
| `iso27001` | `A.8.8` | Management of Technical Vulnerabilities |
| `soc2` | `CC7.1` | System Operations - Vulnerabilities |
| `soc2` | `CC7.2` | System Operations - Monitoring |

_Tags:_ `patching`, `vulnerability`

---

### `do-firewall-ssh-from-any`

**Firewalls must not allow SSH (port 22) from the public internet** &middot; severity `high` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

An inbound firewall rule allowing TCP port 22 from 0.0.0.0/0 or ::/0 exposes SSH brute-force attempts to every host on the internet. Restrict SSH to bastion IPs, VPN ranges, or use the DigitalOcean web console SSH gateway. SOC 2 CC6.6, ISO 27001 A.8.21, and CIS Controls v8 4.4 all require restricted administrative access.

_Remediation:_

> Replace the rule with a narrow source range: 'doctl compute firewall update <id> --inbound-rules "protocol:tcp,ports:22,sources:address:203.0.113.0/24"'. In Terraform, narrow the 'sources.addresses' list on the matching inbound_rule block.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `exposure`, `network`, `ssh`

---

## linux

### `linux-aslr-enabled`

**Address Space Layout Randomization must be fully enabled** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

ASLR randomizes the address space of running processes, raising the cost of memory-corruption exploits. kernel.randomize_va_space=2 is the full-strength setting (stack + heap + brk + vdso + mmap). 0 disables; 1 is a weakened subset. CIS Ubuntu 3.2.1.

_Remediation:_

> sysctl -w kernel.randomize_va_space=2 (runtime) and add the line to /etc/sysctl.conf or a drop-in under /etc/sysctl.d/ for persistence.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.8` | Management of Technical Vulnerabilities |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `exploit-mitigation`, `kernel`

---

### `linux-auditd-running`

**auditd must be running** &middot; severity `medium` &middot; service `audit` &middot; resource `linux.host`

auditd captures syscall-level audit events that satisfy 'log access to sensitive systems' controls. Without it, evidence for SOC 2 CC7.2, ISO 27001 A.8.15, and CIS Controls v8 8.5 is hard to produce.

_Remediation:_

> Install and enable auditd: 'sudo apt install auditd && sudo systemctl enable --now auditd' (Debian/Ubuntu) or the equivalent on your distro.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Operations - Monitoring |
| `soc2` | `CC7.3` | System Operations - Incident Evaluation |

_Tags:_ `audit`, `logging`

---

### `linux-firewall-active`

**A host firewall must be active** &middot; severity `high` &middot; service `firewall` &middot; resource `linux.host`

A host with no active firewall accepts every packet its NIC sees. ufw and nftables are the two modern Linux options; this check passes when either reports an active state. SOC 2 CC6.6, ISO 27001 A.8.20, and CIS Controls v8 4.4 all require network access controls on production hosts.

_Remediation:_

> Enable ufw ('sudo ufw enable' on Debian/Ubuntu) or nftables ('sudo systemctl enable --now nftables'). Verify with 'sudo ufw status' or 'sudo nft list ruleset'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks Security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `firewall`, `network`

---

### `linux-firewall-default-deny`

**Firewall default-incoming policy must be deny** &middot; severity `high` &middot; service `firewall` &middot; resource `linux.host`

An active firewall whose default policy is allow is only slightly safer than no firewall at all -- every port without an explicit deny rule is reachable. Default-deny with explicit allows is the only defensible posture. SOC 2 CC6.6, ISO 27001 A.8.20, and CIS Controls v8 4.4 require this.

_Remediation:_

> On ufw: 'sudo ufw default deny incoming'. On nftables, set the inet filter input chain policy to drop.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks Security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `default-policy`, `firewall`, `network`

---

### `linux-journald-persistent`

**journald must use persistent storage** &middot; severity `low` &middot; service `audit` &middot; resource `linux.host`

systemd's journald default ('auto') writes to disk only if /var/log/journal exists, and falls back to a volatile ramdisk otherwise. A reboot wipes the latter and breaks the audit trail. Setting Storage=persistent forces disk storage and creates the directory if missing.

_Remediation:_

> Set 'Storage=persistent' in /etc/systemd/journald.conf and 'systemctl restart systemd-journald'. Confirm with 'journalctl --header | head'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Operations - Monitoring |

_Tags:_ `audit`, `journald`, `logging`

---

### `linux-no-empty-passwords`

**No account may have an empty password** &middot; severity `high` &middot; service `users` &middot; resource `linux.host`

An account whose /etc/shadow password field is literally empty can be logged in to with any password (or no password, depending on PAM config). CIS Ubuntu 7.2.4 requires that no entry have an empty hash; locked accounts use '!' or '*' instead.

_Remediation:_

> passwd -l <user> to lock the account, or set a strong password.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.2` | Use Unique Passwords |
| `iso27001` | `A.8.5` | Secure Authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `passwords`, `users`

---

### `linux-no-source-routing`

**Kernel must not accept source-routed packets** &middot; severity `low` &middot; service `kernel` &middot; resource `linux.host`

Source-routed packets let a sender dictate the path taken across the network, defeating egress filtering and enabling spoofing. Modern Linux defaults to 0 (drop); this check confirms the default has not been overridden. CIS Ubuntu 3.3.1.

_Remediation:_

> sysctl -w net.ipv4.conf.all.accept_source_route=0 and persist via /etc/sysctl.d/.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `iso27001` | `A.8.20` | Networks Security |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `kernel`, `network`

---

### `linux-passwd-perms`

**/etc/passwd must be 0644 or stricter** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

/etc/passwd must be world-readable (login commands need it) but must not be writable by anyone but root. CIS Ubuntu 7.1.2 prescribes mode 0644 exactly; we accept 0644 or stricter (0640, 0600).

_Remediation:_

> chmod 0644 /etc/passwd && chown root:root /etc/passwd.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.3` | Information Access Restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `filesystem`, `passwd`

---

### `linux-shadow-perms`

**/etc/shadow must be 0640 root:shadow** &middot; severity `high` &middot; service `filesystem` &middot; resource `linux.host`

/etc/shadow holds the password hashes for every local account. Read access for non-root, non-shadow users enables offline cracking and is the textbook CIS Ubuntu 7.1.3 finding. Correct ownership is root:shadow with mode 0640.

_Remediation:_

> chmod 0640 /etc/shadow && chown root:shadow /etc/shadow.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `cis-v8` | `5.1` | Establish and Maintain an Inventory of Accounts |
| `iso27001` | `A.8.3` | Information Access Restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `filesystem`, `shadow`

---

### `linux-sshd-login-grace-time`

**SSH LoginGraceTime should be 60 seconds or less** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

LoginGraceTime is the window between connection and authentication completion. A long window lets a misbehaving client (or attacker) hold a connection slot open, enabling slowloris-style resource exhaustion. OpenSSH default is 2 minutes; CIS recommends 60 seconds or less.

_Remediation:_

> Set 'LoginGraceTime 60' in /etc/ssh/sshd_config and reload sshd.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.2` | Use Unique Passwords |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `resource-exhaustion`, `sshd`

---

### `linux-sshd-max-auth-tries`

**SSH MaxAuthTries should be 4 or less** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

MaxAuthTries caps the number of authentication attempts per connection; a low value frustrates online brute-force. The OpenSSH default is 6; CIS Controls v8 recommends 4 or less.

_Remediation:_

> Set 'MaxAuthTries 4' (or lower) in /etc/ssh/sshd_config and reload sshd.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.2` | Use Unique Passwords |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `brute-force`, `sshd`

---

### `linux-sshd-no-password-auth`

**SSH must not accept password authentication** &middot; severity `medium` &middot; service `sshd` &middot; resource `linux.host`

Password authentication exposes SSH to credential stuffing and online brute-force. Public-key authentication is the modern baseline. SOC 2 CC6.1 and CIS Controls v8 5.2 both require strong authentication for remote administrative access.

_Remediation:_

> Set 'PasswordAuthentication no' in /etc/ssh/sshd_config (and confirm operators have working public-key access first to avoid lockout). Reload sshd to apply.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.2` | Use Unique Passwords |
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.21` | Security of Network Services |
| `iso27001` | `A.8.5` | Secure Authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `authentication`, `sshd`

---

### `linux-sshd-no-root-login`

**SSH must not permit root login** &middot; severity `high` &middot; service `sshd` &middot; resource `linux.host`

Direct root SSH logins bypass per-user auditability and remove the speed bump that catches automated brute-force. SOC 2 CC6.1 / CC6.6, ISO 27001 A.8.21, and CIS Controls v8 5.4 all require unique attribution for privileged access.

_Remediation:_

> Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd (systemctl reload sshd). Operators should use a named user + sudo instead.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `access-control`, `sshd`

---

### `linux-sshd-protocol-2`

**SSH must use protocol version 2 only** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

SSH-1 was retired in 2017 and is cryptographically broken. Modern OpenSSH defaults to Protocol 2 and refuses to build SSH-1 without explicit flags; this check confirms the observed config has not been weakened. Mostly an audit-trail check at this point.

_Remediation:_

> Remove any 'Protocol 1' line from /etc/ssh/sshd_config (or set 'Protocol 2' explicitly). Reload sshd to apply.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.20` | Networks Security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `crypto`, `sshd`

---

### `linux-uid-zero-only-root`

**Only the root account may have UID 0** &middot; severity `high` &middot; service `users` &middot; resource `linux.host`

A second account with UID 0 is a stealth backdoor: sudo / auditd see the username but every privilege check resolves to root. CIS Ubuntu 5.4.3 requires that only the literal 'root' user holds UID 0.

_Remediation:_

> userdel <hidden-root-account> or change its UID to a non-zero value with usermod -u <uid> <name>.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `privilege`, `users`

---


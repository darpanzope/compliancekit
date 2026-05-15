// Package ansible implements remediate.Strategy renderers for the
// FormatAnsible output. Linux/CIS host findings get expressed as
// Ansible playbook task fragments operators paste into their
// configuration-management repo.
//
// Each strategy emits one or more `tasks:` entries with idempotent
// modules (lineinfile, sysctl, service, file). Strategies pin
// `become: true` because every Linux hardening change needs root.
package ansible

import (
	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

type strategyFunc func(core.Finding) (remediate.Snippet, error)

type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatAnsible} }
func (s *strategy) Render(f core.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatAnsible {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}

func init() {
	register("ansible-sshd-hardening",
		[]string{
			"linux-sshd-no-root-login",
			"linux-sshd-no-password-auth",
			"linux-sshd-max-auth-tries",
			"linux-sshd-login-grace-time",
			"linux-sshd-protocol-2",
		},
		renderSSHDHardening)
	register("ansible-firewall",
		[]string{"linux-firewall-active", "linux-firewall-default-deny"},
		renderFirewall)
	register("ansible-sysctl-hardening",
		[]string{"linux-aslr-enabled", "linux-no-source-routing"},
		renderSysctlHardening)
	register("ansible-auditd",
		[]string{"linux-auditd-running"}, renderAuditd)
	register("ansible-journald-persistent",
		[]string{"linux-journald-persistent"}, renderJournaldPersistent)
	register("ansible-passwd-perms",
		[]string{"linux-passwd-perms", "linux-shadow-perms"}, renderPasswdPerms)
	register("ansible-no-empty-passwords",
		[]string{"linux-no-empty-passwords"}, renderNoEmptyPasswords)
	register("ansible-uid-zero-only-root",
		[]string{"linux-uid-zero-only-root"}, renderUIDZeroOnlyRoot)
}

func renderSSHDHardening(_ core.Finding) (remediate.Snippet, error) {
	tasks := `- name: Harden sshd
  become: true
  block:
    - name: PermitRootLogin no
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?\s*PermitRootLogin'
        line: 'PermitRootLogin no'
        validate: '/usr/sbin/sshd -t -f %s'
    - name: PasswordAuthentication no
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?\s*PasswordAuthentication'
        line: 'PasswordAuthentication no'
        validate: '/usr/sbin/sshd -t -f %s'
    - name: MaxAuthTries 4
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?\s*MaxAuthTries'
        line: 'MaxAuthTries 4'
        validate: '/usr/sbin/sshd -t -f %s'
    - name: LoginGraceTime 30
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?\s*LoginGraceTime'
        line: 'LoginGraceTime 30'
        validate: '/usr/sbin/sshd -t -f %s'
    - name: Protocol 2 (commentary-only on modern OpenSSH which dropped Protocol 1)
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?\s*Protocol'
        line: 'Protocol 2'
        validate: '/usr/sbin/sshd -t -f %s'
    - name: Reload sshd
      ansible.builtin.service:
        name: sshd
        state: reloaded
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: tasks,
		VerifyCmd: "sshd -T 2>/dev/null | grep -iE 'permitrootlogin|passwordauthentication|maxauthtries|logingracetime'",
		Notes:     "Validates with `sshd -t` before reload — a syntax error won't lock you out. Verify you have key-based access BEFORE applying PasswordAuthentication no.",
	}, nil
}

func renderFirewall(_ core.Finding) (remediate.Snippet, error) {
	tasks := `- name: Enable + default-deny firewall (UFW on Debian/Ubuntu)
  become: true
  when: ansible_os_family == "Debian"
  block:
    - name: Install UFW
      ansible.builtin.apt:
        name: ufw
        state: present
    - name: Allow SSH (22/tcp)
      community.general.ufw:
        rule: allow
        port: 22
        proto: tcp
    - name: Default deny inbound
      community.general.ufw:
        default: deny
        direction: incoming
    - name: Default allow outbound (keep simple — tighten later)
      community.general.ufw:
        default: allow
        direction: outgoing
    - name: Enable UFW
      community.general.ufw:
        state: enabled

- name: Enable + default-deny firewall (firewalld on RHEL/CentOS/Rocky)
  become: true
  when: ansible_os_family == "RedHat"
  block:
    - name: Install firewalld
      ansible.builtin.dnf:
        name: firewalld
        state: present
    - name: Start firewalld
      ansible.builtin.service:
        name: firewalld
        state: started
        enabled: yes
    - name: Set public zone target to DROP
      ansible.posix.firewalld:
        zone: public
        target: DROP
        permanent: yes
        state: enabled
    - name: Allow ssh service
      ansible.posix.firewalld:
        service: ssh
        permanent: yes
        state: enabled
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: tasks,
		Notes: "Allows SSH (port 22) before enabling — confirm you can re-connect via your existing session before disconnecting. Add additional 'allow' tasks before enable if you have other inbound services.",
	}, nil
}

func renderSysctlHardening(_ core.Finding) (remediate.Snippet, error) {
	tasks := `- name: Sysctl hardening — kernel + network
  become: true
  ansible.posix.sysctl:
    name: '{{ item.name }}'
    value: '{{ item.value }}'
    state: present
    reload: yes
    sysctl_set: yes
  loop:
    - { name: 'kernel.randomize_va_space', value: '2' }              # ASLR fully on
    - { name: 'net.ipv4.conf.all.accept_source_route', value: '0' }  # source routing off
    - { name: 'net.ipv4.conf.default.accept_source_route', value: '0' }
    - { name: 'net.ipv6.conf.all.accept_source_route', value: '0' }
    - { name: 'net.ipv6.conf.default.accept_source_route', value: '0' }
    - { name: 'net.ipv4.conf.all.accept_redirects', value: '0' }
    - { name: 'net.ipv4.conf.default.accept_redirects', value: '0' }
    - { name: 'net.ipv4.conf.all.send_redirects', value: '0' }
    - { name: 'net.ipv4.conf.default.send_redirects', value: '0' }
    - { name: 'net.ipv4.tcp_syncookies', value: '1' }
`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: tasks,
		VerifyCmd: "sysctl kernel.randomize_va_space net.ipv4.conf.all.accept_source_route",
	}, nil
}

func renderAuditd(_ core.Finding) (remediate.Snippet, error) {
	tasks := `- name: Install + start auditd
  become: true
  block:
    - name: Install (Debian)
      ansible.builtin.apt:
        name: auditd
        state: present
      when: ansible_os_family == "Debian"
    - name: Install (RHEL)
      ansible.builtin.dnf:
        name: audit
        state: present
      when: ansible_os_family == "RedHat"
    - name: Start + enable auditd
      ansible.builtin.service:
        name: auditd
        state: started
        enabled: yes
`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: tasks,
		VerifyCmd: "systemctl is-active auditd && auditctl -s",
	}, nil
}

func renderJournaldPersistent(_ core.Finding) (remediate.Snippet, error) {
	tasks := `- name: Make systemd-journald storage persistent
  become: true
  block:
    - name: Set Storage=persistent in journald.conf
      ansible.builtin.lineinfile:
        path: /etc/systemd/journald.conf
        regexp: '^#?\s*Storage='
        line: 'Storage=persistent'
    - name: Ensure /var/log/journal exists
      ansible.builtin.file:
        path: /var/log/journal
        state: directory
        owner: root
        group: systemd-journal
        mode: '2755'
    - name: Restart systemd-journald
      ansible.builtin.service:
        name: systemd-journald
        state: restarted
`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: tasks,
		VerifyCmd: "journalctl --header | grep -E 'File path:'",
	}, nil
}

func renderPasswdPerms(_ core.Finding) (remediate.Snippet, error) {
	tasks := `- name: Fix /etc/passwd and /etc/shadow permissions
  become: true
  block:
    - name: /etc/passwd 644 root:root
      ansible.builtin.file:
        path: /etc/passwd
        owner: root
        group: root
        mode: '0644'
    - name: /etc/shadow 640 root:shadow
      ansible.builtin.file:
        path: /etc/shadow
        owner: root
        group: shadow
        mode: '0640'
    - name: /etc/group 644 root:root
      ansible.builtin.file:
        path: /etc/group
        owner: root
        group: root
        mode: '0644'
    - name: /etc/gshadow 640 root:shadow
      ansible.builtin.file:
        path: /etc/gshadow
        owner: root
        group: shadow
        mode: '0640'
`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: tasks,
		VerifyCmd: "stat -c '%n %a %U %G' /etc/passwd /etc/shadow /etc/group /etc/gshadow",
	}, nil
}

func renderNoEmptyPasswords(_ core.Finding) (remediate.Snippet, error) {
	tasks := `- name: Remove any empty-password lines from /etc/shadow
  become: true
  ansible.builtin.shell: |
    awk -F: '($2 == "") {print $1}' /etc/shadow > /tmp/empty-pw-users
    while read -r u; do
      passwd -l "$u"   # lock instead of leaving empty
    done < /tmp/empty-pw-users
    rm -f /tmp/empty-pw-users
  args:
    executable: /bin/bash
  changed_when: false
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: tasks,
		Notes: "Locks accounts with empty passwords rather than deleting them — review the listed users before continuing. A locked account can still log in via SSH keys; if you want full lockout, also remove their authorized_keys.",
	}, nil
}

func renderUIDZeroOnlyRoot(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: `# Manual remediation — multiple UID 0 accounts is a severe finding.
awk -F: '($3 == 0) {print $1}' /etc/passwd
# Investigate every name returned. Standard installs have only "root".
# Any other UID 0 entry is either: 1) an intentional second admin (rare; usually a bad
# practice — give the human their own UID + sudo), or 2) a backdoor. Remove via:
#   userdel BAD_USER
# but ONLY after confirming with the system owner.
`,
		Notes: "This is one of the highest-priority Linux findings and almost always indicates either misconfiguration or compromise. Do not auto-remediate.",
	}, nil
}

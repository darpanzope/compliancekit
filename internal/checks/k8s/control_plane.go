package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.21 phase 7 — CIS Kubernetes Benchmark §1 (Control Plane
// Components) + §4.2 (kubelet) manual-verify checks. 15 checks
// covering the configuration dimensions an auditor needs evidence
// for, structured per the v0.20 manualVerifySpec pattern.
//
// All checks are manual-verify because the relevant configuration
// lives on the control-plane nodes (apiserver flags via static pod
// manifest, kubelet flags via /var/lib/kubelet/config.yaml or the
// systemd unit) which the K8s API does not expose. The auditor
// SSHs to the control-plane node + greps the static pod manifest
// or kubelet config; on managed K8s (EKS / GKE / DOKS) the flag is
// vendor-fixed and the auditor confirms via the cloud provider's
// docs.

// cpvSpec encodes one control-plane manual-verify check.
type cpvSpec struct {
	id, title, group string
	cis              []string
	soc2, iso        []string
	severity         core.Severity
	description      string
	remediation      string
	hint             string
	tags             []string
	scanner          string
}

var cpvSpecs = []cpvSpec{
	// ----- apiserver §1.2 -----
	{
		id: "k8s-cp-apiserver-anonymous-auth", title: "kube-apiserver --anonymous-auth must be false",
		group: "apiserver", cis: []string{"1.2.1"}, severity: core.SeverityHigh,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.15"},
		description: "AnonymousAuth lets system:anonymous reach the API. " +
			"Even read-only endpoints can leak resource shape under enumeration. " +
			"The k8s default is true on self-managed clusters before 1.6 + " +
			"some hardened defaults flip to false.",
		remediation: "On self-managed: set --anonymous-auth=false in the " +
			"apiserver static pod manifest at /etc/kubernetes/manifests/kube-" +
			"apiserver.yaml. On managed K8s the vendor sets this — confirm in " +
			"the cloud provider's API server hardening docs.",
		hint:    "ssh <cp-node> 'grep anonymous-auth /etc/kubernetes/manifests/kube-apiserver.yaml'  # should be false or absent (k8s ≥ 1.6 default)",
		tags:    []string{"k8s", "control-plane", "apiserver", "cis-k8s", "manual-verify"},
		scanner: "controlplane.APIServerAnonymousAuth",
	},
	{
		id: "k8s-cp-apiserver-authorization-mode", title: "kube-apiserver --authorization-mode must include Node + RBAC",
		group: "apiserver", cis: []string{"1.2.7", "1.2.8", "1.2.9"}, severity: core.SeverityCritical,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.15"},
		description: "AuthorizationMode=AlwaysAllow disables authorization entirely. " +
			"Production-safe value is Node,RBAC — Node restricts kubelets to " +
			"per-node resources; RBAC enforces every other authorization decision.",
		remediation: "Set --authorization-mode=Node,RBAC in the apiserver static " +
			"pod manifest. On managed K8s the vendor sets this — confirm in docs.",
		hint:    "ssh <cp-node> 'grep authorization-mode /etc/kubernetes/manifests/kube-apiserver.yaml'  # must contain Node,RBAC",
		tags:    []string{"k8s", "control-plane", "apiserver", "cis-k8s", "manual-verify"},
		scanner: "controlplane.APIServerAuthzMode",
	},
	{
		id: "k8s-cp-apiserver-node-restriction-admission", title: "kube-apiserver admission-plugins must include NodeRestriction",
		group: "apiserver", cis: []string{"1.2.16"}, severity: core.SeverityHigh,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.15"},
		description: "NodeRestriction limits kubelet writes to its own Node + Pod " +
			"objects. Without it, a compromised kubelet token can modify cluster-" +
			"wide resources. Default-enabled on k8s ≥ 1.13.",
		remediation: "Ensure --enable-admission-plugins includes NodeRestriction " +
			"(don't override the default-on list without adding it back).",
		hint:    "ssh <cp-node> 'grep enable-admission-plugins /etc/kubernetes/manifests/kube-apiserver.yaml'  # must contain NodeRestriction",
		tags:    []string{"k8s", "control-plane", "apiserver", "admission", "cis-k8s", "manual-verify"},
		scanner: "controlplane.APIServerNodeRestriction",
	},
	{
		id: "k8s-cp-apiserver-audit-log-path", title: "kube-apiserver --audit-log-path must be set",
		group: "apiserver", cis: []string{"1.2.18"}, severity: core.SeverityHigh,
		soc2: []string{"CC7.2"}, iso: []string{"A.8.15"},
		description: "Without --audit-log-path the apiserver emits no audit log. " +
			"SOC 2 + ISO 27001 require API audit trails; this is the " +
			"load-bearing setting.",
		remediation: "Set --audit-log-path=/var/log/kubernetes/audit/audit.log + " +
			"--audit-policy-file with a Policy that captures at least RequestResponse " +
			"for Secret + ConfigMap writes. On managed K8s, vendor exposes the audit " +
			"log via cloud-provider logging — confirm + retain ≥30d.",
		hint:    "ssh <cp-node> 'grep audit-log-path /etc/kubernetes/manifests/kube-apiserver.yaml'  # must be set",
		tags:    []string{"k8s", "control-plane", "apiserver", "audit", "cis-k8s", "manual-verify"},
		scanner: "controlplane.APIServerAuditLogPath",
	},
	{
		id: "k8s-cp-apiserver-audit-log-retention", title: "kube-apiserver --audit-log-maxage must be ≥30 days",
		group: "apiserver", cis: []string{"1.2.19", "1.2.20", "1.2.21"}, severity: core.SeverityMedium,
		soc2: []string{"CC7.2"}, iso: []string{"A.8.15"},
		description: "--audit-log-maxage (days), --audit-log-maxbackup (rotated " +
			"files), --audit-log-maxsize (MB per file). Defaults are too small " +
			"for SOC 2 evidence — 30d + 10 backups + 100MB is the canonical " +
			"production tuning.",
		remediation: "--audit-log-maxage=30 --audit-log-maxbackup=10 --audit-" +
			"log-maxsize=100. On managed K8s, configure cloud-provider log " +
			"retention to ≥30d (CloudWatch / Stackdriver / DO Logging).",
		hint:    "ssh <cp-node> 'grep -E audit-log-(maxage|maxbackup|maxsize) /etc/kubernetes/manifests/kube-apiserver.yaml'",
		tags:    []string{"k8s", "control-plane", "apiserver", "audit", "cis-k8s", "manual-verify"},
		scanner: "controlplane.APIServerAuditLogRetention",
	},
	{
		id: "k8s-cp-apiserver-encryption-at-rest", title: "kube-apiserver --encryption-provider-config must be set (etcd encryption)",
		group: "apiserver", cis: []string{"1.2.29", "1.2.30"}, severity: core.SeverityHigh,
		soc2: []string{"CC6.1", "CC6.7"}, iso: []string{"A.8.24", "A.5.34"},
		description: "Without --encryption-provider-config, every Secret in etcd " +
			"is stored at-rest in plaintext. EncryptionConfiguration must use " +
			"aescbc or kms (not aesgcm — IV reuse risk) + cover at least secrets, " +
			"with a non-identity provider as the first entry.",
		remediation: "Create /etc/kubernetes/encryption.yaml with kind: " +
			"EncryptionConfiguration + at least one aescbc/kms provider as the " +
			"first entry for resources: [secrets]. Reference via --encryption-" +
			"provider-config. On managed K8s, enable cloud-provider envelope " +
			"encryption (EKS Secrets Encryption with KMS; GKE Application-layer " +
			"Secrets Encryption; DOKS encryption at rest is on by default).",
		hint:    "ssh <cp-node> 'grep encryption-provider-config /etc/kubernetes/manifests/kube-apiserver.yaml'  # path must point at a valid EncryptionConfiguration",
		tags:    []string{"k8s", "control-plane", "apiserver", "encryption", "cis-k8s", "manual-verify"},
		scanner: "controlplane.APIServerEncryptionAtRest",
	},
	{
		id: "k8s-cp-apiserver-profiling-disabled", title: "kube-apiserver --profiling must be false",
		group: "apiserver", cis: []string{"1.2.17"}, severity: core.SeverityMedium,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"},
		description: "--profiling enables /debug/pprof endpoints. Unauthenticated " +
			"access to pprof leaks heap layout + can DoS the process. Default " +
			"is true on legacy clusters; CIS recommends explicit false.",
		remediation: "Set --profiling=false on the kube-apiserver. Same for " +
			"controller-manager + scheduler. Managed K8s typically defaults to " +
			"false — confirm in vendor docs.",
		hint:    "ssh <cp-node> 'grep profiling /etc/kubernetes/manifests/kube-apiserver.yaml'  # must be false",
		tags:    []string{"k8s", "control-plane", "apiserver", "cis-k8s", "manual-verify"},
		scanner: "controlplane.APIServerProfiling",
	},
	// ----- etcd §1.3 -----
	{
		id: "k8s-cp-etcd-client-cert-auth", title: "etcd --client-cert-auth must be true",
		group: "etcd", cis: []string{"1.3.3"}, severity: core.SeverityCritical,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.15"},
		description: "Without --client-cert-auth=true any client reaching the etcd " +
			"port can read + write the entire cluster state. The apiserver " +
			"presents a client cert; etcd MUST require it.",
		remediation: "Set --client-cert-auth=true on the etcd static pod. " +
			"Pair with --cert-file / --key-file / --trusted-ca-file. Managed K8s " +
			"vendors run etcd in their control plane; not operator-controllable.",
		hint:    "ssh <cp-node> 'grep client-cert-auth /etc/kubernetes/manifests/etcd.yaml'  # must be true",
		tags:    []string{"k8s", "control-plane", "etcd", "cis-k8s", "manual-verify"},
		scanner: "controlplane.EtcdClientCertAuth",
	},
	{
		id: "k8s-cp-etcd-peer-client-cert-auth", title: "etcd --peer-client-cert-auth must be true",
		group: "etcd", cis: []string{"1.3.5"}, severity: core.SeverityCritical,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.15"},
		description: "Peer authentication between etcd nodes prevents a rogue " +
			"etcd-like server from joining the cluster + receiving the data " +
			"replication stream. Without it, any pod on the etcd network can " +
			"impersonate a peer.",
		remediation: "Set --peer-client-cert-auth=true. Pair with --peer-cert-" +
			"file / --peer-key-file / --peer-trusted-ca-file. Managed K8s vendor-" +
			"controlled.",
		hint:    "ssh <cp-node> 'grep peer-client-cert-auth /etc/kubernetes/manifests/etcd.yaml'",
		tags:    []string{"k8s", "control-plane", "etcd", "cis-k8s", "manual-verify"},
		scanner: "controlplane.EtcdPeerClientCertAuth",
	},
	{
		id: "k8s-cp-etcd-auto-tls-false", title: "etcd --auto-tls + --peer-auto-tls must be false",
		group: "etcd", cis: []string{"1.3.1", "1.3.2"}, severity: core.SeverityHigh,
		soc2: []string{"CC6.1", "CC6.7"}, iso: []string{"A.8.24"},
		description: "auto-tls / peer-auto-tls generate self-signed certs at " +
			"startup. Self-signed = no path validation, no rotation, no audit. " +
			"Production posture is operator-issued certs.",
		remediation: "Set --auto-tls=false + --peer-auto-tls=false; provide " +
			"proper certs via --cert-file / --peer-cert-file.",
		hint:    "ssh <cp-node> 'grep -E (peer-)?auto-tls /etc/kubernetes/manifests/etcd.yaml'  # both should be false or absent",
		tags:    []string{"k8s", "control-plane", "etcd", "tls", "cis-k8s", "manual-verify"},
		scanner: "controlplane.EtcdAutoTLS",
	},
	// ----- controller-manager §1.4 -----
	{
		id: "k8s-cp-cm-use-service-account-credentials", title: "controller-manager --use-service-account-credentials must be true",
		group: "controller-manager", cis: []string{"1.4.3"}, severity: core.SeverityHigh,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.15"},
		description: "When true, each controller runs with its own ServiceAccount " +
			"token rather than sharing the controller-manager's master token. " +
			"Per-controller RBAC isolation = compromise of one controller doesn't " +
			"hand the attacker the master credentials.",
		remediation: "Set --use-service-account-credentials=true on kube-" +
			"controller-manager. Default is true on k8s ≥ 1.6; confirm not " +
			"overridden.",
		hint:    "ssh <cp-node> 'grep use-service-account-credentials /etc/kubernetes/manifests/kube-controller-manager.yaml'",
		tags:    []string{"k8s", "control-plane", "controller-manager", "cis-k8s", "manual-verify"},
		scanner: "controlplane.CMUseServiceAccountCreds",
	},
	{
		id: "k8s-cp-cm-bind-address-localhost", title: "controller-manager --bind-address must be 127.0.0.1",
		group: "controller-manager", cis: []string{"1.4.7"}, severity: core.SeverityMedium,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"},
		description: "controller-manager's healthz + metrics are unauthenticated. " +
			"Binding only to 127.0.0.1 means only the kubelet on the same node " +
			"can reach them, not pods or external clients.",
		remediation: "Set --bind-address=127.0.0.1. Same for kube-scheduler " +
			"(check k8s-cp-scheduler-bind-address-localhost).",
		hint:    "ssh <cp-node> 'grep bind-address /etc/kubernetes/manifests/kube-controller-manager.yaml'  # should be 127.0.0.1",
		tags:    []string{"k8s", "control-plane", "controller-manager", "cis-k8s", "manual-verify"},
		scanner: "controlplane.CMBindAddressLocalhost",
	},
	// ----- scheduler §1.5 -----
	{
		id: "k8s-cp-scheduler-bind-address-localhost", title: "scheduler --bind-address must be 127.0.0.1",
		group: "scheduler", cis: []string{"1.5.2"}, severity: core.SeverityMedium,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"},
		description: "scheduler's healthz + metrics endpoints share the apiserver-" +
			"adjacent risk profile of controller-manager. Loopback-only binding " +
			"prevents lateral discovery.",
		remediation: "Set --bind-address=127.0.0.1 on kube-scheduler.",
		hint:        "ssh <cp-node> 'grep bind-address /etc/kubernetes/manifests/kube-scheduler.yaml'  # should be 127.0.0.1",
		tags:        []string{"k8s", "control-plane", "scheduler", "cis-k8s", "manual-verify"},
		scanner:     "controlplane.SchedulerBindAddressLocalhost",
	},
	// ----- kubelet §4.2 -----
	{
		id: "k8s-cp-kubelet-anonymous-auth-false", title: "kubelet --anonymous-auth must be false",
		group: "kubelet", cis: []string{"4.2.1"}, severity: core.SeverityHigh,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.15"},
		description: "Anonymous kubelet access lets unauthenticated callers query " +
			"/spec, /stats, /logs — all leaking workload secrets or facilitating " +
			"container escape. Default false on k8s ≥ 1.10 but explicit check " +
			"catches downgraded configs.",
		remediation: "In /var/lib/kubelet/config.yaml set:\n  authentication:\n    " +
			"anonymous:\n      enabled: false\n    webhook:\n      enabled: true\n  " +
			"authorization:\n    mode: Webhook\nThen restart kubelet.",
		hint:    "ssh <node> 'grep -A 5 authentication: /var/lib/kubelet/config.yaml'  # anonymous.enabled must be false",
		tags:    []string{"k8s", "control-plane", "kubelet", "cis-k8s", "manual-verify"},
		scanner: "controlplane.KubeletAnonymousAuth",
	},
	{
		id: "k8s-cp-kubelet-read-only-port-zero", title: "kubelet --read-only-port must be 0 (disabled)",
		group: "kubelet", cis: []string{"4.2.4"}, severity: core.SeverityHigh,
		soc2: []string{"CC6.1", "CC6.6"}, iso: []string{"A.5.15", "A.8.20"},
		description: "The kubelet read-only port (default 10255, since-removed " +
			"in upstream defaults but lingering in older configs) exposes pod " +
			"status + spec without authentication. Set to 0 to disable.",
		remediation: "In /var/lib/kubelet/config.yaml set readOnlyPort: 0. " +
			"Restart kubelet.",
		hint:    "ssh <node> 'grep readOnlyPort /var/lib/kubelet/config.yaml'  # must be 0",
		tags:    []string{"k8s", "control-plane", "kubelet", "cis-k8s", "manual-verify"},
		scanner: "controlplane.KubeletReadOnlyPort",
	},
}

func init() {
	for _, spec := range cpvSpecs {
		spec := spec
		core.Register(cpvCheck(spec), cpvCheckFunc(spec))
	}
}

func cpvCheck(spec cpvSpec) core.Check {
	cis := ""
	if len(spec.cis) > 0 {
		cis = spec.cis[0]
	}
	return core.Check{
		ID: spec.id, Title: spec.title, Severity: spec.severity,
		Provider: "kubernetes", Service: spec.group,
		ResourceType: k8scol.ClusterType,
		Description: fmt.Sprintf("CIS Kubernetes Benchmark §%s. %s",
			cis, spec.description),
		Remediation: spec.remediation,
		Frameworks: map[string][]string{
			"soc2":     spec.soc2,
			"iso27001": spec.iso,
			"cis-v8":   spec.cis,
		},
		Tags:    spec.tags,
		Scanner: spec.scanner,
	}
}

func cpvCheckFunc(spec cpvSpec) core.CheckFunc {
	return func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		findings := []core.Finding{}
		ctxs := g.ByType(k8scol.ClusterType)
		if len(ctxs) == 0 {
			return findings, nil
		}
		for _, c := range ctxs {
			findings = append(findings, core.Finding{
				CheckID: spec.id, Severity: spec.severity,
				Resource: c.Ref(), Tags: spec.tags,
				Status: core.StatusError,
				Message: fmt.Sprintf("cluster %q (CIS §%s): %s — hint: %s",
					c.Name, strings.Join(spec.cis, ","), spec.title, spec.hint),
			})
		}
		return findings, nil
	}
}

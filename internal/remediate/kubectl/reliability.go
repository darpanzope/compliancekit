package kubectl

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 2 — kubectl strategies for the 12 reliability + supply-
// chain checks. Same two-block shape (patch + GitOps manifest) as
// pod_security_extra.go.

var reliabilityEntries = map[string]psExtraEntry{
	"k8s-pod-readiness-probe": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/containers/0/readinessProbe","value":{"httpGet":{"path":"/healthz","port":8080},"initialDelaySeconds":5,"periodSeconds":10}}]'`,
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          readinessProbe:\n            httpGet:\n              path: /healthz\n              port: 8080\n            initialDelaySeconds: 5\n            periodSeconds: 10\n            failureThreshold: 3",
		risk:     remediate.RiskSafe,
		notes:    "Pick the probe shape that matches your app — httpGet (most common), tcpSocket (raw port), or exec (custom command). initialDelaySeconds should be ≥ typical startup time.",
	},
	"k8s-pod-startup-probe-for-slow-start": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/containers/0/startupProbe","value":{"httpGet":{"path":"/healthz","port":8080},"failureThreshold":30,"periodSeconds":10}}]'`,
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          startupProbe:\n            httpGet:\n              path: /healthz\n              port: 8080\n            failureThreshold: 30\n            periodSeconds: 10\n          # liveness + readiness take over once startupProbe succeeds:\n          livenessProbe:\n            httpGet:\n              path: /healthz\n              port: 8080\n            periodSeconds: 10\n            failureThreshold: 3",
		risk:     remediate.RiskReview,
		notes:    "Tune failureThreshold × periodSeconds for the app's worst-case cold start. JVM apps often need 5+ minutes (failureThreshold: 30, periodSeconds: 10).",
	},
	"k8s-pod-ephemeral-storage-limit": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/containers/0/resources/limits/ephemeral-storage","value":"1Gi"},{"op":"add","path":"/spec/template/spec/containers/0/resources/requests/ephemeral-storage","value":"500Mi"}]'`,
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          resources:\n            limits:\n              ephemeral-storage: 1Gi    # max writable layer + emptyDir + logs\n            requests:\n              ephemeral-storage: 500Mi  # scheduler-reserved budget",
		risk:     remediate.RiskSafe,
	},
	"k8s-pod-topology-spread-constraints": {
		patch:    `# topologySpreadConstraints can't easily be added via patch — use kubectl edit + manifest.`,
		manifest: "spec:\n  template:\n    spec:\n      topologySpreadConstraints:\n        - maxSkew: 1\n          topologyKey: topology.kubernetes.io/zone\n          whenUnsatisfiable: DoNotSchedule\n          labelSelector:\n            matchLabels:\n              app: <app-label>\n        - maxSkew: 1\n          topologyKey: kubernetes.io/hostname\n          whenUnsatisfiable: ScheduleAnyway   # per-host softer than per-zone\n          labelSelector:\n            matchLabels:\n              app: <app-label>",
		risk:     remediate.RiskSafe,
		notes:    "labelSelector MUST match the pod's labels. Use ScheduleAnyway during initial rollout; switch to DoNotSchedule once you have enough nodes that skew=1 is achievable.",
	},
	"k8s-pod-image-digest-pinned": {
		patch:    `# Resolve the digest then patch:\nDIGEST=$(crane digest <REGISTRY>/<IMAGE>:<TAG>)\nkubectl patch deployment <NAME> -n <NS> --type=json -p="[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/image\",\"value\":\"<REGISTRY>/<IMAGE>@${DIGEST}\"}]"`,
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          # pinned by digest — defeats tag-mutation supply-chain attack:\n          image: ghcr.io/org/app@sha256:abc123def456...\n          # NOT: image: ghcr.io/org/app:v1.2.3",
		risk:     remediate.RiskReview,
		notes:    "Renovate + dependabot can update digest-pinned images automatically — same UX as tag pinning. cosign verify-and-resolve in CI translates a verified tag into the digest before push.",
	},
	"k8s-pod-termination-grace-period-explicit": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"replace","path":"/spec/template/spec/terminationGracePeriodSeconds","value":60}]'`,
		manifest: "spec:\n  template:\n    spec:\n      # Sized to the workload — 60s for typical web tier, 120-300s for\n      # databases needing flush, 5-10s for batch jobs.\n      terminationGracePeriodSeconds: 60",
		risk:     remediate.RiskReview,
		notes:    "Pair with preStop hook (k8s-pod-prestop-hook-for-graceful-drain) for actual graceful shutdown signaling. Otherwise SIGTERM hits and the budget just delays SIGKILL.",
	},
	"k8s-pod-init-container-resource-limits": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/initContainers/0/resources","value":{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"100m","memory":"64Mi"}}}]'`,
		manifest: "spec:\n  template:\n    spec:\n      initContainers:\n        - name: <init-name>\n          resources:\n            limits:\n              cpu: 500m\n              memory: 128Mi\n            requests:\n              cpu: 100m\n              memory: 64Mi",
		risk:     remediate.RiskSafe,
	},
	"k8s-pod-init-container-readonly-rootfs": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/initContainers/0/securityContext","value":{"readOnlyRootFilesystem":true}}]'`,
		manifest: "spec:\n  template:\n    spec:\n      initContainers:\n        - name: <init-name>\n          securityContext:\n            readOnlyRootFilesystem: true\n          volumeMounts:\n            # Mount writable scratch via emptyDir if the init step needs /tmp:\n            - name: tmp\n              mountPath: /tmp\n      volumes:\n        - name: tmp\n          emptyDir: {}",
		risk:     remediate.RiskSafe,
	},
	"k8s-pod-init-container-no-priv-escalation": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/initContainers/0/securityContext/allowPrivilegeEscalation","value":false}]'`,
		manifest: "spec:\n  template:\n    spec:\n      initContainers:\n        - name: <init-name>\n          securityContext:\n            allowPrivilegeEscalation: false",
		risk:     remediate.RiskSafe,
	},
	"k8s-pod-prestop-hook-for-graceful-drain": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/containers/0/lifecycle","value":{"preStop":{"exec":{"command":["/bin/sh","-c","curl -fsS http://localhost:8080/shutdown && sleep 5"]}}}}]'`,
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          lifecycle:\n            preStop:\n              # Call the app's drain endpoint, then sleep so connection-\n              # draining from the load balancer side completes:\n              exec:\n                command: [\"/bin/sh\", \"-c\", \"curl -fsS http://localhost:8080/shutdown && sleep 5\"]\n              # Alternative — httpGet:\n              # httpGet:\n              #   path: /shutdown\n              #   port: 8080\n      # terminationGracePeriodSeconds must be ≥ preStop runtime + drain:\n      terminationGracePeriodSeconds: 30",
		risk:     remediate.RiskManual,
		notes:    "preStop content is workload-specific — there is no universal command. Common patterns: HTTP shutdown endpoint, SIGUSR2 to graceful-stop, nginx -s quit. terminationGracePeriodSeconds must cover preStop runtime + connection-drain time.",
	},
	"k8s-pod-has-owner-ref": {
		patch:    `# Wrap the pod spec in a controller. Cannot be done via kubectl patch.\nkubectl get pod <NAME> -n <NS> -o yaml > /tmp/pod.yaml\n# Edit /tmp/pod.yaml into the Deployment shape below, then:\nkubectl delete pod <NAME> -n <NS>\nkubectl apply -f deployment.yaml`,
		manifest: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: <name>\n  namespace: <ns>\nspec:\n  replicas: 2\n  selector:\n    matchLabels:\n      app: <name>\n  template:\n    metadata:\n      labels:\n        app: <name>\n    spec:\n      # ... move the orphan pod's spec here ...",
		risk:     remediate.RiskManual,
		notes:    "Standalone pods are usually a debug primitive that escaped into production. Wrap in Deployment / StatefulSet / Job as appropriate.",
	},
	"k8s-pod-no-host-ports": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"remove","path":"/spec/template/spec/containers/0/ports/0/hostPort"}]'`,
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          ports:\n            - containerPort: 8080\n              # hostPort: 8080   # remove\n              protocol: TCP\n      # If you need node-local ingress, prefer a NodePort Service:\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: <name>\nspec:\n  type: NodePort\n  selector:\n    app: <name>\n  ports:\n    - port: 80\n      targetPort: 8080\n      nodePort: 30080",
		risk:     remediate.RiskReview,
		notes:    "Removing hostPort breaks workloads that bind directly to a node port. Migrate to NodePort / LoadBalancer Service first; verify external clients reach the new endpoint before removing.",
	},
}

func init() {
	for id, e := range reliabilityEntries {
		id := id
		e := e
		register("kubectl-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := "# === kubectl patch ===\n" + e.patch + "\n\n# === Manifest (GitOps) ===\n" + e.manifest + "\n"
			return remediate.Snippet{
				Risk: e.risk, Idempotent: true, Content: body,
				Notes: e.notes,
			}, nil
		})
	}
}

// v0.21 phase 10 — kubectl backfill for the 5 legacy job /
// cronjob / daemonset legacy check IDs. See backfill_helper.go
// for the renderer.
func init() {
	registerBackfillIDs(
		"k8s-cronjob-concurrency",
		"k8s-cronjob-history-limit",
		"k8s-cronjob-starting-deadline",
		"k8s-daemonset-control-plane-tolerance",
		"k8s-job-backoff-limit",
	)
}

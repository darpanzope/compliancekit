# compliancekit-operator

Basic K8s operator for compliancekit. Watches two CRDs:

| CRD | Purpose |
|---|---|
| `ComplianceSchedule` | Cron-driven scan trigger against a daemon URL |
| `ScanJob` | One-shot scan via a freshly-created Pod |

The full reconciler (CRD-driven profiles, waivers, framework
tailoring) lands at v2.10 per ROADMAP; v1.15 ships the lightweight
shape that covers the two most-asked-for workflows.

## Install

```sh
kubectl apply -f deploy/operator/crds/
kubectl apply -f deploy/operator/install.yaml
```

That installs the operator into the `compliancekit-operator`
namespace with leader-election enabled.

## ComplianceSchedule example

```yaml
apiVersion: compliancekit.io/v1alpha1
kind: ComplianceSchedule
metadata:
  name: weekly-aws-scan
  namespace: default
spec:
  cronExpr: "0 9 * * 1"        # Mon 09:00 UTC
  providers: [aws]
  daemonRef:
    url: https://compliancekit.example.com
    bearerSecret:
      name: compliancekit-bearer
      key: token
```

## ScanJob example

```yaml
apiVersion: compliancekit.io/v1alpha1
kind: ScanJob
metadata:
  name: one-shot-aws
  namespace: default
spec:
  # Default image when omitted: ghcr.io/darpanzope/compliancekit:latest
  args:
    - --provider=aws
    - --out=/work/findings.json
  evidencePackPVC: ck-evidence
  envFromSecret: aws-creds
```

The operator creates a Pod, watches it to completion, and mirrors
the phase onto `.status.phase`. Operators who want retries author a
new ScanJob — the CR is the desired-state record, not a Job
controller.

## Reference

| File | Purpose |
|---|---|
| `crds/compliancekit.io_complianceschedules.yaml` | CRD manifest |
| `crds/compliancekit.io_scanjobs.yaml` | CRD manifest |
| `install.yaml` | Namespace + RBAC + Deployment |

| Operator flag | Default | Purpose |
|---|---|---|
| `--metrics-bind-address` | `:8080` | controller-runtime Prometheus metrics |
| `--health-probe-bind-address` | `:8081` | `/healthz` + `/readyz` |
| `--leader-elect` | `false` | enable Lease-based leader election |
| `--default-image` | `ghcr.io/darpanzope/compliancekit:latest` | fallback for ScanJob spec.image |

# compliancekit Kustomize templates

Community-template-style layout. Base + three overlays:

```
deploy/kustomize/
├── base/                   single-replica + SQLite (the chart-zero shape)
└── overlays/
    ├── dev/                latest tag + --insecure-cookies + 1Gi PVC
    ├── staging/            v1.15.0 tag + Ingress + cert-manager-staging
    └── prod/               HA Postgres mode + 2 replicas + cert-manager-prod
```

## Render

```sh
# Default base (compliancekit namespace, SQLite, no Ingress)
kubectl kustomize deploy/kustomize/base

# Per-environment
kubectl kustomize deploy/kustomize/overlays/dev
kubectl kustomize deploy/kustomize/overlays/staging
kubectl kustomize deploy/kustomize/overlays/prod
```

## Apply

```sh
kubectl apply -k deploy/kustomize/overlays/prod
```

## Customize

The base/ resources are kept minimal so overlays can patch
narrowly. New environment? Copy `dev/kustomization.yaml`, change
the namespace + nameSuffix + image tag, add per-overlay resources
as needed.

## When to pick Kustomize vs. Helm

|  | Helm | Kustomize |
|---|---|---|
| **Templating** | Go template + values.yaml flexibility | YAML patches only — easier to audit |
| **Release tracking** | `helm history` + atomic rollback | git is the rollback |
| **Secret management** | values.yaml or existingSecret ref | inline `Secret` (use sealed-secrets / SOPS!) |
| **GitOps fit** | ArgoCD + Helm hooks | ArgoCD + raw kustomize (zero dependencies) |

Helm is the maintained default; Kustomize is here for operators
who already invested in Kustomize-as-source-of-truth tooling.

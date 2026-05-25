# compliancekit deployment artifacts

The daemon ships with first-party templates for every deployment
pattern operators reach for. Pick the one that matches the
environment; each subdirectory below has its own README with the
install one-liner.

| Subdirectory | Use when |
|---|---|
| [helm/](./helm) | Kubernetes via Helm (default for K8s ops) |
| [kustomize/](./kustomize) | Kubernetes via Kustomize overlays |
| [operator/](./operator) | Kubernetes via the basic CRD reconciler |
| [terraform/](./terraform) | AWS / GCP / DigitalOcean / Hetzner VMs |
| [systemd/](./systemd) | Plain Linux host (Ubuntu / RHEL / Debian) |
| [nixos/](./nixos) | NixOS module |
| [grafana/](./grafana) | Prometheus + Grafana dashboard bundle |
| [install.sh](./install.sh) | One-line installer for macOS + Linux |

## Container image

The daemon container is `ghcr.io/darpanzope/compliancekit:<tag>`
(also tagged `:latest`). Multi-arch (`linux/amd64` + `linux/arm64`),
distroless, non-root.

| Property | Value |
|---|---|
| Base image | `gcr.io/distroless/static-debian12:nonroot` |
| User | `nonroot` (uid 65532) |
| Working dir | `/work` |
| Entrypoint | `/usr/local/bin/compliancekit` |
| Stripped size | ~25 MB / arch (target — enforced by the [size-budget script](./scripts/image-size-budget.sh)) |
| Signed | cosign keyless via GitHub OIDC (see [SUPPLY-CHAIN.md](../SUPPLY-CHAIN.md)) |
| SBOM | syft SPDX-JSON attached as a release asset |

Pull + run:

```sh
docker run --rm -p 8080:8080 ghcr.io/darpanzope/compliancekit:latest serve --addr 0.0.0.0
```

## v1.15 phase index

The v1.15 milestone (Deploy & operate) ships the artifacts in this
directory across 10 self-contained phases. Each phase commit lands a
single subdirectory + its README + tests. See the [v1.15 tracking
issue](https://github.com/darpanzope/compliancekit/issues/47) for the
phase-by-phase log.

## Healthchecks

Two endpoints, intentionally split:

| Path | Purpose |
|---|---|
| `/health` | Cheap liveness probe — returns 200 + `ok` if the HTTP server is up. Safe for Kubernetes liveness, uptime monitors, load-balancer health checks. |
| `/health/ready` | Deep readiness — checks DB writable + migrations current + queue alive + (HA mode) leader-elected. Use for Kubernetes readiness + zero-downtime rolling updates. v1.15 phase 7. |

## Reverse proxy

The daemon ships strict security headers (HSTS + frame-options +
content-type-options + a tight CSP). Always run behind TLS in
production — terminate at nginx / Caddy / Traefik / a cloud
load-balancer. The Helm chart, Kustomize overlay, and Terraform
modules under this directory all default to enabling TLS at the
ingress layer.

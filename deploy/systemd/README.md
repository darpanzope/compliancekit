# systemd unit for compliancekit

Drop-in unit for any systemd Linux host (Ubuntu / RHEL / Debian /
Arch / openSUSE / etc.).

## Install

```sh
# 1. Create the system user + state dir.
sudo useradd --system --user-group --create-home \
  --home-dir /var/lib/compliancekit --shell /usr/sbin/nologin compliancekit
sudo install -d -o compliancekit -g compliancekit /var/lib/compliancekit

# 2. Install the binary (or use the v1.15 phase 9 install.sh).
sudo curl -fsSL https://github.com/darpanzope/compliancekit/releases/download/v1.15.0/compliancekit_1.15.0_linux_amd64.tar.gz \
  | sudo tar xz -C /usr/local/bin compliancekit
sudo chmod +x /usr/local/bin/compliancekit

# 3. Install + enable the unit.
sudo cp deploy/systemd/compliancekit.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now compliancekit
```

## Overrides

Use `systemctl edit compliancekit` to drop a `/etc/systemd/system/
compliancekit.service.d/override.conf` without touching the
shipped unit:

```ini
[Service]
# Switch from SQLite to Postgres.
Environment=
Environment=CK_DB=postgres://compliancekit:CHANGEME@db.internal:5432/compliancekit?sslmode=require

# Pin to a non-loopback bind via a reverse proxy on the same host.
ExecStart=
ExecStart=/usr/local/bin/compliancekit serve \
  --addr 127.0.0.1 \
  --port 8080 \
  --db ${CK_DB}

# Wire CK_SAML_* / CK_OIDC_* / CK_SCIM_* via EnvironmentFile.
EnvironmentFile=-/etc/compliancekit/env
```

## Hardening

The unit's sandbox set is tuned for `systemd-analyze security
compliancekit` < 2.0. Notable:

* `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
  `ProtectHome`, `ProtectKernel*` — full kernel-surface lockdown.
* `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` — no raw
  sockets, no AF_PACKET.
* `SystemCallFilter=@system-service` minus `@privileged @resources`
  — fail-fast on any privileged syscall slip.
* `CapabilityBoundingSet=` (empty) + `AmbientCapabilities=` (empty)
  — strip every capability; the daemon binds 8080 via the systemd-
  managed user-namespace TCP socket, not via CAP_NET_BIND_SERVICE.

## Logs + status

```sh
sudo systemctl status compliancekit
sudo journalctl -u compliancekit -f --since "1 hour ago"
```

## Reverse proxy

The default binds loopback (`--addr 127.0.0.1`). Front with
nginx / Caddy / Traefik for TLS termination + public ingress.
Caddy example:

```caddy
compliancekit.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

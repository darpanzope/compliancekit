# HA Postgres mode

The default daemon ships SQLite + a single replica. To scale beyond
one pod, switch the daemon to a shared Postgres DB + enable leader
election so only one replica claims work at a time.

## Architecture

```
        ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
        │  daemon-1   │    │  daemon-2   │    │  daemon-3   │
        │ leader  ⬤  │    │ standby  ◯  │    │ standby  ◯  │
        └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
               │                  │                  │
               │   pg_advisory_lock(ck_lead)         │
               └─────────────┐    │    ┌─────────────┘
                             │    │    │
                          ┌──┴────┴────┴──┐
                          │  Postgres 14+  │
                          │ (primary + N   │
                          │  read replicas │
                          │  via streaming │
                          │  replication)  │
                          └────────────────┘
```

Every daemon serves the UI + REST API. **Only the leader dispatches
queued scans + fires cron schedules.** Standbys skip the
`drainQueue` loop entirely; if the leader dies, a standby acquires
the advisory lock within ~10s and takes over.

## Why advisory locks (not Lease / etcd / Raft)

* **Already required:** Postgres is the state store; reusing it for
  leader election eliminates an entire dependency.
* **Session-scoped:** `pg_advisory_lock(key)` dies with its
  Postgres session. Hard process kill → TCP keepalive drops → lock
  released. No partition-tolerance gotchas.
* **One key, fixed:** `0x636B5F6C656164` ("ck_lead"). Disjoint from
  the migration lock at `0x636B5F6D69677261` ("ck_migra") so the
  two never deadlock.

## Postgres provisioning

The daemon doesn't ship a Postgres operator — pick whatever your
platform already runs. Verified shapes:

| Platform | Recipe |
|---|---|
| AWS RDS | `db.t4g.small`, multi-AZ, encrypted at rest. Storage 50 GB autoscaling. |
| GCP Cloud SQL | `db-custom-1-3840`, regional HA, encrypted, automated backups. |
| DigitalOcean Managed | Basic 1 GB, optional standby, daily backups. |
| Self-hosted | `pg-cluster` Helm chart or `cloudnative-pg` operator; min 3 replicas; streaming replication; `synchronous_commit = on` on the primary. |

Minimum supported version: **Postgres 14**. The daemon's migrations
target 14+ syntax and the leader-election advisory-lock path was
tested against 14, 15, 16, 17.

## Connection string

The daemon takes a single `--db` flag carrying a PG DSN. Example:

```
postgres://compliancekit:CHANGEME@compliancekit-postgres.svc:5432/compliancekit?sslmode=require
```

* `sslmode=require` is mandatory in production.
* The user needs `CREATE`, `INSERT`, `UPDATE`, `DELETE`, `SELECT`,
  `REFERENCES`, plus the ability to take advisory locks (every
  ordinary role can).

## Replica count

```yaml
# Helm values
replicaCount: 3
ha:
  enabled: true
  postgres:
    existingSecret: ck-postgres
    existingSecretKey: dsn
```

3 replicas is the sweet spot for a typical compliance workload:
two standbys + the leader leave room for a rolling restart without
falling below 1 live daemon.

## Leader-failover test

```sh
# Identify the current leader (the only pod logging 'leader: acquired pg_advisory_lock').
kubectl logs -l app.kubernetes.io/name=compliancekit --tail=200 \
  | grep "leader: acquired"

# Kill the leader.
kubectl delete pod <leader-pod-name> --grace-period=5

# A standby acquires within ~10s (the leader.PollInterval).
kubectl logs -l app.kubernetes.io/name=compliancekit --tail=200 \
  | grep "leader: acquired"
```

## Monitoring

The daemon's `/metrics` endpoint exposes:

| Metric | Use |
|---|---|
| `compliancekit_worker_queue_depth` | Already at v1.11. Pin alerts to this; if depth grows + no scans complete, the leader is wedged. |
| `compliancekit_leader_status` (v1.15.x) | Gauge — 1 when this replica holds the lock, 0 otherwise. Use to confirm exactly one leader at any time. |

`pg_advisory_lock` itself is observable via the Postgres
`pg_locks` view:

```sql
SELECT pid, granted, locktype, classid, objid
  FROM pg_locks
 WHERE locktype = 'advisory'
   AND objid = 1668246833361252; -- 0x636B5F6C656164 in decimal
```

Exactly one row with `granted = t` = healthy.

## Postgres connection limits

Default Postgres ships with `max_connections = 100`. The daemon
holds:

* 1 connection per replica for the leader-election advisory lock
  (HA mode only).
* Up to `concurrency × 2` connections from the worker pool for
  scan + ingest writes.
* Up to ~10 connections from the API + UI for read traffic.

For a 3-replica HA install: `3 × (1 + 2×2 + 10) = 45` connections.
Plus headroom for ad-hoc psql sessions — `max_connections = 100` is
usually enough.

## Backup interaction

The v1.12 phase 8 backup catalog uses `pg_dump --format=custom` for
the Postgres path. Backups run on the daemon, not on Postgres, and
don't interact with the advisory lock. Schedule them via cron
externally + tag them in the `/settings/backups` admin UI.

# Grafana dashboards for compliancekit

Three boards consuming the daemon's `/metrics` endpoint. Import
into any Grafana instance pointed at the Prometheus scraping the
daemon.

| Dashboard | Use for |
|---|---|
| [`compliancekit-operations.json`](./dashboards/compliancekit-operations.json) | Daemon liveness / HTTP latency / error rate. The on-call default board. |
| [`compliancekit-findings.json`](./dashboards/compliancekit-findings.json) | Findings ingested / severity mix / top failing checks. |
| [`compliancekit-worker-pool.json`](./dashboards/compliancekit-worker-pool.json) | Queue depth + autoscale + scan duration + leader-election invariant. |

## Import

```sh
# Via Grafana CLI
grafana-cli dashboards import deploy/grafana/dashboards/compliancekit-operations.json

# Via the API
curl -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GRAFANA_TOKEN" \
  -d "$(cat deploy/grafana/dashboards/compliancekit-operations.json)" \
  https://grafana.example.com/api/dashboards/db
```

## Prometheus scrape config

Add the daemon as a scrape target. Example for a daemon running
inside a Kubernetes namespace:

```yaml
- job_name: compliancekit
  kubernetes_sd_configs:
    - role: pod
      namespaces:
        names: [compliancekit]
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
      action: keep
      regex: compliancekit
    - source_labels: [__meta_kubernetes_pod_container_port_number]
      action: keep
      regex: 8080
  metrics_path: /metrics
  scheme: http
```

For a systemd / standalone daemon:

```yaml
- job_name: compliancekit
  static_configs:
    - targets: ['compliancekit.example.com:8080']
  metrics_path: /metrics
  scheme: http
```

(Prometheus 2.45+ recommended for the
`compliancekit_http_request_duration_seconds` native histogram
support.)

## Provisioning via the Grafana provisioner

Drop the three JSON files into your Grafana provisioning
directory (`/etc/grafana/provisioning/dashboards/`) alongside a
`compliancekit.yaml`:

```yaml
apiVersion: 1
providers:
  - name: compliancekit
    folder: Compliancekit
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards/compliancekit
```

## Alerts

Recommended starter alerts (Grafana unified alerting or
Alertmanager):

| Alert | Expression | Severity |
|---|---|---|
| Daemon down | `up{job="compliancekit"} == 0` for 1m | page |
| Readiness fail rate | `rate(compliancekit_http_requests_total{path="/health/ready", status="503"}[5m]) > 0.1` for 2m | page |
| Queue not draining | `compliancekit_worker_queue_depth > 5` for 10m | warn |
| Multiple leaders | `sum(compliancekit_leader_status) > 1` | page (HA invariant violated) |
| 5xx rate | `rate(compliancekit_http_requests_total{status=~"5.."}[5m]) > 1` for 5m | warn |
| Goroutine leak | `rate(go_goroutines[10m]) > 50` | warn |

The `compliancekit_leader_status` + `compliancekit_findings_open`
metrics wire in at v1.15.x; the dashboards reference them now so
the panels light up automatically once the metric ships.

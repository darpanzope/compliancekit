# compliancekit Helm chart

Single-replica + SQLite by default; toggle `ha.enabled=true` to lift
into Postgres + advisory-lock leader election (multi-replica).

## Install

```sh
helm install ck oci://ghcr.io/darpanzope/compliancekit-chart \
  --version 1.15.0 \
  --namespace compliancekit --create-namespace
```

For a custom values file:

```sh
helm install ck oci://ghcr.io/darpanzope/compliancekit-chart \
  --version 1.15.0 \
  --namespace compliancekit --create-namespace \
  --values my-values.yaml
```

## Common overrides

```yaml
# Switch to HA mode against an external Postgres.
replicaCount: 2
ha:
  enabled: true
  postgres:
    existingSecret: ck-postgres
    existingSecretKey: dsn

# Expose via Ingress.
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: compliancekit.example.com
      paths: [ { path: /, pathType: Prefix } ]
  tls:
    - secretName: compliancekit-tls
      hosts: [ compliancekit.example.com ]

# Wire one SAML IdP (Okta).
auth:
  saml:
    providers:
      okta:
        rootUrl: https://compliancekit.example.com
        entryPoint: https://example.okta.com/app/.../sso/saml
        spCertPem: |
          -----BEGIN CERTIFICATE-----
          ...
          -----END CERTIFICATE-----
        spKeyPem: |
          -----BEGIN RSA PRIVATE KEY-----
          ...
          -----END RSA PRIVATE KEY-----

# Enable SCIM.
auth:
  scim:
    enabled: true
    bearerToken: ${SCIM_BEARER_TOKEN}
```

## Smoke test

A `helm lint` + `helm template` gate runs on every push touching this
directory; CI's chart-testing harness builds a kind cluster + runs
`helm install --wait` against the chart at release time.

See [Chart.yaml](./Chart.yaml) + [values.yaml](./values.yaml) for the
full knob set.

# Authoring a check

Every check is two artifacts: YAML metadata and Go scanner logic. From v0.16, Rego is a third option for logic.

This guide walks through the contributor flow.

## Anatomy

```
internal/checks/digitalocean/spaces.yaml          ← metadata
internal/collectors/digitalocean/spaces.go        ← scanner Go code
internal/collectors/digitalocean/spaces_test.go   ← unit test
internal/collectors/digitalocean/testdata/spaces_*.json   ← fixtures
```

## YAML schema

```yaml
- id: do-spaces-public-acl        # required. kebab-case. Stable forever.
  title: "Spaces buckets must not allow public read"
  severity: high                  # info | low | medium | high | critical

  provider: digitalocean
  service: spaces
  resource_type: bucket

  description: |
    Public-read Spaces buckets can leak customer data. Buckets should
    default to private; objects intended for public distribution should
    be served through the CDN with explicit per-object ACLs.

  rationale: |                    # optional. The "why this is bad."
    A misconfigured public bucket caused the 2019 Capital One incident.
    Detection is cheap; remediation is one CLI command.

  remediation: |                  # human-readable
    For each public bucket:
      doctl spaces update <name> --acl private

  remediations:                   # v0.15+: machine-applicable snippets
    bash: |
      doctl spaces update {{ .Resource.Name }} --acl private
    terraform: |
      resource "digitalocean_spaces_bucket" "{{ .Resource.Name }}" {
        acl = "private"
      }
    ansible: |
      - name: Set bucket ACL to private
        community.digitalocean.digital_ocean_spaces:
          name: "{{ .Resource.Name }}"
          acl: private

  frameworks:                     # required. At least one framework mapping.
    soc2: [CC6.1, CC6.6]
    iso27001: [A.5.10, A.8.2]
    cis-v8: ["3.3"]
    mitre-attack: [T1530]

  tags: [data-exposure, public-access]

  references:                     # optional. Authoritative sources.
    - https://docs.digitalocean.com/products/spaces/how-to/manage-access/
    - https://cwe.mitre.org/data/definitions/284.html

  scanner: spaces.PublicACL       # required at v0.1: Go function reference

  # v0.16+: alternative Rego policy
  # policy: file://policies/do-spaces-public-acl.rego
```

### Required fields

`id`, `title`, `severity`, `provider`, `description`, `remediation`, `frameworks`, plus exactly one of (`scanner` | `policy`).

### Optional fields

`service`, `resource_type`, `rationale`, `remediations` (machine-applicable), `tags`, `references`.

## Severity guide

| Severity | When to use | Example |
|---|---|---|
| `critical` | exploitable now, data at immediate risk | public DB with no auth |
| `high` | meaningful exposure, audit-failing | public bucket, no firewall on droplet |
| `medium` | best-practice gap, hardening miss | password auth enabled, no MFA on team |
| `low` | hygiene, recommended setting | old API token, no billing alert |
| `info` | observation, no action required | resource without required tag |

When uncertain, err lower. False-positive "high" findings burn user trust faster than false-negative "low" ones.

## Naming conventions

Check IDs are forever-stable. Format: `<provider>-<service>-<concise-rule>`. All lowercase, hyphen-separated.

| Pattern | Example |
|---|---|
| `do-<service>-<rule>` | `do-spaces-public-acl` |
| `linux-<subsystem>-<rule>` | `linux-sshd-no-root-login` |
| `k8s-<resource>-<rule>` | `k8s-pod-no-privileged` |

**Never rename a check ID.** To deprecate, add `deprecated: true` to YAML and a `replaced_by:` pointer.

## Scanner function (Go)

```go
// internal/collectors/digitalocean/spaces.go

package digitalocean

import (
    "context"
    "fmt"

    "github.com/darpanzope/compliancekit/internal/core"
)

// PublicACL is the scanner referenced by spaces.yaml#scanner.
// Signature is fixed: takes context + graph, returns findings.
func PublicACL(ctx context.Context, graph core.ResourceGraph) ([]core.Finding, error) {
    var findings []core.Finding

    for _, bucket := range graph.ByType("digitalocean.spaces.bucket") {
        if bucket.Attr("acl") != "private" {
            findings = append(findings, core.Finding{
                CheckID:  "do-spaces-public-acl",
                Status:   core.Fail,
                Resource: bucket.Ref(),
                Message:  fmt.Sprintf("bucket %q has acl=%s", bucket.Name(), bucket.Attr("acl")),
                Evidence: core.EvidencePtr{Path: bucket.RawPath()},
            })
        }
    }

    return findings, nil
}
```

Key properties of the signature:

- **Reads from the resource graph**, not the cloud API. Collectors do API fetches.
- **Pure function** of inputs. Same graph → same findings.
- **Returns errors** for "I couldn't evaluate this," not for "the resource is non-compliant." Non-compliance is a Finding, not an error.
- **Context-aware.** Long-running checks must honor `ctx.Done()`.
- **No I/O.** Scanner functions never make network calls. If you need data, ask the collector.

## Resource graph access

The graph exposes typed queries:

```go
graph.ByType("digitalocean.spaces.bucket")           // all buckets
graph.ByID("digitalocean.droplet.123")               // one resource
graph.Related(droplet, "firewall")                   // droplets→firewalls
graph.Query(`type = "droplet" AND tag CONTAINS "prod"`)  // filter expr (v0.6+)
```

Resource attribute access:

```go
bucket.Attr("acl")            // string
bucket.AttrInt("size_bytes")  // int
bucket.AttrBool("encrypted")  // bool
bucket.Tags()                 // []string
```

## Status values

| Status | Meaning |
|---|---|
| `core.Pass` | the check evaluated and the resource is compliant |
| `core.Fail` | the check evaluated and the resource is non-compliant |
| `core.Skip` | the check was not applicable (e.g. resource type doesn't apply) |
| `core.Error` | the check could not be evaluated (data missing, ambiguous) |

A scanner function may emit a mix — for a graph of 10 buckets, you might emit 7 `Pass`, 2 `Fail`, 1 `Skip`.

Only `Fail` and `Error` count against severity gates. `Pass` and `Skip` are recorded for evidence-pack completeness.

## Test pattern

```go
// spaces_test.go

func TestPublicACL(t *testing.T) {
    graph := loadFixture(t, "testdata/spaces_two_buckets.json")

    findings, err := PublicACL(context.Background(), graph)
    require.NoError(t, err)
    require.Len(t, findings, 1)
    assert.Equal(t, "do-spaces-public-acl", findings[0].CheckID)
    assert.Equal(t, core.Fail, findings[0].Status)
    assert.Equal(t, "public-read-bucket", findings[0].Resource.Name)
}
```

Every check requires at least:

1. One test with a fixture containing a non-compliant resource (must produce `Fail`).
2. One test with a fixture containing only compliant resources (must produce no `Fail`).

## Fixtures

Fixtures are real recorded API responses. To create a new one:

```
RECORD=1 DO_API_TOKEN=<read-only-token> \
  go test ./internal/collectors/digitalocean -run TestPublicACL
```

The recorder redacts tokens, account UUIDs, and emails automatically. **Always manually review** the recorded file before committing — automated redaction is best-effort.

Fixture naming: `<service>_<scenario>.json`. Example: `spaces_two_buckets.json`, `droplets_no_firewall.json`.

## Framework mapping conventions

Every check must map to at least one framework. Mappings must be specific:

| Framework | ID format | Example |
|---|---|---|
| SOC 2 | Trust Services Criteria IDs | `CC6.1`, `CC6.6`, `CC7.2` |
| ISO 27001 | Annex A control IDs | `A.5.10`, `A.8.2` |
| CIS Controls v8 | numeric IDs as strings | `"3.3"`, `"4.1"` |
| NIST 800-53 r5 | control IDs | `AC-2`, `SC-7` |
| MITRE ATT&CK | technique IDs | `T1530`, `T1078.004` |
| HIPAA | safeguard references | `164.312(a)(1)` |
| PCI-DSS 4.0 | requirement IDs | `1.2.1`, `7.3.2` |

If you don't know the right control, ask in the PR — getting this wrong costs us auditor trust.

**Required for all v0.1+ checks:** at least one SOC 2 *and* one CIS v8 mapping. Other frameworks land later.

## Contributor checklist

When adding a check:

- [ ] YAML metadata under `internal/checks/<provider>/<service>.yaml`
- [ ] Scanner function in `internal/collectors/<provider>/<service>.go`
- [ ] Unit test with at least one `Pass` and one `Fail` case
- [ ] Fixture recorded with `RECORD=1`, manually reviewed for leaked secrets
- [ ] At least one SOC 2 + one CIS v8 mapping
- [ ] Severity matches the guide above
- [ ] Remediation text is specific (a command, not "review settings")
- [ ] `make check` passes locally
- [ ] If introducing a new tag or MITRE technique, update docs

## v0.16+: writing a check in Rego

When Rego support lands, simpler checks can ship as `.rego` files:

```yaml
- id: do-spaces-public-acl
  # ... metadata as above ...
  policy: file://policies/do-spaces-public-acl.rego
  # 'scanner:' field is omitted when 'policy:' is set
```

```rego
# internal/policies/do-spaces-public-acl.rego
package compliancekit.do.spaces.public_acl

deny[finding] {
    bucket := input.resources[_]
    bucket.type == "digitalocean.spaces.bucket"
    bucket.attributes.acl != "private"

    finding := {
        "status": "fail",
        "resource": bucket.id,
        "message": sprintf("bucket %q has acl=%s", [bucket.name, bucket.attributes.acl]),
    }
}
```

Choose Rego when the logic is declarative (matching, filtering, set membership). Stay with Go when you need cross-resource queries, performance optimization, or complex state.

## v0.15+: machine-applicable remediation

`remediations.<tool>` becomes a Go template rendered with the failing resource as context:

```yaml
remediations:
  bash: |
    doctl spaces update {{ .Resource.Name }} --acl private
  terraform: |
    resource "digitalocean_spaces_bucket" "{{ .Resource.Name }}" {
      acl = "private"
    }
```

Run by users via:

```
compliancekit remediate --finding=<id> --as=terraform
```

At v2.x (opt-in), the same snippets are applied directly via `--apply` + `--yes-i-mean-it`.

Template context exposes:

```go
type RemediationContext struct {
    Resource core.Resource   // the failing resource
    Finding  core.Finding    // the finding being remediated
    Project  string          // from config
    Env      string          // from config
}
```

Use only `{{ .Resource.* }}` and `{{ .Finding.* }}` fields documented in `core/`. Anything else may change without notice.

## Deprecating a check

```yaml
- id: do-old-check
  deprecated: true
  deprecated_in: v0.7
  replaced_by: do-new-check
```

Deprecated checks still run unless `severity: info` is set; they print a warning in the report. Remove only after two minor versions.

## Cross-resource checks (v0.6+)

When a check needs to relate multiple resources, walk the graph via `Related`:

```go
func DropletWithoutFirewall(ctx context.Context, graph core.ResourceGraph) ([]core.Finding, error) {
    var findings []core.Finding

    for _, droplet := range graph.ByType("digitalocean.droplet") {
        firewalls := graph.Related(droplet, "firewall")
        if len(firewalls) == 0 {
            findings = append(findings, core.Finding{
                CheckID:  "do-droplet-no-firewall",
                Status:   core.Fail,
                Resource: droplet.Ref(),
                Message:  fmt.Sprintf("droplet %q has no firewall attached", droplet.Name()),
            })
        }
    }

    return findings, nil
}
```

Edges are populated by the collector when it fetches data. Adding a new edge type requires updating the collector to emit it.

## Performance notes

- A scanner runs in <100 ms over typical resource graphs.
- Hot path: avoid map allocations inside the resource loop; pre-allocate the findings slice if the count is bounded.
- The engine fans out scanners across goroutines automatically — your code doesn't need to. Don't spawn your own.
- If a check needs *new* data that isn't in the graph, extend the collector. Don't make the scanner do I/O.

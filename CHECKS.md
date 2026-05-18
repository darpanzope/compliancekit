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
// internal/checks/digitalocean/spaces.go

package digitalocean

import (
    "context"
    "fmt"

    "github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// PublicACL is the scanner referenced by spaces.yaml#scanner.
// Signature is fixed: takes context + graph, returns findings.
func PublicACL(ctx context.Context, graph *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
    var findings []compliancekit.Finding

    for _, bucket := range graph.ByType("digitalocean.spaces.bucket") {
        if bucket.Attr("acl") != "private" {
            findings = append(findings, compliancekit.Finding{
                CheckID:  "do-spaces-public-acl",
                Status:   compliancekit.StatusFail,
                Resource: bucket.Ref(),
                Message:  fmt.Sprintf("bucket %q has acl=%s", bucket.Name, bucket.Attr("acl")),
                Evidence: compliancekit.EvidencePtr{Path: bucket.RawPath},
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
graph.Query(`type = "digitalocean.droplet" AND tag CONTAINS "prod"`) // filter expr
```

Resource attribute access:

```go
bucket.Attr("acl")            // string, "" on miss
bucket.AttrInt("size_bytes")  // int, 0 on miss
bucket.AttrBool("encrypted")  // bool, false on miss
bucket.HasTag("prod")         // bool
bucket.Tags                   // []string field
```

## Status values

| Status | Meaning |
|---|---|
| `compliancekit.StatusPass` | the check evaluated and the resource is compliant |
| `compliancekit.StatusFail` | the check evaluated and the resource is non-compliant |
| `compliancekit.StatusSkip` | the check was not applicable (e.g. resource type doesn't apply) |
| `compliancekit.StatusError` | the check could not be evaluated (data missing, ambiguous) |

A scanner function may emit a mix — for a graph of 10 buckets, you might emit 7 `StatusPass`, 2 `StatusFail`, 1 `StatusSkip`.

Only `StatusFail` and `StatusError` count against severity gates. `StatusPass` and `StatusSkip` are recorded for evidence-pack completeness.

## Test pattern

```go
// spaces_test.go

func TestPublicACL(t *testing.T) {
    graph := loadFixture(t, "testdata/spaces_two_buckets.json")

    findings, err := PublicACL(context.Background(), graph)
    require.NoError(t, err)
    require.Len(t, findings, 1)
    assert.Equal(t, "do-spaces-public-acl", findings[0].CheckID)
    assert.Equal(t, compliancekit.StatusFail, findings[0].Status)
    assert.Equal(t, "public-read-bucket", findings[0].Resource.Name)
}
```

Every check requires at least:

1. One test with a fixture containing a non-compliant resource (must produce `StatusFail`).
2. One test with a fixture containing only compliant resources (must produce no `StatusFail`).

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
    Resource compliancekit.Resource   // the failing resource
    Finding  compliancekit.Finding    // the finding being remediated
    Project  string                   // from config
    Env      string                   // from config
}
```

Use only `{{ .Resource.* }}` and `{{ .Finding.* }}` fields documented in the [`compliancekit` godoc](https://pkg.go.dev/github.com/darpanzope/compliancekit/pkg/compliancekit). Anything else may change without notice.

## Deprecating a check

```yaml
- id: do-old-check
  deprecated: true
  deprecated_in: v0.7
  replaced_by: do-new-check
```

Deprecated checks still run unless `severity: info` is set; they print a warning in the report. Remove only after two minor versions.

## Cross-resource checks (v0.6+ — query DSL shipped)

When a check needs to relate multiple resources, walk the graph via `Related`:

```go
func DropletWithoutFirewall(ctx context.Context, graph *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
    var findings []compliancekit.Finding

    for _, droplet := range graph.ByType("digitalocean.droplet") {
        firewalls := graph.Related(droplet, "firewall")
        if len(firewalls) == 0 {
            findings = append(findings, compliancekit.Finding{
                CheckID:  "do-droplet-no-firewall",
                Status:   compliancekit.StatusFail,
                Resource: droplet.Ref(),
                Message:  fmt.Sprintf("droplet %q has no firewall attached", droplet.Name),
            })
        }
    }

    return findings, nil
}
```

Edges are populated by the collector when it fetches data. Adding a new edge type requires updating the collector to emit it.

For the "give me a filtered slice of resources" case, prefer the v0.6 query DSL over manual filtering:

```go
prod, err := graph.Query(`type = "digitalocean.droplet" AND tag CONTAINS "prod"`)
if err != nil {
    return nil, err  // parse error -- fail loudly, do not silently return zero matches
}
for _, droplet := range prod {
    // ...
}
```

Supported syntax: `=`, `!=`, `CONTAINS`, `AND`, `OR`, `NOT`, `(...)`. Identifiers map to `type`, `provider`, `region`, `name`, `id`, the special `tag` (matches any tag in the slice), or any key in `Resource.Attributes`. Values are quoted strings, bare integers, or `true`/`false`. See [`pkg/compliancekit/query.go`](pkg/compliancekit/query.go) for the parser and [`pkg/compliancekit/query_test.go`](pkg/compliancekit/query_test.go) for runnable examples.

A parse error is the loud signal — the check author has a typo. The function returns `(nil, error)`; the scanner surfaces it as `StatusError` per check, so the operator sees what's wrong without losing findings from other checks.

## Performance notes

- A scanner runs in <100 ms over typical resource graphs.
- Hot path: avoid map allocations inside the resource loop; pre-allocate the findings slice if the count is bounded.
- The engine fans out scanners across goroutines automatically — your code doesn't need to. Don't spawn your own.
- If a check needs *new* data that isn't in the graph, extend the collector. Don't make the scanner do I/O.

## Writing a check in Rego (v0.16+)

From v0.16, the Go scanner is one of two implementation paths. The other is a Rego policy that ships as a `.rego` file and registers into the same Check registry. Pick Rego when:

- The check is a straightforward attribute test ("flag every resource where `attributes.X` is missing or wrong"). Most posture checks fit this pattern.
- You want to ship a check without compiling Go or invoking the full contributor flow (clone the repo, install golangci-lint, etc.).
- You're a security engineer who already writes Rego for Gatekeeper / Conftest / Trivy and want to reuse the muscle memory.

Pick Go when:

- The check needs cross-resource traversal (graph queries spanning multiple resource types).
- The check needs computed values that Rego built-ins can't express (regex over strings is fine; non-trivial parsing of nested formats is not).
- The check's metadata is computed at runtime from external sources.

### Policy shape

Every shipped Rego policy follows this structure:

```rego
package compliancekit.<provider>.<service>.<short_name>

# One-line summary of what this policy flags.

metadata := {
  "id":            "<provider>-<service>-<rule>",      # required, kebab-case, forever-stable
  "title":         "Short human-readable title",       # required
  "description":   "Prose explaining what + why.",     # required
  "severity":      "critical" | "high" | "medium" | "low" | "info",  # required
  "provider":      "<provider>",                       # required (aws, gcp, …)
  "service":       "<service>",                        # optional
  "resource_type": "<provider>.<type>",                # optional
  "rationale":     "Why this fires; cite incidents.",  # optional
  "remediation":   "How to fix; copy-paste command.",  # optional
  "frameworks": {
    "soc2":     ["CC6.1"],
    "iso27001": ["A.8.3"],
    "cis-v8":   ["3.3"],
  },                                                   # optional but expected for shipped policies
  "tags":        ["data-exposure", "public-access"],  # optional
  "references":  ["https://docs.aws.amazon.com/..."], # optional
}

findings := [f |
  r := input.resources[_]
  r.type == "<provider>.<type>"
  # ...filtering conditions...
  f := {
    "resource_id": r.id,
    "status":      "fail" | "pass" | "skip" | "error",
    "message":     "human-readable detail",   # optional
    "severity":    "high",                    # optional override of metadata.severity
    "tags":        ["extra-tag"],             # optional addition to metadata.tags
  }
]
```

### Built-ins

Four `compliancekit.` built-ins eliminate the most common boilerplate:

| Built-in | Returns | Behavior |
|---|---|---|
| `compliancekit.has_tag(resource, name)` | bool | True iff resource.tags[] contains name. False (not error) if tags is missing. |
| `compliancekit.attr_str(resource, key)` | string | resource.attributes[key] as string; `""` on miss or wrong type. |
| `compliancekit.attr_bool(resource, key)` | bool | resource.attributes[key] as bool; `false` on miss or wrong type. |
| `compliancekit.cvss_band(score)` | string | CVSS v3 score → `"critical"` (9+), `"high"` (7+), `"medium"` (4+), `"low"` (0.1+), `"info"`. |

These match the semantics of `compliancekit.Resource.Attr` / `AttrBool` / `HasTag` in Go and the `cvssToSeverity` helper in the ingest packages, so a check author moving between Go and Rego doesn't have to learn two sets of rules.

### Local authoring loop

```bash
# 1. Author the policy
$EDITOR mypolicy.rego

# 2. Build a fixture matching the resource shape the policy reads
cat > fixture.json <<'JSON'
[
  {"id": "demo.bucket.x", "type": "demo.bucket", "name": "x",
   "provider": "demo", "attributes": {"public": true}}
]
JSON

# 3. Evaluate against the fixture
compliancekit policy test fixture.json mypolicy.rego
# {"check_id":"...", "status":"fail", ...}

# 4. Compile-check + metadata-validate before shipping
compliancekit policy validate ./policies/

# 5. Reformat to canonical
compliancekit policy fmt mypolicy.rego
```

### Worked examples

15 representative policies live under [examples/policies/](examples/policies/) — three per provider lane (AWS, GCP, DigitalOcean, Kubernetes, Linux). Start by reading the one closest to what you're flagging; copy + adapt.

### What policies cannot do

- **No I/O.** Rego is pure-functional. The data plane is the in-memory `ResourceGraph` snapshot passed in as `input.resources[]`. A policy cannot reach the cloud APIs, the filesystem, or the network. Collectors do all data fetching.
- **No cross-policy state.** Each policy is evaluated independently; there is no shared `data` between policies in compliancekit's invocation.
- **No mutation of findings.** A policy returns findings; the engine consumes them. Per ADR-006 the binary is read-only end-to-end.

# hello — reference compliancekit plugin

The canonical starter pack referenced by the v1.13 plugin docs.
Copy this directory + iterate.

## Install

```sh
compliancekit plugins install ./examples/plugins/hello --allow-unsigned
compliancekit plugins list
```

## What it does

Flags every resource whose `attrs.audit_tag` is missing with a
medium-severity finding. The Rego is intentionally tiny — the value
of this pack is the manifest shape + the install round-trip, not
the check body.

## Shape

```
hello/
├── manifest.yaml          # plugin metadata (apiVersion / name / kinds)
├── rego/
│   └── hello.rego         # the check itself
└── README.md              # this file
```

## Sign

For production, generate a cosign keypair and sign the manifest:

```sh
cosign generate-key-pair
cosign sign-blob --output-signature signature.sig manifest.yaml
```

Then point the daemon at `cosign.pub` with `--plugin-pubkey` and
drop `--allow-unsigned`.

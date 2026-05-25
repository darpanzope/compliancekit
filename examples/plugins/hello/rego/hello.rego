# Reference Rego pack for the hello plugin.
#
# Demonstrates the minimum a compliancekit plugin needs: a `package`
# header under compliancekit.checks.<id>, and a `violation` rule that
# returns one or more {"message", "severity"} objects per resource
# the daemon hands in via input.resource.
#
# The hello plugin flags every resource whose attrs map omits the
# "audit_tag" key — useful as a sanity check that the plugin SDK
# wires the input/output contract correctly.

package compliancekit.checks.hello

violation[result] {
    not input.resource.attrs.audit_tag
    result := {
        "message": "resource missing required attrs.audit_tag",
        "severity": "medium",
    }
}

package render

import (
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "''"},
		{"simple", "simple"},
		{"with space", "'with space'"},
		{"with$dollar", "'with$dollar'"},
		{"don't", `'don'"'"'t'`},
		{"safe-chars_only.123/path:colon", "safe-chars_only.123/path:colon"},
	}
	for _, c := range cases {
		got := ShellQuote(c.in)
		if got != c.want {
			t.Errorf("ShellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCommentBash(t *testing.T) {
	got := CommentBash("line one\nline two")
	want := "# line one\n# line two"
	if got != want {
		t.Errorf("CommentBash multiline = %q, want %q", got, want)
	}
	if CommentBash("") != "" {
		t.Errorf("CommentBash empty should be empty")
	}
}

func TestHCLBlock_Basic(t *testing.T) {
	b := NewHCLBlock("resource", "aws_s3_bucket_public_access_block", "fix")
	b.Attr("bucket", "my-bucket")
	b.Attr("block_public_acls", true)
	b.Attr("block_public_policy", true)
	got := b.String()

	mustContain(t, got, `resource "aws_s3_bucket_public_access_block" "fix"`)
	mustContain(t, got, `bucket              = "my-bucket"`)
	mustContain(t, got, `block_public_acls   = true`)
}

func TestHCLBlock_SubBlocks(t *testing.T) {
	b := NewHCLBlock("resource", "aws_kms_key", "fix")
	b.Attr("description", "scanner-generated")
	b.Attr("enable_key_rotation", true)
	lifecycle := b.SubBlock("lifecycle")
	lifecycle.Attr("prevent_destroy", true)

	got := b.String()
	mustContain(t, got, "lifecycle {")
	mustContain(t, got, "prevent_destroy = true")
}

func TestHCLBlock_QuotingEdgeCases(t *testing.T) {
	b := NewHCLBlock("locals")
	b.Attr("with_quotes", `value "x"`)
	b.Attr("with_interpolation", "before${var}after")
	b.Attr("list", []string{"a", "b"})

	got := b.String()
	mustContain(t, got, `\"x\"`)
	mustContain(t, got, "$${var}")
	mustContain(t, got, `["a", "b"]`)
}

func TestYAMLDoc_Nested(t *testing.T) {
	d := NewYAMLDoc()
	d.Set("apiVersion", "apps/v1")
	d.Set("kind", "Deployment")
	d.Set("metadata.name", "fix-me")
	d.Set("spec.template.spec.securityContext.runAsNonRoot", true)

	got := d.String()
	mustContain(t, got, "apiVersion: apps/v1")
	mustContain(t, got, "kind: Deployment")
	mustContain(t, got, "metadata:\n  name: fix-me")
	mustContain(t, got, "securityContext:\n        runAsNonRoot: true")
}

func TestYAMLDoc_ScalarsQuotedWhenAmbiguous(t *testing.T) {
	d := NewYAMLDoc()
	d.Set("v_true", "true")  // string "true", not boolean
	d.Set("v_yes", "yes")    // string "yes"
	d.Set("v_bare", "abc")   // safe to leave unquoted
	d.Set("v_colon", "a: b") // colon → quote
	got := d.String()
	mustContain(t, got, `v_true: "true"`)
	mustContain(t, got, `v_yes: "yes"`)
	mustContain(t, got, `v_bare: abc`)
	mustContain(t, got, `v_colon: "a: b"`)
}

func TestPatchPath(t *testing.T) {
	op := PatchPath("add", "/spec/securityContext/runAsNonRoot", true)
	if op["op"] != "add" || op["path"] != "/spec/securityContext/runAsNonRoot" || op["value"] != true {
		t.Errorf("PatchPath = %+v", op)
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("missing substring:\nwant: %q\ngot:\n%s", needle, haystack)
	}
}

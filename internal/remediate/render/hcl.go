package render

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// boolean-literal token constants. HCL and YAML both use the same
// "true" / "false" strings, but goconst (rightly) wants them named
// rather than free-floating string literals.
const (
	tokTrue  = "true"
	tokFalse = "false"
)

// HCLBlock is a minimal HCL2 emitter used by Terraform strategies.
// It is NOT a full HCL printer — we only need enough to produce the
// surgical-fix blocks strategies emit (resource / data / module).
// Anything more elaborate should call out to hashicorp/hcl directly.
//
// Usage:
//
//	b := NewHCLBlock("resource", "aws_s3_bucket_public_access_block", "fix")
//	b.Attr("bucket", "my-bucket")
//	b.Attr("block_public_acls", true)
//	out := b.String()
//
// Produces:
//
//	resource "aws_s3_bucket_public_access_block" "fix" {
//	  bucket             = "my-bucket"
//	  block_public_acls  = true
//	}
type HCLBlock struct {
	blockType string   // "resource", "data", "module", ...
	labels    []string // ["aws_s3_bucket_public_access_block", "fix"]
	attrs     []hclAttr
	children  []*HCLBlock
}

type hclAttr struct {
	key string
	val string // pre-rendered HCL literal
}

// NewHCLBlock creates a top-level block with the given type and labels.
// Common patterns:
//
//	NewHCLBlock("resource", "<type>", "<name>")
//	NewHCLBlock("data", "<type>", "<name>")
//	NewHCLBlock("module", "<name>")
//	NewHCLBlock("locals")                       // no labels
func NewHCLBlock(blockType string, labels ...string) *HCLBlock {
	return &HCLBlock{blockType: blockType, labels: labels}
}

// Attr appends a key = value pair. value is converted to its HCL
// literal form: string → quoted string, bool → true/false, int →
// digits, []string → list-of-strings, map[string]string → object.
// Anything else is rendered via fmt.Sprintf("%v") with quoting,
// which is correct enough for the unusual case but not for nested
// maps — strategies needing those should use SubBlock or RawAttr.
func (b *HCLBlock) Attr(key string, value any) *HCLBlock {
	b.attrs = append(b.attrs, hclAttr{key: key, val: hclLiteral(value)})
	return b
}

// RawAttr appends a key = value pair where value is already an HCL
// expression (e.g. an interpolation, a heredoc, a function call).
// Used when Attr's reflection-based literal rendering is wrong, e.g.
// `policy = jsonencode({...})`.
func (b *HCLBlock) RawAttr(key, expr string) *HCLBlock {
	b.attrs = append(b.attrs, hclAttr{key: key, val: expr})
	return b
}

// SubBlock appends a nested block (e.g. `lifecycle { ... }` inside
// a resource). Returns the new block so the caller can chain Attr
// calls on it.
func (b *HCLBlock) SubBlock(blockType string, labels ...string) *HCLBlock {
	child := NewHCLBlock(blockType, labels...)
	b.children = append(b.children, child)
	return child
}

// String renders the block as canonical HCL. Attribute alignment
// pads the `=` to the longest key in the block so the output reads
// like `terraform fmt` output.
func (b *HCLBlock) String() string {
	return b.render(0)
}

func (b *HCLBlock) render(indent int) string {
	pad := strings.Repeat("  ", indent)
	var sb strings.Builder
	sb.WriteString(pad)
	sb.WriteString(b.blockType)
	for _, l := range b.labels {
		sb.WriteString(` "`)
		sb.WriteString(l)
		sb.WriteString(`"`)
	}
	sb.WriteString(" {\n")
	maxKey := 0
	for _, a := range b.attrs {
		if len(a.key) > maxKey {
			maxKey = len(a.key)
		}
	}
	for _, a := range b.attrs {
		fmt.Fprintf(&sb, "%s  %-*s = %s\n", pad, maxKey, a.key, a.val)
	}
	if len(b.attrs) > 0 && len(b.children) > 0 {
		sb.WriteString("\n")
	}
	for i, c := range b.children {
		sb.WriteString(c.render(indent + 1))
		if i != len(b.children)-1 {
			sb.WriteString("\n")
		}
	}
	sb.WriteString(pad)
	sb.WriteString("}\n")
	return sb.String()
}

// hclLiteral renders a Go value as its HCL2 literal. Unsupported
// types fall back to a quoted fmt.Sprintf("%v") with backslash
// escaping — wrong for some shapes but never a parse error.
func hclLiteral(v any) string {
	switch x := v.(type) {
	case string:
		return hclQuote(x)
	case bool:
		if x {
			return tokTrue
		}
		return tokFalse
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case []string:
		quoted := make([]string, len(x))
		for i, s := range x {
			quoted[i] = hclQuote(s)
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	case map[string]string:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = fmt.Sprintf("%s = %s", k, hclQuote(x[k]))
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	default:
		return hclQuote(fmt.Sprintf("%v", x))
	}
}

// hclQuote wraps s in double quotes and escapes the characters HCL2
// requires: backslash, double quote, and the literal $ when followed
// by { (which would otherwise start an interpolation).
func hclQuote(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			sb.WriteString(`\\`)
		case '"':
			sb.WriteString(`\"`)
		case '\n':
			sb.WriteString(`\n`)
		case '\t':
			sb.WriteString(`\t`)
		case '$':
			if i+1 < len(s) && s[i+1] == '{' {
				sb.WriteString(`$$`)
			} else {
				sb.WriteByte('$')
			}
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

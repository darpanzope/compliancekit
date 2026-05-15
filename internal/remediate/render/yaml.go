package render

import (
	"fmt"
	"sort"
	"strings"
)

// YAMLDoc is a tiny, deterministic YAML emitter for the patch + helm
// + ansible strategies. Avoids pulling in gopkg.in/yaml.v3 because
// (a) its output ordering is map-iteration-dependent unless you build
// a yaml.Node tree, which is more code than this; (b) the blocks we
// emit are small and structurally simple; (c) the bigger risk is
// silent key reordering across runs producing noisy diffs, which
// this implementation explicitly prevents by emitting in insertion
// order.
//
// Strategies build documents via Set("a.b.c", v). Each dot creates a
// nested map. Slices are emitted as block sequences.
type YAMLDoc struct {
	root *yamlMap
}

type yamlValue struct {
	scalar string
	list   []yamlValue
	mapv   *yamlMap
}

type yamlMap struct {
	keys []string
	vals map[string]yamlValue
}

func newMap() *yamlMap {
	return &yamlMap{vals: map[string]yamlValue{}}
}

func (m *yamlMap) set(key string, v yamlValue) {
	if _, ok := m.vals[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.vals[key] = v
}

// NewYAMLDoc creates an empty YAML document.
func NewYAMLDoc() *YAMLDoc { return &YAMLDoc{root: newMap()} }

// Set assigns value at the dotted path, creating intermediate maps
// as needed. Value types accepted: string, bool, int, []string,
// []any, map[string]any. Anything else is coerced via fmt.Sprintf.
//
// Set("metadata.name", "fix") → metadata: {name: fix}.
// Set("spec.containers", []any{...}) → list of maps.
func (d *YAMLDoc) Set(path string, value any) *YAMLDoc {
	if path == "" {
		return d
	}
	parts := strings.Split(path, ".")
	cur := d.root
	for i, p := range parts {
		if i == len(parts)-1 {
			cur.set(p, valueOf(value))
			return d
		}
		existing, ok := cur.vals[p]
		if !ok || existing.mapv == nil {
			child := newMap()
			cur.set(p, yamlValue{mapv: child})
			cur = child
			continue
		}
		cur = existing.mapv
	}
	return d
}

// String renders the document as YAML.
func (d *YAMLDoc) String() string {
	if d.root == nil || len(d.root.keys) == 0 {
		return ""
	}
	var sb strings.Builder
	renderMap(&sb, d.root, 0)
	return sb.String()
}

func renderMap(sb *strings.Builder, m *yamlMap, indent int) {
	pad := strings.Repeat("  ", indent)
	for _, k := range m.keys {
		v := m.vals[k]
		switch {
		case v.mapv != nil && len(v.mapv.keys) > 0:
			fmt.Fprintf(sb, "%s%s:\n", pad, k)
			renderMap(sb, v.mapv, indent+1)
		case v.list != nil:
			fmt.Fprintf(sb, "%s%s:\n", pad, k)
			for _, item := range v.list {
				renderListItem(sb, item, indent)
			}
		default:
			fmt.Fprintf(sb, "%s%s: %s\n", pad, k, v.scalar)
		}
	}
}

func renderListItem(sb *strings.Builder, v yamlValue, indent int) {
	pad := strings.Repeat("  ", indent)
	switch {
	case v.mapv != nil && len(v.mapv.keys) > 0:
		first := true
		for _, k := range v.mapv.keys {
			child := v.mapv.vals[k]
			var prefix string
			if first {
				prefix = pad + "- "
				first = false
			} else {
				prefix = pad + "  "
			}
			switch {
			case child.mapv != nil && len(child.mapv.keys) > 0:
				fmt.Fprintf(sb, "%s%s:\n", prefix, k)
				renderMap(sb, child.mapv, indent+2)
			case child.list != nil:
				fmt.Fprintf(sb, "%s%s:\n", prefix, k)
				for _, sub := range child.list {
					renderListItem(sb, sub, indent+1)
				}
			default:
				fmt.Fprintf(sb, "%s%s: %s\n", prefix, k, child.scalar)
			}
		}
	default:
		fmt.Fprintf(sb, "%s- %s\n", pad, v.scalar)
	}
}

// valueOf converts a Go value into the internal representation.
// Unknown types fall back to fmt.Sprintf("%v") with YAML quoting.
func valueOf(v any) yamlValue {
	if scalar, ok := scalarOf(v); ok {
		return yamlValue{scalar: scalar}
	}
	switch x := v.(type) {
	case yamlValue:
		return x
	case []string:
		out := make([]yamlValue, len(x))
		for i, s := range x {
			out[i] = yamlValue{scalar: yamlQuote(s)}
		}
		return yamlValue{list: out}
	case []any:
		out := make([]yamlValue, len(x))
		for i, item := range x {
			out[i] = valueOf(item)
		}
		return yamlValue{list: out}
	case map[string]any:
		m := newMap()
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m.set(k, valueOf(x[k]))
		}
		return yamlValue{mapv: m}
	default:
		return yamlValue{scalar: yamlQuote(fmt.Sprintf("%v", x))}
	}
}

// scalarOf collapses the scalar branches of valueOf. Returns (rendered, true)
// when v is one of the recognized scalar types, (_, false) when v needs the
// composite branches in valueOf.
func scalarOf(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "null", true
	case string:
		return yamlQuote(x), true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case int:
		return fmt.Sprintf("%d", x), true
	case int64:
		return fmt.Sprintf("%d", x), true
	case float64:
		return fmt.Sprintf("%g", x), true
	}
	return "", false
}

// yamlQuote applies double-quote-with-escaping when the string
// contains YAML-interpretable characters; otherwise it returns the
// string bare. Conservative: prefers quotes over a parse surprise.
func yamlQuote(s string) string {
	if s == "" {
		return `""`
	}
	if needsYAMLQuoting(s) {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return `"` + s + `"`
	}
	return s
}

// needsYAMLQuoting flags strings that would be interpreted as
// non-string scalars (booleans, numbers, null) or that contain
// characters meaningful to the YAML block grammar.
func needsYAMLQuoting(s string) bool {
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off", "null", "~", "":
		return true
	}
	for _, r := range s {
		switch r {
		case ':', '#', '&', '*', '!', '|', '>', '%', '@', '`',
			'"', '\'', '\n', '\t', '{', '}', '[', ']', ',':
			return true
		}
	}
	if s[0] == '-' || s[0] == '?' || s[0] == ' ' {
		return true
	}
	return false
}

// PatchPath is a small helper for kubectl patch strategies: it
// returns a JSONPatch operation as a YAML mapping. Useful when the
// strategy wants to emit both the structured patch (for `kubectl
// patch --type=json -p '<...>'`) and the equivalent YAML form for
// the operator's review.
func PatchPath(op, path string, value any) map[string]any {
	out := map[string]any{
		"op":   op,
		"path": path,
	}
	if value != nil {
		out["value"] = value
	}
	return out
}

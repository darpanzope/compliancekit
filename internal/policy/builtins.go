package policy

import (
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
)

// Custom Rego built-ins compliancekit registers on every policy
// evaluator. These four are unblockers — without them every
// policy reimplements the same boilerplate for tag membership,
// attribute access, and CVSS bucketing.
//
// Each built-in is pure: no I/O, no goroutines, deterministic.
// Adding a fifth built-in is a stability change governed by SemVer
// once v1.0 freezes the API; the policy authors who depend on
// `compliancekit.has_tag` need to be able to trust it sticks.
//
// Registered automatically by every call to NewEvaluator(...) and
// Compile(...) via the builtinOptions slice exported below.
//
// Naming: every built-in lives under the `compliancekit.` prefix
// so authors never confuse them with Rego's stdlib (`strings.*`,
// `time.*`, etc.).

// builtinHasTag returns true iff the supplied resource carries the
// named tag. Tags live at `resource.tags[]` as the v0.1 schema.
//
//	compliancekit.has_tag(resource, "production")  →  true | false
var builtinHasTag = &rego.Function{
	Name: "compliancekit.has_tag",
	Decl: types.NewFunction(types.Args(
		types.Named("resource", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
		types.Named("tag", types.S),
	), types.B),
}

func implHasTag(_ rego.BuiltinContext, resource, tagTerm *ast.Term) (*ast.Term, error) {
	obj, ok := resource.Value.(ast.Object)
	if !ok {
		return ast.BooleanTerm(false), nil
	}
	tagsTerm := obj.Get(ast.StringTerm("tags"))
	if tagsTerm == nil {
		return ast.BooleanTerm(false), nil
	}
	want, ok := tagsTerm.Value.(*ast.Array)
	if !ok {
		return ast.BooleanTerm(false), nil
	}
	tagStr, ok := tagTerm.Value.(ast.String)
	if !ok {
		return ast.BooleanTerm(false), nil
	}
	tag := string(tagStr)
	found := false
	want.Foreach(func(t *ast.Term) {
		if s, ok := t.Value.(ast.String); ok && string(s) == tag {
			found = true
		}
	})
	return ast.BooleanTerm(found), nil
}

// builtinAttrStr returns the string-typed attribute at the supplied
// key, or "" if the attribute is missing or not a string. Mirrors
// core.Resource.Attr in semantics so policy authors get the same
// behavior as Go check authors.
//
//	compliancekit.attr_str(resource, "encryption")  →  "AES256" | ""
var builtinAttrStr = &rego.Function{
	Name: "compliancekit.attr_str",
	Decl: types.NewFunction(types.Args(
		types.Named("resource", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
		types.Named("key", types.S),
	), types.S),
}

func implAttrStr(_ rego.BuiltinContext, resource, keyTerm *ast.Term) (*ast.Term, error) {
	attrs := getAttrs(resource)
	if attrs == nil {
		return ast.StringTerm(""), nil
	}
	v := attrs.Get(ast.StringTerm(string(keyTerm.Value.(ast.String))))
	if v == nil {
		return ast.StringTerm(""), nil
	}
	if s, ok := v.Value.(ast.String); ok {
		return ast.StringTerm(string(s)), nil
	}
	return ast.StringTerm(""), nil
}

// builtinAttrBool returns the bool-typed attribute at the supplied
// key, or false if the attribute is missing or not a bool.
//
//	compliancekit.attr_bool(resource, "public")  →  true | false
var builtinAttrBool = &rego.Function{
	Name: "compliancekit.attr_bool",
	Decl: types.NewFunction(types.Args(
		types.Named("resource", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
		types.Named("key", types.S),
	), types.B),
}

func implAttrBool(_ rego.BuiltinContext, resource, keyTerm *ast.Term) (*ast.Term, error) {
	attrs := getAttrs(resource)
	if attrs == nil {
		return ast.BooleanTerm(false), nil
	}
	v := attrs.Get(ast.StringTerm(string(keyTerm.Value.(ast.String))))
	if v == nil {
		return ast.BooleanTerm(false), nil
	}
	if b, ok := v.Value.(ast.Boolean); ok {
		return ast.BooleanTerm(bool(b)), nil
	}
	return ast.BooleanTerm(false), nil
}

// builtinCVSSBand maps a CVSS v3 base score (0-10) onto the
// compliancekit Severity band. Centralized here so every CVE-aware
// policy uses the same bucketing as the SARIF / Trivy / Grype
// adapters (`cvssToSeverity` in the ingest packages).
//
//	compliancekit.cvss_band(8.1)  →  "high"
//	compliancekit.cvss_band(9.4)  →  "critical"
//	compliancekit.cvss_band(0)    →  "info"
var builtinCVSSBand = &rego.Function{
	Name: "compliancekit.cvss_band",
	Decl: types.NewFunction(types.Args(
		types.Named("score", types.N),
	), types.S),
}

func implCVSSBand(_ rego.BuiltinContext, scoreTerm *ast.Term) (*ast.Term, error) {
	n, ok := scoreTerm.Value.(ast.Number)
	if !ok {
		return ast.StringTerm("info"), nil
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(string(n)), 64)
	if err != nil {
		// Deliberately swallow: a malformed CVSS value should
		// default to "info" rather than aborting an entire scan.
		// Policy authors can detect bad input by guarding with
		// is_number() before calling.
		return ast.StringTerm("info"), nil //nolint:nilerr // swallow: malformed CVSS → safe default, not a scan-abort
	}
	switch {
	case f >= 9.0:
		return ast.StringTerm("critical"), nil
	case f >= 7.0:
		return ast.StringTerm("high"), nil
	case f >= 4.0:
		return ast.StringTerm("medium"), nil
	case f >= 0.1:
		return ast.StringTerm("low"), nil
	}
	return ast.StringTerm("info"), nil
}

// getAttrs extracts the `attributes` object from a resource term,
// returning nil if missing or wrong-shaped. Shared by attr_str +
// attr_bool above; tightly scoped to avoid surfacing typed errors
// to the policy author (returning a zero value is the contract).
func getAttrs(resource *ast.Term) ast.Object {
	obj, ok := resource.Value.(ast.Object)
	if !ok {
		return nil
	}
	a := obj.Get(ast.StringTerm("attributes"))
	if a == nil {
		return nil
	}
	o, ok := a.Value.(ast.Object)
	if !ok {
		return nil
	}
	return o
}

// builtinOptions returns the slice of rego.Option that registers
// every compliancekit built-in on a rego.New() builder. Used by
// policy.go's Evaluate and policy.go's Compile so the built-ins
// are always available; never absent in one path.
func builtinOptions() []func(*rego.Rego) {
	return []func(*rego.Rego){
		rego.Function2(builtinHasTag, implHasTag),
		rego.Function2(builtinAttrStr, implAttrStr),
		rego.Function2(builtinAttrBool, implAttrBool),
		rego.Function1(builtinCVSSBand, implCVSSBand),
	}
}

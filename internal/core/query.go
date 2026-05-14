package core

import (
	"fmt"
	"strings"
	"unicode"
)

// Query filters the graph and returns the resources matching expr.
// The expression is a small DSL designed to express the "give me
// resources of type X with attribute Y" filters that check scanners
// repeat by hand today.
//
// Supported syntax:
//
//	identifier OP value      a single comparison
//	expr AND expr            both must hold
//	expr OR expr             either holds
//	NOT expr                 negation
//	( expr )                 grouping
//
// Identifiers:
//
//	type                     matches Resource.Type
//	provider                 matches Resource.Provider
//	region                   matches Resource.Region
//	name                     matches Resource.Name
//	id                       matches Resource.ID
//	tag                      special: matches any value in Resource.Tags
//	<any other ident>        matches Resource.Attributes[ident]
//
// Operators:
//
//	=                        string or bool equality
//	!=                       negation of =
//	CONTAINS                 substring match (strings only)
//
// Values are double-quoted strings, the literal true / false, or
// bare integers. Identifiers are case-sensitive (matching the
// attribute map's case); operators and keywords are case-insensitive.
//
// Example queries:
//
//	type = "digitalocean.droplet"
//	type = "digitalocean.droplet" AND tag CONTAINS "prod"
//	provider = "linux" AND reachable = true
//	NOT (region = "nyc1" OR region = "nyc3")
//
// Errors: a malformed expression returns nil and a parse error.
// Scanners are expected to fail loudly on parse errors -- a typo
// in a check's query should fail tests, not silently produce zero
// matches.
func (g *ResourceGraph) Query(expr string) ([]Resource, error) {
	node, err := parseQuery(expr)
	if err != nil {
		return nil, fmt.Errorf("query %q: %w", expr, err)
	}
	all := g.All()
	out := []Resource{}
	for _, r := range all {
		if node.match(r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// opContains is the keyword form of the substring operator. Hoisted
// to a constant so goconst stops complaining and so a rename can
// happen in one place.
const opContains = "CONTAINS"

// queryNode is the parsed expression tree. Three concrete variants:
//
//   - compareNode: leaf, an `ident OP value` comparison
//   - boolNode:    binary AND / OR of two children
//   - notNode:     unary negation
//
// All implement match(Resource) bool.
type queryNode interface {
	match(Resource) bool
}

type compareNode struct {
	ident string // lowercase
	op    string // "=", "!=", "CONTAINS"
	value any    // string, bool, or int
}

func (n compareNode) match(r Resource) bool {
	got := resolveIdent(r, n.ident)
	switch v := n.value.(type) {
	case string:
		gs := asString(got)
		switch n.op {
		case "=":
			return gs == v
		case "!=":
			return gs != v
		case opContains:
			// tag is special: it's a []string. CONTAINS means "any tag equals or contains v".
			if n.ident == "tag" {
				for _, t := range r.Tags {
					if strings.Contains(t, v) {
						return true
					}
				}
				return false
			}
			return strings.Contains(gs, v)
		}
	case bool:
		gb := asBool(got)
		switch n.op {
		case "=":
			return gb == v
		case "!=":
			return gb != v
		}
	case int:
		gi := asInt(got)
		switch n.op {
		case "=":
			return gi == v
		case "!=":
			return gi != v
		}
	}
	return false
}

type boolNode struct {
	op    string // "AND" or "OR"
	left  queryNode
	right queryNode
}

func (n boolNode) match(r Resource) bool {
	if n.op == "AND" {
		return n.left.match(r) && n.right.match(r)
	}
	return n.left.match(r) || n.right.match(r)
}

type notNode struct {
	child queryNode
}

func (n notNode) match(r Resource) bool {
	return !n.child.match(r)
}

// resolveIdent maps an identifier to the corresponding Resource field
// or attribute value. Returns the raw any from the attribute map; the
// caller's match() compares via asString / asBool / asInt.
func resolveIdent(r Resource, ident string) any {
	switch ident {
	case "type":
		return r.Type
	case "provider":
		return r.Provider
	case "region":
		return r.Region
	case "name":
		return r.Name
	case "id":
		return r.ID
	case "tag":
		// `tag CONTAINS "x"` is handled in match(); for `tag = "x"`
		// we accept "any tag equals x".
		return r.Tags
	}
	return r.Attributes[ident]
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []string:
		// `tag = "x"` -> any tag equals x; render via Contains check
		// at the caller.
		for _, s := range x {
			if s != "" {
				return s
			}
		}
		return ""
	}
	return ""
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func asInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

// ============================================================
// Parser
// ============================================================

// parseQuery is the entry point. Returns the root node.
func parseQuery(s string) (queryNode, error) {
	p := &queryParser{tokens: tokenize(s)}
	node, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.tokens) {
		return nil, fmt.Errorf("unexpected token %q at position %d", p.tokens[p.pos].value, p.pos)
	}
	return node, nil
}

type queryParser struct {
	tokens []token
	pos    int
}

type token struct {
	kind  string // ident, string, int, bool, op, keyword, lparen, rparen
	value string
}

// parseExpr parses: term (OR term)*
func (p *queryParser) parseExpr() (queryNode, error) {
	left, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	for p.peekKeyword("OR") {
		p.pos++
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		left = boolNode{op: "OR", left: left, right: right}
	}
	return left, nil
}

// parseTerm parses: factor (AND factor)*
func (p *queryParser) parseTerm() (queryNode, error) {
	left, err := p.parseFactor()
	if err != nil {
		return nil, err
	}
	for p.peekKeyword("AND") {
		p.pos++
		right, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		left = boolNode{op: "AND", left: left, right: right}
	}
	return left, nil
}

// parseFactor parses: NOT factor | ( expr ) | compare
func (p *queryParser) parseFactor() (queryNode, error) {
	if p.peekKeyword("NOT") {
		p.pos++
		child, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		return notNode{child: child}, nil
	}
	if p.peekKind("lparen") {
		p.pos++
		expr, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if !p.peekKind("rparen") {
			return nil, fmt.Errorf("expected ')'")
		}
		p.pos++
		return expr, nil
	}
	return p.parseCompare()
}

// parseCompare parses: ident OP value
func (p *queryParser) parseCompare() (queryNode, error) {
	if p.pos >= len(p.tokens) || p.tokens[p.pos].kind != "ident" {
		return nil, fmt.Errorf("expected identifier")
	}
	ident := p.tokens[p.pos].value
	p.pos++

	if p.pos >= len(p.tokens) {
		return nil, fmt.Errorf("expected operator after %q", ident)
	}
	opTok := p.tokens[p.pos]
	if opTok.kind != "op" && opTok.kind != "keyword" {
		return nil, fmt.Errorf("expected operator after %q, got %q", ident, opTok.value)
	}
	op := strings.ToUpper(opTok.value)
	if op != "=" && op != "!=" && op != opContains {
		return nil, fmt.Errorf("unknown operator %q", opTok.value)
	}
	p.pos++

	if p.pos >= len(p.tokens) {
		return nil, fmt.Errorf("expected value after %q", op)
	}
	valTok := p.tokens[p.pos]
	p.pos++

	switch valTok.kind {
	case "string":
		return compareNode{ident: ident, op: op, value: valTok.value}, nil
	case "bool":
		return compareNode{ident: ident, op: op, value: valTok.value == "true"}, nil
	case "int":
		// Don't parse the int here; let asInt do it via int conversion.
		// Actually we need it for direct compare -- parse now.
		var i int
		_, err := fmt.Sscanf(valTok.value, "%d", &i)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q", valTok.value)
		}
		return compareNode{ident: ident, op: op, value: i}, nil
	}
	return nil, fmt.Errorf("expected value, got %q", valTok.value)
}

func (p *queryParser) peekKeyword(kw string) bool {
	if p.pos >= len(p.tokens) {
		return false
	}
	t := p.tokens[p.pos]
	return t.kind == "keyword" && strings.EqualFold(t.value, kw)
}

func (p *queryParser) peekKind(kind string) bool {
	if p.pos >= len(p.tokens) {
		return false
	}
	return p.tokens[p.pos].kind == kind
}

// tokenize splits the input into tokens. Whitespace is skipped; the
// tokenizer recognizes:
//
//   - "..." quoted string (no escapes; queries are short)
//   - bare integer
//   - identifier (letters, digits, underscore, dot, dash)
//   - operators: =, !=
//   - parens: ( )
//   - keywords: AND OR NOT CONTAINS (case-insensitive)
func tokenize(s string) []token {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}
		if tok, n, ok := scanPunct(s, i); ok {
			out = append(out, tok)
			i += n
			continue
		}
		if c == '"' {
			tok, n := scanString(s, i)
			out = append(out, tok)
			i += n
			continue
		}
		if c >= '0' && c <= '9' {
			tok, n := scanInt(s, i)
			out = append(out, tok)
			i += n
			continue
		}
		tok, n := scanIdent(s, i)
		out = append(out, tok)
		i += n
	}
	return out
}

// scanPunct recognizes the single-char and != operators. Returns the
// token, the number of bytes consumed, and whether the byte at i was
// recognized. tokenize falls through to scanString / scanInt /
// scanIdent for the remaining cases.
func scanPunct(s string, i int) (tok token, n int, ok bool) {
	switch s[i] {
	case '(':
		return token{kind: "lparen", value: "("}, 1, true
	case ')':
		return token{kind: "rparen", value: ")"}, 1, true
	case '=':
		return token{kind: "op", value: "="}, 1, true
	case '!':
		if i+1 < len(s) && s[i+1] == '=' {
			return token{kind: "op", value: "!="}, 2, true
		}
		return token{kind: "op", value: "!"}, 1, true
	}
	return token{}, 0, false
}

func scanString(s string, i int) (tok token, n int) {
	end := i + 1
	for end < len(s) && s[end] != '"' {
		end++
	}
	if end < len(s) {
		return token{kind: "string", value: s[i+1 : end]}, end + 1 - i
	}
	// Unterminated string; emit a string token of whatever was found
	// and let the parser surface a clear error.
	return token{kind: "string", value: s[i+1:]}, len(s) - i
}

func scanInt(s string, i int) (tok token, n int) {
	end := i
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	return token{kind: "int", value: s[i:end]}, end - i
}

func scanIdent(s string, i int) (tok token, n int) {
	end := i
	for end < len(s) && isIdentRune(rune(s[end])) {
		end++
	}
	if end == i {
		// Single unknown byte; consume it as an op so the parser
		// surfaces a clear error.
		return token{kind: "op", value: string(s[i])}, 1
	}
	word := s[i:end]
	upper := strings.ToUpper(word)
	switch upper {
	case "AND", "OR", "NOT", opContains:
		return token{kind: "keyword", value: upper}, end - i
	case "TRUE":
		return token{kind: "bool", value: "true"}, end - i
	case "FALSE":
		return token{kind: "bool", value: "false"}, end - i
	}
	return token{kind: "ident", value: word}, end - i
}

func isIdentRune(r rune) bool {
	return r == '_' || r == '.' || r == '-' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

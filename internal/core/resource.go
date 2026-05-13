package core

// Resource is the typed, normalized node in the resource graph.
//
// A Collector emits Resources; an Evaluator queries them. Edges between
// resources (a droplet's firewall, a bucket's CDN) live in Relations,
// keyed by edge name. The graph is the single source of truth during
// evaluation -- scanners read from it instead of re-fetching from the
// cloud API. See DECISIONS.md ADR-001 for the reasoning.
type Resource struct {
	// ID is globally unique across providers, e.g. "digitalocean.droplet.123456".
	// Convention: "<provider>.<type>.<provider-native-id>".
	ID string `json:"id"`

	// Type is the resource type, e.g. "digitalocean.droplet".
	// Convention: "<provider>.<resource-kind>".
	Type string `json:"type"`

	// Name is the human-friendly identifier, typically the name set in the
	// cloud console. Surfaced in finding messages and the HTML report.
	Name string `json:"name"`

	// Provider is the source, e.g. "digitalocean" or "linux".
	Provider string `json:"provider"`

	// Region is the cloud region or, for hosts, a logical zone.
	// Empty for resources without a regional concept (e.g. accounts).
	Region string `json:"region,omitempty"`

	// Attributes carries provider-specific fields. Access via the typed
	// helpers (Attr / AttrInt / AttrBool) so scanners stay agnostic of
	// how a particular value was decoded.
	Attributes map[string]any `json:"attributes,omitempty"`

	// Relations maps an edge name to the IDs of related resources.
	// Example: a droplet may have Relations["firewall"] = []string{"do-fw-1"}.
	// Collectors populate edges; scanners traverse them via ResourceGraph.Related.
	Relations map[string][]string `json:"relations,omitempty"`

	// Tags are arbitrary string labels assigned to the resource in the cloud.
	Tags []string `json:"tags,omitempty"`

	// RawPath points to the captured raw API response on disk, for the
	// evidence pack to copy into the audit-ready output. Empty when the
	// collector did not persist raw evidence (e.g. in tests).
	RawPath string `json:"raw_path,omitempty"`
}

// Attr returns the string value of an attribute, or "" if missing or non-string.
// Scanners use this instead of map access so the type-switch lives in one place.
func (r Resource) Attr(key string) string {
	v, ok := r.Attributes[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// AttrInt returns the int value of an attribute, or 0 if missing or non-numeric.
// JSON unmarshalling yields float64 for numbers, so we accept that case too.
func (r Resource) AttrInt(key string) int {
	v, ok := r.Attributes[key]
	if !ok {
		return 0
	}
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	default:
		return 0
	}
}

// AttrBool returns the bool value of an attribute, or false if missing or non-bool.
func (r Resource) AttrBool(key string) bool {
	v, ok := r.Attributes[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	if !ok {
		return false
	}
	return b
}

// HasTag reports whether the resource carries the given tag.
func (r Resource) HasTag(tag string) bool {
	for _, t := range r.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// Ref returns a lightweight reference suitable for embedding in a Finding.
// Findings carry refs rather than full Resources so finding payloads stay
// small and serialize cheaply.
func (r Resource) Ref() ResourceRef {
	return ResourceRef{
		ID:       r.ID,
		Type:     r.Type,
		Name:     r.Name,
		Provider: r.Provider,
	}
}

// ResourceRef is a lightweight pointer to a Resource. Findings carry refs
// rather than full resources to keep finding payloads small. Consumers
// can look up the full Resource via ResourceGraph.ByID(ref.ID).
type ResourceRef struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

// EvidencePtr is a pointer to raw evidence captured during collection.
// The evidence pack reporter (v0.4) uses Path to copy the underlying
// file into the audit-ready output folder.
type EvidencePtr struct {
	Path string `json:"path,omitempty"`
}

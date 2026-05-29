// Package search hosts the v1.19 phase 5 global search index — an
// in-memory, periodically-rebuilt index spanning findings, resources,
// scans, users, waivers, settings, and docs. Queries fuzzy-rank against
// it with a recency weight so a search for "ec2" surfaces the most
// relevant + most recent hits across every entity type.
//
// The index is rebuilt on a 60s tick (Indexer) + can be rebuilt on
// demand (Rebuild) from SSE-event hooks. Reads take an RLock so search
// stays fast during a rebuild.
package search

import (
	"context"
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lithammer/fuzzysearch/fuzzy"

	"github.com/darpanzope/compliancekit/internal/server/store"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// entry is one indexed document. haystack is the lowercased, space-
// joined match target; recency is a 0..1 weight (1 = newest).
type entry struct {
	res      compliancekit.SearchResult
	haystack string
	recency  float64
}

// Index is the in-memory global search index. Safe for concurrent
// Search + Rebuild.
type Index struct {
	store *store.Store

	mu      sync.RWMutex
	entries []entry
	builtAt time.Time
}

// New constructs an empty index. Call Rebuild (or start an Indexer)
// before the first Search.
func New(st *store.Store) *Index { return &Index{store: st} }

const (
	// maxPerType caps how many rows of each entity type the index pulls
	// so a huge fleet can't blow memory; the newest rows win.
	maxPerType = 2000
	// recencyWeight scales the recency term against the fuzzy-rank term
	// in the final score.
	recencyWeight = 8.0
	// defaultLimit is the page size when the caller doesn't specify one.
	defaultLimit = 20
	maxLimit     = 100
)

// BuiltAt reports when the index was last rebuilt (zero if never).
func (i *Index) BuiltAt() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.builtAt
}

// Size reports the number of indexed entries.
func (i *Index) Size() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.entries)
}

// Rebuild reloads the whole index from the store. On error the previous
// index is left intact (the swap only happens after a successful build).
func (i *Index) Rebuild(ctx context.Context) error {
	ents := make([]entry, 0, 1024)
	ents = appendStatic(ents)
	var err error
	if ents, err = i.appendFindings(ctx, ents); err != nil {
		return err
	}
	if ents, err = i.appendResources(ctx, ents); err != nil {
		return err
	}
	if ents, err = i.appendScans(ctx, ents); err != nil {
		return err
	}
	if ents, err = i.appendUsers(ctx, ents); err != nil {
		return err
	}
	if ents, err = i.appendWaivers(ctx, ents); err != nil {
		return err
	}
	i.mu.Lock()
	i.entries = ents
	i.builtAt = time.Now()
	i.mu.Unlock()
	return nil
}

// Search fuzzy-ranks the index against q, filtered to types (empty =
// all), and returns one page starting at the opaque cursor. An empty q
// returns the most-recent entries (recency-ranked), so the palette can
// show useful suggestions before the user types.
func (i *Index) Search(q string, types []compliancekit.SearchType, limit int, cursor string) compliancekit.SearchResponse {
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	offset := decodeCursor(cursor)
	typeSet := map[compliancekit.SearchType]bool{}
	for _, t := range types {
		typeSet[t] = true
	}
	qNorm := strings.TrimSpace(strings.ToLower(q))

	i.mu.RLock()
	src := i.entries
	i.mu.RUnlock()

	type scored struct {
		res   compliancekit.SearchResult
		score float64
	}
	hits := make([]scored, 0, len(src))
	for _, e := range src {
		if len(typeSet) > 0 && !typeSet[e.res.Type] {
			continue
		}
		var score float64
		if qNorm == "" {
			// No query: rank purely by recency (suggestions).
			score = e.recency * recencyWeight
		} else {
			rank := fuzzy.RankMatchFold(qNorm, e.haystack)
			if rank < 0 {
				continue // no fuzzy match
			}
			// Lower rank = closer match. Convert to a descending score
			// + add the recency weight so ties break toward newer items.
			score = 1000.0 - float64(rank) + e.recency*recencyWeight
		}
		r := e.res
		r.Score = score
		hits = append(hits, scored{r, score})
	}
	sort.SliceStable(hits, func(a, b int) bool {
		if hits[a].score != hits[b].score {
			return hits[a].score > hits[b].score
		}
		return hits[a].res.Title < hits[b].res.Title
	})

	resp := compliancekit.SearchResponse{Query: q}
	if offset >= len(hits) {
		return resp
	}
	end := offset + limit
	if end > len(hits) {
		end = len(hits)
	}
	for _, h := range hits[offset:end] {
		resp.Results = append(resp.Results, h.res)
	}
	if end < len(hits) {
		resp.NextCursor = encodeCursor(end)
	}
	return resp
}

// ─── builders ────────────────────────────────────────────────────────

func (i *Index) appendFindings(ctx context.Context, ents []entry) ([]entry, error) {
	rows, err := i.store.DB().QueryContext(ctx,
		`SELECT id, check_id, severity, resource_name, resource_type, COALESCE(message,''), provider, created_at
		   FROM findings ORDER BY created_at DESC LIMIT `+strconv.Itoa(maxPerType))
	if err != nil {
		return ents, err
	}
	defer func() { _ = rows.Close() }()
	now := time.Now()
	for rows.Next() {
		var id, checkID, sev, resName, resType, msg, provider, createdAt string
		if err := rows.Scan(&id, &checkID, &sev, &resName, &resType, &msg, &provider, &createdAt); err != nil {
			return ents, err
		}
		title := msg
		if title == "" {
			title = checkID
		}
		ents = append(ents, entry{
			res: compliancekit.SearchResult{
				Type: compliancekit.SearchTypeFinding, ID: id, Title: title,
				Subtitle: sev + " · " + resName, Href: "/findings/" + id + "/detail",
			},
			haystack: lower(title, checkID, sev, resName, resType, provider),
			recency:  recencyOf(createdAt, now),
		})
	}
	return ents, rows.Err()
}

func (i *Index) appendResources(ctx context.Context, ents []entry) ([]entry, error) {
	rows, err := i.store.DB().QueryContext(ctx,
		`SELECT id, name, type, provider, last_seen_at
		   FROM resources ORDER BY last_seen_at DESC LIMIT `+strconv.Itoa(maxPerType))
	if err != nil {
		return ents, err
	}
	defer func() { _ = rows.Close() }()
	now := time.Now()
	for rows.Next() {
		var id, name, typ, provider, lastSeen string
		if err := rows.Scan(&id, &name, &typ, &provider, &lastSeen); err != nil {
			return ents, err
		}
		ents = append(ents, entry{
			res: compliancekit.SearchResult{
				Type: compliancekit.SearchTypeResource, ID: id, Title: name,
				Subtitle: typ + " · " + provider, Href: "/resources?q=" + name,
			},
			haystack: lower(name, typ, provider, id),
			recency:  recencyOf(lastSeen, now),
		})
	}
	return ents, rows.Err()
}

func (i *Index) appendScans(ctx context.Context, ents []entry) ([]entry, error) {
	rows, err := i.store.DB().QueryContext(ctx,
		`SELECT id, status, score, created_at
		   FROM scans ORDER BY created_at DESC LIMIT `+strconv.Itoa(maxPerType))
	if err != nil {
		return ents, err
	}
	defer func() { _ = rows.Close() }()
	now := time.Now()
	for rows.Next() {
		var id, status, createdAt string
		var score int
		if err := rows.Scan(&id, &status, &score, &createdAt); err != nil {
			return ents, err
		}
		short := id
		if len(short) > 12 {
			short = short[:12]
		}
		ents = append(ents, entry{
			res: compliancekit.SearchResult{
				Type: compliancekit.SearchTypeScan, ID: id, Title: "Scan " + short,
				Subtitle: status + " · score " + strconv.Itoa(score), Href: "/scans/" + id,
			},
			haystack: lower("scan", id, status, createdAt),
			recency:  recencyOf(createdAt, now),
		})
	}
	return ents, rows.Err()
}

func (i *Index) appendUsers(ctx context.Context, ents []entry) ([]entry, error) {
	rows, err := i.store.DB().QueryContext(ctx,
		`SELECT id, email, COALESCE(display_name,''), created_at
		   FROM users ORDER BY created_at DESC LIMIT `+strconv.Itoa(maxPerType))
	if err != nil {
		return ents, err
	}
	defer func() { _ = rows.Close() }()
	now := time.Now()
	for rows.Next() {
		var id, email, name, createdAt string
		if err := rows.Scan(&id, &email, &name, &createdAt); err != nil {
			return ents, err
		}
		title := name
		if title == "" {
			title = email
		}
		ents = append(ents, entry{
			res: compliancekit.SearchResult{
				Type: compliancekit.SearchTypeUser, ID: id, Title: title,
				Subtitle: email, Href: "/settings/teams",
			},
			haystack: lower(title, email),
			recency:  recencyOf(createdAt, now),
		})
	}
	return ents, rows.Err()
}

func (i *Index) appendWaivers(ctx context.Context, ents []entry) ([]entry, error) {
	rows, err := i.store.DB().QueryContext(ctx,
		`SELECT id, check_id, resource_id, reason, created_at
		   FROM waivers WHERE revoked_at IS NULL ORDER BY created_at DESC LIMIT `+strconv.Itoa(maxPerType))
	if err != nil {
		return ents, err
	}
	defer func() { _ = rows.Close() }()
	now := time.Now()
	for rows.Next() {
		var id, checkID, resID, reason, createdAt string
		if err := rows.Scan(&id, &checkID, &resID, &reason, &createdAt); err != nil {
			return ents, err
		}
		ents = append(ents, entry{
			res: compliancekit.SearchResult{
				Type: compliancekit.SearchTypeWaiver, ID: id, Title: checkID,
				Subtitle: "waiver · " + reason, Href: "/waivers",
			},
			haystack: lower(checkID, resID, reason, "waiver"),
			recency:  recencyOf(createdAt, now),
		})
	}
	return ents, rows.Err()
}

// staticEntry is a compile-time settings/docs target.
type staticEntry struct {
	typ             compliancekit.SearchType
	id, title, href string
	keywords        string
}

// appendStatic adds the settings + docs navigation targets. These have
// a neutral recency (0.5) so they rank below fresh findings but stay
// discoverable.
func appendStatic(ents []entry) []entry {
	statics := []staticEntry{
		{compliancekit.SearchTypeSetting, "providers", "Settings · Providers", "/settings/providers", "connect aws gcp digitalocean hetzner kubernetes linux credentials"},
		{compliancekit.SearchTypeSetting, "frameworks", "Settings · Frameworks", "/settings/frameworks", "soc2 cis iso27001 pci tailoring controls"},
		{compliancekit.SearchTypeSetting, "teams", "Settings · Teams", "/settings/teams", "users members roles collaboration invite"},
		{compliancekit.SearchTypeSetting, "tokens", "Settings · API tokens", "/settings/tokens", "api token scope issue revoke"},
		{compliancekit.SearchTypeSetting, "sessions", "Settings · Sessions", "/settings/sessions", "login session revoke device"},
		{compliancekit.SearchTypeSetting, "webhooks", "Settings · Webhooks", "/settings/webhooks", "notify slack discord teams webhook"},
		{compliancekit.SearchTypeSetting, "feedback", "Admin · Feedback", "/admin/feedback", "bug feature feedback queue"},
		{compliancekit.SearchTypeDoc, "onboarding", "Docs · Onboarding & tours", "/onboarding", "tour walkthrough getting started replay changelog"},
		{compliancekit.SearchTypeDoc, "checks", "Docs · Check catalog", "/checks", "checks controls catalog tailor disable"},
		{compliancekit.SearchTypeDoc, "rules", "Docs · Rules engine", "/rules", "automation if this then that route webhook"},
		{compliancekit.SearchTypeDoc, "scores", "Docs · Score over time", "/scores", "hardening score trend history"},
		{compliancekit.SearchTypeDoc, "design", "Docs · Design system", "/design", "components tokens palette zoo"},
	}
	for _, s := range statics {
		ents = append(ents, entry{
			res:      compliancekit.SearchResult{Type: s.typ, ID: s.id, Title: s.title, Href: s.href},
			haystack: lower(s.title, s.keywords),
			recency:  0.5,
		})
	}
	return ents
}

// ─── helpers ─────────────────────────────────────────────────────────

func lower(parts ...string) string {
	return strings.ToLower(strings.Join(parts, " "))
}

// recencyOf maps an RFC3339 timestamp to a 0..1 weight using a 90-day
// half-window: now → 1, 90+ days old → ~0.
func recencyOf(ts string, now time.Time) float64 {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0
	}
	ageDays := now.Sub(t).Hours() / 24
	if ageDays < 0 {
		ageDays = 0
	}
	w := 1.0 - ageDays/90.0
	if w < 0 {
		return 0
	}
	return w
}

func encodeCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

func decodeCursor(cursor string) int {
	if cursor == "" {
		return 0
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(string(b))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

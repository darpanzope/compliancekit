package digitalocean

import (
	"context"
	"fmt"
	"strings"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	// DomainType is the resource type for managed DNS zones.
	DomainType = "digitalocean.domain"

	// CertificateType is the resource type for managed TLS
	// certificates (Let's Encrypt or custom).
	CertificateType = "digitalocean.certificate"
)

// collectDomains enumerates managed DNS zones and, for each zone,
// summarizes the record set so DMARC/SPF/CAA checks can read the
// presence flags without re-querying.
func (c *Collector) collectDomains(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		domains, resp, err := c.client.Domains.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, d := range domains {
			r, err := c.domainResource(ctx, d)
			if err != nil {
				// Per-domain record-listing failure: emit
				// the domain anyway with a collect error.
				r.Attributes["collect_error_records"] = err.Error()
			}
			out = append(out, r)
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return out, fmt.Errorf("pagination: %w", err)
		}
		opt.Page = page + 1
	}
	return out, nil
}

func (c *Collector) domainResource(ctx context.Context, d godo.Domain) (core.Resource, error) {
	records, err := c.fetchDomainRecords(ctx, d.Name)
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", DomainType, d.Name),
		Type:     DomainType,
		Name:     d.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"domain":         d.Name,
			"ttl":            d.TTL,
			"has_caa":        records.hasCAA,
			"has_spf":        records.hasSPF,
			"has_dmarc":      records.hasDMARC,
			"has_mx":         records.hasMX,
			"record_count":   records.count,
			"caa_records":    records.caaRecords,
			"dmarc_records":  records.dmarcRecords,
			"spf_records":    records.spfRecords,
			"dkim_selectors": records.dkimSelectors,
			"ns_records":     records.nsRecords,
		},
	}
	c.stamp(&r, "")
	return r, err
}

// domainRecordSummary collapses the per-record results into
// presence flags + raw record-data lists for the higher-level
// checks. Pulled into its own type so the cyclomatic complexity
// of the parent stays low.
//
// v0.19 phase 3 expands the surface: spfRecords carries every root-
// level SPF body so checks can inspect qualifier + redirect=;
// dkimSelectors lists selector names found under *._domainkey so a
// "DKIM at all?" check can pass/fail; nsRecords carries the NS set
// so a "delegated to DO" check can confirm authority lives where the
// scan expects.
type domainRecordSummary struct {
	count         int
	hasCAA        bool
	hasSPF        bool
	hasDMARC      bool
	hasMX         bool
	caaRecords    []string
	dmarcRecords  []string
	spfRecords    []string
	dkimSelectors []string
	nsRecords     []string
}

func (c *Collector) fetchDomainRecords(ctx context.Context, domain string) (domainRecordSummary, error) {
	sum := domainRecordSummary{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		records, resp, err := c.client.Domains.Records(ctx, domain, opt)
		if err != nil {
			return sum, err
		}
		for _, rec := range records {
			sum.count++
			classifyDomainRecord(rec, &sum)
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return sum, fmt.Errorf("pagination: %w", err)
		}
		opt.Page = page + 1
	}
	return sum, nil
}

// classifyDomainRecord routes a single record into the right summary
// bucket. Extracted to keep the fetch loop simple AND to let the new
// v0.19 phase 3 surface (NS records for DNSSEC-via-registrar checks,
// DKIM selector enumeration, raw SPF/CAA bodies) live in one place.
func classifyDomainRecord(rec godo.DomainRecord, sum *domainRecordSummary) {
	switch strings.ToUpper(rec.Type) {
	case "CAA":
		sum.hasCAA = true
		sum.caaRecords = append(sum.caaRecords, rec.Data)
	case "MX":
		sum.hasMX = true
	case "NS":
		sum.nsRecords = append(sum.nsRecords, rec.Data)
	case "TXT":
		summarizeTxt(rec, sum)
	}
}

// summarizeTxt classifies TXT records as SPF (root-level "v=spf1"),
// DMARC (on _dmarc.<domain>), or DKIM (on *._domainkey.<domain>).
// The DO API stores the name without the trailing dot, so a record
// on "_dmarc.example.com" comes back as Name = "_dmarc" when queried
// within example.com.
func summarizeTxt(rec godo.DomainRecord, sum *domainRecordSummary) {
	switch {
	case rec.Name == "_dmarc" && strings.HasPrefix(strings.ToLower(rec.Data), "v=dmarc1"):
		sum.hasDMARC = true
		sum.dmarcRecords = append(sum.dmarcRecords, rec.Data)
	case rec.Name == "@" && strings.HasPrefix(strings.ToLower(rec.Data), "v=spf1"):
		sum.hasSPF = true
		sum.spfRecords = append(sum.spfRecords, rec.Data)
	case strings.HasSuffix(rec.Name, "._domainkey") || strings.Contains(rec.Name, "._domainkey."):
		// DKIM selector. Strip the trailing "._domainkey" to surface
		// the selector name (e.g. "google" from "google._domainkey").
		selector := strings.TrimSuffix(rec.Name, "._domainkey")
		if dot := strings.Index(rec.Name, "._domainkey."); dot != -1 {
			selector = rec.Name[:dot]
		}
		sum.dkimSelectors = append(sum.dkimSelectors, selector)
	}
}

// collectCertificates enumerates managed certificates.
func (c *Collector) collectCertificates(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		certs, resp, err := c.client.Certificates.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, ct := range certs {
			out = append(out, c.certificateResource(ct))
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return out, fmt.Errorf("pagination: %w", err)
		}
		opt.Page = page + 1
	}
	return out, nil
}

func (c *Collector) certificateResource(ct godo.Certificate) core.Resource {
	dnsNames := append([]string(nil), ct.DNSNames...)
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", CertificateType, ct.ID),
		Type:     CertificateType,
		Name:     ct.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"certificate_id": ct.ID,
			"dns_names":      dnsNames,
			"not_after":      ct.NotAfter,
			"state":          ct.State,
			"type":           ct.Type,
		},
	}
	c.stamp(&r, "")
	return r
}

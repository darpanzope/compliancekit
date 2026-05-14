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
			"domain":        d.Name,
			"ttl":           d.TTL,
			"has_caa":       records.hasCAA,
			"has_spf":       records.hasSPF,
			"has_dmarc":     records.hasDMARC,
			"has_mx":        records.hasMX,
			"record_count":  records.count,
			"caa_records":   records.caaRecords,
			"dmarc_records": records.dmarcRecords,
		},
	}
	c.stamp(&r, "")
	return r, err
}

// domainRecordSummary collapses the per-record results into
// presence flags + raw record-data lists for the higher-level
// checks. Pulled into its own type so the cyclomatic complexity
// of the parent stays low.
type domainRecordSummary struct {
	count        int
	hasCAA       bool
	hasSPF       bool
	hasDMARC     bool
	hasMX        bool
	caaRecords   []string
	dmarcRecords []string
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
			switch strings.ToUpper(rec.Type) {
			case "CAA":
				sum.hasCAA = true
				sum.caaRecords = append(sum.caaRecords, rec.Data)
			case "MX":
				sum.hasMX = true
			case "TXT":
				summarizeTxt(rec, &sum)
			}
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

// summarizeTxt classifies TXT records as SPF (root-level
// "v=spf1") or DMARC (on _dmarc.<domain>). The DO API stores
// the name without the trailing dot, so a record on
// "_dmarc.example.com" comes back with Name = "_dmarc" when
// queried within example.com.
func summarizeTxt(rec godo.DomainRecord, sum *domainRecordSummary) {
	switch {
	case rec.Name == "_dmarc" && strings.HasPrefix(strings.ToLower(rec.Data), "v=dmarc1"):
		sum.hasDMARC = true
		sum.dmarcRecords = append(sum.dmarcRecords, rec.Data)
	case rec.Name == "@" && strings.HasPrefix(strings.ToLower(rec.Data), "v=spf1"):
		sum.hasSPF = true
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

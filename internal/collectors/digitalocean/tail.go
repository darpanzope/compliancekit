package digitalocean

import (
	"context"
	"fmt"
	"strings"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Resource types for the six remaining DO services that round out
// v0.9. Each collector is small and lives in this file so the per-
// service file count stays manageable.
const (
	CDNType         = "digitalocean.cdn"
	ReservedIPType  = "digitalocean.reserved_ip"
	SSHKeyType      = "digitalocean.ssh_key"
	ImageType       = "digitalocean.image"
	AlertPolicyType = "digitalocean.alert_policy"
	ProjectType     = "digitalocean.project"
)

func (c *Collector) collectCDN(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		cdns, resp, err := c.client.CDNs.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, cd := range cdns {
			r := core.Resource{
				ID:       fmt.Sprintf("%s.%s", CDNType, cd.ID),
				Type:     CDNType,
				Name:     cd.Endpoint,
				Provider: providerName,
				Attributes: map[string]any{
					"origin":            cd.Origin,
					"endpoint":          cd.Endpoint,
					"ttl":               cd.TTL,
					"custom_domain":     cd.CustomDomain,
					"certificate_id":    cd.CertificateID,
					"has_custom_cert":   cd.CertificateID != "",
					"has_custom_domain": cd.CustomDomain != "",
				},
			}
			c.stamp(&r, "")
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

func (c *Collector) collectReservedIPs(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		ips, resp, err := c.client.ReservedIPs.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, ip := range ips {
			region := ""
			if ip.Region != nil {
				region = ip.Region.Slug
			}
			attached := ip.Droplet != nil
			r := core.Resource{
				ID:       fmt.Sprintf("%s.%s", ReservedIPType, ip.IP),
				Type:     ReservedIPType,
				Name:     ip.IP,
				Provider: providerName,
				Attributes: map[string]any{
					"ip":         ip.IP,
					"attached":   attached,
					"locked":     ip.Locked,
					"project_id": ip.ProjectID,
				},
			}
			c.stamp(&r, region)
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

func (c *Collector) collectSSHKeys(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		keys, resp, err := c.client.Keys.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, k := range keys {
			algo := keyAlgorithm(k.PublicKey)
			weak := isWeakKeyAlgo(algo, k.PublicKey)
			r := core.Resource{
				ID:       fmt.Sprintf("%s.%d", SSHKeyType, k.ID),
				Type:     SSHKeyType,
				Name:     k.Name,
				Provider: providerName,
				Attributes: map[string]any{
					"fingerprint":  k.Fingerprint,
					"algorithm":    algo,
					"is_weak_algo": weak,
				},
			}
			c.stamp(&r, "")
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

// keyAlgorithm extracts the algorithm token from an SSH public key
// (the first space-delimited field). Returns "" for unparsable.
func keyAlgorithm(pub string) string {
	pub = strings.TrimSpace(pub)
	if pub == "" {
		return ""
	}
	idx := strings.IndexByte(pub, ' ')
	if idx < 0 {
		return pub
	}
	return pub[:idx]
}

// isWeakKeyAlgo returns true for DSA (always weak), RSA shorter
// than 3072 bits (heuristic via b64 length), or any unknown
// algorithm. ed25519, ecdsa-sha2-nistp256+, and rsa-sha2-* are
// accepted.
func isWeakKeyAlgo(algo, pub string) bool {
	switch algo {
	case "ssh-dss":
		return true
	case "ssh-rsa":
		// RSA-SHA1 modulus < 3072 bits is weak. Heuristic: the
		// base64-encoded blob length is ~344 chars for 2048-bit
		// keys, ~544 for 4096. <500 chars = probably <3072.
		idx := strings.IndexByte(pub, ' ')
		if idx < 0 {
			return true
		}
		rest := pub[idx+1:]
		end := strings.IndexByte(rest, ' ')
		if end < 0 {
			end = len(rest)
		}
		return end < 500
	case "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-256", "rsa-sha2-512":
		return false
	}
	// Unknown algorithm: treat as weak rather than silently pass.
	return true
}

func (c *Collector) collectImages(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		// ListUser returns only user-owned (non-public) images;
		// this is what compliance cares about.
		images, resp, err := c.client.Images.ListUser(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, img := range images {
			r := core.Resource{
				ID:       fmt.Sprintf("%s.%d", ImageType, img.ID),
				Type:     ImageType,
				Name:     img.Name,
				Provider: providerName,
				Attributes: map[string]any{
					"image_id":      img.ID,
					"type":          img.Type,
					"distribution":  img.Distribution,
					"public":        img.Public,
					"min_disk_size": img.MinDiskSize,
					"created_at":    img.Created,
				},
				Tags: img.Tags,
			}
			c.stamp(&r, "")
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

func (c *Collector) collectAlerts(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		alerts, resp, err := c.client.Monitoring.ListAlertPolicies(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, a := range alerts {
			r := core.Resource{
				ID:       fmt.Sprintf("%s.%s", AlertPolicyType, a.UUID),
				Type:     AlertPolicyType,
				Name:     a.Description,
				Provider: providerName,
				Attributes: map[string]any{
					"alert_type":   a.Type,
					"compare":      string(a.Compare),
					"value":        a.Value,
					"window":       a.Window,
					"enabled":      a.Enabled,
					"entity_count": len(a.Entities),
					"tag_count":    len(a.Tags),
				},
			}
			c.stamp(&r, "")
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

func (c *Collector) collectProjects(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		projects, resp, err := c.client.Projects.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, p := range projects {
			r := core.Resource{
				ID:       fmt.Sprintf("%s.%s", ProjectType, p.ID),
				Type:     ProjectType,
				Name:     p.Name,
				Provider: providerName,
				Attributes: map[string]any{
					"project_id":  p.ID,
					"description": p.Description,
					"purpose":     p.Purpose,
					"environment": p.Environment,
					"is_default":  p.IsDefault,
				},
			}
			c.stamp(&r, "")
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

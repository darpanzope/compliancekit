package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// SpacesKeyType is the resource type for DO Spaces access keys
// (the S3-compatible credentials).
const SpacesKeyType = "digitalocean.spaces_key"

func (c *Collector) collectSpacesKeys(ctx context.Context) ([]compliancekit.Resource, error) {
	out := []compliancekit.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		keys, resp, err := c.client.SpacesKeys.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, k := range keys {
			out = append(out, c.spacesKeyResource(k))
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

func (c *Collector) spacesKeyResource(k *godo.SpacesKey) compliancekit.Resource {
	grants := []map[string]any{}
	for _, g := range k.Grants {
		grants = append(grants, map[string]any{
			"bucket":     g.Bucket,
			"permission": string(g.Permission),
		})
	}
	r := compliancekit.Resource{
		ID:       fmt.Sprintf("%s.%s", SpacesKeyType, k.AccessKey),
		Type:     SpacesKeyType,
		Name:     k.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"name":           k.Name,
			"access_key":     k.AccessKey,
			"created_at":     k.CreatedAt,
			"grants":         grants,
			"grant_count":    len(grants),
			"is_full_access": isFullAccessKey(k),
		},
	}
	c.stamp(&r, "")
	return r
}

// isFullAccessKey returns true when the key has any grant of
// permission "fullaccess" OR has zero grants (godo returns an
// empty list for the legacy "this key sees everything" shape).
func isFullAccessKey(k *godo.SpacesKey) bool {
	if len(k.Grants) == 0 {
		return true
	}
	for _, g := range k.Grants {
		if g.Permission == godo.SpacesKeyFullAccess {
			return true
		}
	}
	return false
}

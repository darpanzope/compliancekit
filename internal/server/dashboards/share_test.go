package dashboards

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCreateShareAndTrade(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	link, err := s.CreateShare(ctx, d.ID, "", time.Time{}, "auditor@firm.com")
	if err != nil {
		t.Fatalf("CreateShare: %v", err)
	}
	if len(link.Token) != 64 {
		t.Errorf("token len = %d want 64 (32 bytes hex)", len(link.Token))
	}
	got, gotD, err := s.TradeShare(ctx, link.Token)
	if err != nil {
		t.Fatalf("TradeShare: %v", err)
	}
	if gotD.ID != d.ID {
		t.Errorf("traded dashboard ID mismatch")
	}
	if got.ViewCount != 1 {
		t.Errorf("view_count = %d want 1", got.ViewCount)
	}
}

func TestTradeShare_Revoked(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	link, _ := s.CreateShare(ctx, d.ID, "", time.Time{}, "x@x.com")
	if err := s.RevokeShare(ctx, link.Token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, _, err := s.TradeShare(ctx, link.Token); !errors.Is(err, ErrShareGone) {
		t.Errorf("expected ErrShareGone after revoke, got %v", err)
	}
}

func TestTradeShare_Expired(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	past := time.Now().UTC().Add(-1 * time.Hour)
	link, _ := s.CreateShare(ctx, d.ID, "", past, "x@x.com")
	if _, _, err := s.TradeShare(ctx, link.Token); !errors.Is(err, ErrShareGone) {
		t.Errorf("expected ErrShareGone for expired, got %v", err)
	}
}

func TestTradeShare_Unknown(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	if _, _, err := s.TradeShare(ctx, "not-a-token"); !errors.Is(err, ErrShareGone) {
		t.Errorf("expected ErrShareGone for missing token, got %v", err)
	}
}

func TestWatermarkText(t *testing.T) {
	if got := WatermarkText(""); got != "" {
		t.Errorf("empty recipient should produce empty watermark, got %q", got)
	}
	got := WatermarkText("auditor@firm.com")
	if !strings.Contains(got, "auditor@firm.com") || !strings.Contains(got, "—") {
		t.Errorf("watermark missing recipient/separator: %q", got)
	}
}

func TestListShares(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	for i := 0; i < 3; i++ {
		if _, err := s.CreateShare(ctx, d.ID, "", time.Time{}, ""); err != nil {
			t.Fatalf("share %d: %v", i, err)
		}
	}
	got, err := s.ListShares(ctx, d.ID)
	if err != nil {
		t.Fatalf("ListShares: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("got %d shares, want 3", len(got))
	}
}

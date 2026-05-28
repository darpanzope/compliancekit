package design_test

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/ui/design"
)

func TestParseBrandPrimary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		hex     string
		wantOK  bool
		wantHue string // substring of the HSL triple when ok
	}{
		{"#1d4ed8", true, "224 76% 48%"}, // indigo-700 — dark enough for white text
		{"#4338ca", true, ""},            // indigo — fine
		{"1d4ed8", true, ""},             // no leading # is accepted
		{"#000000", true, "0%"},          // black — max contrast with white
		{"#ffff00", false, ""},           // yellow — white text fails contrast
		{"#ffffff", false, ""},           // white on white — fails
		{"#fff", false, ""},              // shorthand white — fails
		{"#xyz123", false, ""},           // malformed
		{"not-a-color", false, ""},       // malformed
		{"", false, ""},                  // empty
	}
	for _, c := range cases {
		hsl, contrast, ok := design.ParseBrandPrimary(c.hex)
		if ok != c.wantOK {
			t.Errorf("ParseBrandPrimary(%q): ok=%v want %v (hsl=%q contrast=%.2f)", c.hex, ok, c.wantOK, hsl, contrast)
			continue
		}
		if ok {
			if !strings.Contains(hsl, "%") {
				t.Errorf("ParseBrandPrimary(%q): hsl %q not in 'H S%% L%%' form", c.hex, hsl)
			}
			if contrast < design.BrandPrimaryMinContrast {
				t.Errorf("ParseBrandPrimary(%q): accepted contrast %.2f below floor %.2f", c.hex, contrast, design.BrandPrimaryMinContrast)
			}
			if c.wantHue != "" && !strings.Contains(hsl, c.wantHue) {
				t.Errorf("ParseBrandPrimary(%q): hsl %q missing %q", c.hex, hsl, c.wantHue)
			}
		}
	}
}

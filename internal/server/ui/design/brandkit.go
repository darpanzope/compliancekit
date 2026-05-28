package design

import (
	"fmt"
	"math"
	"strings"
)

// BrandPrimaryMinContrast is the floor a brand primary color must clear
// against white text (the daemon's --primary-foreground). 3.0:1 is the
// WCAG AA threshold for UI components + large text; the primary is used
// for buttons + accents, so we reject anything that would make white
// button labels unreadable.
const BrandPrimaryMinContrast = 3.0

// ParseBrandPrimary parses an operator's #rrggbb (or #rgb) brand color
// into the daemon's HSL-triple token form ("H S% L%") that the
// --primary CSS variable expects, validating that white text on the
// color clears BrandPrimaryMinContrast. Returns ok=false for a
// malformed hex or a color that fails the contrast floor — so a
// low-contrast brand override is rejected rather than shipping an
// unreadable button.
func ParseBrandPrimary(hex string) (hslTriple string, contrast float64, ok bool) {
	r, g, b, parsed := parseHex(hex)
	if !parsed {
		return "", 0, false
	}
	c := contrastRatio(relativeLuminance(r, g, b), 1.0) // 1.0 = white
	if c < BrandPrimaryMinContrast {
		return "", c, false
	}
	h, s, l := rgbToHSL(r, g, b)
	return fmt.Sprintf("%d %d%% %d%%", int(math.Round(h)), int(math.Round(s*100)), int(math.Round(l*100))), c, true
}

// parseHex accepts "#rgb" / "#rrggbb" (with or without the leading #)
// and returns the channels as 0..1 floats.
func parseHex(hex string) (r, g, b float64, ok bool) {
	s := strings.TrimPrefix(strings.TrimSpace(hex), "#")
	switch len(s) {
	case 3:
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	case 6:
		// ok
	default:
		return 0, 0, 0, false
	}
	var ri, gi, bi int
	if _, err := fmt.Sscanf(s, "%02x%02x%02x", &ri, &gi, &bi); err != nil {
		return 0, 0, 0, false
	}
	return float64(ri) / 255, float64(gi) / 255, float64(bi) / 255, true
}

// relativeLuminance per WCAG 2.x.
func relativeLuminance(r, g, b float64) float64 {
	lin := func(c float64) float64 {
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(r) + 0.7152*lin(g) + 0.0722*lin(b)
}

// contrastRatio per WCAG 2.x (l1, l2 are relative luminances).
func contrastRatio(l1, l2 float64) float64 {
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05)
}

// rgbToHSL converts 0..1 RGB to HSL (h in degrees, s/l in 0..1).
func rgbToHSL(r, g, b float64) (h, s, l float64) {
	maxc := math.Max(r, math.Max(g, b))
	minc := math.Min(r, math.Min(g, b))
	l = (maxc + minc) / 2
	if maxc == minc {
		return 0, 0, l // achromatic
	}
	d := maxc - minc
	if l > 0.5 {
		s = d / (2 - maxc - minc)
	} else {
		s = d / (maxc + minc)
	}
	switch maxc {
	case r:
		h = (g - b) / d
		if g < b {
			h += 6
		}
	case g:
		h = (b-r)/d + 2
	default:
		h = (r-g)/d + 4
	}
	return h * 60, s, l
}

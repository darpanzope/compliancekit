// genicons writes the PWA icon set into internal/server/assets/.
// Run via `go run ./cmd/genicons` whenever the brand icon changes
// (manual; not part of the standard build). Produces:
//
//	icon-192.png         — primary install icon
//	icon-512.png         — splash-screen + larger surface
//	icon-maskable-512.png — Android adaptive icon (safe area + padding)
//	apple-touch-icon.png — iOS Safari Add-to-Home-Screen (180×180)
//	favicon-32.png       — browser tab + bookmark
//
// The icons are procedural: brand-blue background with a centered
// shield outline + "CK" mark. v1.18 design-system milestone will
// replace with proper brand artwork; v1.16 phase 0 ships
// functionally-valid PNGs so the PWA install prompt fires.
package main

import (
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"path/filepath"
)

// Brand palette — keep in sync with the Tailwind tokens
// (--primary in internal/server/ui/src/app.css).
var (
	brand     = color.RGBA{R: 30, G: 64, B: 175, A: 255}   // indigo-700
	brandDark = color.RGBA{R: 23, G: 37, B: 84, A: 255}    // indigo-900
	ink       = color.RGBA{R: 255, G: 255, B: 255, A: 255} // white
)

func main() {
	dst := "internal/server/assets"
	if len(os.Args) > 1 {
		dst = os.Args[1]
	}
	if err := os.MkdirAll(dst, 0o750); err != nil {
		log.Fatalf("mkdir %s: %v", dst, err)
	}

	must(write(filepath.Join(dst, "icon-192.png"), renderIcon(192, 0)))
	must(write(filepath.Join(dst, "icon-512.png"), renderIcon(512, 0)))
	// Maskable icons need a 20% safe-area padding so launcher masks
	// don't crop the foreground. Render at 512 with the foreground
	// drawn inside a 410×410 inner box.
	must(write(filepath.Join(dst, "icon-maskable-512.png"), renderIcon(512, 51)))
	must(write(filepath.Join(dst, "apple-touch-icon.png"), renderIcon(180, 0)))
	must(write(filepath.Join(dst, "favicon-32.png"), renderIcon(32, 0)))

	log.Printf("wrote 5 PWA icons under %s", dst)
}

// renderIcon draws an `size`×`size` brand-blue square with a centered
// shield + "CK" mark, leaving `padding` pixels of margin around the
// foreground (for maskable safe areas).
func renderIcon(size, padding int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	// Background fill.
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.Set(x, y, brand)
		}
	}

	// Shield outline (rounded rectangle with a darker stroke).
	stroke := size / 32 // 6px at 192, 16px at 512
	if stroke < 2 {
		stroke = 2
	}
	margin := padding + size/12
	if margin < 1 {
		margin = 1
	}
	drawRoundedRect(img, margin, margin, size-margin, size-margin, size/8, stroke, brandDark)

	// Centered "CK" mark — built from blocky strokes so we don't need
	// a font dep. Letters are sized so the pair fits inside the shield
	// with comfortable margin on every side.
	letterH := (size - 2*margin) * 3 / 5
	letterW := letterH * 5 / 8
	letterStroke := letterH / 5
	if letterStroke < 2 {
		letterStroke = 2
	}
	totalW := 2*letterW + letterW/4 // letter gap = quarter-letter
	startX := (size - totalW) / 2
	startY := (size - letterH) / 2
	drawC(img, startX, startY, letterW, letterH, letterStroke, ink)
	drawK(img, startX+letterW+letterW/4, startY, letterW, letterH, letterStroke, ink)
	return img
}

// drawRoundedRect strokes a `stroke`-px outline of a rounded
// rectangle with corner radius `r` between (x0,y0) and (x1,y1).
func drawRoundedRect(img *image.RGBA, x0, y0, x1, y1, r, stroke int, c color.Color) {
	for s := 0; s < stroke; s++ {
		// Top + bottom edges, skipping corner radius.
		for x := x0 + r; x <= x1-r; x++ {
			img.Set(x, y0+s, c)
			img.Set(x, y1-s, c)
		}
		// Left + right edges, skipping corner radius.
		for y := y0 + r; y <= y1-r; y++ {
			img.Set(x0+s, y, c)
			img.Set(x1-s, y, c)
		}
		// Corner arcs — approximate with quarter-circle plotting.
		drawCornerArc(img, x0+r, y0+r, r-s, "tl", c)
		drawCornerArc(img, x1-r, y0+r, r-s, "tr", c)
		drawCornerArc(img, x0+r, y1-r, r-s, "bl", c)
		drawCornerArc(img, x1-r, y1-r, r-s, "br", c)
	}
}

func drawCornerArc(img *image.RGBA, cx, cy, r int, quadrant string, c color.Color) {
	for a := 0; a <= 90; a++ {
		// Use Bresenham-style integer plotting; quarter-circle.
		dx := int(float64(r) * cosDeg(a))
		dy := int(float64(r) * sinDeg(a))
		switch quadrant {
		case "tl":
			img.Set(cx-dx, cy-dy, c)
		case "tr":
			img.Set(cx+dx, cy-dy, c)
		case "bl":
			img.Set(cx-dx, cy+dy, c)
		case "br":
			img.Set(cx+dx, cy+dy, c)
		}
	}
}

// drawC draws a block-stroke capital C inside the box (x,y,w,h).
func drawC(img *image.RGBA, x, y, w, h, stroke int, c color.Color) {
	fillRect(img, x, y, x+w, y+stroke, c)     // top bar
	fillRect(img, x, y+h-stroke, x+w, y+h, c) // bottom bar
	fillRect(img, x, y, x+stroke, y+h, c)     // left bar
}

// drawK draws a block-stroke capital K inside the box (x,y,w,h).
func drawK(img *image.RGBA, x, y, w, h, stroke int, c color.Color) {
	fillRect(img, x, y, x+stroke, y+h, c) // vertical bar
	// Two diagonals meeting at the mid-height of the vertical bar.
	midY := y + h/2
	for i := 0; i <= w-stroke; i++ {
		// Upper diagonal (mid → top-right).
		yy := midY - i*(h/2)/(w-stroke)
		for s := 0; s < stroke; s++ {
			img.Set(x+stroke+i, yy+s, c)
		}
		// Lower diagonal (mid → bottom-right).
		yy2 := midY + i*(h/2)/(w-stroke)
		for s := 0; s < stroke; s++ {
			img.Set(x+stroke+i, yy2-s, c)
		}
	}
}

func fillRect(img *image.RGBA, x0, y0, x1, y1 int, c color.Color) {
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			img.Set(x, y, c)
		}
	}
}

func write(path string, img *image.RGBA) error {
	f, err := os.Create(path) //nolint:gosec // operator-supplied via cmd arg
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return png.Encode(f, img)
}

// Tiny trig table — we only need 0..90 degrees. Avoids pulling in
// math.Cos/Sin so the icon generator stays dep-free.
var (
	cosTable [91]float64
	sinTable [91]float64
)

func init() {
	for i := 0; i <= 90; i++ {
		// 5-term Taylor expansion of cos / sin is enough for 90 deg.
		rad := float64(i) * 3.14159265358979 / 180.0
		cosTable[i] = taylorCos(rad)
		sinTable[i] = taylorSin(rad)
	}
}

func cosDeg(d int) float64 { return cosTable[d] }
func sinDeg(d int) float64 { return sinTable[d] }

func taylorCos(x float64) float64 {
	x2 := x * x
	x4 := x2 * x2
	x6 := x4 * x2
	x8 := x4 * x4
	return 1 - x2/2 + x4/24 - x6/720 + x8/40320
}

func taylorSin(x float64) float64 {
	x2 := x * x
	x3 := x2 * x
	x5 := x3 * x2
	x7 := x5 * x2
	x9 := x7 * x2
	return x - x3/6 + x5/120 - x7/5040 + x9/362880
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

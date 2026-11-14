package breakglass

import (
	"fmt"
	"math"
)

// Colour helpers shared by the card layout and the admin pages: WCAG
// relative luminance and contrast, and a blend towards white. They match the
// prototype's lum, contrast and mix.

// ParseHex reads "#rrggbb", reporting ok=false for anything else.
func ParseHex(s string) (r, g, b int, ok bool) {
	c := hexOr(s, rgb{-1, -1, -1})
	if c.r < 0 {
		return 0, 0, 0, false
	}
	return c.r, c.g, c.b, true
}

func (c rgb) hex() string { return fmt.Sprintf("#%02x%02x%02x", c.r, c.g, c.b) }

// lum is the WCAG relative luminance of c.
func lum(c rgb) float64 {
	ch := func(v int) float64 {
		x := float64(v) / 255
		if x <= 0.03928 {
			return x / 12.92
		}
		return math.Pow((x+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(c.r) + 0.7152*ch(c.g) + 0.0722*ch(c.b)
}

// contrast is the WCAG contrast ratio of two colours, from 1 to 21.
func contrast(a, b rgb) float64 {
	x, y := lum(a), lum(b)
	if x < y {
		x, y = y, x
	}
	return (x + 0.05) / (y + 0.05)
}

// Contrast is the WCAG contrast ratio of two "#rrggbb" colours. A colour that
// does not parse counts as black.
func Contrast(a, b string) float64 {
	return contrast(hexOr(a, rgb{}), hexOr(b, rgb{}))
}

// inkOn is the text colour for a background: white or near-black, whichever
// contrasts more, as the prototype's card header chooses it.
func inkOn(bg rgb) rgb {
	if contrast(colWhite, bg) >= contrast(colNearBlack, bg) {
		return colWhite
	}
	return colNearBlack
}

// mixWhite blends c toward white; w is the fraction of white (0..1).
func mixWhite(c rgb, w float64) rgb {
	m := func(v int) int { return int(math.Round(float64(v) + (255-float64(v))*w)) }
	return rgb{m(c.r), m(c.g), m(c.b)}
}

// LogoReadable is the readability check of a design's logo against its
// header. Best is the treatment that reads more easily ("white" or "asis");
// OK is false when the chosen treatment contrasts less than 3:1. A design
// with no logo, or the logo on a white panel, is always OK. ink is the
// logo's own colour (see LogoInk).
func LogoReadable(header, mode string, ink string, hasLogo bool) (best string, ok bool) {
	h := hexOr(header, colNavy)
	in := hexOr(ink, colLogoInk)
	best = "asis"
	if contrast(colWhite, h) >= contrast(in, h) {
		best = "white"
	}
	if !hasLogo || mode == LogoPanel {
		return best, true
	}
	c := in
	if mode == LogoWhite {
		c = colWhite
	}
	return best, contrast(c, h) >= 3
}

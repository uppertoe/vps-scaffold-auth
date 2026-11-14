package breakglass

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// rgb is an 8-bit colour.
type rgb struct{ r, g, b int }

// PDF draws the card's layout as a one-page PDF at the design's printed
// size. Pure Go (go-pdf/fpdf and an SVG rasteriser), so it works in the
// CGO-free image; every image is embedded from memory.
func (c Card) PDF() ([]byte, error) {
	return c.Layout().PDF(true)
}

// PDF writes the drawing as a PDF. compress is false only in tests, which
// read the page's text.
func (d Drawing) PDF(compress bool) ([]byte, error) {
	pdf := fpdf.NewCustom(&fpdf.InitType{
		OrientationStr: "P", UnitStr: "mm", Size: fpdf.SizeType{Wd: d.W, Ht: d.H},
	})
	pdf.SetCompression(compress)
	pdf.SetAutoPageBreak(false, 0)
	pdf.SetMargins(0, 0, 0)
	pdf.AddPage()
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	for i, it := range d.Items {
		switch it.Kind {
		case ItemRect:
			style := ""
			if it.Fill != nil {
				setFill(pdf, *it.Fill)
				style += "F"
			}
			if it.Stroke != nil {
				setDraw(pdf, *it.Stroke)
				pdf.SetLineWidth(it.StrokeW)
				style += "D"
			}
			if it.Radius > 0 {
				pdf.RoundedRect(it.X, it.Y, it.W, it.H, it.Radius, "1234", style)
			} else {
				pdf.Rect(it.X, it.Y, it.W, it.H, style)
			}
		case ItemText:
			st := ""
			if it.Bold {
				st = "B"
			}
			pdf.SetFont(fontFamily, st, it.Size*ptPerMM)
			setText(pdf, it.Color)
			pdf.Text(it.X, it.Y, tr(it.Text))
		case ItemImage:
			name := fmt.Sprintf("img%d", i)
			opts := fpdf.ImageOptions{ImageType: "PNG"}
			pdf.RegisterImageOptionsReader(name, opts, bytes.NewReader(it.PNG))
			pdf.ImageOptions(name, it.X, it.Y, it.W, it.H, false, opts, 0, "")
		case ItemQR:
			// The code goes in as an image with whole pixels per module, so
			// no viewer draws seams between modules.
			png, err := modulesPNG(it.Modules, 1024)
			if err != nil {
				return nil, err
			}
			name := fmt.Sprintf("qr%d", i)
			opts := fpdf.ImageOptions{ImageType: "PNG"}
			pdf.RegisterImageOptionsReader(name, opts, bytes.NewReader(png))
			pdf.ImageOptions(name, it.X, it.Y, it.W, it.H, false, opts, 0, "")
		}
	}
	if err := pdf.Error(); err != nil {
		return nil, fmt.Errorf("breakglass: pdf render: %w", err)
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func setFill(pdf *fpdf.Fpdf, c rgb) { pdf.SetFillColor(c.r, c.g, c.b) }
func setText(pdf *fpdf.Fpdf, c rgb) { pdf.SetTextColor(c.r, c.g, c.b) }
func setDraw(pdf *fpdf.Fpdf, c rgb) { pdf.SetDrawColor(c.r, c.g, c.b) }

// hexOr parses a "#rrggbb" (or "rrggbb") colour, returning def on any problem.
func hexOr(s string, def rgb) rgb {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "#"))
	if len(s) != 6 {
		return def
	}
	var v [3]int
	for i := 0; i < 3; i++ {
		h, ok := hexByte(s[i*2], s[i*2+1])
		if !ok {
			return def
		}
		v[i] = h
	}
	return rgb{v[0], v[1], v[2]}
}

func hexByte(hi, lo byte) (int, bool) {
	h, ok1 := hexNibble(hi)
	l, ok2 := hexNibble(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return h*16 + l, true
}

func hexNibble(b byte) (int, bool) {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0'), true
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10, true
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10, true
	}
	return 0, false
}

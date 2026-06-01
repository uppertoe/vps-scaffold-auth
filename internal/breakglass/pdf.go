package breakglass

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// DefaultPalette is the RCH colour palette (hex), used as the admin defaults
// and whenever a Card leaves a colour blank.
var DefaultPalette = struct{ Header, Accent, Bar1, Bar2, Bar3 string }{
	Header: "#003a5c",
	Accent: "#008ccc",
	Bar1:   "#fdb913",
	Bar2:   "#f26c52",
	Bar3:   "#82c341",
}

// rgb is an 8-bit colour.
type rgb struct{ r, g, b int }

// The Royal Children's Hospital palette used across the card.
var (
	colNavy   = rgb{0, 58, 92}    // #003a5c wordmark navy (default header)
	colBlue   = rgb{0, 140, 204}  // #008ccc (default accent)
	colYellow = rgb{253, 185, 19} // #fdb913 (default bar 1)
	colCoral  = rgb{242, 108, 82} // #f26c52 (default bar 2)
	colGreen  = rgb{130, 195, 65} // #82c341 (default bar 3)
	colInk    = rgb{45, 52, 60}
	colGrey   = rgb{120, 128, 136}
	colWhite  = rgb{255, 255, 255}
)

// Card holds the content rendered onto a printable break-glass PDF. Title, Body
// and Instructions are the admin-configurable branding; Label and Note identify
// the individual code. Logo and Glyph are optional raw image bytes
// (PNG/JPEG/SVG) with their MIME type. The colour fields are hex strings (e.g.
// "#003a5c"); an empty value falls back to the RCH default.
type Card struct {
	Title        string
	Label        string
	Body         string
	Instructions string
	Note         string
	QRPNG        []byte
	LogoData     []byte
	LogoType     string
	GlyphData    []byte
	GlyphType    string

	HeaderColor string // header band (default navy)
	AccentColor string // QR frame, headings, footer rule, panel tint (default blue)
	Bar1Color   string // accent bar segment 1 (default yellow)
	Bar2Color   string // accent bar segment 2 (default coral)
	Bar3Color   string // accent bar segment 3 (default green)
}

// PDF renders a single A4 card, RCH-branded. Pure-Go (go-pdf/fpdf + an SVG
// rasterizer) so it works in the CGO-free distroless image; all images are
// embedded from memory.
func (c Card) PDF() ([]byte, error) {
	const (
		pageW    = 210.0
		margin   = 18.0
		contentW = pageW - 2*margin
		headerH  = 42.0
	)
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(false, 0)
	pdf.AddPage()
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	// Resolve the palette: stored hex colours, or the RCH defaults.
	header := hexOr(c.HeaderColor, colNavy)
	accent := hexOr(c.AccentColor, colBlue)
	bar1 := hexOr(c.Bar1Color, colYellow)
	bar2 := hexOr(c.Bar2Color, colCoral)
	bar3 := hexOr(c.Bar3Color, colGreen)
	titleColor := contrastColor(header) // legible on the chosen header
	panel := mixWhite(accent, 0.88)     // light tint of the accent

	// --- Header band with logo + title ---
	setFill(pdf, header)
	pdf.Rect(0, 0, pageW, headerH, "F")

	titleX := margin
	align := "CM" // centred when there's no logo
	if img := registerImage(pdf, "logo", c.LogoData, c.LogoType, 256); img != nil {
		// Fit the logo inside a bounded box (max height and width) so a wide
		// wordmark can't crowd out the title.
		const maxLogoH, maxLogoW = 22.0, 60.0
		lh, lw := maxLogoH, maxLogoH*img.ratio
		if lw > maxLogoW {
			lw, lh = maxLogoW, maxLogoW/img.ratio
		}
		pdf.ImageOptions("logo", margin, (headerH-lh)/2, lw, lh, false, img.opts, 0, "")
		titleX = margin + lw + 10
		align = "LM"
	}
	// Auto-shrink the title to fit the remaining header width on one line.
	title := tr(orDefault(c.Title, "Emergency access"))
	availW := pageW - titleX - margin
	setText(pdf, titleColor)
	size := fitFontSize(pdf, "Helvetica", "B", title, availW, 24, 13)
	pdf.SetFont("Helvetica", "B", size)
	pdf.SetXY(titleX, 0)
	pdf.CellFormat(availW, headerH, title, "", 0, align, false, 0, "")

	// --- Accent tri-bar ---
	barY, barH := headerH, 3.0
	third := pageW / 3
	setFill(pdf, bar1)
	pdf.Rect(0, barY, third, barH, "F")
	setFill(pdf, bar2)
	pdf.Rect(third, barY, third, barH, "F")
	setFill(pdf, bar3)
	pdf.Rect(2*third, barY, pageW-2*third, barH, "F")

	y := barY + barH + 14

	// --- Optional glyph ---
	if img := registerImage(pdf, "glyph", c.GlyphData, c.GlyphType, 256); img != nil {
		gh := 20.0
		gw := gh * img.ratio
		pdf.ImageOptions("glyph", (pageW-gw)/2, y, gw, gh, false, img.opts, 0, "")
		y += gh + 8
	}

	// --- Location label ---
	setText(pdf, header)
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetXY(margin, y)
	pdf.MultiCell(contentW, 10, tr(c.Label), "", "C", false)
	y = pdf.GetY() + 4

	// --- Body paragraph ---
	if body := orDefault(c.Body, ""); body != "" {
		setText(pdf, colInk)
		pdf.SetFont("Helvetica", "", 12)
		pdf.SetXY(margin, y)
		pdf.MultiCell(contentW, 6, tr(body), "", "C", false)
		y = pdf.GetY() + 8
	}

	// --- QR in a rounded, bordered box ---
	const qrSize, boxPad = 76.0, 8.0
	boxSize := qrSize + 2*boxPad
	boxX := (pageW - boxSize) / 2
	setDraw(pdf, accent)
	pdf.SetLineWidth(0.7)
	pdf.RoundedRect(boxX, y, boxSize, boxSize, 4, "1234", "D")
	if len(c.QRPNG) > 0 {
		pdf.RegisterImageOptionsReader("qr", fpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(c.QRPNG))
		pdf.ImageOptions("qr", boxX+boxPad, y+boxPad, qrSize, qrSize, false, fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	}
	y += boxSize + 12

	// --- Instructions panel ---
	if instr := orDefault(c.Instructions, ""); instr != "" {
		const pad, headH, lineH = 7.0, 8.0, 6.0
		pdf.SetFont("Helvetica", "", 12)
		lines := wrappedLines(pdf, instr, contentW-2*pad)
		panelH := pad + headH + float64(len(lines))*lineH + pad
		setFill(pdf, panel)
		pdf.RoundedRect(margin, y, contentW, panelH, 3, "1234", "F")

		setText(pdf, accent)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.SetXY(margin+pad, y+pad)
		pdf.CellFormat(contentW-2*pad, headH, tr("How to use"), "", 0, "L", false, 0, "")

		setText(pdf, colInk)
		pdf.SetFont("Helvetica", "", 12)
		pdf.SetXY(margin+pad, y+pad+headH)
		pdf.MultiCell(contentW-2*pad, lineH, tr(instr), "", "L", false)
		y += panelH + 10
	}

	// --- Footer: per-code note + accent rule ---
	if c.Note != "" {
		setText(pdf, colGrey)
		pdf.SetFont("Helvetica", "I", 10)
		pdf.SetXY(margin, 274)
		pdf.MultiCell(contentW, 5, tr(c.Note), "", "C", false)
	}
	setFill(pdf, accent)
	pdf.Rect(0, 294, pageW, 3, "F")

	if err := pdf.Error(); err != nil {
		return nil, fmt.Errorf("breakglass: pdf render: %w", err)
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// imageRef bundles a registered image's aspect ratio and embed options.
type imageRef struct {
	ratio float64 // width / height
	opts  fpdf.ImageOptions
}

// registerImage prepares and registers an optional image under name. Returns
// nil when there is no image or it cannot be decoded (the card still renders).
func registerImage(pdf *fpdf.Fpdf, name string, data []byte, mime string, size int) *imageRef {
	if len(data) == 0 {
		return nil
	}
	pngOrRaw, typ, err := pdfImage(data, mime, size)
	if err != nil {
		return nil
	}
	opts := fpdf.ImageOptions{ImageType: typ}
	info := pdf.RegisterImageOptionsReader(name, opts, bytes.NewReader(pngOrRaw))
	if info == nil || pdf.Err() || info.Height() == 0 {
		return nil
	}
	return &imageRef{ratio: info.Width() / info.Height(), opts: opts}
}

// wrappedLines returns how the text wraps at width w (honouring explicit
// newlines), so a background panel can be sized to fit.
func wrappedLines(pdf *fpdf.Fpdf, text string, w float64) []string {
	var out []string
	for _, para := range strings.Split(text, "\n") {
		seg := pdf.SplitText(para, w)
		if len(seg) == 0 {
			out = append(out, "")
			continue
		}
		out = append(out, seg...)
	}
	return out
}

// fitFontSize returns the largest point size in [min,start] at which text fits
// within width w on a single line for the given font.
func fitFontSize(pdf *fpdf.Fpdf, family, style, text string, w, start, min float64) float64 {
	for size := start; size > min; size-- {
		pdf.SetFont(family, style, size)
		if pdf.GetStringWidth(text) <= w {
			return size
		}
	}
	return min
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

// contrastColor returns near-black or white, whichever is more legible on bg.
func contrastColor(bg rgb) rgb {
	// Perceived luminance (ITU-R BT.601).
	lum := 0.299*float64(bg.r) + 0.587*float64(bg.g) + 0.114*float64(bg.b)
	if lum > 150 {
		return rgb{30, 35, 40}
	}
	return colWhite
}

// mixWhite blends c toward white; w is the fraction of white (0..1).
func mixWhite(c rgb, w float64) rgb {
	m := func(v int) int { return int(float64(v)*(1-w) + 255*w + 0.5) }
	return rgb{m(c.r), m(c.g), m(c.b)}
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

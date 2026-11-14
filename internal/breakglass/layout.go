package breakglass

import (
	"strings"
	"unicode/utf8"

	"github.com/boombuler/barcode/qr"
	"github.com/go-pdf/fpdf"
)

// The printed card is laid out once, here, as positioned primitives in
// millimetres. The PDF writer (pdf.go) and the SVG preview (svg.go) each draw
// the same Drawing, so the preview on the admin pages is the printed card.
//
// The layout follows the prototype's card, which is drawn in units of the
// card's own width (u, a hundredth of the width). A6, A5 and A4 are all close
// to 1:√2, so the three sizes share one layout and differ only in scale.

// Printed sizes a design may choose, in millimetres.
var Sizes = map[string][2]float64{
	"A6": {105, 148},
	"A5": {148, 210},
	"A4": {210, 297},
}

// SizeOrder lists the sizes as the design editor offers them.
var SizeOrder = []string{"A6", "A5", "A4"}

// Fixed wording printed on every card.
const (
	HowToUse      = "How to use this card"
	RecordedLine  = "Each use is recorded, and the administrators are notified."
	DefaultTitle  = "Emergency access"
	DefaultSteps  = "Open your phone's camera and point it at the code.\nTap the link that appears.\nPress Continue to open the app."
	opensPrefix   = "Opens "
	sampleQR      = "This is a preview of a break-glass card. It opens nothing."
	maxStepLines  = 12
	ellipsis      = "…"
	fontFamily    = "Helvetica"
	ptPerMM       = 72 / 25.4
	textBaseline  = 0.35 // a line's baseline sits this many font sizes below its centre
	stepIndentU   = 4.5  // the hanging indent of a numbered step
	headerHeightU = 24.0
)

// The colours of the card's fixed parts.
var (
	colNavy      = rgb{0, 58, 92}    // #003a5c default header
	colBlue      = rgb{11, 123, 191} // #0b7bbf default accent
	colYellow    = rgb{253, 185, 19} // #fdb913
	colCoral     = rgb{242, 108, 82} // #f26c52
	colGreen     = rgb{130, 195, 65} // #82c341
	colWhite     = rgb{255, 255, 255}
	colNearBlack = rgb{27, 31, 36}  // #1b1f24
	colAppLine   = rgb{71, 84, 103} // #475467
	colFooter    = rgb{95, 102, 112}
	colQR        = rgb{0, 0, 0}
	colLogoInk   = rgb{34, 50, 74}
)

// DefaultPalette is the Department preset, in hex.
var DefaultPalette = struct{ Header, Accent, Bar1, Bar2, Bar3 string }{
	Header: "#003a5c",
	Accent: "#0b7bbf",
	Bar1:   "#fdb913",
	Bar2:   "#f26c52",
	Bar3:   "#82c341",
}

// Design is what a card design sets: colours, the stripe, the logo and its
// treatment, the title, the steps and the printed size.
type Design struct {
	Header, Accent   string // "#rrggbb"
	Stripe           bool
	Bar1, Bar2, Bar3 string
	// Logo is the logo to draw (the site logo or the design's own), or nil
	// for none. LogoMode is LogoAsIs, LogoWhite or LogoPanel.
	Logo     []byte
	LogoType string
	LogoMode string
	Title    string
	Steps    string // one step per line
	Size     string // "A6", "A5" or "A4"
}

// Card is one printed card: its design, the location printed on it, the
// app it opens, and the address its code holds. An empty QR draws a sample
// code that opens nothing, for previews of a card not yet made.
type Card struct {
	Design   Design
	Location string
	App      string
	QR       string
}

// Item kinds.
const (
	ItemRect = iota
	ItemText
	ItemImage
	ItemQR
)

// Item is one positioned primitive. Coordinates are millimetres from the
// top left. A text item's Y is its baseline, X its left edge and W its
// measured width; BoxX and BoxW are the span it must stay inside.
type Item struct {
	Kind       int
	X, Y, W, H float64
	Fill       *rgb
	Stroke     *rgb
	StrokeW    float64
	Radius     float64
	// Text.
	Text       string
	Size       float64 // font size in millimetres
	Bold       bool
	Color      rgb
	BoxX, BoxW float64
	// Image: PNG bytes. QR: the module grid, dark modules true, with the
	// quiet zone included.
	PNG     []byte
	Modules [][]bool
}

// Drawing is a laid-out card: the page size and the primitives in drawing
// order.
type Drawing struct {
	W, H  float64
	Items []Item
}

// measurer measures text in the PDF's own font metrics, so the preview
// wraps exactly where the PDF does.
type measurer struct {
	pdf *fpdf.Fpdf
	tr  func(string) string
}

func newMeasurer() *measurer {
	p := fpdf.New("P", "mm", "A4", "")
	return &measurer{pdf: p, tr: p.UnicodeTranslatorFromDescriptor("")}
}

func (m *measurer) width(s string, size float64, bold bool) float64 {
	style := ""
	if bold {
		style = "B"
	}
	m.pdf.SetFont(fontFamily, style, size*ptPerMM)
	return m.pdf.GetStringWidth(m.tr(s))
}

// fit returns the largest size from start down to min (in steps of 2%) at
// which s fits in w on one line, and s itself; when even min is too wide, s
// is cut and ends in an ellipsis.
func (m *measurer) fit(s string, w, start, min float64, bold bool) (string, float64) {
	for size := start; size >= min; size -= start * 0.02 {
		if m.width(s, size, bold) <= w {
			return s, size
		}
	}
	return m.cut(s, w, min, bold), min
}

// cut shortens s, ending it in an ellipsis, until it fits in w.
func (m *measurer) cut(s string, w, size float64, bold bool) string {
	if m.width(s, size, bold) <= w {
		return s
	}
	r := []rune(strings.TrimSpace(s))
	for len(r) > 0 {
		r = r[:len(r)-1]
		t := strings.TrimRight(string(r), " ,.;:") + ellipsis
		if m.width(t, size, bold) <= w {
			return t
		}
	}
	return ""
}

// wrap breaks s into lines no wider than w, at spaces where it can and
// inside a word only when one word is wider than a line.
func (m *measurer) wrap(s string, w, size float64, bold bool) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		try := word
		if line != "" {
			try = line + " " + word
		}
		if m.width(try, size, bold) <= w {
			line = try
			continue
		}
		if line != "" {
			lines = append(lines, line)
			line = ""
		}
		for m.width(word, size, bold) > w && utf8.RuneCountInString(word) > 1 {
			r := []rune(word)
			n := len(r) - 1
			for n > 1 && m.width(string(r[:n]), size, bold) > w {
				n--
			}
			lines = append(lines, string(r[:n]))
			word = string(r[n:])
		}
		line = word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// StepLines splits a design's steps into the lines printed as numbered
// steps, dropping blank lines and any numbering an administrator typed.
func StepLines(steps string) []string {
	var out []string
	for _, l := range strings.Split(steps, "\n") {
		l = strings.TrimSpace(stripNumber(l))
		if l != "" {
			out = append(out, l)
		}
	}
	if len(out) > maxStepLines {
		out = out[:maxStepLines]
	}
	return out
}

// stripNumber drops a leading "1." or "1)" from a step.
func stripNumber(l string) string {
	t := strings.TrimSpace(l)
	i := 0
	for i < len(t) && t[i] >= '0' && t[i] <= '9' {
		i++
	}
	if i > 0 && i < len(t) && (t[i] == '.' || t[i] == ')') {
		return t[i+1:]
	}
	return l
}

// Layout lays out the card. It never fails: a logo that cannot be read is
// left out, and text that cannot fit is shrunk and then cut short.
func (c Card) Layout() Drawing {
	d := c.Design
	size, ok := Sizes[d.Size]
	if !ok {
		size = Sizes["A6"]
	}
	W, H := size[0], size[1]
	u := W / 100
	m := newMeasurer()
	header := hexOr(d.Header, colNavy)
	accent := hexOr(d.Accent, colBlue)
	ink := inkOn(header)
	out := Drawing{W: W, H: H}
	add := func(it Item) { out.Items = append(out.Items, it) }
	rect := func(x, y, w, h float64, fill rgb, radius float64) {
		f := fill
		add(Item{Kind: ItemRect, X: x, Y: y, W: w, H: h, Fill: &f, Radius: radius})
	}
	text := func(s string, x, baseline, size float64, bold bool, col rgb, boxX, boxW float64) {
		if s == "" {
			return
		}
		add(Item{Kind: ItemText, Text: s, X: x, Y: baseline, W: m.width(s, size, bold), H: size, Size: size, Bold: bold, Color: col, BoxX: boxX, BoxW: boxW})
	}
	centred := func(s string, centreY, size float64, bold bool, col rgb, boxX, boxW float64) {
		w := m.width(s, size, bold)
		text(s, boxX+(boxW-w)/2, centreY+textBaseline*size, size, bold, col, boxX, boxW)
	}

	// The header: the logo above the title, centred together.
	headerH := headerHeightU * u
	rect(0, 0, W, headerH, header, 0)
	title := strings.TrimSpace(d.Title)
	if title == "" {
		title = DefaultTitle
	}
	titleBox := W - 12*u
	title, ts := m.fit(title, titleBox, 7*u, 4*u, true)
	titleLine := ts * 1.1
	var logo preparedLogo
	hasLogo := false
	if d.Logo != nil {
		logo, hasLogo = prepareLogo(d.Logo, d.LogoType, d.LogoMode)
	}
	var lw, lh, block float64
	panel := hasLogo && d.LogoMode == LogoPanel
	if hasLogo {
		lh = 7 * u
		lw = lh * logo.ratio
		if lw > 60*u {
			lw, lh = 60*u, 60*u/logo.ratio
		}
		block = lh + 2.4*u
		if panel {
			block += 2 * u
		}
	}
	block += titleLine
	y := (headerH - block) / 2
	if hasLogo {
		if panel {
			rect((W-lw)/2-2*u, y, lw+4*u, lh+2*u, colWhite, 1.4*u)
			y += u
		}
		add(Item{Kind: ItemImage, X: (W - lw) / 2, Y: y, W: lw, H: lh, PNG: logo.png})
		y += lh + 2.4*u
		if panel {
			y += u
		}
	}
	centred(title, y+titleLine/2, ts, true, ink, 6*u, titleBox)

	// The stripe, or a rule in the accent colour.
	y = headerH
	if d.Stripe {
		third := W / 3
		rect(0, y, third, 1.6*u, hexOr(d.Bar1, colYellow), 0)
		rect(third, y, third, 1.6*u, hexOr(d.Bar2, colCoral), 0)
		rect(2*third, y, W-2*third, 1.6*u, hexOr(d.Bar3, colGreen), 0)
	} else {
		rect(0, y, W, 1.6*u, accent, 0)
	}

	// The footer, from the bottom up: the accent rule and the line about
	// recording each use.
	rect(0, H-1.6*u, W, 1.6*u, accent, 0)
	footBox := W - 12*u
	fs := 2.9 * u
	footLines := m.wrap(RecordedLine, footBox, fs, false)
	footTop := H - 1.6*u - 3*u - float64(len(footLines))*fs*1.45 - 3*u

	// The body: location, the app, the code and the steps. Steps shrink, then
	// the code, then steps are cut, until the body fits above the footer.
	body := headerH + 1.6*u + 5*u
	box := W - 14*u
	loc := strings.TrimSpace(c.Location)
	if loc == "" {
		loc = "Location"
	}
	loc, locSize := m.fit(loc, box, 7.2*u, 4.5*u, true)
	app := ""
	appSize := 4.2 * u
	if a := strings.TrimSpace(c.App); a != "" {
		app, appSize = m.fit(opensPrefix+a, box, 4.2*u, 3*u, false)
	}
	steps := StepLines(d.Steps)
	if len(steps) == 0 {
		steps = StepLines(DefaultSteps)
	}
	hs := 3.5 * u
	stepIndent := stepIndentU * u
	panelPadX, panelPadY := 4.4*u, 3.2*u
	stepBox := box - 2*panelPadX - stepIndent
	type plan struct {
		qr     float64
		ss     float64
		lines  [][]string
		height float64
	}
	measure := func(qrBox, ss float64) plan {
		p := plan{qr: qrBox, ss: ss}
		h := locSize*1.15 + 3.5*u + qrBox + 3.5*u
		if app != "" {
			h += 1.2*u + appSize*1.2
		}
		ph := 2*panelPadY + hs*1.45 + u
		for _, s := range steps {
			ls := m.wrap(s, stepBox, ss, false)
			p.lines = append(p.lines, ls)
			ph += float64(len(ls)) * ss * 1.45
		}
		p.height = h + ph
		return p
	}
	avail := footTop - u - body
	var p plan
	fitted := false
	for _, qrBox := range []float64{44 * u, 40 * u, 36 * u} {
		for ss := 3.3 * u; ss >= 2.5*u-1e-9; ss -= 0.1 * u {
			if p = measure(qrBox, ss); p.height <= avail {
				fitted = true
				break
			}
		}
		if fitted {
			break
		}
	}
	if !fitted {
		// Cut the steps, from the last, until they fit.
		for p.height > avail && len(p.lines) > 0 {
			last := len(p.lines) - 1
			ls := p.lines[last]
			if len(ls) > 1 {
				ls = ls[:len(ls)-1]
				ls[len(ls)-1] = m.cut(ls[len(ls)-1]+" "+ellipsis, stepBox, p.ss, false)
				p.lines[last] = ls
			} else {
				p.lines = p.lines[:last]
			}
			p.height -= p.ss * 1.45
		}
	}

	y = body
	centred(loc, y+locSize*1.15/2, locSize, true, colNearBlack, 7*u, box)
	y += locSize * 1.15
	if app != "" {
		y += 1.2 * u
		centred(app, y+appSize*1.2/2, appSize, false, colAppLine, 7*u, box)
		y += appSize * 1.2
	}
	y += 3.5 * u
	// The code, in a rounded frame of the accent colour.
	qrBox := p.qr
	qx := (W - qrBox) / 2
	white := colWhite
	add(Item{Kind: ItemRect, X: qx, Y: y, W: qrBox, H: qrBox, Fill: &white, Stroke: &accent, StrokeW: 0.8 * u, Radius: 3 * u})
	inner := qrBox - 2*0.8*u - 2*3*u
	content := c.QR
	if content == "" {
		content = sampleQR
	}
	if mods := qrModules(content); mods != nil {
		add(Item{Kind: ItemQR, X: qx + 0.8*u + 3*u, Y: y + 0.8*u + 3*u, W: inner, H: inner, Modules: mods})
	}
	y += qrBox + 3.5*u

	// How to use this card: a tinted panel with the numbered steps.
	ph := p.height - (y - body)
	rect(7*u, y, box, ph, mixWhite(accent, 0.9), 2.4*u)
	ty := y + panelPadY
	text(HowToUse, 7*u+panelPadX, ty+hs*1.45/2+textBaseline*hs, hs, true, accent, 7*u+panelPadX, box-2*panelPadX)
	ty += hs*1.45 + u
	for i, ls := range p.lines {
		num := itoa(i+1) + "."
		text(num, 7*u+panelPadX, ty+p.ss*1.45/2+textBaseline*p.ss, p.ss, false, colNearBlack, 7*u+panelPadX, stepIndent)
		for _, l := range ls {
			text(l, 7*u+panelPadX+stepIndent, ty+p.ss*1.45/2+textBaseline*p.ss, p.ss, false, colNearBlack, 7*u+panelPadX+stepIndent, stepBox)
			ty += p.ss * 1.45
		}
	}

	fy := footTop + 3*u
	for _, l := range footLines {
		centred(l, fy+fs*1.45/2, fs, false, colFooter, 6*u, footBox)
		fy += fs * 1.45
	}
	return out
}

// qrModules encodes content as a QR code (error correction Q) and returns
// its modules with the four-module quiet zone, dark true.
func qrModules(content string) [][]bool {
	code, err := qr.Encode(content, qr.Q, qr.Auto)
	if err != nil {
		return nil
	}
	n := code.Bounds().Dx()
	total := n + 2*quietModules
	out := make([][]bool, total)
	for y := range out {
		out[y] = make([]bool, total)
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if r, _, _, _ := code.At(x, y).RGBA(); r < 0x8000 {
				out[y+quietModules][x+quietModules] = true
			}
		}
	}
	return out
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

package breakglass

import (
	"bytes"
	"encoding/xml"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

// testLogo is a dark logo on a transparent background, 300 by 80 pixels.
func testLogo(t *testing.T) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 300, 80))
	for y := 10; y < 70; y++ {
		for x := 10; x < 290; x++ {
			img.Set(x, y, color.NRGBA{34, 50, 74, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// checkFits fails when anything lies outside the page or a line of text is
// wider than the span it was given.
func checkFits(t *testing.T, name string, d Drawing) {
	t.Helper()
	const eps = 0.01
	for _, it := range d.Items {
		x0, y0, x1, y1 := it.X, it.Y, it.X+it.W, it.Y+it.H
		if it.Stroke != nil {
			x0, y0, x1, y1 = x0-it.StrokeW/2, y0-it.StrokeW/2, x1+it.StrokeW/2, y1+it.StrokeW/2
		}
		if it.Kind == ItemText {
			y0, y1 = it.Y-it.Size, it.Y+0.25*it.Size
			if it.X < it.BoxX-eps || it.X+it.W > it.BoxX+it.BoxW+eps {
				t.Errorf("%s: text %q (%.2f..%.2f) overflows its box %.2f..%.2f", name, it.Text, it.X, it.X+it.W, it.BoxX, it.BoxX+it.BoxW)
			}
		}
		if x0 < -eps || y0 < -eps || x1 > d.W+eps || y1 > d.H+eps {
			t.Errorf("%s: item %d %q lies outside the %gx%g page: %.2f,%.2f to %.2f,%.2f", name, it.Kind, it.Text, d.W, d.H, x0, y0, x1, y1)
		}
	}
}

// TestLayoutFitsEverySize lays out ordinary and extreme cards at A6, A5 and
// A4: nothing may leave the page, no text its box, and the body may not run
// into the footer.
func TestLayoutFitsEverySize(t *testing.T) {
	logo := testLogo(t)
	long := strings.Repeat("Paediatric intensive care unit bed ", 6)
	many := strings.Repeat("Open your phone's camera and point it at the code, then wait for the link to appear before you tap it.\n", 12)
	cases := []Card{
		{Location: "Angiography Lab 1", App: "NeverDrugs"},
		{Location: long, App: long},
		{Location: "Theatre 6", App: "Handbook", Design: Design{Steps: many, Title: long}},
		{Location: "Supercalifragilisticexpialidociousandmorewordswithoutspaces", App: "x"},
	}
	for _, size := range SizeOrder {
		for _, mode := range []string{LogoAsIs, LogoWhite, LogoPanel} {
			for i, c := range cases {
				c.Design.Size = size
				c.Design.Logo, c.Design.LogoType, c.Design.LogoMode = logo, "image/png", mode
				c.Design.Stripe = i%2 == 0
				d := c.Layout()
				want := Sizes[size]
				if d.W != want[0] || d.H != want[1] {
					t.Fatalf("%s: page %gx%g, want %v", size, d.W, d.H, want)
				}
				checkFits(t, size+"/"+mode, d)
				// The steps' panel ends above the footer line.
				var footer, panelEnd float64
				for _, it := range d.Items {
					if it.Kind == ItemText && it.Text == RecordedLine {
						footer = it.Y - it.Size
					}
					if it.Kind == ItemText && (strings.HasSuffix(it.Text, ".") || strings.HasSuffix(it.Text, ellipsis)) && it.Text != RecordedLine {
						panelEnd = max(panelEnd, it.Y)
					}
				}
				if footer == 0 || panelEnd >= footer {
					t.Errorf("%s case %d: the steps (to %.1f) reach the footer (%.1f)", size, i, panelEnd, footer)
				}
			}
		}
	}
}

// TestPDFAndSVGFromOneLayout draws one layout both ways: every line of text
// the layout placed is in the PDF and in the SVG, at the same size of page.
func TestPDFAndSVGFromOneLayout(t *testing.T) {
	c := Card{Location: "Angiography Lab 1", App: "NeverDrugs", QR: "https://auth.example.com/break/abc",
		Design: Design{Size: "A5", Stripe: true, Logo: testLogo(t), LogoType: "image/png", LogoMode: LogoWhite}}
	d := c.Layout()
	pdf, err := d.PDF(false)
	if err != nil {
		t.Fatal(err)
	}
	svg := string(d.SVG())
	if err := xml.Unmarshal([]byte(svg), new(struct{})); err != nil {
		t.Fatalf("the SVG is not well formed: %v", err)
	}
	if !strings.Contains(svg, `viewBox="0 0 148 210"`) || !bytes.Contains(pdf, []byte("/MediaBox [0 0 419.53 595.28]")) {
		t.Errorf("the PDF and SVG are not both A5")
	}
	texts := 0
	for _, it := range d.Items {
		if it.Kind != ItemText {
			continue
		}
		texts++
		if !strings.Contains(svg, ">"+xmlEscape(it.Text)+"</text>") {
			t.Errorf("the SVG lacks %q", it.Text)
		}
		if !bytes.Contains(pdf, []byte("("+it.Text+")")) {
			t.Errorf("the PDF lacks %q", it.Text)
		}
	}
	if got := strings.Count(svg, "<text "); got != texts {
		t.Errorf("the SVG has %d lines of text, the layout %d", got, texts)
	}
	if strings.Count(svg, "<image ") != 1 || bytes.Count(pdf, []byte("/Subtype /Image")) < 2 {
		t.Errorf("want the logo once in the SVG, and the logo and the code in the PDF")
	}
	for _, want := range []string{HowToUse, RecordedLine, "Opens NeverDrugs", "Press Continue to open the app."} {
		if !strings.Contains(svg, want) && !strings.Contains(svg, xmlEscape(want)) {
			t.Errorf("the card lacks the fixed line %q", want)
		}
	}
}

// TestWhiteLogoIsWhite: the white treatment keeps the logo's shape and
// makes every visible pixel white.
func TestWhiteLogoIsWhite(t *testing.T) {
	p, ok := prepareLogo(testLogo(t), "image/png", LogoWhite)
	if !ok {
		t.Fatal("the logo was not prepared")
	}
	img, err := png.Decode(bytes.NewReader(p.png))
	if err != nil {
		t.Fatal(err)
	}
	c := color.NRGBAModel.Convert(img.At(img.Bounds().Dx()/2, img.Bounds().Dy()/2)).(color.NRGBA)
	if c != (color.NRGBA{255, 255, 255, 255}) {
		t.Errorf("the middle of the white logo is %v", c)
	}
	if c := color.NRGBAModel.Convert(img.At(0, 0)).(color.NRGBA); c.A != 0 {
		t.Errorf("the transparent corner became %v", c)
	}
}

// TestLogoReadable follows the prototype's logoCheck.
func TestLogoReadable(t *testing.T) {
	ink, ok := LogoInk(testLogo(t), "image/png")
	if !ok || ink != "#22324a" {
		t.Fatalf("ink %q", ink)
	}
	if best, ok := LogoReadable("#003a5c", LogoAsIs, ink, true); best != LogoWhite || ok {
		t.Errorf("dark header, logo as uploaded: best %s ok %v", best, ok)
	}
	if best, ok := LogoReadable("#eef2f5", LogoAsIs, ink, true); best != LogoAsIs || !ok {
		t.Errorf("light header, logo as uploaded: best %s ok %v", best, ok)
	}
	if _, ok := LogoReadable("#eef2f5", LogoWhite, ink, true); ok {
		t.Error("a white logo on a light header passed")
	}
	if _, ok := LogoReadable("#003a5c", LogoPanel, ink, true); !ok {
		t.Error("a logo on a white panel failed")
	}
}

func TestStepLinesDropNumbering(t *testing.T) {
	got := StepLines("1. Open the camera.\n\n2) Tap the link.\n  Press Continue.  ")
	want := []string{"Open the camera.", "Tap the link.", "Press Continue."}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q", got)
	}
}

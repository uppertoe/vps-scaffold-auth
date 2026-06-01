package breakglass

import (
	"bytes"
	"image"
	"image/png"
	"testing"
)

func TestGenerateTokenUniqueAndURLSafe(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) < 20 { // 16 bytes base64url == 22 chars
			t.Errorf("token too short: %q", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token: %q", tok)
		}
		seen[tok] = true
	}
}

func TestQRPNGEncodesPNG(t *testing.T) {
	data, err := QRPNG("https://auth.example.com/break/abc", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G'}) {
		t.Errorf("output is not a PNG (prefix %x)", data[:4])
	}
}

func TestQRPNGHasQuietZoneAndContrast(t *testing.T) {
	data, err := QRPNG("https://auth.example.com/break/abcdef", 900)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	// Corners must be white (the quiet zone), so scanners can acquire the code.
	for _, pt := range []image.Point{
		{b.Min.X, b.Min.Y}, {b.Max.X - 1, b.Min.Y},
		{b.Min.X, b.Max.Y - 1}, {b.Max.X - 1, b.Max.Y - 1},
	} {
		if r, _, _, _ := img.At(pt.X, pt.Y).RGBA(); r < 0x8000 {
			t.Errorf("corner %v is not white; quiet zone missing", pt)
		}
	}
	// Pure two-tone: every pixel is fully black or fully white (no anti-aliasing).
	for y := b.Min.Y; y < b.Max.Y; y += 7 {
		for x := b.Min.X; x < b.Max.X; x += 7 {
			r, _, _, _ := img.At(x, y).RGBA()
			if r != 0 && r != 0xffff {
				t.Fatalf("non-binary pixel at %d,%d: r=%#x", x, y, r)
			}
		}
	}
}

func TestCardPDF(t *testing.T) {
	qr, err := QRPNG("https://auth.example.com/break/abc", 256)
	if err != nil {
		t.Fatal(err)
	}
	card := Card{
		Title:        "Emergency access",
		Label:        "Angiography Lab 1",
		Body:         "Scan to gain temporary access. Every use is logged.",
		Instructions: "1. Open your phone camera.\n2. Point it at the code.\n3. Tap the link that appears.",
		Note:         "Placed by the workstation.",
		QRPNG:        qr,
	}
	pdf, err := card.PDF()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF")) {
		t.Errorf("output is not a PDF (prefix %q)", pdf[:4])
	}
}

func TestCardPDFWithSVGGlyph(t *testing.T) {
	qr, _ := QRPNG("https://auth.example.com/break/abc", 256)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect x="42" y="20" width="16" height="60" fill="#f26c52"/><rect x="20" y="42" width="60" height="16" fill="#f26c52"/></svg>`)
	card := Card{
		Title:     "Emergency access",
		Label:     "Resus Bay 2",
		QRPNG:     qr,
		GlyphData: svg,
		GlyphType: "image/svg+xml",
	}
	pdf, err := card.PDF()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF")) {
		t.Error("SVG-glyph card did not render a PDF")
	}
}

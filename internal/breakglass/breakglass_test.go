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

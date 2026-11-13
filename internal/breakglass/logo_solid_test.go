package breakglass

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// badge is a blue tile with transparent corners and a white bar of
// lettering across it, 200 by 100 pixels.
func badge(t *testing.T) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 200, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 200; x++ {
			corner := (x < 6 || x >= 194) && (y < 6 || y >= 94)
			switch {
			case corner:
			case y >= 40 && y < 60 && x >= 40 && x < 160:
				img.Set(x, y, color.NRGBA{255, 255, 255, 255})
			default:
				img.Set(x, y, color.NRGBA{0, 58, 140, 255})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// lettering is dark strokes on transparency: a thin frame, 200 by 100.
func lettering(t *testing.T) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 200, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 200; x++ {
			if x < 8 || x >= 192 || y < 8 || y >= 92 {
				img.Set(x, y, color.NRGBA{20, 20, 20, 255})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLogoSolid(t *testing.T) {
	if solid, ok := LogoSolid(badge(t), "image/png"); !ok || !solid {
		t.Error("a badge on a solid tile is not found solid")
	}
	if solid, ok := LogoSolid(lettering(t), "image/png"); !ok || solid {
		t.Error("strokes on transparency are found solid")
	}
}

// Made white, a badge keeps its lettering as a cut-out rather than turning
// into a white block.
func TestWhiteBadgeKeepsItsLettering(t *testing.T) {
	raw, ok := LogoPNG(badge(t), "image/png", LogoWhite)
	if !ok {
		t.Fatal("badge not drawn")
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	_, _, _, tile := img.At(b.Dx()/10, b.Dy()/5).RGBA()
	_, _, _, text := img.At(b.Dx()/2, b.Dy()/2).RGBA()
	if tile < 0xc000 || text > 0x2000 {
		t.Errorf("tile alpha %x, lettering alpha %x: want an opaque tile with the lettering cut out", tile, text)
	}
}

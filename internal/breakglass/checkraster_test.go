package breakglass

import (
	"bytes"
	"errors"
	"image"
	"image/png"
	"testing"
)

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Oversized or 16-bit images are refused before embedding, so an image stored
// before the upload limit existed cannot be decoded at full size; the card
// then renders without it.
func TestCheckRasterAndPDFImage(t *testing.T) {
	ok := encodePNG(t, image.NewNRGBA(image.Rect(0, 0, MaxRasterSide, 10)))
	wide := encodePNG(t, image.NewNRGBA(image.Rect(0, 0, MaxRasterSide+1, 1)))
	deep := encodePNG(t, image.NewNRGBA64(image.Rect(0, 0, 4, 4)))
	if err := CheckRaster(ok); err != nil {
		t.Errorf("a %d px image was refused: %v", MaxRasterSide, err)
	}
	for name, data := range map[string][]byte{"wide": wide, "16-bit": deep} {
		if err := CheckRaster(data); !errors.Is(err, ErrImageTooLarge) {
			t.Errorf("%s: CheckRaster = %v, want ErrImageTooLarge", name, err)
		}
		if _, _, err := pdfImage(data, "image/png", 256); err == nil {
			t.Errorf("%s: pdfImage embedded an image it should refuse", name)
		}
	}
}

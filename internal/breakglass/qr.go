package breakglass

import (
	"bytes"
	"image"
	"image/png"

	"github.com/boombuler/barcode/qr"
)

// quietModules is the mandatory white border around a QR code, in modules. The
// spec requires 4; scanners are far more reliable with it present.
const quietModules = 4

// QRPNG renders content into a QR-code PNG roughly `size` pixels square,
// optimised for scanning:
//   - error-correction level Q (25%: ample tolerance for a laminated card while
//     keeping the module count low so the modules print large),
//   - a 4-module quiet zone (so scanners reliably acquire the code),
//   - integer pixels-per-module with no anti-aliasing (crisp, even modules),
//   - pure black-on-white (maximum contrast).
//
// Rendering is done by hand from the module grid rather than via barcode.Scale
// so module edges always fall on whole pixels.
func QRPNG(content string, size int) ([]byte, error) {
	code, err := qr.Encode(content, qr.Q, qr.Auto)
	if err != nil {
		return nil, err
	}
	mods := code.Bounds().Dx() // QR is square; one source pixel == one module
	total := mods + 2*quietModules

	scale := size / total
	if scale < 1 {
		scale = 1
	}
	dim := total * scale

	img := image.NewGray(image.Rect(0, 0, dim, dim))
	// White background (including the quiet zone).
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	// Fill each dark module as a solid scale×scale block.
	for my := 0; my < mods; my++ {
		for mx := 0; mx < mods; mx++ {
			r, _, _, _ := code.At(mx, my).RGBA()
			if r >= 0x8000 {
				continue // light module: leave white
			}
			x0 := (mx + quietModules) * scale
			y0 := (my + quietModules) * scale
			for dy := 0; dy < scale; dy++ {
				row := (y0+dy)*img.Stride + x0
				for dx := 0; dx < scale; dx++ {
					img.Pix[row+dx] = 0x00
				}
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

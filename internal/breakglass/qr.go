package breakglass

import (
	"bytes"
	"errors"
	"image"
	"image/png"
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
func QRPNG(content string, size int) ([]byte, error) {
	mods := qrModules(content)
	if mods == nil {
		return nil, errors.New("breakglass: cannot encode the QR code")
	}
	return modulesPNG(mods, size)
}

// modulesPNG draws a module grid (quiet zone included) as a PNG about size
// pixels square. Rendering is done by hand so module edges always fall on
// whole pixels.
func modulesPNG(mods [][]bool, size int) ([]byte, error) {
	total := len(mods)
	if total == 0 {
		return nil, errors.New("breakglass: empty QR code")
	}
	scale := max(size/total, 1)
	dim := total * scale
	img := image.NewGray(image.Rect(0, 0, dim, dim))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	for my, row := range mods {
		for mx, dark := range row {
			if !dark {
				continue
			}
			for dy := 0; dy < scale; dy++ {
				off := (my*scale+dy)*img.Stride + mx*scale
				for dx := 0; dx < scale; dx++ {
					img.Pix[off+dx] = 0x00
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

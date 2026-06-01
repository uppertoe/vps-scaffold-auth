package breakglass

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"math"
	"strings"

	"github.com/srwiley/oksvg"
	"github.com/srwiley/rasterx"
)

// pdfImage prepares an uploaded image for embedding in a PDF. PNG and JPEG pass
// through unchanged; SVG is rasterized (pure Go, preserving aspect ratio) to a
// transparent PNG whose longest side is `size` pixels. It returns the bytes and
// the fpdf image type ("PNG" or "JPG").
func pdfImage(data []byte, mime string, size int) ([]byte, string, error) {
	switch detectImage(data, mime) {
	case "svg":
		png, err := rasterizeSVG(data, size)
		return png, "PNG", err
	case "png":
		return data, "PNG", nil
	case "jpeg":
		return data, "JPG", nil
	default:
		return nil, "", fmt.Errorf("breakglass: unsupported image type %q", mime)
	}
}

// ImageKind classifies uploaded image bytes as "png", "jpeg", "svg", or ""
// (unsupported), for upload validation.
func ImageKind(data []byte, mime string) string {
	return detectImage(data, mime)
}

// detectImage classifies an image by MIME hint and content sniffing.
func detectImage(data []byte, mime string) string {
	m := strings.ToLower(mime)
	switch {
	case strings.Contains(m, "svg"):
		return "svg"
	case strings.Contains(m, "png"):
		return "png"
	case strings.Contains(m, "jpeg"), strings.Contains(m, "jpg"):
		return "jpeg"
	}
	switch {
	case len(data) >= 8 && bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G'}):
		return "png"
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xD8:
		return "jpeg"
	case bytes.Contains(data[:min(512, len(data))], []byte("<svg")):
		return "svg"
	}
	return ""
}

// rasterizeSVG renders an SVG to a PNG no larger than size on its longest side,
// preserving the source aspect ratio.
func rasterizeSVG(data []byte, size int) ([]byte, error) {
	icon, err := oksvg.ReadIconStream(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("breakglass: parse svg: %w", err)
	}
	w, h := icon.ViewBox.W, icon.ViewBox.H
	if w <= 0 || h <= 0 {
		w, h = float64(size), float64(size)
	}
	scale := float64(size) / math.Max(w, h)
	ow, oh := int(w*scale+0.5), int(h*scale+0.5)
	if ow < 1 {
		ow = 1
	}
	if oh < 1 {
		oh = 1
	}
	icon.SetTarget(0, 0, float64(ow), float64(oh))
	rgba := image.NewRGBA(image.Rect(0, 0, ow, oh))
	scanner := rasterx.NewScannerGV(ow, oh, rgba, rgba.Bounds())
	icon.Draw(rasterx.NewDasher(ow, oh, scanner), 1.0)
	var buf bytes.Buffer
	if err := png.Encode(&buf, rgba); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

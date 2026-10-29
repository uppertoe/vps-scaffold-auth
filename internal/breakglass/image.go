package breakglass

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg" // registers JPEG for image.DecodeConfig
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
		if err := CheckRaster(data); err != nil {
			return nil, "", err
		}
		return data, "PNG", nil
	case "jpeg":
		if err := CheckRaster(data); err != nil {
			return nil, "", err
		}
		return data, "JPG", nil
	default:
		return nil, "", fmt.Errorf("breakglass: unsupported image type %q", mime)
	}
}

// MaxRasterSide bounds a PNG or JPEG's width and height in pixels. The PDF
// library decodes the whole image to embed it, so a small file declaring large
// dimensions costs memory: about 20 MB at 1000 px a side for 8-bit RGBA, but
// over 128 MB at 3000 px, enough to kill the service and with it forward_auth
// for every gated site. Cards draw images at 256 px, so 1000 px loses nothing.
const MaxRasterSide = 1000

// ErrImageTooLarge reports an image refused by CheckRaster for its dimensions
// or bit depth.
var ErrImageTooLarge = errors.New("breakglass: image too large to embed")

// CheckRaster reads only a PNG or JPEG's header and refuses dimensions over
// MaxRasterSide or 16-bit colour (which doubles the decoded size). It is
// applied at upload and again before embedding, so images stored before the
// limit existed are covered too.
func CheckRaster(data []byte) error {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("breakglass: unreadable image: %w", err)
	}
	if cfg.Width > MaxRasterSide || cfg.Height > MaxRasterSide {
		return ErrImageTooLarge
	}
	switch cfg.ColorModel {
	case color.RGBA64Model, color.NRGBA64Model, color.Gray16Model:
		return ErrImageTooLarge
	}
	return nil
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

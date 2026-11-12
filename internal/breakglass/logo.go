package breakglass

import (
	"bytes"
	"crypto/sha256"
	"image"
	"image/color"
	"image/png"
	"sync"

	"golang.org/x/image/draw"
)

// Logo treatments a design may choose.
const (
	LogoAsIs  = "asis"  // the logo keeps its own colours
	LogoWhite = "white" // the gateway makes a white version from the same file
	LogoPanel = "panel" // the logo keeps its colours, on a white rounded panel
)

// logoSide is the longest side, in pixels, of the logo as a card draws it.
// At A4 the logo is at most 60 mm wide, so 600 px prints at about 250 dpi.
const logoSide = 600

// preparedLogo is a logo ready to draw: PNG bytes and the aspect ratio.
type preparedLogo struct {
	png   []byte
	ratio float64 // width / height
}

var logoCache = struct {
	sync.Mutex
	m map[[32]byte]preparedLogo
}{m: map[[32]byte]preparedLogo{}}

// prepareLogo decodes an uploaded logo (PNG, JPEG or SVG), scales it so its
// longest side is logoSide, and in the white treatment makes it white. A
// card's PDF and its preview both draw these bytes. Results are cached, as
// a list of cards draws the same logo many times. ok is false for a logo
// that cannot be read; the card then draws without it.
func prepareLogo(data []byte, mime, mode string) (preparedLogo, bool) {
	if len(data) == 0 {
		return preparedLogo{}, false
	}
	key := sha256.Sum256(append([]byte(mode+"\x00"+mime+"\x00"), data...))
	logoCache.Lock()
	if p, ok := logoCache.m[key]; ok {
		logoCache.Unlock()
		return p, true
	}
	logoCache.Unlock()
	img, ok := decodeLogo(data, mime)
	if !ok {
		return preparedLogo{}, false
	}
	b := img.Bounds()
	if b.Dx() == 0 || b.Dy() == 0 {
		return preparedLogo{}, false
	}
	w, h := b.Dx(), b.Dy()
	if w > logoSide || h > logoSide {
		if w >= h {
			w, h = logoSide, max(1, h*logoSide/w)
		} else {
			w, h = max(1, w*logoSide/h), logoSide
		}
	}
	out := image.NewNRGBA(image.Rect(0, 0, w, h))
	draw.CatmullRom.Scale(out, out.Bounds(), img, b, draw.Src, nil)
	if mode == LogoWhite {
		whiten(out)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, out); err != nil {
		return preparedLogo{}, false
	}
	p := preparedLogo{png: buf.Bytes(), ratio: float64(w) / float64(h)}
	logoCache.Lock()
	if len(logoCache.m) >= 32 {
		clear(logoCache.m)
	}
	logoCache.m[key] = p
	logoCache.Unlock()
	return p, true
}

// decodeLogo reads a stored logo as an image. An SVG is rasterised first.
func decodeLogo(data []byte, mime string) (image.Image, bool) {
	raw, _, err := pdfImage(data, mime, logoSide)
	if err != nil {
		return nil, false
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	return img, true
}

// whiten turns a logo white. A logo with transparency keeps its shape and
// every visible pixel becomes white; a logo without (a JPEG, or a PNG on a
// solid background) takes its shape from how dark each pixel is, so dark
// marks on a light background become white marks on nothing.
func whiten(img *image.NRGBA) {
	transparent := false
	for i := 3; i < len(img.Pix); i += 4 {
		if img.Pix[i] < 250 {
			transparent = true
			break
		}
	}
	for i := 0; i < len(img.Pix); i += 4 {
		a := img.Pix[i+3]
		if !transparent {
			l := lum(rgb{int(img.Pix[i]), int(img.Pix[i+1]), int(img.Pix[i+2])})
			a = uint8(255 - int(l*255+0.5))
		}
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = 255, 255, 255, a
	}
}

// LogoInk is a logo's own colour as "#rrggbb": the average of its visible
// pixels, weighted by how opaque they are, or (for a logo without
// transparency) by how dark they are. ok is false for a logo that cannot be
// read.
func LogoInk(data []byte, mime string) (string, bool) {
	img, ok := decodeLogo(data, mime)
	if !ok {
		return "", false
	}
	b := img.Bounds()
	transparent := false
	for y := b.Min.Y; y < b.Max.Y && !transparent; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a < 0xf000 {
				transparent = true
				break
			}
		}
	}
	var sr, sg, sb, sw float64
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			w := float64(c.A) / 255
			if !transparent {
				w = 1 - lum(rgb{int(c.R), int(c.G), int(c.B)})
			}
			sr += float64(c.R) * w
			sg += float64(c.G) * w
			sb += float64(c.B) * w
			sw += w
		}
	}
	if sw == 0 {
		return colWhite.hex(), true
	}
	return rgb{int(sr/sw + .5), int(sg/sw + .5), int(sb/sw + .5)}.hex(), true
}

// LogoPNG is a logo as cards draw it in a treatment: PNG bytes, white in the
// white treatment. ok is false for a logo that cannot be read.
func LogoPNG(data []byte, mime, mode string) ([]byte, bool) {
	p, ok := prepareLogo(data, mime, mode)
	return p.png, ok
}

// InkOn is the title colour on a header colour: white or near-black.
func InkOn(header string) string { return inkOn(hexOr(header, colNavy)).hex() }

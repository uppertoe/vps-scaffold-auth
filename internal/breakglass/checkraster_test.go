package breakglass

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/png"
	"strings"
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

// pngWith builds a PNG whose header says w by h RGBA, with the given raw
// (pre-zlib) pixel stream, so a test can make the stream disagree with the
// header.
func pngWith(t *testing.T, w, h int, raw []byte, interlace byte) []byte {
	t.Helper()
	chunk := func(typ string, data []byte) []byte {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(len(data)))
		b.WriteString(typ)
		b.Write(data)
		binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(typ), data...)))
		return b.Bytes()
	}
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], uint32(w))
	binary.BigEndian.PutUint32(ihdr[4:], uint32(h))
	ihdr[8], ihdr[9], ihdr[12] = 8, 6, interlace // 8-bit RGBA
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(raw)
	zw.Close()
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, chunk("IHDR", ihdr)...)
	out = append(out, chunk("IDAT", z.Bytes())...)
	return append(out, chunk("IEND", nil)...)
}

// A small file with a truthful header but far more pixel data than the header
// allows (a decompression bomb for the PDF library), or too little, is refused.
func TestCheckRasterRefusesCraftedPNGs(t *testing.T) {
	row := 1 + 4*MaxRasterSide
	bomb := pngWith(t, MaxRasterSide, MaxRasterSide, make([]byte, row*MaxRasterSide*8), 0)
	short := pngWith(t, MaxRasterSide, MaxRasterSide, make([]byte, row*10), 0)
	if len(bomb) > 64<<10 {
		t.Fatalf("bomb is %d bytes; it should be small", len(bomb))
	}
	for name, data := range map[string][]byte{"bomb": bomb, "short": short} {
		if err := CheckRaster(data); err == nil {
			t.Errorf("%s PNG passed CheckRaster", name)
		}
	}
	if err := CheckRaster(pngWith(t, 10, 10, make([]byte, 41*10), 0)); err != nil {
		t.Errorf("a well-formed PNG was refused: %v", err)
	}
}

// hiddenStreamPNG is a valid 1x1 RGBA PNG to Go, whose pHYs chunk is longer
// than its 9 standard bytes. Go skips the declared length; the PDF library
// reads 9 bytes and a CRC, then parses the rest of the payload as chunks and
// finds a hidden IDAT that inflates to `inflated` bytes.
func hiddenStreamPNG(t *testing.T, inflated int) []byte {
	t.Helper()
	chunk := func(typ string, data []byte) []byte {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(len(data)))
		b.WriteString(typ)
		b.Write(data)
		binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(typ), data...)))
		return b.Bytes()
	}
	var z bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
	zeros := make([]byte, 1<<20)
	for n := 0; n < inflated; n += len(zeros) {
		zw.Write(zeros)
	}
	zw.Close()
	var hidden bytes.Buffer
	hidden.Write(make([]byte, 9+4))
	hidden.Write(chunk("IDAT", z.Bytes()))
	hidden.Write(chunk("IEND", nil))
	img := image.NewNRGBA(image.Rect(0, 0, 1, 1))
	img.Pix[3] = 128
	real := encodePNG(t, img)
	out := append([]byte{}, real[:33]...) // signature and IHDR
	out = append(out, chunk("pHYs", hidden.Bytes())...)
	return append(out, real[33:]...)
}

// The PDF library never receives an uploaded PNG's own bytes: Go re-encodes it,
// so a hidden pixel stream that Go skips cannot reach the PDF library.
func TestPDFImageReencodesPNG(t *testing.T) {
	bomb := hiddenStreamPNG(t, 64<<20)
	out, typ, err := pdfImage(bomb, "image/png", 256)
	if err != nil {
		t.Fatalf("pdfImage refused a PNG that Go decodes: %v", err)
	}
	if typ != "PNG" || len(out) > 1<<10 || bytes.Contains(out, []byte("pHYs")) {
		t.Errorf("pdfImage passed on %d bytes (type %s); want Go's small re-encoding", len(out), typ)
	}
	canon, err := CanonicalPNG(bomb)
	if err != nil || !bytes.Equal(canon, out) {
		t.Errorf("CanonicalPNG and pdfImage disagree (err %v)", err)
	}
}

// SVGs that make the SVG library expand or recurse without bound are refused
// before it parses them; an ordinary logo passes.
func TestCheckSVG(t *testing.T) {
	logo := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><defs><linearGradient id="g"><stop offset="0"/><stop offset="1"/></linearGradient></defs><g><rect width="10" height="10" fill="url(#g)"/></g></svg>`)
	if err := CheckSVG(logo); err != nil {
		t.Fatalf("an ordinary SVG was refused: %v", err)
	}
	use := []byte(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><defs><path id="a" d="M0 0h1"/></defs><use xlink:href="#a"/></svg>`)
	doctype := []byte(`<!DOCTYPE svg [<!ENTITY a "aaaa">]><svg xmlns="http://www.w3.org/2000/svg"><text>&a;</text></svg>`)
	deep := []byte(`<svg xmlns="http://www.w3.org/2000/svg">` + strings.Repeat("<g>", maxSVGDepth+1) + strings.Repeat("</g>", maxSVGDepth+1) + `</svg>`)
	many := []byte(`<svg xmlns="http://www.w3.org/2000/svg">` + strings.Repeat(`<rect width="1" height="1"/>`, maxSVGElements+1) + `</svg>`)
	stops := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><linearGradient>` + strings.Repeat(`<stop/>`, maxSVGStops+1) + `</linearGradient></svg>`)
	for name, data := range map[string][]byte{"use": use, "doctype": doctype, "deep": deep, "many": many, "stops": stops} {
		if err := CheckSVG(data); err == nil {
			t.Errorf("%s SVG passed CheckSVG", name)
		}
		if _, _, err := pdfImage(data, "image/svg+xml", 256); err == nil {
			t.Errorf("%s SVG was rasterised for a card", name)
		}
	}
}

// The bytes decide an image's kind before the declared type, so a PNG labelled
// as a JPEG is still re-encoded.
func TestDetectImageSniffsFirst(t *testing.T) {
	data := encodePNG(t, image.NewNRGBA(image.Rect(0, 0, 2, 2)))
	if k := detectImage(data, "image/jpeg"); k != "png" {
		t.Errorf("PNG bytes declared as JPEG classified %q", k)
	}
}

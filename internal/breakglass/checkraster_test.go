package breakglass

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"hash/crc32"
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
// allows (a decompression bomb for the PDF library), or too little, or an
// interlaced image the PDF library cannot embed, is refused.
func TestCheckRasterRefusesCraftedPNGs(t *testing.T) {
	row := 1 + 4*MaxRasterSide
	bomb := pngWith(t, MaxRasterSide, MaxRasterSide, make([]byte, row*MaxRasterSide*8), 0)
	short := pngWith(t, MaxRasterSide, MaxRasterSide, make([]byte, row*10), 0)
	interlaced := pngWith(t, 10, 10, make([]byte, 41*10), 1)
	if len(bomb) > 64<<10 {
		t.Fatalf("bomb is %d bytes; it should be small", len(bomb))
	}
	for name, data := range map[string][]byte{"bomb": bomb, "short": short, "interlaced": interlaced} {
		if err := CheckRaster(data); err == nil {
			t.Errorf("%s PNG passed CheckRaster", name)
		}
	}
	if err := CheckRaster(pngWith(t, 10, 10, make([]byte, 41*10), 0)); err != nil {
		t.Errorf("a well-formed PNG was refused: %v", err)
	}
}

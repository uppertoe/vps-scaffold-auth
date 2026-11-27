package passkey

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The canonical COSE key of a fixed P-256 point, as an authenticator writes it.
func canonicalCOSE() []byte {
	x := bytes.Repeat([]byte{0x11}, 32)
	y := bytes.Repeat([]byte{0x22}, 32)
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, y...)
}

// coseDecode refuses, on its own, each encoding its options rule out. The
// canonical re-encoding in matchCOSEKey would refuse these too; this test
// pins the decoder's options so that neither defence can be dropped
// unnoticed. Each input is one that cbor's default decoder accepts.
func TestCOSEDecoderOptions(t *testing.T) {
	k := canonicalCOSE()
	var ok coseEC2
	if rest, err := coseDecode.UnmarshalFirst(k, &ok); err != nil || len(rest) != 0 || ok.Kty != 2 || ok.Alg != -7 || ok.Crv != 1 {
		t.Fatalf("canonical key: %+v rest %x err %v", ok, rest, err)
	}
	for name, in := range map[string][]byte{
		// DupMapKey: kty given twice.
		"duplicate label": append([]byte{0xa6, 0x01, 0x02}, k[1:]...),
		// IndefLength: the map as an indefinite-length one.
		"indefinite-length map": append(append([]byte{0xbf}, k[1:]...), 0xff),
		// TagsMd: x wrapped in tag 64.
		"tag": append(append(append([]byte(nil), k[:8]...), 0xd8, 0x40), k[8:]...),
		// ExtraReturnErrors: a sixth label, 4, that coseEC2 does not have.
		"unknown label": append(append([]byte{0xa6}, k[1:]...), 0x04, 0x01),
	} {
		var lax coseEC2
		if _, err := cbor.UnmarshalFirst(in, &lax); err != nil {
			t.Fatalf("%s: the default decoder refuses it too (%v), so this case pins nothing", name, err)
		}
		var got coseEC2
		if _, err := coseDecode.UnmarshalFirst(in, &got); err == nil {
			t.Errorf("%s: coseDecode accepted %x", name, in)
		}
	}
}

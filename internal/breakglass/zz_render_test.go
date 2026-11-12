package breakglass

import (
	"os"
	"testing"
)

func TestZZRender(t *testing.T) {
	dir := os.Getenv("CARD_OUT")
	if dir == "" {
		t.Skip()
	}
	for _, s := range SizeOrder {
		c := Card{Location: "Angiography Lab 1", App: "NeverDrugs", QR: "https://auth.rch-anaesthesia.org/break/AbCdEfGhIjKlMnOpQrStUv",
			Design: Design{Size: s, Stripe: true, Header: "#003a5c", Accent: "#0b7bbf", Logo: testLogo(t), LogoType: "image/png", LogoMode: LogoWhite, Steps: DefaultSteps}}
		pdf, err := c.PDF()
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(dir+"/card-"+s+".pdf", pdf, 0644)
		os.WriteFile(dir+"/card-"+s+".svg", c.SVG(), 0644)
	}
}

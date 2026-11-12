package breakglass

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// SVG draws the card's layout as a standalone SVG document, sized in
// millimetres. The admin pages show it as the card's preview.
func (c Card) SVG() []byte { return c.Layout().SVG() }

// SVG writes the drawing as an SVG document. Text is placed where the layout
// measured it, with its measured width (textLength), so a browser's choice of
// Helvetica or Arial cannot move a line or let it overflow. Images are
// embedded as data: addresses, so the document needs nothing else.
func (d Drawing) SVG() []byte {
	var b strings.Builder
	f := func(v float64) string { return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", v), "0"), ".") }
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %s %s" width="%smm" height="%smm">`, f(d.W), f(d.H), f(d.W), f(d.H))
	fmt.Fprintf(&b, `<rect width="%s" height="%s" fill="#ffffff"/>`, f(d.W), f(d.H))
	for _, it := range d.Items {
		switch it.Kind {
		case ItemRect:
			fill, stroke := "none", ""
			if it.Fill != nil {
				fill = it.Fill.hex()
			}
			if it.Stroke != nil {
				stroke = fmt.Sprintf(` stroke="%s" stroke-width="%s"`, it.Stroke.hex(), f(it.StrokeW))
			}
			radius := ""
			if it.Radius > 0 {
				radius = fmt.Sprintf(` rx="%s"`, f(it.Radius))
			}
			fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s"%s fill="%s"%s/>`, f(it.X), f(it.Y), f(it.W), f(it.H), radius, fill, stroke)
		case ItemText:
			weight := ""
			if it.Bold {
				weight = ` font-weight="700"`
			}
			fmt.Fprintf(&b, `<text x="%s" y="%s" font-family="Helvetica, Arial, sans-serif" font-size="%s"%s fill="%s" textLength="%s" lengthAdjust="spacingAndGlyphs">%s</text>`,
				f(it.X), f(it.Y), f(it.Size), weight, it.Color.hex(), f(it.W), xmlEscape(it.Text))
		case ItemImage:
			fmt.Fprintf(&b, `<image x="%s" y="%s" width="%s" height="%s" preserveAspectRatio="none" href="data:image/png;base64,%s"/>`,
				f(it.X), f(it.Y), f(it.W), f(it.H), base64.StdEncoding.EncodeToString(it.PNG))
		case ItemQR:
			n := len(it.Modules)
			if n == 0 {
				continue
			}
			// One path in module units, scaled into place; each run of dark
			// modules in a row is one rectangle.
			var p strings.Builder
			for y, row := range it.Modules {
				for x := 0; x < len(row); {
					if !row[x] {
						x++
						continue
					}
					start := x
					for x < len(row) && row[x] {
						x++
					}
					fmt.Fprintf(&p, "M%d %dh%dv1h-%dz", start, y, x-start, x-start)
				}
			}
			fmt.Fprintf(&b, `<g transform="translate(%s %s) scale(%s)"><rect width="%d" height="%d" fill="#ffffff"/><path d="%s" fill="#000000" shape-rendering="crispEdges"/></g>`,
				f(it.X), f(it.Y), f(it.W/float64(n)), n, n, p.String())
		}
	}
	b.WriteString(`</svg>`)
	return []byte(b.String())
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

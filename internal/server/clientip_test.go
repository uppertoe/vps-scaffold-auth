package server

import (
	"net/http"
	"testing"
)

// TestClientIP_TrustsRightmostXFF pins the rate-limit key derivation: Caddy
// appends the real peer as the last X-Forwarded-For element, so the rightmost
// entry is authoritative. A client-supplied (spoofed) leftmost value must be
// ignored, otherwise per-IP rate limits could be bypassed by rotating the header.
func TestClientIP_TrustsRightmostXFF(t *testing.T) {
	tests := []struct {
		name string
		xff  string
		addr string
		want string
	}{
		{"no xff falls back to remote addr", "", "203.0.113.7:54321", "203.0.113.7"},
		{"single entry", "198.51.100.4", "10.0.0.1:9", "198.51.100.4"},
		{"spoofed leftmost, real rightmost", "1.2.3.4, 198.51.100.4", "10.0.0.1:9", "198.51.100.4"},
		{"multiple spoofed entries", "9.9.9.9, 8.8.8.8, 198.51.100.4", "10.0.0.1:9", "198.51.100.4"},
		{"whitespace trimmed", "1.1.1.1,  198.51.100.4 ", "10.0.0.1:9", "198.51.100.4"},
		// A malformed rightmost value means the trusted-proxy contract was broken;
		// fall back to RemoteAddr rather than let an attacker-shaped string become
		// its own rate-limit key (rotating it would defeat per-IP limits).
		{"malformed rightmost falls back to remote addr", "1.2.3.4, not-an-ip", "10.0.0.1:9", "10.0.0.1"},
		{"garbage single xff falls back", "%%garbage%%", "10.0.0.1:9", "10.0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}, RemoteAddr: tc.addr}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(r); got != tc.want {
				t.Fatalf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

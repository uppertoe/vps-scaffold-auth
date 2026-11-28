// Reading single environment values: keys, flags, numbers, durations, rates, lists and network ranges.

package config

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// gethexkey decodes an optional hex-encoded key. Empty yields a nil key; a
// non-empty value must decode to exactly 32 bytes (AES-256).
func gethexkey(key string) ([]byte, error) {
	v := getenv(key, "")
	if v == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return nil, fmt.Errorf("%s: invalid hex: %w", key, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%s: must decode to 32 bytes (got %d)", key, len(b))
	}
	return b, nil
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// distinctBytes counts the distinct byte values in b — a cheap entropy floor
// that rejects degenerate secrets (a single repeated character, short cycles)
// while comfortably passing any real random secret.
func distinctBytes(b []byte) int {
	var seen [256]bool
	n := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
}

// getbool reads a boolean setting. An unset or empty value yields def; a value
// that is not one strconv.ParseBool accepts (true/false, 1/0, t/f, in any
// case) is an error, never the default. TOTP_ENABLED=yes starting the service
// with TOTP silently off is exactly the failure this prevents.
func getbool(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def, fmt.Errorf("%s: %q is not a boolean (use true or false)", key, v)
	}
	return b, nil
}

func getint(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func getdur(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// getrate parses a "count/window" rule such as "5/15m".
func getrate(key string, def RateLimit) (RateLimit, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	parts := strings.SplitN(strings.TrimSpace(v), "/", 2)
	if len(parts) != 2 {
		return RateLimit{}, fmt.Errorf("%s: want COUNT/WINDOW (e.g. 5/15m), got %q", key, v)
	}
	count, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || count < 1 {
		return RateLimit{}, fmt.Errorf("%s: invalid count %q", key, parts[0])
	}
	win, err := time.ParseDuration(strings.TrimSpace(parts[1]))
	if err != nil || win <= 0 {
		return RateLimit{}, fmt.Errorf("%s: invalid window %q", key, parts[1])
	}
	return RateLimit{Count: count, Window: win}, nil
}

// splitLowerList splits on spaces or commas, trims and lowercases, and drops
// empties; for lists of group names.
func splitLowerList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitLowerCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// NetworkNamesAsWritten returns each network's name in NETWORK_RANGES as
// written, by its lower-case name: "RCH=10.0.0.0/8" names "rch" "RCH". It
// reads only the names; ParseNetworkRanges checks the value.
func NetworkNamesAsWritten(v string) map[string]string {
	out := map[string]string{}
	for _, entry := range strings.Split(v, ";") {
		name, _, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if name = strings.TrimSpace(name); ok && name != "" {
			out[strings.ToLower(name)] = name
		}
	}
	return out
}

// ParseNetworkRanges parses NETWORK_RANGES: networks separated by ";", each
// "name=prefix[,prefix...]". A name is lower-case letters, digits, "-" or
// "_". A bare address is read as a single-host prefix. Empty means none.
func ParseNetworkRanges(v string) (map[string][]netip.Prefix, error) {
	out := map[string][]netip.Prefix{}
	for _, entry := range strings.Split(v, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, list, ok := strings.Cut(entry, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || !validNetworkName(name) {
			return nil, fmt.Errorf("NETWORK_RANGES: %q must read name=prefix[,prefix...]", entry)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("NETWORK_RANGES: network %q is listed twice", name)
		}
		var prefixes []netip.Prefix
		for _, raw := range strings.Split(list, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			pfx, err := netip.ParsePrefix(raw)
			if err != nil {
				addr, aerr := netip.ParseAddr(raw)
				if aerr != nil {
					return nil, fmt.Errorf("NETWORK_RANGES: %q in network %q is not an address or prefix", raw, name)
				}
				pfx = netip.PrefixFrom(addr, addr.BitLen())
			}
			// The client address is matched in its IPv4 form, so an
			// IPv4-mapped range (::ffff:a.b.c.d/n) is read as the IPv4 range
			// it names, or it would never match. One shorter than /96 reaches
			// beyond the mapped addresses, and is refused.
			if pfx.Addr().Is4In6() {
				if pfx.Bits() < 96 {
					return nil, fmt.Errorf("NETWORK_RANGES: %q in network %q mixes IPv4-mapped and other IPv6 addresses; write the IPv4 range instead", raw, name)
				}
				pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
			}
			if pfx.Bits() == 0 {
				return nil, fmt.Errorf("NETWORK_RANGES: %q in network %q would admit every address", raw, name)
			}
			prefixes = append(prefixes, pfx.Masked())
		}
		if len(prefixes) == 0 {
			return nil, fmt.Errorf("NETWORK_RANGES: network %q has no prefixes", name)
		}
		out[name] = prefixes
	}
	return out, nil
}

func validNetworkName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

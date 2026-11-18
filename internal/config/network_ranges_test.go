package config

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParseNetworkRanges(t *testing.T) {
	got, err := ParseNetworkRanges(" rch=10.0.0.0/8, 172.16.5.9 ; MCH=10.64.0.0/10,2001:db8::/32;")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]netip.Prefix{
		"rch": {netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.5.9/32")},
		"mch": {netip.MustParsePrefix("10.64.0.0/10"), netip.MustParsePrefix("2001:db8::/32")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	names := NetworkNamesAsWritten(" rch=10.0.0.0/8, 172.16.5.9 ; MCH=10.64.0.0/10,2001:db8::/32;")
	if want := map[string]string{"rch": "rch", "mch": "MCH"}; !reflect.DeepEqual(names, want) {
		t.Errorf("names: got %v, want %v", names, want)
	}
	// An IPv4-mapped range or address is read as the IPv4 one it names, as
	// the client address is.
	mapped, err := ParseNetworkRanges("rch=::ffff:192.168.0.0/112,::ffff:10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("10.1.2.3/32")}; !reflect.DeepEqual(mapped["rch"], want) {
		t.Errorf("mapped: got %v, want %v", mapped["rch"], want)
	}
	if got, err := ParseNetworkRanges(""); err != nil || len(got) != 0 {
		t.Errorf("empty: %v, %v", got, err)
	}
	for _, bad := range []string{
		"10.0.0.0/8",                     // no name
		"rch=",                           // no prefixes
		"rch=10.0.0.0/8;rch=10.1.0.0/16", // a name twice
		"r ch=10.0.0.0/8",                // a bad name
		"rch=not-an-address",             // a bad prefix
		"rch=0.0.0.0/0",                  // everyone
		"rch=::ffff:0.0.0.0/96",          // every IPv4 address
		"rch=::ffff:0:0/80",              // mapped and other IPv6 addresses
	} {
		if _, err := ParseNetworkRanges(bad); err == nil {
			t.Errorf("ParseNetworkRanges(%q) accepted", bad)
		}
	}
}

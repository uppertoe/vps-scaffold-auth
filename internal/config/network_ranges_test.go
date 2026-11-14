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
	} {
		if _, err := ParseNetworkRanges(bad); err == nil {
			t.Errorf("ParseNetworkRanges(%q) accepted", bad)
		}
	}
}

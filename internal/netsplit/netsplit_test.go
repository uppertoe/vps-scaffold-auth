package netsplit

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func ifaces(s ...string) LocalAddrs {
	return func() ([]net.Addr, error) {
		var out []net.Addr
		for _, a := range s {
			_, n, _ := net.ParseCIDR(a)
			ip, _, _ := net.ParseCIDR(a)
			out = append(out, &net.IPNet{IP: ip, Mask: n.Mask})
		}
		return out, nil
	}
}

func resolves(a ...string) Resolver {
	return func(context.Context, string) ([]netip.Addr, error) { return addrs(a...), nil }
}

// The members addresses are the gateway's own among the answers: an address
// another container claimed under the alias is dropped, and loopback never
// counts.
func TestOwnAddrsKeepsOnlyThisHostsAddresses(t *testing.T) {
	got, err := OwnAddrs(context.Background(), "auth-members",
		resolves("172.20.0.2", "172.21.0.3", "172.20.0.9", "127.0.0.1"),
		ifaces("127.0.0.1/8", "172.19.0.4/16", "172.20.0.2/16", "172.21.0.3/16"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != netip.MustParseAddr("172.20.0.2") || got[1] != netip.MustParseAddr("172.21.0.3") {
		t.Fatalf("own addresses = %v", got)
	}
}

// A name that resolves to none of the gateway's addresses, or not at all,
// stops start-up rather than leave the public listener open to every network.
func TestOwnAddrsRefusesANameThatIsNotOurs(t *testing.T) {
	if _, err := OwnAddrs(context.Background(), "auth-members", resolves("172.20.0.9"), ifaces("172.20.0.2/16")); err == nil {
		t.Fatal("a foreign-only answer was accepted")
	}
	fail := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	if _, err := OwnAddrs(context.Background(), "auth-members", fail, ifaces("172.20.0.2/16")); err == nil {
		t.Fatal("a failed lookup was accepted")
	}
}

// The public listener closes a connection that arrived on a members address
// and serves one that arrived on any other.
func TestRefusingClosesMembersConnections(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	served := make(chan net.Conn, 1)
	go func() {
		c, err := Refusing(l, NewSet(addrs("127.0.0.1"))).Accept()
		if err == nil {
			served <- c
		}
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection on a refused address was kept open")
	}
	select {
	case <-served:
		t.Fatal("a connection on a refused address was served")
	default:
	}

	ok, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Close()
	go func() {
		c, err := Refusing(ok, NewSet(addrs("172.20.0.2"))).Accept()
		if err == nil {
			served <- c
		}
	}()
	d, err := net.Dial("tcp", ok.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	select {
	case c := <-served:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("a connection on another address was not served")
	}
}

// Package netsplit keeps the gateway's two listeners on their own networks.
//
// The gateway shares a Docker network with Caddy, and, when apps read group
// members, one more network with each such app. Docker gives the gateway an
// address on every network it joins, and a listener bound to all of them
// answers on each. An app on its members network could then reach the public
// listener directly, past Caddy: it would set X-Forwarded-For, Origin and the
// policy header itself, and its requests would never reach Caddy's log.
//
// The members networks are told apart by a name the scaffold gives the
// gateway on each of them (an alias such as auth-members), which is the host
// in MEMBERS_LISTEN_ADDR. At start-up the gateway resolves that name and keeps
// the addresses that are its own. The members listener binds to those
// addresses alone, and the public listener refuses any connection that
// arrives on one of them.
package netsplit

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Resolver looks a host name up, as net.Resolver.LookupNetIP does.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// LocalAddrs lists the addresses of this host's interfaces, as
// net.InterfaceAddrs does.
type LocalAddrs func() ([]net.Addr, error)

// OwnAddrs resolves host and returns the addresses among the answers that
// belong to this host. An address another container has claimed under the
// same name is never one of this host's own, so it is dropped. An empty
// result is an error: the members listener would have nothing to bind to,
// and the public listener nothing to refuse.
func OwnAddrs(ctx context.Context, host string, resolve Resolver, local LocalAddrs) ([]netip.Addr, error) {
	answers, err := resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	ifaces, err := local()
	if err != nil {
		return nil, fmt.Errorf("list interface addresses: %w", err)
	}
	mine := map[netip.Addr]bool{}
	for _, a := range ifaces {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			mine[p.Addr().Unmap()] = true
		} else if ip, err := netip.ParseAddr(a.String()); err == nil {
			mine[ip.Unmap()] = true
		}
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, a := range answers {
		a = a.Unmap()
		if mine[a] && !a.IsLoopback() && !a.IsUnspecified() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%q names none of this host's own addresses (answers %v)", host, answers)
	}
	return out, nil
}

// Set is a fixed set of addresses.
type Set map[netip.Addr]bool

// NewSet builds a Set.
func NewSet(addrs []netip.Addr) Set {
	s := Set{}
	for _, a := range addrs {
		s[a.Unmap()] = true
	}
	return s
}

// Has reports whether the connection's local address is in the set.
func (s Set) Has(local net.Addr) bool {
	ap, err := netip.ParseAddrPort(local.String())
	if err != nil {
		return false
	}
	return s[ap.Addr().Unmap()]
}

// Refusing wraps a listener so that it closes, unanswered, every connection
// whose local address is in refuse: a connection that arrived on a members
// network. Refusals are logged at most once a minute.
func Refusing(l net.Listener, refuse Set) net.Listener {
	return &refusing{Listener: l, refuse: refuse}
}

type refusing struct {
	net.Listener
	refuse Set
	mu     sync.Mutex
	logged time.Time
	count  int
}

func (r *refusing) Accept() (net.Conn, error) {
	for {
		c, err := r.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !r.refuse.Has(c.LocalAddr()) {
			return c, nil
		}
		r.note(c.RemoteAddr())
		c.Close()
	}
}

func (r *refusing) note(from net.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	if time.Since(r.logged) < time.Minute {
		return
	}
	log.Printf("refused %d connection(s) to the public listener from a members network (last from %s)", r.count, from)
	r.logged, r.count = time.Now(), 0
}

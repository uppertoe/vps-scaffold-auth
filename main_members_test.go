package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
)

// The gateway's address on a members network, under the alias auth-members.
var membersAddr = netip.MustParseAddr("10.9.0.5")

func ownLocal() ([]net.Addr, error) {
	return []net.Addr{&net.IPNet{IP: net.ParseIP("10.9.0.5"), Mask: net.CIDRMask(24, 32)}, &net.IPNet{IP: net.ParseIP("172.18.0.3"), Mask: net.CIDRMask(16, 32)}}, nil
}

func resolveTo(addrs ...netip.Addr) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) {
		if len(addrs) == 0 {
			return nil, errors.New("no such host")
		}
		return addrs, nil
	}
}

// fakeListen records the addresses bound and returns a real loopback
// listener in their place.
func fakeListen(t *testing.T, bound *[]string) func(string, string) (net.Listener, error) {
	return func(network, addr string) (net.Listener, error) {
		*bound = append(*bound, addr)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			t.Cleanup(func() { ln.Close() })
		}
		return ln, err
	}
}

func publicListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// splitMembers wraps the public listener whenever the members alias names one
// of the gateway's own addresses, whatever the state of the readers (the
// wrapper's refusals are proven in internal/netsplit). Only MEMBER_READERS
// makes a failure fatal.
func TestSplitMembers(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg        config.Config
		resolve    func(context.Context, string) ([]netip.Addr, error)
		wantErr    bool
		wantRefuse bool
		wantBound  []string
		wantLog    string
	}{
		// An alias naming every address names Caddy's too: never refuse
		// there, never bind, never stop, whatever the settings.
		"neither setting, alias names every address": {
			cfg:     config.Config{MembersAlias: "auth"},
			resolve: resolveTo(membersAddr, netip.MustParseAddr("172.18.0.3")), wantLog: "names every one of the gateway's addresses",
		},
		"file only, alias names every address": {
			cfg:     config.Config{MembersAlias: "auth", MembersListenAddr: "auth:8081", MembersReadersSet: true},
			resolve: resolveTo(membersAddr, netip.MustParseAddr("172.18.0.3")), wantLog: "names every one of the gateway's addresses",
		},
		"env, alias names every address": {
			cfg:     config.Config{MembersAlias: "auth", MembersListenAddr: "auth:8081", MembersReadersSet: true, MembersRequired: true},
			resolve: resolveTo(membersAddr, netip.MustParseAddr("172.18.0.3")), wantLog: "names every one of the gateway's addresses",
		},
		"off": {
			cfg: config.Config{}, resolve: resolveTo(membersAddr),
		},
		// Neither setting is set, but the gateway is on a members network
		// (the scaffold joined it): the public listener still refuses there.
		"neither setting, alias resolves": {
			cfg:     config.Config{MembersAlias: "auth-members"},
			resolve: resolveTo(membersAddr), wantRefuse: true,
		},
		"neither setting, no members network": {
			cfg:     config.Config{MembersAlias: "auth-members"},
			resolve: resolveTo(),
		},
		"file only, alias resolves": {
			cfg:     config.Config{MembersAlias: "auth-members", MembersListenAddr: "auth-members:8081", MembersReadersSet: true},
			resolve: resolveTo(membersAddr), wantRefuse: true, wantBound: []string{"10.9.0.5:8081"},
		},
		"file only, bad address": {
			// config logged the address and left MembersListenAddr empty.
			cfg:     config.Config{MembersAlias: "auth-members", MembersReadersSet: true},
			resolve: resolveTo(membersAddr), wantRefuse: true,
		},
		"file only, alias names another container": {
			cfg:     config.Config{MembersAlias: "auth-members", MembersListenAddr: "auth-members:8081", MembersReadersSet: true},
			resolve: resolveTo(netip.MustParseAddr("10.9.0.9")),
		},
		"file only, alias does not resolve": {
			cfg:     config.Config{MembersAlias: "auth-members", MembersListenAddr: "auth-members:8081", MembersReadersSet: true},
			resolve: resolveTo(),
		},
		"env, alias names another container": {
			cfg:     config.Config{MembersAlias: "auth-members", MembersListenAddr: "auth-members:8081", MembersRequired: true, MembersReadersSet: true},
			resolve: resolveTo(netip.MustParseAddr("10.9.0.9")), wantErr: true,
		},
		"env, alias resolves": {
			cfg:     config.Config{MembersAlias: "auth-members", MembersListenAddr: "auth-members:8081", MembersRequired: true, MembersReadersSet: true},
			resolve: resolveTo(membersAddr), wantRefuse: true, wantBound: []string{"10.9.0.5:8081"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			log.SetOutput(&logs)
			defer log.SetOutput(os.Stderr)
			pub := publicListener(t)
			var bound []string
			got, lns, err := splitMembers(context.Background(), &tc.cfg, pub, tc.resolve, ownLocal, fakeListen(t, &bound))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if (got != pub) != tc.wantRefuse {
				t.Errorf("public listener wrapped = %v, want %v", got != pub, tc.wantRefuse)
			}
			if strings.Join(bound, " ") != strings.Join(tc.wantBound, " ") || len(lns) != len(tc.wantBound) {
				t.Errorf("bound %v (%d listeners), want %v", bound, len(lns), tc.wantBound)
			}
			if tc.wantLog != "" && !strings.Contains(logs.String(), "ERROR members endpoint: \""+tc.cfg.MembersAlias+"\" "+tc.wantLog) {
				t.Errorf("log = %q", logs.String())
			}
		})
	}
}

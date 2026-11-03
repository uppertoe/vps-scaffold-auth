package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/ratelimit"
)

// The members endpoint lets an app ask who is in a group, for work it does
// outside a request (a weekly digest to the coordinators, say), so that group
// membership is kept in the gateway and nowhere else.
//
// It is served on its own listener (MEMBERS_LISTEN_ADDR), which Caddy never
// proxies, so only containers on the server's Docker network can reach it.
// Each app has its own bearer token and may read only the groups listed for
// it in MEMBER_READERS. The answer is the members the gateway applies now,
// through includes, less any address the allow-list does not admit: a guest
// member is told about the group when signed in, but is never reported here
// (the owner's choice, 2026-11-03).

// memberReader is a configured app, with its token hashed for comparison.
type memberReader struct {
	app    string
	hash   [32]byte
	groups []string
}

type membersAPI struct {
	readers []memberReader
	// perApp bounds how often one app may read; perIP bounds requests that
	// arrive without a valid token.
	perApp, perIP *ratelimit.Limiter
}

func newMembersAPI(readers []config.MemberReader) *membersAPI {
	api := &membersAPI{
		perApp: ratelimit.New(120, time.Minute),
		perIP:  ratelimit.New(30, time.Minute),
	}
	for _, r := range readers {
		api.readers = append(api.readers, memberReader{app: r.App, hash: sha256.Sum256([]byte(r.Token)), groups: r.Groups})
	}
	return api
}

// reader returns the app a bearer token belongs to. Every configured token is
// compared, in constant time, whatever matches first.
func (a *membersAPI) reader(token string) (memberReader, bool) {
	h := sha256.Sum256([]byte(token))
	var found memberReader
	ok := false
	for _, r := range a.readers {
		if subtle.ConstantTimeCompare(h[:], r.hash[:]) == 1 {
			found, ok = r, true
		}
	}
	return found, ok
}

// MembersHandler serves the members endpoint. It is mounted on its own
// listener by main, never on the one Caddy proxies.
func (s *Server) MembersHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/groups/{group}/members", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			membersError(w, http.StatusMethodNotAllowed, "only GET is served")
			return
		}
		s.handleGroupMembers(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		membersError(w, http.StatusNotFound, "not found")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only a container on the server's own network may ask. A port
		// published by mistake (compose "ports:") keeps the caller's public
		// address through Docker's NAT, so this refuses it; the token is the
		// boundary between containers on the network.
		if !privateSource(r.RemoteAddr) {
			log.Printf("members: refused a request from outside the private network (%s)", r.RemoteAddr)
			membersError(w, http.StatusForbidden, "this endpoint answers only the server's own network")
			return
		}
		// A request carrying forwarding headers went through a proxy, which
		// no app on the network needs; refuse it as a second sign of a
		// wiring mistake.
		for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-Ip"} {
			if r.Header.Get(h) != "" {
				log.Printf("members: refused a proxied request (%s) from %s", h, r.RemoteAddr)
				membersError(w, http.StatusForbidden, "this endpoint is not served through a proxy")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) handleGroupMembers(w http.ResponseWriter, r *http.Request) {
	api := s.members
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	token, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	reader, ok := api.reader(strings.TrimSpace(token))
	if !hasBearer || !ok {
		if !api.perIP.Allow(ip) {
			membersError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		log.Printf("members: refused a request with no valid token from %s", ip)
		w.Header().Set("WWW-Authenticate", `Bearer realm="members"`)
		membersError(w, http.StatusUnauthorized, "a valid bearer token is required")
		return
	}
	if !api.perApp.Allow(reader.app) {
		membersError(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	group := normalizeGroupName(r.PathValue("group"))
	// A group the app may not read and a group that does not exist get the
	// same answer, so an app cannot learn which groups exist.
	const notPermitted = "this app may not read that group, or the group does not exist"
	if !slices.Contains(reader.groups, group) {
		log.Printf("members: %s asked for %q, which it may not read", reader.app, group)
		membersError(w, http.StatusForbidden, notPermitted)
		return
	}
	all, exists, err := s.store.GroupMembersResolved(r.Context(), group)
	if err != nil {
		log.Printf("members: %s reading %q: %v", reader.app, group, err)
		membersError(w, http.StatusInternalServerError, "the members could not be read")
		return
	}
	if !exists {
		membersError(w, http.StatusForbidden, notPermitted)
		return
	}
	// Only people the allow-list admits: they are the ones the gateway
	// signs in as members. A membership kept for an address the allow-list
	// no longer admits is not reported.
	members := make([]string, 0, len(all))
	for _, e := range all {
		if s.policy.Allowed(e) {
			members = append(members, e)
		}
	}
	now := s.now()
	if err := s.store.RecordMemberRead(r.Context(), reader.app, group, ip, now); err != nil {
		// The audit is part of the contract: no record, no answer.
		log.Printf("members: recording %s reading %q: %v", reader.app, group, err)
		membersError(w, http.StatusInternalServerError, "the members could not be read")
		return
	}
	writeMembersJSON(w, http.StatusOK, map[string]any{
		"group":   group,
		"members": members,
		"as_of":   now.UTC().Format(time.RFC3339),
	})
}

// privateSource reports whether a remote address is loopback or private
// (RFC 1918, or an IPv6 unique local address), as every Docker network is.
func privateSource(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func membersError(w http.ResponseWriter, status int, msg string) {
	writeMembersJSON(w, status, map[string]string{"error": msg})
}

func writeMembersJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

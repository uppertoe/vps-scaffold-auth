package breakglass

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/email"
)

// stalledSender blocks until its context ends, like a relay that never answers.
type stalledSender struct{}

func (stalledSender) Send(ctx context.Context, _ email.Message) error {
	<-ctx.Done()
	return ctx.Err()
}

// A stalled mail relay must not delay or starve the webhook: the two channels
// have independent deadlines and run independently.
func TestWebhookDeliversWhileEmailStalls(t *testing.T) {
	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := NewNotifier(stalledSender{}, []string{"oncall@example.com"}, srv.URL, time.Second)
	n.blocked = func(net.IP) bool { return false } // the test server is on loopback
	n.Notify(UseEvent{Label: "Lab 1", TargetGroup: "g1", Outcome: "granted", Time: time.Now()})

	select {
	case <-hit:
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was not delivered while email stalled")
	}
}

// A webhook whose hostname resolves to a blocked address is never connected
// to, even though the literal-address check at the settings form cannot see
// through the name. The test server listens on loopback; "localhost" resolves
// there, and the default guard refuses it.
func TestWebhookRefusesNameResolvingToBlockedAddress(t *testing.T) {
	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- struct{}{}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	byName := "http://" + strings.Replace(u.Host, "127.0.0.1", "localhost", 1)

	n := NewNotifier(nil, nil, byName, time.Second)
	n.Notify(UseEvent{Label: "Lab 1", Time: time.Now()})
	select {
	case <-hit:
		t.Fatal("webhook reached a blocked destination through a hostname")
	case <-time.After(1500 * time.Millisecond):
	}
}

// A redirect is not followed: the destination that was checked is the only one
// connected to.
func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	hit := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- r.URL.Path
		if r.URL.Path == "/hook" {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
		}
	}))
	defer srv.Close()
	n := NewNotifier(nil, nil, srv.URL+"/hook", time.Second)
	n.blocked = func(net.IP) bool { return false }
	n.Notify(UseEvent{Label: "Lab 1", Time: time.Now()})
	if p := <-hit; p != "/hook" {
		t.Fatalf("first request path = %q", p)
	}
	select {
	case p := <-hit:
		t.Fatalf("redirect was followed to %q", p)
	case <-time.After(time.Second):
	}
}

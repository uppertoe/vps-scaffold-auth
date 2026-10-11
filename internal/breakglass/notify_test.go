package breakglass

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	n.Notify(UseEvent{Label: "Lab 1", TargetGroup: "g1", Outcome: "granted", Time: time.Now()})

	select {
	case <-hit:
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was not delivered while email stalled")
	}
}

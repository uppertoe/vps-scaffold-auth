package breakglass

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/email"
)

// UseEvent describes a single break-glass use for notification purposes.
type UseEvent struct {
	Label       string    `json:"label"`
	TargetGroup string    `json:"group"`
	Outcome     string    `json:"outcome"`
	ClientIP    string    `json:"client_ip"`
	UserAgent   string    `json:"user_agent"`
	Time        time.Time `json:"time"`
}

// Notifier delivers break-glass use-notifications to administrators via email
// and/or an optional webhook. Delivery is best-effort and must never block the
// scan request, so call Notify, which fans out on its own goroutine.
type Notifier struct {
	sender         email.Sender
	recipients     []string
	webhookURL     string
	webhookTimeout time.Duration
	httpClient     *http.Client
}

// NewNotifier builds a Notifier. sender and recipients may be empty (no email);
// webhookURL may be empty (no webhook).
func NewNotifier(sender email.Sender, recipients []string, webhookURL string, webhookTimeout time.Duration) *Notifier {
	if webhookTimeout <= 0 {
		webhookTimeout = 5 * time.Second
	}
	return &Notifier{
		sender:         sender,
		recipients:     recipients,
		webhookURL:     webhookURL,
		webhookTimeout: webhookTimeout,
		httpClient:     &http.Client{Timeout: webhookTimeout},
	}
}

// Notify delivers ev asynchronously. It returns immediately; failures are
// logged, not surfaced, so an emergency grant is never delayed or blocked by a
// slow mail server or webhook.
func (n *Notifier) Notify(ev UseEvent) {
	if n == nil {
		return
	}
	go func() {
		// Detached context: the request that triggered this has already been
		// answered, so r.Context() would be canceled.
		ctx, cancel := context.WithTimeout(context.Background(), n.webhookTimeout+2*time.Second)
		defer cancel()
		n.sendEmails(ctx, ev)
		n.sendWebhook(ctx, ev)
	}()
}

func (n *Notifier) sendEmails(ctx context.Context, ev UseEvent) {
	if n.sender == nil || len(n.recipients) == 0 {
		return
	}
	subject := fmt.Sprintf("Break-glass used: %s", ev.Label)
	text := fmt.Sprintf(
		"A break-glass code was used.\n\nLocation: %s\nGroup granted: %s\nOutcome: %s\nClient IP: %s\nUser agent: %s\nTime: %s\n",
		ev.Label, ev.TargetGroup, ev.Outcome, ev.ClientIP, ev.UserAgent, ev.Time.UTC().Format(time.RFC3339))
	for _, to := range n.recipients {
		msg := email.Message{To: to, Subject: subject, Text: text}
		if err := n.sender.Send(ctx, msg); err != nil {
			log.Printf("breakglass notify: email to %s: %v", to, err)
		}
	}
}

func (n *Notifier) sendWebhook(ctx context.Context, ev UseEvent) {
	if n.webhookURL == "" {
		return
	}
	body, err := json.Marshal(ev)
	if err != nil {
		log.Printf("breakglass notify: marshal: %v", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("breakglass notify: build webhook request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.httpClient.Do(req)
	if err != nil {
		log.Printf("breakglass notify: webhook POST: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("breakglass notify: webhook returned %s", resp.Status)
	}
}

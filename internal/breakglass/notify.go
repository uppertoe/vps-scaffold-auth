package breakglass

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
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
	// blocked decides which resolved webhook addresses may not be dialled.
	blocked func(net.IP) bool
}

// NewNotifier builds a Notifier. sender and recipients may be empty (no email);
// webhookURL may be empty (no webhook).
func NewNotifier(sender email.Sender, recipients []string, webhookURL string, webhookTimeout time.Duration) *Notifier {
	if webhookTimeout <= 0 {
		webhookTimeout = 5 * time.Second
	}
	n := &Notifier{
		sender:         sender,
		recipients:     recipients,
		webhookURL:     webhookURL,
		webhookTimeout: webhookTimeout,
		blocked:        blockedWebhookIP,
	}
	// One notifier is built per event, so its transport is one-shot: keep-
	// alives are off and the connection is closed once the delivery is done,
	// otherwise every completed delivery would leave an idle connection (and
	// its goroutines) behind until the receiver dropped it.
	n.httpClient = &http.Client{
		Timeout: webhookTimeout,
		Transport: &http.Transport{
			DialContext:         n.dialGuarded,
			TLSHandshakeTimeout: webhookTimeout,
			DisableKeepAlives:   true,
			MaxIdleConns:        1,
			IdleConnTimeout:     time.Second,
		},
		// A redirect could point an otherwise acceptable destination at a
		// blocked one. The 3xx is returned as the response and logged instead.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return n
}

// blockedWebhookIP reports whether a resolved webhook address must not be
// connected to: loopback, link-local (cloud metadata), unspecified and
// multicast. Private ranges are intentionally allowed, since notifications
// legitimately target internal services on this stack. The admin settings
// form checks a literal address the same way; this check runs on what the
// hostname actually resolves to, at connection time, so a name that points
// at a blocked address is refused as well.
func blockedWebhookIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast()
}

// dialGuarded resolves the host, drops blocked addresses, and dials the first
// acceptable one. Dialling the resolved address directly means the check and
// the connection see the same answer.
func (n *Notifier) dialGuarded(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: n.webhookTimeout}
	var lastErr error
	for _, ip := range ips {
		if n.blocked(ip.IP) {
			lastErr = fmt.Errorf("webhook host %s resolves to a blocked address %s", host, ip.IP)
			continue
		}
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("webhook host %s has no address", host)
	}
	return nil, lastErr
}

// Notify delivers ev asynchronously. It returns immediately; failures are
// logged, not surfaced, so an emergency grant is never delayed or blocked by a
// slow mail server or webhook.
func (n *Notifier) Notify(ev UseEvent) {
	if n == nil {
		return
	}
	// Each channel runs on its own goroutine with its own deadline, so a slow
	// mail relay cannot consume the webhook's time (or the reverse): the
	// webhook is the channel that pages someone, and it must not wait behind
	// email. Contexts are detached from the request, which has already been
	// answered.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), emailTimeout)
		defer cancel()
		n.sendEmails(ctx, ev)
	}()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), n.webhookTimeout+2*time.Second)
		defer cancel()
		n.sendWebhook(ctx, ev)
	}()
}

// emailTimeout bounds the whole email fan-out for one event.
const emailTimeout = 30 * time.Second

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
	req.Close = true
	defer n.httpClient.CloseIdleConnections()
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

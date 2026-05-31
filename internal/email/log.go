package email

import (
	"context"
	"log"
)

// LogSender writes messages to the process log instead of sending them. It is
// for local development and CI end-to-end tests, where the OTP code is read
// back from the container logs. Never use in production.
type LogSender struct{}

// Send logs the message (including the body that carries the code).
func (s *LogSender) Send(ctx context.Context, msg Message) error {
	log.Printf("[email:log] to=%s subject=%q text=%q", msg.To, msg.Subject, msg.Text)
	return nil
}

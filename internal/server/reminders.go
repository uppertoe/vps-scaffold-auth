package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Reminders before a role ends. Seven days before a person's role ends, the
// person and the administrator who gave it are emailed, once: the store
// records each reminder by assignment and end date, so a restart sends
// nothing twice, and an extended role is reminded again before its new end.

// reminderLead is how long before the end a reminder is sent, and
// reminderEvery how often the gateway looks.
const (
	reminderLead  = 7 * 24 * time.Hour
	reminderEvery = time.Hour
)

// The reminders' strings, approved on 13 November 2026.
const (
	msgEndsPersonSubject = "Your access to %s ends on %s."
	msgEndsPersonBody    = "Your access to %s as %s ends on %s. If you still need it after that date, you can ask %s to extend it.\n"
	msgEndsAdminSubject  = "Access for %s ends on %s."
	msgEndsAdminBody     = "%s holds %s in %s until %s. You can extend it on the app's page.\n\n%s\n"
	msgEndsNoAdmin       = "an administrator"
)

// StartReminders checks for roles about to end shortly after start and then
// every reminderEvery, until ctx ends. It does nothing with the app-roles
// model off.
func (s *Server) StartReminders(ctx context.Context) {
	if !s.rolesOn() {
		return
	}
	go func() {
		t := time.NewTimer(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			s.sendReminders(ctx)
			t.Reset(reminderEvery)
		}
	}()
}

// sendReminders emails the reminder for every person assignment that ends
// within reminderLead and has not been reminded yet. Each reminder is
// recorded before it is sent, so a failure to send is logged and not
// retried, rather than risking a second email.
func (s *Server) sendReminders(ctx context.Context) {
	now := s.now()
	as, err := s.store.ListRoleAssignments(ctx, "")
	if err != nil {
		log.Printf("reminders: reading assignments: %v", err)
		return
	}
	for _, a := range as {
		if a.Kind != store.AssignPerson || a.Until.IsZero() || !now.Before(a.Until) || a.Until.Sub(now) > reminderLead {
			continue
		}
		app, ok := s.appRoles.Apps[a.App]
		if !ok {
			continue
		}
		if _, declared := app.Roles[a.Role]; !declared {
			continue
		}
		first, err := s.store.MarkReminderSent(ctx, a.App, a.Role, a.Ref, a.Until, now)
		if err != nil {
			log.Printf("reminders: recording the reminder to %s: %v", a.Ref, err)
			continue
		}
		if !first {
			continue
		}
		for _, m := range s.reminderEmails(a) {
			msg := m
			s.sendNotice("reminder to "+msg.To, func(ctx context.Context) error { return s.sender.Send(ctx, msg) })
		}
	}
}

// reminderEmails are the two emails before an assignment ends: to the person,
// and to the administrator who gave the role, when there is one.
func (s *Server) reminderEmails(a store.RoleAssignment) []email.Message {
	app := s.appRoles.Apps[a.App]
	ends := s.longDate(a.Until.Add(-time.Second))
	role := roleLabel(app, a.Role)
	by := a.CreatedBy
	if by == "" {
		by = msgEndsNoAdmin
	}
	out := []email.Message{{
		To:      a.Ref,
		Subject: fmt.Sprintf(msgEndsPersonSubject, app.Label, ends),
		Text:    fmt.Sprintf(msgEndsPersonBody, app.Label, role, ends, by),
	}}
	if a.CreatedBy != "" && strings.Contains(a.CreatedBy, "@") && a.CreatedBy != a.Ref {
		out = append(out, email.Message{
			To:      a.CreatedBy,
			Subject: fmt.Sprintf(msgEndsAdminSubject, a.Ref, ends),
			Text:    fmt.Sprintf(msgEndsAdminBody, a.Ref, role, app.Label, ends, s.cfg.PublicURL+"/admin/apps/"+a.App),
		})
	}
	return out
}

// Package server wires the HTTP endpoints that implement the email-OTP
// forward_auth flow: the /verify endpoint Caddy calls on every request, and the
// login pages users interact with.
package server

import (
	"net/http"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/ratelimit"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Server holds the dependencies shared by all handlers.
type Server struct {
	cfg          *config.Config
	store        store.Store
	sender       email.Sender
	sessions     *session.Manager
	policy       *authz.Policy
	emailLimiter *ratelimit.Limiter
	ipLimiter    *ratelimit.Limiter
	pages        pages
	handler      http.Handler
	now          func() time.Time
}

// New constructs a Server from its dependencies.
func New(cfg *config.Config, st store.Store, sender email.Sender) (*Server, error) {
	tmpls, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:          cfg,
		store:        st,
		sender:       sender,
		sessions:     session.NewManager(cfg.SessionSecret, cfg.SessionTTL, cfg.SessionRenew, cfg.CookieDomain, !cfg.CookieInsecure),
		policy:       authz.NewPolicy(cfg.AllowedDomains, cfg.AdminEmails),
		emailLimiter: ratelimit.New(cfg.RateLimitPerEmail.Count, cfg.RateLimitPerEmail.Window),
		ipLimiter:    ratelimit.New(cfg.RateLimitPerIP.Count, cfg.RateLimitPerIP.Window),
		pages:        tmpls,
		now:          time.Now,
	}
	s.handler = s.routes()
	return s, nil
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /verify", s.handleVerify)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /request", s.handleRequest)
	mux.HandleFunc("POST /verify-code", s.handleVerifyCode)
	mux.HandleFunc("POST /totp", s.handleTOTP)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /", s.handleRoot)
	return securityHeaders(mux)
}

// securityHeaders applies conservative defaults to every response. The pages
// use only inline styles and no scripts, so the CSP can be very tight.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

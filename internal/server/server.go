// Package server wires the HTTP endpoints that implement the email-OTP
// forward_auth flow: the /verify endpoint Caddy calls on every request, and the
// login pages users interact with.
package server

import (
	"net/http"
	texttemplate "text/template"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/ratelimit"
	"github.com/uppertoe/vps-scaffold-auth/internal/secretbox"
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
	secrets      *secretbox.Box
	emailLimiter *ratelimit.Limiter
	ipLimiter    *ratelimit.Limiter
	pages        pages
	adminPages   pages
	emailTmpl    *texttemplate.Template
	handler      http.Handler
	now          func() time.Time
}

// New constructs a Server from its dependencies.
func New(cfg *config.Config, st store.Store, sender email.Sender) (*Server, error) {
	tmpls, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	adminTmpls, err := loadAdminTemplates()
	if err != nil {
		return nil, err
	}
	emailTmpl, err := loadEmailTemplate()
	if err != nil {
		return nil, err
	}
	secrets, err := secretbox.NewFromConfig(cfg.SessionSecret, cfg.DataEncryptionKey)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:          cfg,
		store:        st,
		sender:       sender,
		sessions:     session.NewManager(cfg.SessionSecret, cfg.SessionTTL, cfg.SessionRenew, cfg.CookieDomain, !cfg.CookieInsecure),
		policy:       authz.NewPolicy(cfg.AllowedDomains, cfg.AdminEmails),
		secrets:      secrets,
		emailLimiter: ratelimit.New(cfg.RateLimitPerEmail.Count, cfg.RateLimitPerEmail.Window),
		ipLimiter:    ratelimit.New(cfg.RateLimitPerIP.Count, cfg.RateLimitPerIP.Window),
		pages:        tmpls,
		adminPages:   adminTmpls,
		emailTmpl:    emailTmpl,
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
	mux.HandleFunc("GET /denied", s.handleDenied)
	mux.HandleFunc("GET /break/{token}", s.handleBreakGlass)
	mux.HandleFunc("GET /logo.img", s.handleLogo)

	// Admin subtree: one gate wraps the whole /admin/ tree. The inner mux
	// matches on the full path, so no prefix stripping is needed.
	admin := http.NewServeMux()
	s.adminRoutes(admin)
	mux.Handle("/admin/", s.requireAdmin(admin))
	// Bare /admin (no trailing slash) redirects into the gated subtree.
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})

	// Catch-all (all methods) so it doesn't conflict with the /admin/ subtree
	// pattern under the Go 1.22 mux precedence rules.
	mux.HandleFunc("/", s.handleRoot)
	return securityHeaders(mux)
}

// cspPolicy is the single Content-Security-Policy applied to every HTML
// response (login and admin alike). It allows same-origin images (the optional
// branding logo and admin QR previews) and inline styles, but forbids scripts
// and all other resource types. Served images override this with an even
// stricter sandbox policy (see writeImage).
const cspPolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// securityHeaders applies conservative defaults to every response. The pages
// use only inline styles and no scripts, so the CSP can be very tight.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", cspPolicy)
		next.ServeHTTP(w, r)
	})
}

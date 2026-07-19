// Package server wires the HTTP endpoints that implement the email-OTP
// forward_auth flow: the /verify endpoint Caddy calls on every request, and the
// login pages users interact with.
package server

import (
	"log"
	"net/http"
	"strings"
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
	breakLimiter *ratelimit.Limiter // per-IP limiter for break-glass scans
	totpReplay   *totpReplay
	access       *accessAudit
	csp          string // precomputed Content-Security-Policy (see cspPolicy)
	pages        pages
	adminPages   pages
	emailTmpl    *texttemplate.Template
	handler      http.Handler
	now          func() time.Time
	loc          *time.Location // timezone for rendering timestamps in the admin UI
}

// New constructs a Server from its dependencies.
func New(cfg *config.Config, st store.Store, sender email.Sender) (*Server, error) {
	loc := cfg.DisplayLocation
	if loc == nil {
		loc = time.UTC
	}
	tmpls, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	adminTmpls, err := loadAdminTemplates(loc)
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
		breakLimiter: newBreakLimiter(cfg),
		access:       newAccessAudit(st, cfg.AuditRetention),
		csp:          cspPolicy(cfg.Domain),
		pages:        tmpls,
		adminPages:   adminTmpls,
		emailTmpl:    emailTmpl,
		now:          time.Now,
		loc:          loc,
	}
	// Anti-replay reads the clock through s.now so tests sharing a fake clock stay
	// consistent with the rest of the server.
	s.totpReplay = newTOTPReplay(func() time.Time { return s.now() })
	if s.policy.OpenRegistration() {
		log.Printf("authz: OPEN REGISTRATION enabled (ALLOWED_EMAIL_DOMAINS contains %q): any email verified by one-time code is admitted as a user. Private apps behind this auth must gate by group or domain, not a bare `import protected`.", authz.Wildcard)
	}
	s.handler = s.routes()
	return s, nil
}

// newBreakLimiter builds the per-IP limiter for break-glass scans. It uses the
// dedicated RATELIMIT_BREAKGLASS_PER_IP rule, falling back to the login per-IP
// rule if that is unset (e.g. a hand-built config), so it is never a zero-count
// limiter that would deny every emergency scan.
func newBreakLimiter(cfg *config.Config) *ratelimit.Limiter {
	rl := cfg.RateLimitBreakGlassPerIP
	if rl.Count <= 0 || rl.Window <= 0 {
		rl = cfg.RateLimitPerIP
	}
	return ratelimit.New(rl.Count, rl.Window)
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
	mux.HandleFunc("GET /logout", s.handleLogoutConfirm)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /denied", s.handleDenied)
	mux.HandleFunc("GET /welcome", s.handleWelcome)
	mux.HandleFunc("GET /break/{token}", s.handleBreakGlass)
	mux.HandleFunc("POST /break/activate", s.handleBreakGlassActivate)
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
	return s.securityHeaders(mux)
}

// cspPolicy builds the single Content-Security-Policy applied to every HTML
// response (login and admin alike). It allows same-origin images (the optional
// branding logo and admin QR previews) and inline styles, but forbids scripts
// and all other resource types. Served images override this with an even
// stricter sandbox policy (see writeImage).
//
// form-action permits 'self' plus the deployment's own app subdomains
// (https://*.<domain>). A successful login POST 302-redirects to the destination
// app, which is always a *different* subdomain than the auth host — and Chrome,
// Safari, and newer Firefox silently refuse to follow a form-submission redirect
// whose target isn't listed in form-action, stranding a freshly-authenticated
// user on the auth host. The permitted set mirrors exactly what servedTarget
// already allows as a post-login destination (subdomains of cfg.Domain); an
// off-domain form post stays blocked.
func cspPolicy(domain string) string {
	formAction := "'self'"
	if d := strings.TrimPrefix(domain, "."); d != "" {
		formAction += " https://*." + d
	}
	return "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action " + formAction + "; base-uri 'none'; frame-ancestors 'none'"
}

// securityHeaders applies conservative defaults to every response. The pages
// use only inline styles and no scripts, so the CSP can be very tight.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", s.csp)
		// Pin HTTPS for the auth host and the whole subdomain estate it sits over.
		// Skipped in dev (CookieInsecure: plain HTTP), where an HSTS pin would make
		// the host unreachable without TLS.
		if !s.cfg.CookieInsecure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

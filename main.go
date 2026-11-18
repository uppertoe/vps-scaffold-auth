// Command vps-scaffold-auth is a minimal email-OTP forward_auth gateway. It
// sits behind Caddy: Caddy calls GET /verify on every request to a protected
// app, and this service grants (200 + identity headers) or redirects the user
// to a passwordless email-code login.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/uppertoe/vps-scaffold-auth/internal/netsplit"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	// Embed the IANA timezone database so DISPLAY_TIMEZONE (time.LoadLocation)
	// works on the distroless/static image, which ships no /usr/share/zoneinfo.
	_ "time/tzdata"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/secretbox"
	"github.com/uppertoe/vps-scaffold-auth/internal/server"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
	"github.com/uppertoe/vps-scaffold-auth/internal/totp"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit")
	totpEnroll := flag.String("totp-enroll", "", "provision a TOTP secret for an admin `email`, print the otpauth URL, and exit")
	totpRemove := flag.String("totp-remove", "", "remove the stored TOTP secret for an admin `email`, and exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}
	if *totpEnroll != "" {
		os.Exit(runTOTPEnroll(*totpEnroll))
	}
	if *totpRemove != "" {
		os.Exit(runTOTPRemove(*totpRemove))
	}
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if len(cfg.DataEncryptionKey) == 0 {
		log.Print("WARNING: DATA_ENCRYPTION_KEY is not set; deriving the at-rest " +
			"encryption key from SESSION_SECRET. Set a dedicated DATA_ENCRYPTION_KEY " +
			"(openssl rand -hex 32) so rotating SESSION_SECRET does not make stored " +
			"break-glass tokens and TOTP secrets undecryptable.")
	}

	// One gateway process per database: sessions ended early, used passkey
	// challenges and the time of the last group change are held in memory and
	// written through, so a second process on the same database would not see
	// the first one's changes. The lock is released when the process exits.
	unlock, err := lockDatabase(cfg.SQLitePath)
	if err != nil {
		return err
	}
	defer unlock()

	st, err := store.OpenSQLite(cfg.SQLitePath)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()

	sender, err := email.New(email.Config{
		Backend:      cfg.EmailBackend,
		From:         cfg.EmailFrom,
		SMTPHost:     cfg.SMTPHost,
		SMTPPort:     cfg.SMTPPort,
		SMTPUsername: cfg.SMTPUsername,
		SMTPPassword: cfg.SMTPPassword,
		ResendAPIKey: cfg.ResendAPIKey,
	})
	if err != nil {
		return fmt.Errorf("email: %w", err)
	}

	srv, err := server.New(cfg, st, sender)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Every gated request's headers, cookies included, reach /verify, so a
		// megabyte of headers per request (Go's default ceiling) is far more
		// than any browser sends and needlessly costly to parse.
		MaxHeaderBytes: 64 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv.StartFeeds(ctx)
	srv.StartReminders(ctx)

	errCh := make(chan error, 8)
	// The members endpoint has its own listener, on a port Caddy never
	// proxies, so membership is never served through the public site. It
	// binds only to the gateway's addresses on the members networks, and the
	// public listener refuses connections arriving on those addresses, so an
	// app on its members network cannot reach the public listener past Caddy
	// (see internal/netsplit).
	publicLn, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.ListenAddr, err)
	}
	resolve := func(ctx context.Context, h string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
	}
	publicLn, membersLns, err := splitMembers(ctx, cfg, publicLn, resolve, net.InterfaceAddrs, net.Listen)
	if err != nil {
		publicLn.Close()
		return err
	}
	var membersServer *http.Server
	if len(membersLns) > 0 {
		membersServer = &http.Server{
			Addr:              cfg.MembersListenAddr,
			Handler:           srv.MembersHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		for _, ln := range membersLns {
			go func(ln net.Listener) {
				log.Printf("members endpoint listening on %s for %d app(s)", ln.Addr(), len(cfg.MemberReaders))
				if err := membersServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- fmt.Errorf("members endpoint: %w", err)
				}
			}(ln)
		}
	}
	go func() {
		log.Printf("listening on %s (email backend: %s, totp: %v)", cfg.ListenAddr, cfg.EmailBackend, cfg.TOTPEnabled)
		if err := httpServer.Serve(publicLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Print("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if membersServer != nil {
			_ = membersServer.Shutdown(shutdownCtx)
		}
		return httpServer.Shutdown(shutdownCtx)
	}
}

// runTOTPEnroll provisions an admin's TOTP secret out-of-band (admin-provisioned
// model: secrets are never self-enrolled at login). Run it in the same container
// and environment as the server so it uses the same at-rest encryption key, e.g.
// `docker compose exec auth /app -totp-enroll you@example.com`. It prints the
// secret once; treat that output as sensitive.
func runTOTPEnroll(rawEmail string) int {
	emailAddr := strings.ToLower(strings.TrimSpace(rawEmail))
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	if !contains(cfg.AdminEmails, emailAddr) {
		fmt.Fprintf(os.Stderr, "warning: %q is not in ADMIN_EMAILS; the secret is stored but only takes effect once that address is an admin\n", emailAddr)
	}
	st, err := store.OpenSQLite(cfg.SQLitePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 1
	}
	defer st.Close()
	box, err := secretbox.NewFromConfig(cfg.SessionSecret, cfg.DataEncryptionKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretbox:", err)
		return 1
	}
	issuer := cfg.TOTPIssuer
	if issuer == "" {
		issuer = cfg.Domain
	}
	en, err := totp.Enroll(issuer, emailAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "totp:", err)
		return 1
	}
	sealed, err := box.Seal(en.Secret)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seal:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := st.SetTOTPSecret(ctx, emailAddr, sealed); err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 1
	}
	fmt.Printf("Provisioned TOTP for %s\n\n", emailAddr)
	fmt.Printf("  Setup key:    %s\n", en.Secret)
	fmt.Printf("  otpauth URL:  %s\n\n", en.URL)
	fmt.Println("Add this to the authenticator app, then sign in. Treat the above as a secret.")
	return 0
}

// runTOTPRemove deletes an admin's stored TOTP secret. With TOTP enabled, that
// admin cannot sign in until re-provisioned.
func runTOTPRemove(rawEmail string) int {
	emailAddr := strings.ToLower(strings.TrimSpace(rawEmail))
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	st, err := store.OpenSQLite(cfg.SQLitePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 1
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := st.DeleteTOTPSecret(ctx, emailAddr); err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 1
	}
	fmt.Printf("Removed TOTP secret for %s (if one existed).\n", emailAddr)
	return 0
}

// contains reports whether s is in list (used for the admin-email check).
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// runHealthcheck performs an internal GET /healthz. Used as the container
// healthcheck command so the scratch/distroless image needs no curl.
func runHealthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	url := "http://127.0.0.1" + addr + "/healthz"
	if !strings.HasPrefix(addr, ":") {
		url = "http://" + addr + "/healthz"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}

// splitMembers keeps the members networks apart from the public listener (see
// internal/netsplit). It always resolves the members alias and wraps the
// public listener so that it refuses every connection arriving on the
// gateway's own addresses under that name, whatever the settings and whether
// or not any reader is usable. It then binds the members
// listener to those addresses, which answers an unknown token with 401.
//
// When MEMBER_READERS lists an app, a failure stops the gateway, as before.
// When the readers come only from the file, a failure is logged and the
// gateway runs without the members listener, refusing on whatever own
// addresses the alias did name: a gateway that will not start takes sign-in
// away from every app on the server.
func splitMembers(ctx context.Context, cfg *config.Config, publicLn net.Listener, resolve netsplit.Resolver, local netsplit.LocalAddrs,
	listen func(network, addr string) (net.Listener, error)) (net.Listener, []net.Listener, error) {
	if cfg.MembersAlias == "" {
		return publicLn, nil, nil
	}
	// With neither setting, the lookup is a precaution and usually finds
	// nothing, so it is not allowed to hold up start-up for long.
	wait := 10 * time.Second
	if !cfg.MembersReadersSet {
		wait = 2 * time.Second
	}
	lookupCtx, cancel := context.WithTimeout(ctx, wait)
	own, err := netsplit.OwnAddrs(lookupCtx, cfg.MembersAlias, resolve, local)
	cancel()
	// An alias that names every one of the gateway's addresses names the one
	// Caddy reaches too (a leftover MEMBERS_LISTEN_ADDR=auth:8081, say).
	// Refusing there would refuse Caddy and take sign-in away from every
	// app, which is worse than a missing members endpoint, so this is never
	// fatal: the gateway logs it and runs without the split.
	if err == nil && namesEveryAddress(own, local) {
		log.Printf("ERROR members endpoint: %q names every one of the gateway's addresses, including the one Caddy reaches, so the gateway neither refuses public connections on it nor starts the members listener. Give the gateway a name of its own on each members network, such as auth-members, that Caddy's network does not use, and set MEMBERS_LISTEN_ADDR to it.", cfg.MembersAlias)
		return publicLn, nil, nil
	}
	if len(own) > 0 {
		publicLn = netsplit.Refusing(publicLn, netsplit.NewSet(own))
	}
	if err != nil {
		if cfg.MembersRequired {
			return publicLn, nil, fmt.Errorf("members endpoint: MEMBERS_LISTEN_ADDR: %w; give the gateway that name on each members network", err)
		}
		if !cfg.MembersReadersSet {
			// Neither setting is set: a gateway on no members network is
			// the normal case, and needs no log line.
			return publicLn, nil, nil
		}
		log.Printf("ERROR members endpoint: %v; the gateway runs without the members listener. Give the gateway the name %q on each members network, then recreate it.", err, cfg.MembersAlias)
		return publicLn, nil, nil
	}
	if cfg.MembersListenAddr == "" {
		return publicLn, nil, nil
	}
	_, port, _ := net.SplitHostPort(cfg.MembersListenAddr)
	var lns []net.Listener
	for _, a := range own {
		ln, err := listen("tcp", net.JoinHostPort(a.String(), port))
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			if cfg.MembersRequired {
				return publicLn, nil, fmt.Errorf("members endpoint: %w", err)
			}
			log.Printf("ERROR members endpoint: %v; the gateway runs without the members listener", err)
			return publicLn, nil, nil
		}
		lns = append(lns, ln)
	}
	return publicLn, lns, nil
}

// namesEveryAddress reports whether own holds every non-loopback address of
// this host's interfaces.
func namesEveryAddress(own []netip.Addr, local netsplit.LocalAddrs) bool {
	ifaces, err := local()
	if err != nil || len(own) == 0 {
		return false
	}
	mine := netsplit.NewSet(own)
	for _, a := range ifaces {
		var ip netip.Addr
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			ip = p.Addr().Unmap()
		} else if x, err := netip.ParseAddr(a.String()); err == nil {
			ip = x.Unmap()
		} else {
			continue
		}
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		if !mine[ip] {
			return false
		}
	}
	return true
}

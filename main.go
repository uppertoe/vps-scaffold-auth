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
	"log"
	"net/http"
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
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s (email backend: %s, totp: %v)", cfg.ListenAddr, cfg.EmailBackend, cfg.TOTPEnabled)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
		return httpServer.Shutdown(shutdownCtx)
	}
}

// runTOTPEnroll provisions an admin's TOTP secret out-of-band (admin-provisioned
// model: secrets are never self-enrolled at login). Run it in the same container
// and environment as the server so it uses the same at-rest encryption key, e.g.
// `docker compose exec auth auth -totp-enroll you@example.com`. It prints the
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

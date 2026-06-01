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

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/server"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
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

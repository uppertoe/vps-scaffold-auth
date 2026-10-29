package server

import (
	"context"
	"sync"
	"time"
)

// logoCacheTTL bounds how often the public sign-in pages and /logo.img read
// branding from the store. GetBranding loads every branding image, and the
// store has one connection shared with /verify, so a flood of anonymous logo
// or login-page requests must not reach the database on every hit. Saving
// branding clears the cache at once, so the TTL only matters for changes made
// outside the admin UI.
const logoCacheTTL = 30 * time.Second

type logoCache struct {
	mu      sync.Mutex
	loaded  bool
	at      time.Time
	logo    []byte
	mime    string
	version string
}

// siteLogo returns the sign-in logo, its type and its version (see
// logoVersion), from the cache when it is fresh. An empty logo means none is
// set. A store error is returned and not cached.
func (s *Server) siteLogo(ctx context.Context) (logo []byte, mime, version string, err error) {
	c := &s.logo
	c.mu.Lock()
	defer c.mu.Unlock()
	now := s.now()
	if c.loaded && now.Sub(c.at) < logoCacheTTL {
		return c.logo, c.mime, c.version, nil
	}
	b, ok, err := s.store.GetBranding(ctx)
	if err != nil {
		return nil, "", "", err
	}
	c.logo, c.mime, c.version = nil, "", ""
	if ok && len(b.Logo) > 0 {
		c.logo, c.mime, c.version = b.Logo, b.LogoType, logoVersion(b.Logo)
	}
	c.loaded, c.at = true, now
	return c.logo, c.mime, c.version, nil
}

// forgetLogo drops the cached logo, so the next request reads the store.
func (s *Server) forgetLogo() {
	s.logo.mu.Lock()
	s.logo.loaded = false
	s.logo.mu.Unlock()
}

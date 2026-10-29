package server

import (
	"context"
	"sync"
	"time"
)

// brandingCacheTTL bounds how often the public sign-in pages, /logo.img and
// code emails read branding from the store. GetBranding loads every branding
// image, and the store has one connection shared with /verify, so a flood of
// anonymous logo, login-page or code requests must not reach the database on
// every hit. Saving branding clears the cache at once, so the TTL only matters
// for changes made outside the admin UI.
const brandingCacheTTL = 30 * time.Second

// brandingSnapshot is the part of the branding the public pages and code
// emails use.
type brandingSnapshot struct {
	logo                     []byte // shared and never modified: callers must not write to it
	logoType, logoVersion    string
	headerColor, accentColor string
}

type brandingCache struct {
	mu     sync.Mutex
	loaded bool
	at     time.Time
	snap   brandingSnapshot
}

// publicBranding returns the cached snapshot, reading the store when it is
// older than brandingCacheTTL. The lock is held across the read, so a flood
// causes one read, not many. If the read fails, the previous snapshot is kept
// and served for another TTL, so a slow or failing store is not retried by
// every waiting request; with no previous snapshot the error is returned.
func (s *Server) publicBranding(ctx context.Context) (brandingSnapshot, error) {
	c := &s.branding
	c.mu.Lock()
	defer c.mu.Unlock()
	now := s.now()
	if c.loaded && now.Sub(c.at) < brandingCacheTTL {
		return c.snap, nil
	}
	b, ok, err := s.store.GetBranding(ctx)
	if err != nil {
		if c.loaded {
			c.at = now
			return c.snap, nil
		}
		return brandingSnapshot{}, err
	}
	var snap brandingSnapshot
	if ok {
		snap.headerColor, snap.accentColor = b.HeaderColor, b.AccentColor
		if len(b.Logo) > 0 {
			snap.logo, snap.logoType, snap.logoVersion = b.Logo, b.LogoType, logoVersion(b.Logo)
		}
	}
	c.snap, c.loaded, c.at = snap, true, now
	return snap, nil
}

// siteLogo returns the sign-in logo, its type and its version (see
// logoVersion). An empty logo means none is set. The bytes are the cache's own,
// not a copy, so that serving them costs no allocation: callers only write
// them to a response.
func (s *Server) siteLogo(ctx context.Context) (logo []byte, mime, version string, err error) {
	snap, err := s.publicBranding(ctx)
	if err != nil || len(snap.logo) == 0 {
		return nil, "", "", err
	}
	return snap.logo, snap.logoType, snap.logoVersion, nil
}

// forgetBranding drops the cached snapshot, so the next request reads the
// store.
func (s *Server) forgetBranding() {
	s.branding.mu.Lock()
	s.branding.loaded = false
	s.branding.mu.Unlock()
}

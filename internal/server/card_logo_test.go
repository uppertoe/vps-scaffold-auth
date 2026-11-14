package server

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/ratelimit"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

func forgetCardLogos(srv *Server) {
	srv.cardLogos.mu.Lock()
	srv.cardLogos.m = nil
	srv.cardLogos.mu.Unlock()
}

// /card-logo serves only the logo of a design an active card uses, caches
// for a year under its version and revalidates by ETag otherwise, and is
// limited per client address.
func TestCardLogo(t *testing.T) {
	srv, _ := testServer(t)
	ctx := context.Background()
	d := defaultDesign()
	d.Name, d.LogoSource, d.LogoMode = "Lab", store.DesignLogoOwn, store.DesignLogoPanel
	d.Logo, d.LogoType = testPNG(t, 40, 20, false, 7), "image/png"
	id, err := srv.store.CreateCardDesign(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	path := "/card-logo/" + strconv.FormatInt(id, 10)
	c := newClient(t, srv.Handler())
	if rec := c.get(path, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("logo of a design no card uses = %d, want 404", rec.Code)
	}

	mintCode(t, srv, "Lab 1", "bg_lab")
	codes, err := srv.store.ListBreakGlassCodes(ctx)
	if err != nil || len(codes) != 1 {
		t.Fatalf("codes = %v, %v", codes, err)
	}
	if err := srv.store.SetCardDesign(ctx, codes[0].ID, id); err != nil {
		t.Fatal(err)
	}
	forgetCardLogos(srv)

	rec := c.get(path, nil)
	etag := rec.Header().Get("ETag")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" || etag == "" || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("logo without a version = %d, %v", rec.Code, rec.Header())
	}
	version := srv.cardLogo(ctx, id).version
	if etag != `"`+version+`"` {
		t.Errorf("ETag = %s, want the version %q", etag, version)
	}
	if rec := c.get(path+"?v="+version, nil); rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("logo with its version = %d, Cache-Control %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if rec := c.get(path, map[string]string{"If-None-Match": etag}); rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("revalidation = %d with %d bytes, want 304 and none", rec.Code, rec.Body.Len())
	}

	// Revoked, the card no longer uses the design, and the logo is not served.
	if err := srv.store.RevokeBreakGlassCode(ctx, codes[0].ID); err != nil {
		t.Fatal(err)
	}
	forgetCardLogos(srv)
	if rec := c.get(path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("logo once the card is revoked = %d, want 404", rec.Code)
	}

	srv.logoLimiter = ratelimit.New(2, time.Minute)
	c.get(path, nil)
	c.get(path, nil)
	if rec := c.get(path, nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("logo past the per-address limit = %d, want 429", rec.Code)
	}
}

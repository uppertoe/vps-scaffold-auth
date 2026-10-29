package server

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// oversizeMultipart streams a 40 MiB file field without declaring its length,
// so only the read-time cap can stop it.
func oversizeMultipart() (io.Reader, string) {
	const boundary = "body-limit-test"
	head := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"unused\"; filename=\"big.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
	tail := "\r\n--" + boundary + "--\r\n"
	return io.MultiReader(strings.NewReader(head), io.LimitReader(zeroReader{}, 40<<20), strings.NewReader(tail)),
		"multipart/form-data; boundary=" + boundary
}

// No public form parses or spools an oversized body, whichever route it hits,
// and the request is answered without a server error.
func TestPublicFormsCapBodies(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	srv, _ := testServer(t)
	for _, path := range []string{"/request", "/verify-code", "/totp", "/logout", "/break/activate"} {
		body, ctype := oversizeMultipart()
		req := httptest.NewRequest(http.MethodPost, path, body)
		req.ContentLength = -1
		req.RemoteAddr = "192.0.2.1:1234"
		req.Header.Set("Content-Type", ctype)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if req.MultipartForm != nil {
			if f := req.MultipartForm.File["unused"]; len(f) != 0 {
				t.Errorf("%s parsed a %d-byte file field", path, f[0].Size)
			}
			req.MultipartForm.RemoveAll()
		}
		if rec.Code >= 500 {
			t.Errorf("%s answered %d", path, rec.Code)
		}
		var spooled int64
		entries, _ := os.ReadDir(tmp)
		for _, e := range entries {
			if info, err := e.Info(); err == nil {
				spooled += info.Size()
			}
		}
		if spooled > maxPublicBody {
			t.Errorf("%s spooled %d bytes to TMPDIR", path, spooled)
		}
	}
}

// A body that declares more than the ceiling is refused before any handler runs.
func TestDeclaredOversizeIsRefused(t *testing.T) {
	srv, _ := testServer(t)
	for path, size := range map[string]int64{"/verify-code": maxPublicBody + 1, "/admin/branding": maxAdminBody + 1} {
		req := httptest.NewRequest(http.MethodPost, path, io.LimitReader(zeroReader{}, size))
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s with %d bytes: status %d, want 413", path, size, rec.Code)
		}
	}
}

// The admin ceiling leaves room for a real branding upload.
func TestBrandingUploadFitsUnderAdminCeiling(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/branding", nil).Body.String())

	logo := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{1}, 1500<<10)...)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("csrf", tok)
	mw.WriteField("title", "Sign in")
	fw, _ := mw.CreateFormFile("logo", "logo.png")
	fw.Write(logo)
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/branding", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := c.do(req)
	if rec.Code == http.StatusRequestEntityTooLarge || rec.Code >= 500 {
		t.Fatalf("branding upload: status %d", rec.Code)
	}
	b, ok, err := srv.store.GetBranding(context.Background())
	if err != nil || !ok || len(b.Logo) != len(logo) {
		t.Fatalf("logo not saved: ok=%v err=%v len=%d", ok, err, len(b.Logo))
	}
}

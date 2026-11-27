package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// A passkey stored in the database in the format the gateway has always
// written (the fixed bytes in passkeytest) signs in through the handler, so a
// change to the verifier cannot quietly require everyone to add theirs again.
func TestStoredPasskeySignsInThroughTheHandler(t *testing.T) {
	srv, _ := pkServer(t, nil)
	a := passkeytest.Stored()
	if _, err := srv.store.CreatePasskey(context.Background(), store.Passkey{
		Email:        "user@example.com",
		CredentialID: passkeytest.Unhex(passkeytest.StoredCredentialIDHex),
		PublicKey:    passkeytest.Unhex(passkeytest.StoredSPKIHex),
		UserHandle:   passkeytest.Unhex(passkeytest.StoredUserHandleHex),
		Label:        "iPhone",
		CreatedAt:    srv.now(),
	}); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	if rec := signInWith(t, c, a); rec.Code != http.StatusFound {
		t.Fatalf("sign-in with a stored passkey: %d %s", rec.Code, rec.Body.String())
	}
	if verifyAny(t, srv, c).Code != http.StatusOK {
		t.Fatal("no session after signing in with a stored passkey")
	}
	if id := readSession(t, srv, c); id.Email != "user@example.com" || id.PK == 0 {
		t.Fatalf("session %+v does not name the stored passkey", id)
	}
}

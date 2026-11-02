package store

import (
	"context"
	"testing"
	"time"
)

func TestPasskeysStoreAndScope(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	mk := func(email, cred string) int64 {
		id, err := s.CreatePasskey(ctx, Passkey{Email: email, CredentialID: []byte(cred), PublicKey: []byte("k"), UserHandle: []byte("h"), Label: "x", CreatedAt: now})
		if err != nil {
			t.Fatalf("create %s: %v", cred, err)
		}
		return id
	}
	a1 := mk("a@example.com", "cred-a1")
	mk("a@example.com", "cred-a2")
	b1 := mk("b@example.com", "cred-b1")

	if _, err := s.CreatePasskey(ctx, Passkey{Email: "b@example.com", CredentialID: []byte("cred-a1"), PublicKey: []byte("k"), UserHandle: []byte("h"), CreatedAt: now}); err == nil {
		t.Fatal("a credential ID already stored for someone else was accepted")
	}
	p, ok, err := s.PasskeyByCredentialID(ctx, []byte("cred-b1"))
	if err != nil || !ok || p.ID != b1 || p.Email != "b@example.com" || !p.LastUsedAt.IsZero() {
		t.Fatalf("lookup: %+v ok=%v err=%v", p, ok, err)
	}
	if err := s.TouchPasskey(ctx, b1, 7, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if p, _, _ := s.GetPasskey(ctx, b1); p.SignCount != 7 || !p.LastUsedAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("touch not recorded: %+v", p)
	}
	// One person cannot remove another's passkey by ID.
	if ok, err := s.DeletePasskey(ctx, "a@example.com", b1); err != nil || ok {
		t.Fatalf("a removed b's passkey: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.DeletePasskey(ctx, "a@example.com", a1); !ok {
		t.Fatal("a could not remove their own passkey")
	}
	if n, _ := s.DeletePasskeys(ctx, "a@example.com"); n != 1 {
		t.Fatalf("remove all: %d, want 1", n)
	}
	if l, _ := s.ListPasskeys(ctx, "b@example.com"); len(l) != 1 {
		t.Fatalf("b's passkeys after a's removal: %d", len(l))
	}
}

// A session names the passkey that started it by ID, and renewal ends the
// session once that ID is gone. IDs must therefore never be reused, even for
// the highest ID after it is deleted (a plain rowid would reuse it).
func TestPasskeyIDsAreNeverReused(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p := Passkey{Email: "a@example.com", PublicKey: []byte("k"), UserHandle: []byte("h"), CreatedAt: time.Unix(1, 0)}
	p.CredentialID = []byte("one")
	first, _ := s.CreatePasskey(ctx, p)
	s.DeletePasskeys(ctx, "a@example.com")
	p.CredentialID = []byte("two")
	second, _ := s.CreatePasskey(ctx, p)
	if second == first {
		t.Fatalf("passkey ID %d was reused after deletion", first)
	}
}

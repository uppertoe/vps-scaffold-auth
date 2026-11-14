package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A new database has one design, Department standard, at A6.
func TestFreshDatabaseHasTheStandardDesign(t *testing.T) {
	s := newTestStore(t)
	ds, err := s.ListCardDesigns(context.Background())
	if err != nil || len(ds) != 1 {
		t.Fatalf("designs %v, %v", ds, err)
	}
	d := ds[0]
	if d.Name != StandardDesignName || d.Size != "A6" || d.Header != "#003a5c" || !d.Stripe || d.LogoSource != DesignLogoSite || d.LogoMode != DesignLogoWhite || d.Steps != DefaultDesignSteps {
		t.Errorf("standard design %+v", d)
	}
}

// TestBrandingMigratesToDesigns opens a database made before designs: the
// global branding becomes Department standard, every card is given it, and a
// card whose overrides change its look gets a design named after it.
func TestBrandingMigratesToDesigns(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	// Make the database look as an earlier build left it.
	for _, q := range []string{
		`DELETE FROM card_designs`,
		`INSERT INTO pdf_branding (id, title, instructions, header_color, accent_color, bar1_color, bar2_color, bar3_color, pdf_logo, pdf_logo_type, updated_at)
		 VALUES (1, 'Code blue', '1. Open the camera.' || char(10) || '2. Tap the link.', '#222222', '#008ccc', '', '', '', x'89504e47', 'image/png', 1)`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	plain, _ := s.CreateBreakGlassCode(ctx, BreakGlassCode{Label: "Theatre 2", TargetGroup: "ward", TokenEnc: "e1", TokenHash: "h1"})
	same, _ := s.CreateBreakGlassCode(ctx, BreakGlassCode{Label: "Theatre 3", TargetGroup: "ward", TokenEnc: "e2", TokenHash: "h2"})
	own, _ := s.CreateBreakGlassCode(ctx, BreakGlassCode{Label: "PICU bed 4", TargetGroup: "ward", TokenEnc: "e3", TokenHash: "h3"})
	if err := s.SaveCodeBrandingMeta(ctx, same, "Code blue", "", "", "#222222", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCodeBrandingMeta(ctx, own, "", "", "", "#9b1c1c", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE break_glass_codes SET design_id = NULL`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ds, err := s.ListCardDesigns(ctx)
	if err != nil || len(ds) != 2 {
		t.Fatalf("designs %+v, %v", ds, err)
	}
	std, picu := ds[0], ds[1]
	if std.Name != StandardDesignName || std.Title != "Code blue" || std.Header != "#222222" || std.Accent != "#008ccc" ||
		std.Steps != "Open the camera.\nTap the link." || std.Size != "A4" || std.LogoSource != DesignLogoOwn ||
		std.LogoMode != DesignLogoAsIs || string(std.Logo) != "\x89PNG" || std.Bar1 != "#fdb913" {
		t.Errorf("standard design %+v", std)
	}
	if picu.Name != "PICU bed 4" || picu.Header != "#9b1c1c" || picu.Title != "Code blue" {
		t.Errorf("the card's own design %+v", picu)
	}
	for id, want := range map[int64]int64{plain: std.ID, same: std.ID, own: picu.ID} {
		c, _, _ := s.GetBreakGlassCode(ctx, id)
		if c.DesignID != want {
			t.Errorf("card %s has design %d, want %d", c.Label, c.DesignID, want)
		}
	}
}

func TestDesignInUseAndLastDesign(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	ds, _ := s.ListCardDesigns(ctx)
	std := ds[0]
	if err := s.DeleteCardDesign(ctx, std.ID); !errors.Is(err, ErrLastDesign) {
		t.Fatalf("deleting the only design: %v", err)
	}
	d := std
	d.Name = "Theatres, light"
	id, err := s.CreateCardDesign(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateCardDesign(ctx, d); !errors.Is(err, ErrDesignName) {
		t.Fatalf("a second design of the same name: %v", err)
	}
	card, _ := s.CreateBreakGlassCode(ctx, BreakGlassCode{Label: "Theatre 6", App: "handbook", Role: RoleUser, TokenEnc: "e", TokenHash: "h", DesignID: id})
	if err := s.DeleteCardDesign(ctx, id); !errors.Is(err, ErrDesignInUse) {
		t.Fatalf("deleting a design in use: %v", err)
	}
	if err := s.RevokeBreakGlassCode(ctx, card); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCardDesign(ctx, id); err != nil {
		t.Fatalf("deleting a design only a withdrawn card used: %v", err)
	}
	c, _, _ := s.GetBreakGlassCode(ctx, card)
	if c.DesignID != 0 {
		t.Errorf("the withdrawn card still names design %d", c.DesignID)
	}
}

// Replacing a card keeps its old code's hash, and the new card starts with
// no download and no test.
func TestReplaceRetiresTheOldCode(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id, _ := s.CreateBreakGlassCode(ctx, BreakGlassCode{Label: "Theatre 6", TargetGroup: "ward", TokenEnc: "e", TokenHash: "old"})
	now := time.Unix(1_800_000_000, 0)
	s.MarkCardPDF(ctx, id, now)
	s.MarkCardTested(ctx, id, now)
	if c, _, _ := s.GetBreakGlassCode(ctx, id); !c.PDFAt.Equal(now) || !c.TestedAt.Equal(now) {
		t.Fatalf("marks not kept: %+v", c)
	}
	if err := s.RemintBreakGlassCode(ctx, id, "e2", "new"); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.LookupRetiredToken(ctx, "old"); err != nil || !ok || got != id {
		t.Fatalf("retired lookup %d %v %v", got, ok, err)
	}
	if _, ok, _ := s.LookupRetiredToken(ctx, "new"); ok {
		t.Error("the live code is listed as retired")
	}
	if c, _, _ := s.GetBreakGlassCode(ctx, id); !c.PDFAt.IsZero() || !c.TestedAt.IsZero() {
		t.Errorf("the replaced card kept its marks: %+v", c)
	}
}

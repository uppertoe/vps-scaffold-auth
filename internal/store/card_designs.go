package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Card designs. A design sets the colours, logo, title, steps and printed
// size of the break-glass cards that use it. They replace the global card
// branding and the per-card overrides; migrateCardDesigns turns those into
// designs the first time a database without designs is opened.

// Where a design's logo comes from.
const (
	DesignLogoSite = "site" // the site logo, set on the Settings page
	DesignLogoOwn  = "own"  // a logo uploaded for the design's cards
	DesignLogoNone = "none"
)

// The logo treatments, as breakglass names them.
const (
	DesignLogoAsIs  = "asis"
	DesignLogoWhite = "white"
	DesignLogoPanel = "panel"
)

// StandardDesignName names the design made from the global branding.
const StandardDesignName = "Department standard"

// Default design values: the Department preset and the prototype's wording.
const (
	DefaultDesignTitle = "Emergency access"
	DefaultDesignSteps = "Open your phone's camera and point it at the code.\nTap the link that appears.\nPress Continue to open the app."
	oldDefaultSteps    = "1. Open your phone camera and point it at the code.\n2. Tap the link that appears.\n3. You will be signed in for temporary emergency access."
)

var (
	// ErrDesignName refuses a design whose name another design has.
	ErrDesignName = errors.New("a card design with that name already exists")
	// ErrDesignInUse refuses deleting a design an active card uses.
	ErrDesignInUse = errors.New("the card design is in use")
	// ErrLastDesign refuses deleting the only design.
	ErrLastDesign = errors.New("the last card design cannot be deleted")
)

// CardDesign is one named card design.
type CardDesign struct {
	ID               int64
	Name             string
	Header, Accent   string
	Stripe           bool
	Bar1, Bar2, Bar3 string
	LogoSource       string // DesignLogoSite, DesignLogoOwn or DesignLogoNone
	LogoMode         string // DesignLogoAsIs, DesignLogoWhite or DesignLogoPanel
	Logo             []byte // the design's own logo
	LogoType         string
	Title            string
	Steps            string
	Size             string // "A6", "A5" or "A4"
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// CardDesignStore keeps card designs, the design each card uses, when a
// card's PDF was last downloaded and when it was last tested, and the codes
// a replaced card used to hold.
type CardDesignStore interface {
	// ListCardDesigns returns every design, oldest first.
	ListCardDesigns(ctx context.Context) ([]CardDesign, error)
	GetCardDesign(ctx context.Context, id int64) (CardDesign, bool, error)
	// CreateCardDesign adds a design and returns its id; ErrDesignName when
	// the name is taken.
	CreateCardDesign(ctx context.Context, d CardDesign) (int64, error)
	// SaveCardDesign replaces a design's fields. The stored logo is replaced
	// only when replaceLogo is set (d.Logo nil clears it).
	SaveCardDesign(ctx context.Context, d CardDesign, replaceLogo bool) error
	// DeleteCardDesign deletes a design no active card uses: ErrDesignInUse
	// otherwise, and ErrLastDesign for the only design. Withdrawn cards that
	// used it fall back to the first design.
	DeleteCardDesign(ctx context.Context, id int64) error
	// SetCardDesign gives a card a design.
	SetCardDesign(ctx context.Context, codeID, designID int64) error
	// MarkCardPDF records that a card's PDF was downloaded; MarkCardTested
	// that an administrator scanned it as a test.
	MarkCardPDF(ctx context.Context, codeID int64, at time.Time) error
	MarkCardTested(ctx context.Context, codeID int64, at time.Time) error
	// LookupRetiredToken finds the card a replaced code belonged to.
	LookupRetiredToken(ctx context.Context, tokenHash string) (codeID int64, ok bool, err error)
}

const cardDesignSchema = `
CREATE TABLE IF NOT EXISTS card_designs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	header      TEXT NOT NULL,
	accent      TEXT NOT NULL,
	stripe      INTEGER NOT NULL DEFAULT 0,
	bar1        TEXT NOT NULL DEFAULT '',
	bar2        TEXT NOT NULL DEFAULT '',
	bar3        TEXT NOT NULL DEFAULT '',
	logo_source TEXT NOT NULL DEFAULT 'site',
	logo_mode   TEXT NOT NULL DEFAULT 'asis',
	logo        BLOB,
	logo_type   TEXT NOT NULL DEFAULT '',
	title       TEXT NOT NULL,
	steps       TEXT NOT NULL,
	size        TEXT NOT NULL DEFAULT 'A6',
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS break_glass_retired (
	token_hash TEXT PRIMARY KEY,
	code_id    INTEGER NOT NULL REFERENCES break_glass_codes(id) ON DELETE CASCADE,
	retired_at INTEGER NOT NULL
);`

// migrateCardDesigns adds the designs table and the card columns, and on a
// database with no design yet makes them from the old branding: the global
// branding becomes "Department standard", and each card whose overrides
// make it look different gets a design of its own, named after the card.
func (s *SQLite) migrateCardDesigns() error {
	if _, err := s.db.Exec(cardDesignSchema); err != nil {
		return err
	}
	if err := s.ensureColumns("break_glass_codes", []column{
		{"design_id", "INTEGER"},
		{"pdf_at", "INTEGER NOT NULL DEFAULT 0"},
		{"tested_at", "INTEGER NOT NULL DEFAULT 0"},
	}); err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM card_designs`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var g struct {
		title, instr, header, accent, b1, b2, b3 string
		logo, pdfLogo                            []byte
		logoType, pdfLogoType                    string
	}
	err = tx.QueryRow(`SELECT title, instructions, header_color, accent_color, bar1_color, bar2_color, bar3_color,
		logo, logo_type, pdf_logo, pdf_logo_type FROM pdf_branding WHERE id = 1`).
		Scan(&g.title, &g.instr, &g.header, &g.accent, &g.b1, &g.b2, &g.b3, &g.logo, &g.logoType, &g.pdfLogo, &g.pdfLogoType)
	branded := err == nil
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	var cards int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM break_glass_codes`).Scan(&cards); err != nil {
		return err
	}
	std := CardDesign{
		Name: StandardDesignName, Stripe: true,
		Header: or(g.header, "#003a5c"), Accent: or(g.accent, "#0b7bbf"),
		Bar1: or(g.b1, "#fdb913"), Bar2: or(g.b2, "#f26c52"), Bar3: or(g.b3, "#82c341"),
		Title: or(g.title, DefaultDesignTitle), Steps: migratedSteps(g.instr), Size: "A6",
		LogoSource: DesignLogoSite, LogoMode: DesignLogoWhite,
	}
	// Cards already printed were A4, and their logo was drawn as uploaded:
	// the PDF logo when there was one, otherwise the site logo.
	if branded || cards > 0 {
		std.Size = "A4"
		std.LogoMode = DesignLogoAsIs
	}
	if len(g.pdfLogo) > 0 {
		std.LogoSource, std.Logo, std.LogoType = DesignLogoOwn, g.pdfLogo, g.pdfLogoType
	}
	stdID, err := insertDesign(tx, std)
	if err != nil {
		return err
	}

	rows, err := tx.Query(`SELECT id, label, ov_title, ov_instructions, ov_header_color, ov_accent_color,
		ov_bar1_color, ov_bar2_color, ov_bar3_color, ov_logo, ov_logo_type FROM break_glass_codes ORDER BY id`)
	if err != nil {
		return err
	}
	type override struct {
		id                                          int64
		label, title, instr, header, accent, b1, b2 string
		b3, logoType                                string
		logo                                        []byte
	}
	var ovs []override
	for rows.Next() {
		var o override
		if err := rows.Scan(&o.id, &o.label, &o.title, &o.instr, &o.header, &o.accent, &o.b1, &o.b2, &o.b3, &o.logo, &o.logoType); err != nil {
			rows.Close()
			return err
		}
		ovs = append(ovs, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, o := range ovs {
		d := std
		d.Title, d.Steps = or(o.title, std.Title), std.Steps
		if strings.TrimSpace(o.instr) != "" {
			d.Steps = migratedSteps(o.instr)
		}
		d.Header, d.Accent = or(o.header, std.Header), or(o.accent, std.Accent)
		d.Bar1, d.Bar2, d.Bar3 = or(o.b1, std.Bar1), or(o.b2, std.Bar2), or(o.b3, std.Bar3)
		if len(o.logo) > 0 {
			d.LogoSource, d.Logo, d.LogoType, d.LogoMode = DesignLogoOwn, o.logo, o.logoType, DesignLogoAsIs
		}
		if sameLook(d, std) {
			continue
		}
		d.Name = o.label
		if strings.EqualFold(d.Name, StandardDesignName) {
			d.Name += " (card)"
		}
		id, err := insertDesign(tx, d)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE break_glass_codes SET design_id = ? WHERE id = ?`, id, o.id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE break_glass_codes SET design_id = ? WHERE design_id IS NULL`, stdID); err != nil {
		return err
	}
	return tx.Commit()
}

// migratedSteps turns the old instructions into steps: the old default
// becomes the new default (its last step no longer says what happens), and
// typed numbering is dropped, as the card numbers each step.
func migratedSteps(instr string) string {
	instr = strings.TrimSpace(strings.ReplaceAll(instr, "\r\n", "\n"))
	if instr == "" || instr == oldDefaultSteps {
		return DefaultDesignSteps
	}
	var out []string
	for _, l := range strings.Split(instr, "\n") {
		t := strings.TrimSpace(l)
		i := 0
		for i < len(t) && t[i] >= '0' && t[i] <= '9' {
			i++
		}
		if i > 0 && i < len(t) && (t[i] == '.' || t[i] == ')') {
			t = strings.TrimSpace(t[i+1:])
		}
		if t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}

func sameLook(a, b CardDesign) bool {
	return a.Title == b.Title && a.Steps == b.Steps && strings.EqualFold(a.Header, b.Header) &&
		strings.EqualFold(a.Accent, b.Accent) && strings.EqualFold(a.Bar1, b.Bar1) &&
		strings.EqualFold(a.Bar2, b.Bar2) && strings.EqualFold(a.Bar3, b.Bar3) &&
		a.LogoSource == b.LogoSource && string(a.Logo) == string(b.Logo)
}

func or(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func insertDesign(db execer, d CardDesign) (int64, error) {
	now := time.Now().Unix()
	res, err := db.Exec(`INSERT INTO card_designs
		(name, header, accent, stripe, bar1, bar2, bar3, logo_source, logo_mode, logo, logo_type, title, steps, size, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Name, d.Header, d.Accent, boolInt(d.Stripe), d.Bar1, d.Bar2, d.Bar3, d.LogoSource, d.LogoMode,
		nilIfEmpty(d.Logo), d.LogoType, d.Title, d.Steps, d.Size, now, now)
	if err != nil {
		if isUniqueErr(err) {
			return 0, ErrDesignName
		}
		return 0, err
	}
	return res.LastInsertId()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nilIfEmpty(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

const designColumns = `id, name, header, accent, stripe, bar1, bar2, bar3, logo_source, logo_mode, logo, logo_type, title, steps, size, created_at, updated_at`

func scanDesign(sc interface{ Scan(...any) error }) (CardDesign, error) {
	var d CardDesign
	var stripe int
	var created, updated int64
	if err := sc.Scan(&d.ID, &d.Name, &d.Header, &d.Accent, &stripe, &d.Bar1, &d.Bar2, &d.Bar3, &d.LogoSource,
		&d.LogoMode, &d.Logo, &d.LogoType, &d.Title, &d.Steps, &d.Size, &created, &updated); err != nil {
		return CardDesign{}, err
	}
	d.Stripe = stripe != 0
	d.CreatedAt, d.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	return d, nil
}

// ListCardDesigns returns every design, oldest first.
func (s *SQLite) ListCardDesigns(ctx context.Context) ([]CardDesign, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+designColumns+` FROM card_designs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CardDesign
	for rows.Next() {
		d, err := scanDesign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetCardDesign returns one design.
func (s *SQLite) GetCardDesign(ctx context.Context, id int64) (CardDesign, bool, error) {
	d, err := scanDesign(s.db.QueryRowContext(ctx, `SELECT `+designColumns+` FROM card_designs WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return CardDesign{}, false, nil
	}
	if err != nil {
		return CardDesign{}, false, err
	}
	return d, true, nil
}

// CreateCardDesign adds a design.
func (s *SQLite) CreateCardDesign(ctx context.Context, d CardDesign) (int64, error) {
	return insertDesign(s.db, d)
}

// SaveCardDesign replaces a design's fields.
func (s *SQLite) SaveCardDesign(ctx context.Context, d CardDesign, replaceLogo bool) error {
	q := `UPDATE card_designs SET name = ?, header = ?, accent = ?, stripe = ?, bar1 = ?, bar2 = ?, bar3 = ?,
		logo_source = ?, logo_mode = ?, title = ?, steps = ?, size = ?, updated_at = ?`
	args := []any{d.Name, d.Header, d.Accent, boolInt(d.Stripe), d.Bar1, d.Bar2, d.Bar3, d.LogoSource, d.LogoMode,
		d.Title, d.Steps, d.Size, time.Now().Unix()}
	if replaceLogo {
		q += `, logo = ?, logo_type = ?`
		args = append(args, nilIfEmpty(d.Logo), d.LogoType)
	}
	q += ` WHERE id = ?`
	args = append(args, d.ID)
	_, err := s.db.ExecContext(ctx, q, args...)
	if isUniqueErr(err) {
		return ErrDesignName
	}
	return err
}

// DeleteCardDesign deletes a design no active card uses.
func (s *SQLite) DeleteCardDesign(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var inUse, total int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM break_glass_codes WHERE design_id = ? AND status = ?`, id, BreakGlassActive).Scan(&inUse); err != nil {
		return err
	}
	if inUse > 0 {
		return ErrDesignInUse
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM card_designs`).Scan(&total); err != nil {
		return err
	}
	if total <= 1 {
		return ErrLastDesign
	}
	if _, err := tx.ExecContext(ctx, `UPDATE break_glass_codes SET design_id = NULL WHERE design_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM card_designs WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetCardDesign gives a card a design.
func (s *SQLite) SetCardDesign(ctx context.Context, codeID, designID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE break_glass_codes SET design_id = ?, updated_at = ? WHERE id = ?`, designID, time.Now().Unix(), codeID)
	return err
}

// MarkCardPDF records a download of the card's PDF.
func (s *SQLite) MarkCardPDF(ctx context.Context, codeID int64, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE break_glass_codes SET pdf_at = ? WHERE id = ?`, at.Unix(), codeID)
	return err
}

// MarkCardTested records an administrator's test scan.
func (s *SQLite) MarkCardTested(ctx context.Context, codeID int64, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE break_glass_codes SET tested_at = ? WHERE id = ?`, at.Unix(), codeID)
	return err
}

// LookupRetiredToken finds the card a replaced code belonged to.
func (s *SQLite) LookupRetiredToken(ctx context.Context, tokenHash string) (int64, bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT code_id FROM break_glass_retired WHERE token_hash = ?`, tokenHash).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return id, err == nil, err
}

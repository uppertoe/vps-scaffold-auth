// Break-glass cards, their events, and the branding printed on them.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// --- Break-the-glass codes ---

const bgColumns = `id, label, note, target_group, COALESCE(app, ''), COALESCE(role, ''), token_enc, token_hash, redirect, status, created_at, updated_at, COALESCE(design_id, 0), pdf_at, tested_at`

func scanBreakGlass(sc interface{ Scan(...any) error }) (BreakGlassCode, error) {
	var c BreakGlassCode
	var created, updated, pdfAt, testedAt int64
	err := sc.Scan(&c.ID, &c.Label, &c.Note, &c.TargetGroup, &c.App, &c.Role, &c.TokenEnc, &c.TokenHash,
		&c.Redirect, &c.Status, &created, &updated, &c.DesignID, &pdfAt, &testedAt)
	if err != nil {
		return BreakGlassCode{}, err
	}
	c.CreatedAt = time.Unix(created, 0)
	c.UpdatedAt = time.Unix(updated, 0)
	if pdfAt > 0 {
		c.PDFAt = time.Unix(pdfAt, 0)
	}
	if testedAt > 0 {
		c.TestedAt = time.Unix(testedAt, 0)
	}
	return c, nil
}

// CreateBreakGlassCode inserts a code and returns its id.
func (s *SQLite) CreateBreakGlassCode(ctx context.Context, c BreakGlassCode) (int64, error) {
	now := time.Now().Unix()
	if c.Status == "" {
		c.Status = BreakGlassActive
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO break_glass_codes
		 (label, note, target_group, app, role, token_enc, token_hash, redirect, status, created_at, updated_at, design_id)
		 VALUES (?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?, ?, ?, NULLIF(?, 0))`,
		c.Label, c.Note, c.TargetGroup, c.App, c.Role, c.TokenEnc, c.TokenHash, c.Redirect, c.Status, now, now, c.DesignID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListBreakGlassCodes returns all codes, newest first.
func (s *SQLite) ListBreakGlassCodes(ctx context.Context) ([]BreakGlassCode, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+bgColumns+` FROM break_glass_codes ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BreakGlassCode
	for rows.Next() {
		c, err := scanBreakGlass(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetBreakGlassCode returns a code by id.
func (s *SQLite) GetBreakGlassCode(ctx context.Context, id int64) (BreakGlassCode, bool, error) {
	c, err := scanBreakGlass(s.db.QueryRowContext(ctx,
		`SELECT `+bgColumns+` FROM break_glass_codes WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return BreakGlassCode{}, false, nil
	}
	if err != nil {
		return BreakGlassCode{}, false, err
	}
	return c, true, nil
}

// LookupBreakGlassByTokenHash finds a code by its token hash, any status.
func (s *SQLite) LookupBreakGlassByTokenHash(ctx context.Context, tokenHash string) (BreakGlassCode, bool, error) {
	c, err := scanBreakGlass(s.db.QueryRowContext(ctx,
		`SELECT `+bgColumns+` FROM break_glass_codes WHERE token_hash = ?`, tokenHash))
	if err == sql.ErrNoRows {
		return BreakGlassCode{}, false, nil
	}
	if err != nil {
		return BreakGlassCode{}, false, err
	}
	return c, true, nil
}

// RevokeBreakGlassCode marks a code revoked.
func (s *SQLite) RevokeBreakGlassCode(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET status = ?, updated_at = ? WHERE id = ?`,
		BreakGlassRevoked, time.Now().Unix(), id)
	return err
}

// RemintBreakGlassCode replaces a code's token and reactivates it. The old
// token's hash is kept, so a scan of the old card can say it was replaced,
// and the new card starts with no PDF downloaded and no test.
func (s *SQLite) RemintBreakGlassCode(ctx context.Context, id int64, newTokenEnc, newTokenHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	// A withdrawn card stays withdrawn: replacing it would bring it back.
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM break_glass_codes WHERE id = ?`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCardNotActive
		}
		return err
	}
	if status != BreakGlassActive {
		return ErrCardNotActive
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO break_glass_retired (token_hash, code_id, retired_at)
		 SELECT token_hash, id, ? FROM break_glass_codes WHERE id = ?`, now, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE break_glass_codes SET token_enc = ?, token_hash = ?, updated_at = ?, pdf_at = 0, tested_at = 0 WHERE id = ? AND status = ?`,
		newTokenEnc, newTokenHash, now, id, BreakGlassActive); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordBreakGlassEvent appends an audit event.
func (s *SQLite) RecordBreakGlassEvent(ctx context.Context, e BreakGlassEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO break_glass_events (code_id, label, client_ip, user_agent, outcome, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		e.CodeID, e.Label, e.ClientIP, e.UserAgent, e.Outcome, time.Now().Unix())
	return err
}

// GetCodeBranding returns a code's branding overrides (empty = inherit global).
func (s *SQLite) GetCodeBranding(ctx context.Context, codeID int64) (Branding, error) {
	var b Branding
	err := s.db.QueryRowContext(ctx,
		`SELECT ov_title, ov_body, ov_instructions, ov_header_color, ov_accent_color,
		        ov_bar1_color, ov_bar2_color, ov_bar3_color, ov_logo, ov_logo_type, ov_glyph, ov_glyph_type
		 FROM break_glass_codes WHERE id = ?`, codeID).
		Scan(&b.Title, &b.Body, &b.Instructions, &b.HeaderColor, &b.AccentColor,
			&b.Bar1Color, &b.Bar2Color, &b.Bar3Color, &b.Logo, &b.LogoType, &b.Glyph, &b.GlyphType)
	if err == sql.ErrNoRows {
		return Branding{}, nil
	}
	if err != nil {
		return Branding{}, err
	}
	return b, nil
}

// SaveCodeBrandingMeta upserts a code's text + colour overrides.
func (s *SQLite) SaveCodeBrandingMeta(ctx context.Context, codeID int64, title, body, instructions, header, accent, bar1, bar2, bar3 string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET
			ov_title = ?, ov_body = ?, ov_instructions = ?,
			ov_header_color = ?, ov_accent_color = ?, ov_bar1_color = ?, ov_bar2_color = ?, ov_bar3_color = ?,
			updated_at = ?
		 WHERE id = ?`,
		title, body, instructions, header, accent, bar1, bar2, bar3, time.Now().Unix(), codeID)
	return err
}

// SetCodeBrandingImage stores a code's override logo or glyph.
func (s *SQLite) SetCodeBrandingImage(ctx context.Context, codeID int64, which BrandingImage, data []byte, mime string) error {
	blobCol, typeCol := codeBrandingImageColumns(which)
	if blobCol == "" {
		return fmt.Errorf("store: unknown branding image %q", which)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET `+blobCol+` = ?, `+typeCol+` = ?, updated_at = ? WHERE id = ?`,
		data, mime, time.Now().Unix(), codeID)
	return err
}

// ClearCodeBrandingImage removes a code's override logo or glyph.
func (s *SQLite) ClearCodeBrandingImage(ctx context.Context, codeID int64, which BrandingImage) error {
	blobCol, typeCol := codeBrandingImageColumns(which)
	if blobCol == "" {
		return fmt.Errorf("store: unknown branding image %q", which)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET `+blobCol+` = NULL, `+typeCol+` = '', updated_at = ? WHERE id = ?`,
		time.Now().Unix(), codeID)
	return err
}

func codeBrandingImageColumns(which BrandingImage) (blobCol, typeCol string) {
	switch which {
	case BrandingLogo:
		return "ov_logo", "ov_logo_type"
	case BrandingGlyph:
		return "ov_glyph", "ov_glyph_type"
	default:
		return "", ""
	}
}

// ListBreakGlassEvents returns events, newest first. codeID 0 lists all codes.
func (s *SQLite) ListBreakGlassEvents(ctx context.Context, codeID int64, limit, offset int) ([]BreakGlassEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, code_id, label, client_ip, user_agent, outcome, created_at FROM break_glass_events`
	args := []any{}
	if codeID > 0 {
		query += ` WHERE code_id = ?`
		args = append(args, codeID)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BreakGlassEvent
	for rows.Next() {
		var e BreakGlassEvent
		var created int64
		if err := rows.Scan(&e.ID, &e.CodeID, &e.Label, &e.ClientIP, &e.UserAgent, &e.Outcome, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(created, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

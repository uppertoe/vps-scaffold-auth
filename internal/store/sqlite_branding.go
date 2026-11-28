// Gateway branding and app settings.

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// --- PDF branding (singleton row id=1) ---

// GetBranding returns the stored branding row, if any.
func (s *SQLite) GetBranding(ctx context.Context) (Branding, bool, error) {
	var b Branding
	var updated int64
	err := s.db.QueryRowContext(ctx,
		`SELECT title, body, instructions, logo, logo_type, glyph, glyph_type,
		        pdf_logo, pdf_logo_type,
		        header_color, accent_color, bar1_color, bar2_color, bar3_color, updated_at
		 FROM pdf_branding WHERE id = 1`).
		Scan(&b.Title, &b.Body, &b.Instructions, &b.Logo, &b.LogoType, &b.Glyph, &b.GlyphType,
			&b.PDFLogo, &b.PDFLogoType,
			&b.HeaderColor, &b.AccentColor, &b.Bar1Color, &b.Bar2Color, &b.Bar3Color, &updated)
	if err == sql.ErrNoRows {
		return Branding{}, false, nil
	}
	if err != nil {
		return Branding{}, false, err
	}
	b.UpdatedAt = time.Unix(updated, 0)
	return b, true, nil
}

// SaveBrandingColors upserts the palette colours, leaving text/images intact.
func (s *SQLite) SaveBrandingColors(ctx context.Context, header, accent, bar1, bar2, bar3 string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pdf_branding (id, header_color, accent_color, bar1_color, bar2_color, bar3_color, updated_at)
		 VALUES (1, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			header_color = excluded.header_color, accent_color = excluded.accent_color,
			bar1_color = excluded.bar1_color, bar2_color = excluded.bar2_color,
			bar3_color = excluded.bar3_color, updated_at = excluded.updated_at`,
		header, accent, bar1, bar2, bar3, time.Now().Unix())
	return err
}

// GetAppSettings returns the runtime settings row, if saved.
func (s *SQLite) GetAppSettings(ctx context.Context) (AppSettings, error) {
	var a AppSettings
	var updated int64
	err := s.db.QueryRowContext(ctx,
		`SELECT breakglass_secs, notify_emails, webhook_url, updated_at FROM app_settings WHERE id = 1`).
		Scan(&a.BreakGlassSecs, &a.NotifyEmails, &a.WebhookURL, &updated)
	if err == sql.ErrNoRows {
		return AppSettings{}, nil
	}
	if err != nil {
		return AppSettings{}, err
	}
	a.Exists = true
	a.UpdatedAt = time.Unix(updated, 0)
	return a, nil
}

// SaveAppSettings upserts the runtime settings.
func (s *SQLite) SaveAppSettings(ctx context.Context, breakglassSecs int, notifyEmails, webhookURL string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_settings (id, breakglass_secs, notify_emails, webhook_url, updated_at)
		 VALUES (1, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			breakglass_secs = excluded.breakglass_secs, notify_emails = excluded.notify_emails,
			webhook_url = excluded.webhook_url, updated_at = excluded.updated_at`,
		breakglassSecs, notifyEmails, webhookURL, time.Now().Unix())
	return err
}

// SaveBrandingText upserts the text fields, leaving any stored images intact.
func (s *SQLite) SaveBrandingText(ctx context.Context, title, body, instructions string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pdf_branding (id, title, body, instructions, updated_at)
		 VALUES (1, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			title = excluded.title, body = excluded.body,
			instructions = excluded.instructions, updated_at = excluded.updated_at`,
		title, body, instructions, time.Now().Unix())
	return err
}

// SetBrandingImage stores or replaces the logo or glyph image.
func (s *SQLite) SetBrandingImage(ctx context.Context, which BrandingImage, data []byte, mime string) error {
	col, typeCol := brandingImageColumns(which)
	if col == "" {
		return fmt.Errorf("store: unknown branding image %q", which)
	}
	// Ensure the singleton row exists, then update the targeted columns.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO pdf_branding (id, updated_at) VALUES (1, ?) ON CONFLICT(id) DO NOTHING`,
		time.Now().Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE pdf_branding SET `+col+` = ?, `+typeCol+` = ?, updated_at = ? WHERE id = 1`,
		data, mime, time.Now().Unix())
	return err
}

// ClearBrandingImage removes the logo or glyph image.
func (s *SQLite) ClearBrandingImage(ctx context.Context, which BrandingImage) error {
	col, typeCol := brandingImageColumns(which)
	if col == "" {
		return fmt.Errorf("store: unknown branding image %q", which)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE pdf_branding SET `+col+` = NULL, `+typeCol+` = '', updated_at = ? WHERE id = 1`,
		time.Now().Unix())
	return err
}

// brandingImageColumns maps an image slot to its (blob, mime) column names.
// Returning fixed literals keeps these out of user-influenced SQL.
func brandingImageColumns(which BrandingImage) (blobCol, typeCol string) {
	switch which {
	case BrandingLogo:
		return "logo", "logo_type"
	case BrandingGlyph:
		return "glyph", "glyph_type"
	case BrandingPDFLogo:
		return "pdf_logo", "pdf_logo_type"
	default:
		return "", ""
	}
}

package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// adminData carries everything the admin templates might need.
type adminData struct {
	Title   string
	Message string
	CSRF    string
	// Shell: the page being shown (highlights its menu item), the signed-in
	// administrator, and a one-line confirmation of the action just taken.
	Active     string
	AdminEmail string
	Notice     string
	Warning    string
	// Group page: the group shown, so the menu marks Groups.
	OpenGroup string
	// Overview page.
	Overview *overviewView
	// Bulk add confirmation page.
	Bulk   *bulkPlan
	Groups []groupView
	// Group page: the one group shown.
	Group *groupView
	// Groups page: groups the routes require that do not exist yet, and
	// whether the route manifest (ROUTE_GROUPS_FILE) was read at all.
	MissingGroups []missingGroupView
	RouteGroupsOn bool
	Codes         []codeView
	Code          codeView
	// Codes page: the groups offered as a card's target, refused ones marked.
	TargetOptions []targetOptionView
	Events        []store.BreakGlassEvent
	Settings      settingsView
	// Break-glass cards: the list, the new-card form, one card's page, the
	// designs and the design editor (admin_cards.go, admin_designs.go).
	Cards    *cardsView
	NewCard  *newCardView
	CardPage *cardPageView
	Designs  *designsView
	DesignEd *designEditView
	// Admin two-factor page.
	TOTPEnabled bool
	TOTPAdmins  []totpAdminView
	NewTOTP     *newTOTPView // freshly minted secret, shown once
	// Access-log page.
	FilterEmail string
	Access      *accessView
	// Admin-action audit page.
	AdminEvents []adminEventView
	// Access page, filtered to one person, with passkeys on.
	PasskeysOn      bool
	Passkeys        []passkeyRow
	PasskeyRenew    string
	PasskeysRemoved bool
	// App roles: the Apps overview, one app's page, and whether the model is
	// on (which shows the Apps menu item). Script is a page's inline script,
	// allowed by its hash (see rolesScript).
	RolesOn bool
	Apps    *appsView
	App     *appView
	Script  template.JS
	// New group page.
	NewGroup *newGroupView
	// Invitations pages.
	Invites   *invitesView
	NewInvite *newInviteView
	// Access log, one person chosen: offer to sign them out everywhere.
	EndSessionsFor string
	SessionsEnded  bool
}

// stamp renders t in the configured display timezone (default UTC). The "MST"
// token prints the zone abbreviation (e.g. AEDT/AEST/UTC) so the offset is
// unambiguous. stampMin drops the seconds.
func (s *Server) stamp(t time.Time) string    { return t.In(s.tzloc()).Format("2006-01-02 15:04:05 MST") }
func (s *Server) stampMin(t time.Time) string { return t.In(s.tzloc()).Format("2006-01-02 15:04 MST") }

func (s *Server) tzloc() *time.Location {
	if s.loc == nil {
		return time.UTC
	}
	return s.loc
}

// totpAdminView is one configured admin's enrolment status on the 2FA page.
type totpAdminView struct {
	Email    string
	Enrolled bool
}

// newTOTPView carries a just-provisioned secret for one-time display.
type newTOTPView struct {
	Email string
	URL   string
	Key   string
}

type settingsView struct {
	BreakGlassHours string
	NotifyEmails    string
	WebhookURL      string
	WebhookTimeout  string
	HasLogo         bool
}

type groupView struct {
	Name    string
	Label   string
	Members []memberView
	// Hosts whose routes require this group, from the route manifest.
	Hosts []string
	// Unused: the manifest was read and no route names this group, no
	// break-glass card targets it, and no other group includes it.
	Unused bool
	// Includes are the groups whose members this group also admits;
	// IncludedIn the groups that admit this group's members. IncludeOptions
	// are the other groups offered in the "include" menu.
	Includes       []string
	IncludedIn     []string
	IncludeOptions []string
	// Feed is set for a group filled from an endpoint.
	Feed *feedView
	// NotYetCreated: the feed is configured but has never answered, so the
	// group row does not exist yet; the first successful sync creates it.
	NotYetCreated bool
	// App roles (fillGroupRoles): the kind, a domain group's domains, whom
	// the group admits, and the app roles it holds.
	Kind      string
	Domains   []string
	Who       string
	Roles     []appRoleRef
	RoleCount int
	AppCount  int
	UsedBy    string
	// Org is a domain group's organisation name, and OrgText the field's
	// wording.
	Org     string
	OrgText orgNameCopy
}

// feedView is a feed-filled group's source and last sync, for the Groups page.
type feedView struct {
	Host        string // host of the feed URL only; the path may carry secrets
	Status      string
	Detail      string
	LastAttempt string
	LastSuccess string
	// Since is the day of the last successful sync, as "9 November".
	Since   string
	Pending bool
	// The held change, exactly as it would be applied, and its hash (sent
	// back with Accept so only the change on screen can be accepted).
	PendingAdd    []string
	PendingRemove []string
	PendingHash   string
	// AutoAt is when the held change applies on its own; Kept, that an
	// administrator chose to keep the current members instead.
	AutoAt string
	Kept   bool
	// Retry is set while a failed fetch is waiting to be tried again.
	Retry *feedRetryView
}

// feedRetryView is a waiting retry, for the Groups page.
type feedRetryView struct {
	At, Next string
	Reason   string
	Left     int // attempts still to come
}

// overviewView is the admin home page: counts, and the items that need an
// administrator's attention. Break-glass target groups are left out of
// MissingGroups, because a card needs no group to exist.
type overviewView struct {
	Apps              int // apps in the app-roles manifest
	Groups            int
	Members           int
	ActiveCards       int
	RouteGroupsOn     bool
	MissingGroups     []string
	UnusedGroups      []string
	TOTPEnabled       bool
	AdminsWithoutTOTP []string
	// FeedProblems are feed-filled groups whose last sync failed, came back
	// empty or was held.
	FeedProblems []string
	// FeedIncludes are synced groups that still include other groups (made
	// before the group was synced), which widens "whoever the feed lists".
	FeedIncludes []string
	// Sites is the "who can reach what" table (ROUTE_ACCESS_FILE); nil
	// leaves the table out.
	Sites []siteAccessView
}

// Attention reports whether anything on the overview needs action.
func (o *overviewView) Attention() bool {
	return len(o.MissingGroups) > 0 || len(o.UnusedGroups) > 0 || len(o.AdminsWithoutTOTP) > 0 || len(o.FeedProblems) > 0 || len(o.FeedIncludes) > 0
}

// missingGroupView is a group a route requires that has not been created.
// CardTarget marks a group a break-glass card targets, which needs no members
// to work.
type missingGroupView struct {
	Name       string
	Hosts      []string
	CardTarget bool
}

// memberView is one row of a group's member list. Permitted reports whether the
// allow-list (ALLOWED_EMAIL_DOMAINS / ADMIN_EMAILS) still admits the address.
// A membership for an address it does not admit used to be inert, because that
// address could never sign in; once any host is listed in
// OPEN_REGISTRATION_HOSTS the same address can sign in as a guest and the
// membership admits it to every group guard naming this group. The page marks
// such rows so an admin can see which memberships are live doors for strangers.
type memberView struct {
	Email     string
	Permitted bool
	// AddedFrom is the address a feed made this one from, if it did.
	AddedFrom string
}

type codeView struct {
	ID          int64
	Label       string
	Note        string
	TargetGroup string
	Redirect    string
	Status      string
	Active      bool
	Created     string
	Updated     string
	// Refused is the short reason the target group may no longer be a card's
	// target (see refusedTargets); empty for a group that may. A card made
	// before the group became an application role keeps working, so the list
	// marks it for the administrator to reconsider.
	Refused string
}

func (s *Server) toCodeView(c store.BreakGlassCode) codeView {
	return codeView{
		ID:          c.ID,
		Label:       c.Label,
		Note:        c.Note,
		TargetGroup: c.TargetGroup,
		Redirect:    c.Redirect,
		Status:      c.Status,
		Active:      c.Status == store.BreakGlassActive,
		Created:     s.stampMin(c.CreatedAt),
		Updated:     s.stampMin(c.UpdatedAt),
	}
}

// adminEventView is one administrative-action row on the admin audit page.
type adminEventView struct {
	Time        string
	Actor       string
	Action      string
	ActionLabel string // plain-English name of Action
	Target      string
	Detail      string
	ClientIP    string
	UserAgent   string
}

// adminActionLabels names each audited action for the audit page. An action
// missing here (from a newer build) is shown by its code.
var adminActionLabels = map[string]string{
	store.AdminActionBreakCreate:        "Card created",
	store.AdminActionBreakRevoke:        "Card withdrawn",
	store.AdminActionBreakRemint:        "Card replaced",
	store.AdminActionCodeBranding:       "Card design changed",
	store.AdminActionCardDesign:         "Card given another design",
	store.AdminActionDesignCreate:       "Card design created",
	store.AdminActionDesignSave:         "Card design saved",
	store.AdminActionDesignDelete:       "Card design deleted",
	store.AdminActionGroupCreate:        "Group created",
	store.AdminActionGroupDelete:        "Group deleted",
	store.AdminActionGroupLabel:         "Group label changed",
	store.AdminActionGroupAddMember:     "Member added",
	store.AdminActionGroupRemoveMember:  "Member removed",
	store.AdminActionGroupIncludeAdd:    "Group included",
	store.AdminActionGroupIncludeRemove: "Group no longer included",
	store.AdminActionGroupSync:          "Group synced from feed",
	store.AdminActionTOTPGenerate:       "Two-factor secret issued",
	store.AdminActionTOTPRemove:         "Two-factor removed",
	store.AdminActionSessionsEnd:        "Signed out on every device",
	store.AdminActionSettingsUpdate:     "Settings changed",
	store.AdminActionBrandingUpdate:     "Branding changed",
	store.AdminActionRoleGive:           "App role given",
	store.AdminActionRoleTake:           "App role taken away",
	store.AdminActionGroupDomainAdd:     "Domain added to a group",
	store.AdminActionGroupDomainRemove:  "Domain removed from a group",
}

func adminActionLabel(action string) string {
	if l, ok := adminActionLabels[action]; ok {
		return l
	}
	return action
}

func (s *Server) toAdminEventViews(es []store.AdminEvent) []adminEventView {
	out := make([]adminEventView, 0, len(es))
	for _, e := range es {
		out = append(out, adminEventView{
			Time:        s.stamp(e.CreatedAt),
			Actor:       e.Actor,
			Action:      e.Action,
			ActionLabel: adminActionLabel(e.Action),
			Target:      e.Target,
			Detail:      e.Detail,
			ClientIP:    e.ClientIP,
			UserAgent:   e.UserAgent,
		})
	}
	return out
}

func loadAdminTemplates(loc *time.Location) (pages, error) {
	if loc == nil {
		loc = time.UTC
	}
	funcs := template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.In(loc).Format("2006-01-02 15:04:05 MST") },
	}
	base, err := template.New("admin_base.html").Funcs(funcs).ParseFS(templatesFS, "templates/admin_base.html", "templates/admin_roles_parts.html", "templates/admin_groups_css.html", "templates/admin_cards_parts.html")
	if err != nil {
		return nil, err
	}
	out := make(pages)
	for _, name := range []string{"admin_home", "admin_message", "admin_groups", "admin_group", "admin_bulk_add", "admin_codes", "admin_code_detail", "admin_card_new", "admin_designs", "admin_design", "admin_settings", "admin_totp", "admin_access", "admin_audit", "admin_apps", "admin_app", "admin_group_new"} {
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := t.ParseFS(templatesFS, "templates/"+name+".html"); err != nil {
			return nil, err
		}
		out[name] = t
	}
	if err := addPages(out, base, adminInvitePages, "admin_invites_css.html"); err != nil {
		return nil, err
	}
	return out, nil
}

// renderAdmin renders an admin page with the relaxed (image-allowing) CSP and a
// fresh-or-existing CSRF token. The CSRF cookie is set before the status line.
func (s *Server) renderAdmin(w http.ResponseWriter, r *http.Request, status int, page string, data adminData) {
	t, ok := s.adminPages[page]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if tok, err := s.sessions.EnsureCSRF(w, r, csrfTTL, s.now()); err == nil {
		data.CSRF = tok
	}
	data.Active = page
	if id, ok := s.readSession(r, s.now()); ok {
		data.AdminEmail = id.Email
	}
	if data.Notice == "" && data.Warning == "" {
		data.Notice, data.Warning = s.takeNotice(w, r)
	}
	data.RolesOn = s.rolesOn()
	csp := s.csp
	if data.Script != "" {
		csp += "; script-src " + scriptHash(string(data.Script))
	}
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		fmt.Fprint(w, "internal error")
	}
}

func (s *Server) adminError(w http.ResponseWriter, r *http.Request) {
	s.renderAdmin(w, r, http.StatusInternalServerError, "admin_message", adminData{
		Title: "Something went wrong", Message: "The operation could not be completed.",
	})
}

// normalizeGroupName lowercases and trims a group name.
func normalizeGroupName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func trimField(s string) string { return strings.TrimSpace(s) }

// hexOrDefault validates a "#rrggbb" colour, returning def if malformed.
func hexOrDefault(s, def string) string {
	s = strings.TrimSpace(s)
	if len(s) != 7 || s[0] != '#' {
		return def
	}
	for _, r := range s[1:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return def
		}
	}
	return strings.ToLower(s)
}

// pdfFilename builds a safe download filename from a code label.
func pdfFilename(label string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(label) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		name = "break-glass"
	}
	return name + ".pdf"
}

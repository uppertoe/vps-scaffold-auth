package server

import (
	"fmt"
	"sort"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The move to app roles. A site still on an older guard (protected_domains,
// protected_groups and the like) admits people by the rule route-access.tsv
// lists for it. The Apps pages show each such site with that rule, and a
// pending app (an app whose roles are declared before its site moves; see
// internal/roles/manifest.go) with both its roles and the rule. The Groups
// pages name every use of a group: its roles, the older guards that name it,
// the groups that include it and the apps it is fed to.

// The strings of the move to roles. Each is kept here, once.
const (
	msgPendingTag    = "Not yet using roles"
	msgPendingNote   = "%[1]s still admits people by its older guard, which is shown below. Roles given here take effect once %[1]s moves to roles."
	msgPendingState  = "State"
	msgOlderRow      = "Older guard"
	msgOlderHead     = "Sites not yet using roles"
	msgOlderNote     = "Each site below admits people by its older guard, which is set in the site's snippet rather than here."
	msgOlderAppNone  = "The route manifest lists no rule for %s."
	msgOlderDeclared = "The older guard is declared in %s."

	msgOlderSignedIn    = "Anyone signed in"
	msgOlderDomainTitle = "Anyone signed in with an address at %s."
	msgOlderAdmins      = "Administrators"
	msgOlderOpen        = "Open by design"
	msgOlderOpenSome    = "%s open by design"

	msgPendingLastHolder   = "Nobody will hold %s once this is saved, so the role will admit nobody when %s moves to roles."
	msgPendingNetworkOpens = "Anyone on the %s will reach %s without signing in once the site moves to roles."
	msgPendingGuestsOpen   = "Anyone who confirms an email address will reach %s once the site moves to roles."
	// msgPendingNobodyAfter ends the attention line "Nobody holds the User
	// role in <app>" for a pending app.
	msgPendingNobodyAfter = ", so nobody will reach it once it moves to roles."

	msgUseOlder       = "%s (older guard)"
	msgUseIncluded    = "Included in %s"
	msgUseFeed        = "Feed to %s"
	msgOtherUsesHead  = "Also used by"
	msgNoNameSet      = "No name set"
	msgDomainGroupsBy = "Sites on older guards still admit people by email domain directly until they move to roles."
	msgNotUsedTitle   = "This group holds no app role. No sign-in rule, feed, app, setting, other group or break-glass card names it, so the group may be left over from an app that has been removed."
)

// olderSiteView is one site on an older guard, as a row of the Apps pages:
// its name and host, a token for each part of its rule, and the widest
// access the rule gives.
type olderSiteView struct {
	Name, Host string
	Row        roleRowView
}

// siteName names a site for people: the label of the app that serves the
// host, or the host's first label with a capital ("planka.example.org" is
// "Planka"). The apex is named by the domain itself.
func (s *Server) siteName(host string) string {
	for _, a := range s.appRoles.Apps {
		if a.ServesHost(host) {
			return a.Label
		}
	}
	if host == s.cfg.Domain {
		return host
	}
	first, _, _ := strings.Cut(strings.TrimSuffix(host, "."+s.cfg.Domain), ".")
	return capFirst(first)
}

// olderSites are the sites route-access.tsv lists that no app in the
// manifest serves and no role guard guards, sorted by name. Sites of a
// pending app are its own, so they are left out too.
func (s *Server) olderSites(w *rolesWorld, sites []siteAccessView) []olderSiteView {
	var out []olderSiteView
	for _, site := range sites {
		if site.Roles || s.servedByApp(site.Host) || len(site.Rules) == 0 {
			continue
		}
		out = append(out, olderSiteView{Name: s.siteName(site.Host), Host: site.Host, Row: s.olderRow(w, site.Rules)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name); a != b {
			return a < b
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func (s *Server) servedByApp(host string) bool {
	for _, a := range s.appRoles.Apps {
		if a.ServesHost(host) {
			return true
		}
	}
	return false
}

// pendingRows are a pending app's older rules as rows, one for each of its
// hosts route-access.tsv lists, named by host when it has more than one.
func (s *Server) pendingRows(w *rolesWorld, a *roles.App, sites []siteAccessView) []roleRowView {
	older := s.olderRulesFor(a, sites)
	var out []roleRowView
	for _, site := range older {
		row := s.olderRow(w, site.Rules)
		if len(older) > 1 {
			row.Paths, row.PathsMono = site.Host, true
		}
		out = append(out, row)
	}
	return out
}

// olderRulesFor returns the rules of each of the app's hosts that
// route-access.tsv lists, for a pending app.
func (s *Server) olderRulesFor(a *roles.App, sites []siteAccessView) []siteAccessView {
	var out []siteAccessView
	for _, site := range sites {
		if a.ServesHost(site.Host) && len(site.Rules) > 0 {
			out = append(out, site)
		}
	}
	return out
}

// olderRow draws an older rule as a role row does its holders: a token for
// each network, guests, domain and group the rule names, in the role rows'
// order, then one for the paths open by design. The widest access counts
// the whole-site rules only, as a role row's does.
func (s *Server) olderRow(w *rolesWorld, rules []accessRuleView) roleRowView {
	row := roleRowView{Label: msgOlderRow}
	var net, guests, people, doms, groups, open []tokenView
	var openPaths []string
	level := 0
	for _, r := range rules {
		switch r.Kind {
		case "network":
			for _, n := range r.Values {
				net = append(net, s.holderToken(w, store.AssignNetwork, strings.ToLower(n)))
			}
			level = max(level, holderLevel[store.AssignNetwork])
		case "guests":
			guests = append(guests, s.holderToken(w, store.AssignGuests, ""))
			level = max(level, holderLevel[store.AssignGuests])
		case "signed-in":
			people = append(people, tokenView{Icon: iconPerson, Label: msgOlderSignedIn, Title: msgOlderSignedIn + ".", Level: 3})
			level = max(level, 3)
		case "domains":
			for _, d := range r.Values {
				doms = append(doms, tokenView{Icon: iconDomain, Label: "@" + d, Title: fmt.Sprintf(msgOlderDomainTitle, d), Level: 3})
			}
			level = max(level, 3)
		case "groups":
			for _, g := range r.Values {
				groups = append(groups, s.olderGroupToken(w, g))
			}
			level = max(level, 2)
		case "public":
			paths, reason, isPaths := openPathsOf(r.Reason)
			if isPaths {
				openPaths = append(openPaths, paths+": "+reason)
				continue
			}
			open = append(open, tokenView{Icon: iconLock, Label: msgOlderOpen, Title: r.Reason, Level: 6})
			level = max(level, 6)
		}
	}
	if len(openPaths) > 0 {
		open = append(open, tokenView{Icon: iconLock, Label: fmt.Sprintf(msgOlderOpenSome, capFirst(numberWord(len(openPaths)))), Title: strings.Join(openPaths, "\n")})
	}
	for _, ts := range [][]tokenView{net, guests, people, doms, groups, open} {
		row.Tokens = append(row.Tokens, ts...)
	}
	for i := range row.Tokens {
		if row.Tokens[i].Level == level && level > 1 {
			row.Tokens[i].Widest = true
		}
	}
	row.Reach = s.reach(level)
	capTokens(&row)
	return row
}

// olderGroupToken draws a group an older guard names, linked to its page.
// admin is the administrators, and a group that does not exist is drawn as
// missing.
func (s *Server) olderGroupToken(w *rolesWorld, name string) tokenView {
	if name == "admin" {
		return tokenView{Icon: iconPerson, Label: msgOlderAdmins, Title: msgOlderAdmins + ".", Level: 2}
	}
	g, ok := w.groups[name]
	if !ok {
		return tokenView{Icon: iconNone, Tone: "gone", Label: name, Title: msgReaderNoGroup, Level: 2}
	}
	kind := store.AssignList
	if g.Kind == store.GroupKindDomain {
		kind = store.AssignDomainGroup
	}
	t := s.holderToken(w, kind, name)
	t.Href, t.Level = "/admin/groups/"+name, 2
	return t
}

// openPathsOf splits an open path's reason, "<paths>: <why>", where every
// path begins with "/". isPaths is false for a whole site's reason.
func openPathsOf(reason string) (paths, why string, isPaths bool) {
	paths, why, ok := strings.Cut(reason, ": ")
	if !ok {
		return "", reason, false
	}
	for _, p := range strings.Fields(paths) {
		if !strings.HasPrefix(p, "/") {
			return "", reason, false
		}
	}
	return paths, why, paths != ""
}

// --- Groups: every use of a group ---

// groupsCopy is the Groups pages' wording for the move to roles.
type groupsCopy struct {
	NoName, OtherUses, DomainGroupsBy, NotUsedTitle string
}

var groupsText = groupsCopy{NoName: msgNoNameSet, OtherUses: msgOtherUsesHead, DomainGroupsBy: msgDomainGroupsBy, NotUsedTitle: msgNotUsedTitle}

// groupUse is one use of a group: an app role it holds, an older guard that
// names it, a group that includes it, or an app it is fed to.
type groupUse struct {
	Label, Href, Icon string
}

// groupUses lists the uses of a group other than its roles, in that order:
// the older guards that name it (by site), the groups that include it, and
// the apps that read its members.
func (s *Server) groupUses(g *groupView, readers map[string][]string) []groupUse {
	var out []groupUse
	seen := map[string]bool{}
	for _, h := range g.Hosts {
		name := s.siteName(h)
		if seen[name] {
			continue
		}
		seen[name] = true
		u := groupUse{Label: fmt.Sprintf(msgUseOlder, name), Icon: "app"}
		for _, a := range s.appRoles.Apps {
			if a.ServesHost(h) {
				u.Href = "/admin/apps/" + a.Name
			}
		}
		out = append(out, u)
	}
	for _, ref := range g.IncludedInRefs {
		out = append(out, groupUse{Label: fmt.Sprintf(msgUseIncluded, ref.Label), Href: "/admin/groups/" + ref.Name, Icon: "list"})
	}
	var apps []string
	for app, groups := range readers {
		for _, gr := range groups {
			if gr == g.Name {
				apps = append(apps, app)
			}
		}
	}
	sort.Strings(apps)
	for _, app := range apps {
		label := capFirst(app)
		if a, ok := s.appRoles.Apps[app]; ok {
			label = a.Label
		}
		out = append(out, groupUse{Label: fmt.Sprintf(msgUseFeed, label), Href: appFeedsPath, Icon: "feed"})
	}
	return out
}

// readerGroups are the groups each app reads from the members endpoint, from
// the readers file and MEMBER_READERS, usable or not.
func (s *Server) readerGroups() map[string][]string {
	out := map[string][]string{}
	for app, gs := range s.cfg.MemberReadersFilePairs {
		out[app] = append(out[app], gs...)
	}
	for _, r := range s.members.readers {
		if !r.fromFile {
			out[r.app] = append(out[r.app], r.groups...)
		}
	}
	for _, u := range s.cfg.UnusableMemberReaders {
		if _, listed := s.cfg.MemberReadersFilePairs[u.App]; !listed {
			out[u.App] = append(out[u.App], u.Groups...)
		}
	}
	for app, gs := range out {
		sort.Strings(gs)
		out[app] = compactStrings(gs)
	}
	return out
}

func compactStrings(xs []string) []string {
	var out []string
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// markPending marks a pending app's block and adds its older guard's rows.
func (s *Server) markPending(w *rolesWorld, a *roles.App, b *appBlockView, sites []siteAccessView) {
	b.PendingTag, b.PendingTitle = msgPendingTag, fmt.Sprintf(msgPendingNote, a.Label)
	b.Older = s.pendingRows(w, a, sites)
}

// olderMatches is the Apps filter for a site on an older guard: its name or
// host, or the label of a token in its rule.
func olderMatches(o olderSiteView, f string) bool {
	if strings.Contains(strings.ToLower(o.Name), f) || strings.Contains(o.Host, f) {
		return true
	}
	for _, t := range o.Row.Tokens {
		if strings.Contains(strings.ToLower(t.Label), f) {
			return true
		}
	}
	return false
}

// pendingPage fills a pending app's page: the note, the state in the facts,
// and the older guard's rule for each of the app's hosts.
func (s *Server) pendingPage(w *rolesWorld, a *roles.App, v *appView) {
	v.PendingApp = true
	v.PendingNote = fmt.Sprintf(msgPendingNote, a.Label)
	v.StateHead, v.StateText = msgPendingState, msgPendingTag
	v.OlderHead = msgOlderRow
	sites := s.readRouteAccess()
	for _, site := range s.olderRulesFor(a, sites) {
		v.Older = append(v.Older, olderSiteView{Name: a.Label, Host: site.Host, Row: s.olderRow(w, site.Rules)})
	}
	if len(v.Older) == 0 {
		v.OlderNote = fmt.Sprintf(msgOlderAppNone, a.Label)
	} else if a.Source != "" {
		v.OlderNote = fmt.Sprintf(msgOlderDeclared, a.Source)
	}
}

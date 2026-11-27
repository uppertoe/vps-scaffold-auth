package server

import (
	"bufio"
	"log"
	"os"
	"sort"
	"strings"
)

// The Overview's "Who can reach what" wording. Each is kept here, once.
const (
	msgReachIntro = "Each site admits anyone who meets one of its rules, and a site may apply different rules to different paths. For a site behind app roles, the app's page lists who holds each role."
	// msgReachRoles is a role-guarded site's line; %s is the app, linked to
	// its page.
	msgReachRoles = "App roles: see %s"
)

// siteAccessView is one row of the overview's "who can reach what" table.
type siteAccessView struct {
	Host string
	// Rules are the site's paths open by design ("public" in the file).
	Rules []accessRuleView
	// RoleApps are the apps whose roles guard the site ("roles" in the
	// file), in the file's order, each listed once; the overview's table
	// points to each app's page.
	RoleApps []siteRoleApp
}

// siteRoleApp is an app whose roles guard a site, for the overview's table:
// Label is the app's label, Href its Apps page, and Before and After the
// words of its line on either side of the label.
type siteRoleApp struct {
	Name, Label, Href string
	Before, After     string
}

// accessRuleView is a site's open paths: Kind is "public", and Reason the
// public marker's explanation. The scaffold writes no other kind of rule
// since it refuses the older guards; a line of any other kind is skipped.
type accessRuleView struct {
	Kind   string
	Reason string
}

// routeAccess reads ROUTE_ACCESS_FILE for the overview's table, which lists
// every site with a rule, a role guard included. It returns nil when the
// feature is off or the file cannot be read; the overview then leaves the
// table out.
func (s *Server) routeAccess() []siteAccessView {
	all := s.readRouteAccess()
	if all == nil {
		return nil
	}
	out := make([]siteAccessView, 0, len(all))
	for _, v := range all {
		if len(v.Rules) > 0 || len(v.RoleApps) > 0 {
			out = append(out, v)
		}
	}
	return out
}

// readRouteAccess reads every site in ROUTE_ACCESS_FILE, sorted by host. It
// returns nil when the feature is off or the file cannot be read.
func (s *Server) readRouteAccess() []siteAccessView {
	path := s.cfg.RouteAccessFile
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("route access: %v", err)
		return nil
	}
	defer f.Close()

	byHost := map[string]*siteAccessView{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			continue
		}
		kind := strings.TrimSpace(parts[1])
		if kind != "public" && kind != "roles" {
			continue
		}
		value := ""
		if len(parts) == 3 {
			value = strings.TrimSpace(parts[2])
		}
		for _, h := range strings.Split(parts[0], ",") {
			h = strings.TrimSpace(strings.ReplaceAll(h, "{$DOMAIN}", s.cfg.Domain))
			if h == "" {
				continue
			}
			v := byHost[h]
			if v == nil {
				v = &siteAccessView{Host: h}
				byHost[h] = v
			}
			if kind == "roles" {
				if app, _, _ := strings.Cut(value, " "); app != "" {
					v.addRoleApp(s.roleAppRef(app))
				}
				continue
			}
			v.Rules = append(v.Rules, accessRuleView{Kind: kind, Reason: value})
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("route access: %v", err)
		return nil
	}
	out := make([]siteAccessView, 0, len(byHost))
	for _, v := range byHost {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// roleAppRef is an app named by a role guard, linked to its Apps page. An
// app the manifest does not list is named as written, without a link.
func (s *Server) roleAppRef(app string) siteRoleApp {
	ref := siteRoleApp{Name: app, Label: app}
	if a, ok := s.appRoles.Apps[app]; ok {
		ref.Label, ref.Href = a.Label, "/admin/apps/"+app
	}
	ref.Before, ref.After, _ = strings.Cut(msgReachRoles, "%s")
	return ref
}

// addRoleApp adds an app to a site's role apps, once.
func (v *siteAccessView) addRoleApp(ref siteRoleApp) {
	for _, r := range v.RoleApps {
		if r.Name == ref.Name {
			return
		}
	}
	v.RoleApps = append(v.RoleApps, ref)
}

package server

import (
	"bufio"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
)

// routeManifest is the scaffold-rendered list of the gateway groups the
// routes use (ROUTE_GROUPS_FILE). Hosts maps group -> sorted hosts. Declared
// holds the groups an app reads from Remote-Groups itself (a
// "# scaffold-groups:" marker in its snippet), which the renderer marks with
// a "declared" flag in the line's third field; the app decides what such a
// group means, so the gateway treats it as an application role.
type routeManifest struct {
	Hosts    map[string][]string
	Declared map[string]bool
}

// routeGroups reads the route manifest and returns group -> sorted hosts. The
// bool is false when the feature is off or the file cannot be read, so
// callers can tell "no manifest" apart from "no route names a group".
func (s *Server) routeGroups() (map[string][]string, bool) {
	m, ok := s.readRouteManifest()
	if !ok {
		return nil, false
	}
	return m.Hosts, true
}

// readRouteManifest parses ROUTE_GROUPS_FILE: one "group<TAB>host[<TAB>flags]"
// per line, # comments. {$DOMAIN} in a host is replaced with the configured
// domain. Reserved role names (admin, user, guest) are left out: they are
// roles, not groups an administrator creates. The flags field, when present,
// is a space-separated list; "declared" is the only flag read.
func (s *Server) readRouteManifest() (routeManifest, bool) {
	path := s.cfg.RouteGroupsFile
	if path == "" {
		return routeManifest{}, false
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("route groups: %v", err)
		return routeManifest{}, false
	}
	defer f.Close()

	sets := map[string]map[string]struct{}{}
	declared := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		group := normalizeGroupName(fields[0])
		if len(fields) < 2 || group == "" || authz.IsReservedGroup(group) || !authz.ValidGroupName(group) {
			continue
		}
		if sets[group] == nil {
			sets[group] = map[string]struct{}{}
		}
		for _, h := range strings.Split(fields[1], ",") {
			h = strings.TrimSpace(strings.ReplaceAll(h, "{$DOMAIN}", s.cfg.Domain))
			if h != "" {
				sets[group][h] = struct{}{}
			}
		}
		if len(fields) > 2 {
			for _, flag := range strings.Fields(fields[2]) {
				if strings.EqualFold(flag, "declared") {
					declared[group] = true
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("route groups: %v", err)
		return routeManifest{}, false
	}

	out := make(map[string][]string, len(sets))
	for g, hs := range sets {
		list := make([]string, 0, len(hs))
		for h := range hs {
			list = append(list, h)
		}
		sort.Strings(list)
		out[g] = list
	}
	return routeManifest{Hosts: out, Declared: declared}, true
}

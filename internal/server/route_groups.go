package server

import (
	"bufio"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
)

// routeGroups reads the scaffold-rendered manifest of the gateway groups each
// route requires (ROUTE_GROUPS_FILE, "group<TAB>host" per line, # comments)
// and returns group -> sorted hosts. {$DOMAIN} in a host is replaced with the
// configured domain. Reserved role names (admin, user, guest) are left out:
// they are roles, not groups an administrator creates. The bool is false when
// the feature is off or the file cannot be read, so callers can tell "no
// manifest" apart from "no route names a group".
func (s *Server) routeGroups() (map[string][]string, bool) {
	path := s.cfg.RouteGroupsFile
	if path == "" {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("route groups: %v", err)
		return nil, false
	}
	defer f.Close()

	sets := map[string]map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		group, hosts, ok := strings.Cut(line, "\t")
		group = normalizeGroupName(group)
		if !ok || group == "" || authz.IsReservedGroup(group) || !authz.ValidGroupName(group) {
			continue
		}
		if sets[group] == nil {
			sets[group] = map[string]struct{}{}
		}
		for _, h := range strings.Split(hosts, ",") {
			h = strings.TrimSpace(strings.ReplaceAll(h, "{$DOMAIN}", s.cfg.Domain))
			if h != "" {
				sets[group][h] = struct{}{}
			}
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("route groups: %v", err)
		return nil, false
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
	return out, true
}

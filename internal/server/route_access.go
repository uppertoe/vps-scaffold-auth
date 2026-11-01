package server

import (
	"bufio"
	"log"
	"os"
	"sort"
	"strings"
)

// siteAccessView is one row of the overview's "who can reach what" table.
type siteAccessView struct {
	Host  string
	Rules []accessRuleView
}

// accessRuleView is one access rule on a site. Kind is one of groups, domains,
// signed-in, guests, network or public; Values holds the groups, domains or
// network name, and Reason the public marker's explanation.
type accessRuleView struct {
	Kind   string
	Values []string
	Reason string
}

var accessKindOrder = map[string]int{"public": 0, "network": 1, "guests": 2, "signed-in": 3, "domains": 4, "groups": 5}

// routeAccess reads ROUTE_ACCESS_FILE. It returns nil when the feature is off
// or the file cannot be read; the overview then leaves the table out.
func (s *Server) routeAccess() []siteAccessView {
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
		if _, ok := accessKindOrder[kind]; !ok {
			continue
		}
		value := ""
		if len(parts) == 3 {
			value = strings.TrimSpace(parts[2])
		}
		rule := accessRuleView{Kind: kind}
		switch kind {
		case "public":
			rule.Reason = value
		case "network":
			rule.Values = []string{strings.ToUpper(value)}
		case "groups", "domains":
			rule.Values = strings.Fields(value)
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
			v.Rules = append(v.Rules, rule)
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("route access: %v", err)
		return nil
	}
	out := make([]siteAccessView, 0, len(byHost))
	for _, v := range byHost {
		sort.SliceStable(v.Rules, func(i, j int) bool { return accessKindOrder[v.Rules[i].Kind] < accessKindOrder[v.Rules[j].Kind] })
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

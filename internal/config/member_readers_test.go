package config

import (
	"strings"
	"testing"
)

const readerToken = "0123456789abcdef0123456789abcdef-a"

func TestMemberReaders(t *testing.T) {
	setValid(t)
	t.Setenv("MEMBER_READER_TOKEN_TEACHING_CASES", readerToken)
	t.Setenv("MEMBER_READERS", "teaching-cases=teaching_cases_coordinators,Rch-Consultants,rch-consultants")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MemberReaders) != 1 || c.MemberReaders[0].App != "teaching-cases" ||
		strings.Join(c.MemberReaders[0].Groups, " ") != "teaching_cases_coordinators rch-consultants" ||
		c.MembersListenAddr != DefaultMembersListenAddr {
		t.Fatalf("readers = %+v on %q", c.MemberReaders, c.MembersListenAddr)
	}
}

func TestMemberReadersOffByDefault(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MemberReaders) != 0 || c.MembersListenAddr != "" {
		t.Fatalf("readers = %+v on %q", c.MemberReaders, c.MembersListenAddr)
	}
}

func TestMemberReadersRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		readers string
		env     map[string]string
		want    string
	}{
		"a base role":      {"app=admin", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "may not read"},
		"guest":            {"app=staff,guest", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "may not read"},
		"no token":         {"app=staff", nil, "needs MEMBER_READER_TOKEN_APP"},
		"a short token":    {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": "short-token-0123456789"}, "32+"},
		"a shared token":   {"app=staff two=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "MEMBER_READER_TOKEN_TWO": readerToken}, "share a token"},
		"no groups":        {"app=", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "want app=group"},
		"a bad group name": {"app=Staff!", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "may not read"},
		"listed twice":     {"app=a app=b", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "listed twice"},
		"the public port":  {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "LISTEN_ADDR": ":8080", "MEMBERS_LISTEN_ADDR": "0.0.0.0:8080"}, "different port"},
		"the port by name": {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "LISTEN_ADDR": ":80", "MEMBERS_LISTEN_ADDR": ":http"}, "different port"},
		"a padded port":    {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "LISTEN_ADDR": ":8080", "MEMBERS_LISTEN_ADDR": ":08080"}, "different port"},
		"no port":          {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "MEMBERS_LISTEN_ADDR": "auth"}, "needs a port"},
		"no network name":  {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "MEMBERS_LISTEN_ADDR": ":8081"}, "needs the name"},
	} {
		t.Run(name, func(t *testing.T) {
			setValid(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			t.Setenv("MEMBER_READERS", tc.readers)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

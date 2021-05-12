package vulntransformer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/python"
)

func Time(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func TestGolangVulnTransformer(t *testing.T) {
	t.Parallel()
	modMap := map[string]Info{
		"/aahframe.work/@v/881dc9f71d1f7a4e8a9a39df9c5c081d3a2da1ec.info": Info{
			Version: "v0.12.4",
			Time:    Time("2020-03-03T09:27:03Z"),
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, ok := modMap[r.URL.Path]
		if !ok {
			t.Errorf("unable to find mod %s", r.URL.Path)
		}
		out, err := json.Marshal(&resp)
		if err != nil {
			t.Errorf("mock server marshall error %v", err)
		}
		t.Logf("out %s %s", string(out), r.URL)
		w.Write(out)
	}))
	defer srv.Close()
	tt := []golangVulnTestcase{
		{
			Name:   "simple without network calls",
			Server: srv,
			Vulnerability: &Vulnerability{
				ID:          "SNYK-GOLANG-ABC-1234",
				Description: "ABC is a test vuln",
				PackageName: "abc",
				VulnerableVersions: []string{
					">= 2.9.0 < 2.9.7",
					">= 2.7.0 < 2.7.17",
					"< 1.9",
				},
				InitiallyFixedIn: []string{
					"2.9.7",
					"2.8.11",
					"2.7.17",
				},
			},
			Want: []*claircore.Vulnerability{
				{
					Name:        "SNYK-GOLANG-ABC-1234",
					Description: "ABC is a test vuln",
					Package: &claircore.Package{
						Name:    "abc",
						Version: ">=2.9.0,<2.9.7||>=2.7.0,<2.7.17||<1.9",
						Kind:    claircore.BINARY,
					},
					Repo:           &python.Repository,
					Updater:        "snyk-golang",
					FixedInVersion: "2.9.7, 2.8.11, 2.7.17",
				},
			},
		},
		{
			Name:   "pseudo versions",
			Server: srv,
			Vulnerability: &Vulnerability{
				ID:          "SNYK-GOLANG-ABC-1234",
				Description: "ABC is a test vuln",
				PackageName: "aahframe.work",
				VulnerableVersions: []string{
					"<v0.12.4",
				},
				HashesRange: []string{
					"<881dc9f71d1f7a4e8a9a39df9c5c081d3a2da1ec",
				},
				InitiallyFixedIn: []string{
					"v0.12.5",
				},
			},
			Want: []*claircore.Vulnerability{
				{
					Name:        "SNYK-GOLANG-ABC-1234",
					Description: "ABC is a test vuln",
					Package: &claircore.Package{
						Name:    "aahframe.work",
						Version: "<v0.12.4||<v0.12.4-20200303092703-881dc9f71d1f",
						Kind:    claircore.BINARY,
					},
					Repo:           &python.Repository,
					Updater:        "snyk-golang",
					FixedInVersion: "v0.12.5",
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}

type golangVulnTestcase struct {
	Name          string
	Vulnerability *Vulnerability
	Want          []*claircore.Vulnerability
	Server        *httptest.Server
}

func (tc golangVulnTestcase) Run(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	u, err := url.Parse(tc.Server.URL)
	if err != nil {
		t.Error(err)
	}
	transformer, err := NewGoVulnTransformer(WithClient(tc.Server.Client()), WithGoProxyURL(u))
	if err != nil {
		t.Error(err)
	}
	got, err := transformer.VulnTransform(ctx, tc.Vulnerability)
	if err != nil {
		t.Error(err)
	}
	// Sort for the comparison, because the Vulnerabilities method can return
	// the slice in any order.
	sort.SliceStable(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	if !cmp.Equal(tc.Want, got) {
		t.Error(cmp.Diff(tc.Want, got))
	}
}

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
		"/github.com/tendermint/tendermint/@v/8de846663f07e0c2b91186064aeeed3c27f111ed.info": Info{
			Version: "v0.31.12",
			Time:    Time("2020-04-09T13:48:13Z"),
		},
		"/github.com/tendermint/tendermint/@v/747f99fdc198d7ae6456b010c9b8857aae97e25f.info": Info{
			Version: "v0.32.0",
			Time:    Time("2019-06-25T11:57:50Z"),
		},
		"/github.com/tendermint/tendermint/@v/eab4d6d82b1387791fec9511ab2c40a1f71aa628.info": Info{
			Version: "v0.32.10",
			Time:    Time("2020-04-09T13:48:13Z"),
		},
		"/github.com/tendermint/tendermint/@v/af992361055b5541c1bd388994e386652e4d7254.info": Info{
			Version: "v0.33.0",
			Time:    Time("2020-01-15T11:45:10Z"),
		},
		"/github.com/tendermint/tendermint/@v/13eff7f7ed80bb5deb8d294998dc429b29bf9fe3.info": Info{
			Version: "v0.33.3",
			Time:    Time("2020-04-09T13:48:13Z"),
		},
		"/github.com/labstack/echo/v4/@v/v4.2.0.info": Info{
			Version: "v4.2.0",
			Time:    Time("2021-02-11T18:35:16Z"),
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, ok := modMap[r.URL.Path]
		if !ok {
			t.Logf("unable to find mod %s", r.URL.Path)
			http.NotFound(w, r)
		} else {
			t.Logf("found %s ret %#v\n", r.URL.Path, resp)
		}
		out, err := json.Marshal(&resp)
		if err != nil {
			t.Errorf("mock server marshall error %v", err)
		}
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
		{
			Name:   "semver in hashesRange",
			Server: srv,
			Vulnerability: &Vulnerability{
				ID:          "SNYK-GOLANG-ABC-1234",
				Description: "ABC is a test vuln",
				PackageName: "github.com/labstack/echo/v4",
				VulnerableVersions: []string{
					"<v0.12.4",
				},
				HashesRange: []string{
					"<v4.2.0",
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
						Name:    "github.com/labstack/echo/v4",
						Version: "<v0.12.4||<v4.2.0-20210211183516-v4.2.0",
						Kind:    claircore.BINARY,
					},
					Repo:           &python.Repository,
					Updater:        "snyk-golang",
					FixedInVersion: "v0.12.5",
				},
			},
		},
		{
			Name:   "pseudo versions with multiple hash ranges",
			Server: srv,
			Vulnerability: &Vulnerability{
				ID:          "SNYK-GOLANG-ABC-1234",
				Description: "ABC is a test vuln",
				PackageName: "github.com/tendermint/tendermint/p2p",
				VulnerableVersions: []string{
					"<v0.12.4",
				},
				HashesRange: []string{
					"=8de846663f07e0c2b91186064aeeed3c27f111ed",
					">=747f99fdc198d7ae6456b010c9b8857aae97e25f <eab4d6d82b1387791fec9511ab2c40a1f71aa628",
					">=af992361055b5541c1bd388994e386652e4d7254 <13eff7f7ed80bb5deb8d294998dc429b29bf9fe3",
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
						Name:    "github.com/tendermint/tendermint/p2p",
						Version: "<v0.12.4||=v0.31.12-20200409134813-8de846663f07||>=v0.32.0-20190625115750-747f99fdc198,<v0.32.10-20200409134813-eab4d6d82b13||>=v0.33.0-20200115114510-af992361055b,<v0.33.3-20200409134813-13eff7f7ed80",
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

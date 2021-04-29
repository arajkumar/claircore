package snyk_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/snyk"
)

func TestParser(t *testing.T) {
	tt := []parserTestcase{
		{
			Name: "feed_python",
			Want: []*claircore.Vulnerability{
				{
					Name:        "SNYK-PYTHON-ABC-1234",
					Description: "ABC is a test vuln",
					Package: &claircore.Package{
						Name:    "abc",
						Version: "[2.9.0, 2.9.7)",
						Kind:    claircore.BINARY,
					},
					Repo:    &python.Repository,
					Updater: "snyk",
				},
				{
					Name:        "SNYK-PYTHON-ABC-1234",
					Description: "ABC is a test vuln",
					Package: &claircore.Package{
						Name:    "abc",
						Version: "[2.7.0, 2.7.17)",
						Kind:    claircore.BINARY,
					},
					Repo:    &python.Repository,
					Updater: "snyk",
				},
				{
					Name:        "SNYK-PYTHON-XYZ-1234",
					Description: "XYZ is a test vuln",
					Package: &claircore.Package{
						Name:    "xyz",
						Version: "[1.0.0, 1.0.1)",
						Kind:    claircore.BINARY,
					},
					Repo:    &python.Repository,
					Updater: "snyk",
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}

type parserTestcase struct {
	Name string
	Want []*claircore.Vulnerability
}

func (tc parserTestcase) filename() string {
	return filepath.Join("testdata", fmt.Sprintf("%s.json", tc.Name))
}

func (tc parserTestcase) Run(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	f, err := os.Open(tc.filename())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	langToRepo := snyk.LangToRepo{
		"python": &python.Repository,
	}
	updater, err := snyk.NewUpdater(langToRepo)
	if err != nil {
		t.Error(err)
	}
	got, err := updater.Parse(ctx, f)
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

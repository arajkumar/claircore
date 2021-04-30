package vulntransformer

import (
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/python"
)

type Python struct{}

func unifiedVersionRangePython(ranges []string) string {
	return strings.Join(ranges, ", ")
}

func (_ *Python) VulnTransform(e *Vulnerability) []*claircore.Vulnerability {
	v := claircore.Vulnerability{
		Name:        e.ID,
		Description: e.Description,
		Repo:        &python.Repository,
		Package: &claircore.Package{
			// PackageName is case insensitive.
			Name:    strings.ToLower(e.PackageName),
			Version: unifiedVersionRangePython(e.VulnerableVersions),
			Kind:    claircore.BINARY,
		},
		FixedInVersion: strings.Join(e.InitiallyFixedIn, ", "),
		Updater:        "snyk-python",
	}
	return []*claircore.Vulnerability{&v}
}

package vulntransformer

import (
	"context"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/java"
)

type Maven struct{}

func unifiedVersionRangeMaven(ranges []string) string {
	return strings.Join(ranges, ", ")
}

func (_ *Maven) VulnTransform(_ context.Context, e *Vulnerability) ([]*claircore.Vulnerability, error) {
	v := claircore.Vulnerability{
		Name:        e.ID,
		Description: e.Description,
		Repo:        &java.Repository,
		Package: &claircore.Package{
			Name:    e.PackageName,
			Version: unifiedVersionRangeMaven(e.VulnerableVersions),
			Kind:    claircore.BINARY,
		},
		FixedInVersion: strings.Join(e.InitiallyFixedIn, ", "),
		Updater:        "snyk-maven",
	}
	return []*claircore.Vulnerability{&v}, nil
}

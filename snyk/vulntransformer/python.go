package vulntransformer

import (
	"strings"

	"github.com/quay/claircore"
	py "github.com/quay/claircore/python"
)

type Python struct{}

func (_ *Python) VulnTransform(e *Vulnerability) []*claircore.Vulnerability {
	var ret []*claircore.Vulnerability
	for _, vv := range e.VulnerabileVersions {
		v := claircore.Vulnerability{
			Name:        e.ID,
			Description: e.Description,
			Repo:        &py.Repository,
			Package: &claircore.Package{
				Name:    e.PackageName,
				Version: vv,
				Kind:    claircore.BINARY,
			},
			FixedInVersion: strings.Join(e.InitiallyFixedIn, ","),
			Updater:        "snyk",
		}
		ret = append(ret, &v)
	}
	return ret
}

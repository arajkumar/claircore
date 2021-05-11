package vulntransformer

import (
	"context"

	"github.com/quay/claircore"
)

type Vulnerability struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	PackageName        string   `json:"package"`
	Severity           string   `json:"severity"`
	URL                string   `json:"url"`
	HashesRange        []string `json:"hashesRange"`
	VulnerableVersions []string `json:"vulnerableVersions"`
	InitiallyFixedIn   []string `json:"initiallyFixedIn"`
}

// VulnTransformer is an interface exporting the necessary methods
// to convert from snyk.Vulnerability to claircore.Vulnerability
type VulnTransformer interface {
	VulnTransform(ctx context.Context, v *Vulnerability) ([]*claircore.Vulnerability, error)
}

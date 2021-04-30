package snyk

import (
	"context"

	maven "github.com/masahiro331/go-mvn-version"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Matcher = (*MavenMatcher)(nil)
)

// Matcher attempts to correlate discovered python packages with reported
// vulnerabilities.
type MavenMatcher struct{}

// Name implements driver.Matcher.
func (*MavenMatcher) Name() string { return "snyk-maven" }

// Filter implements driver.Matcher.
func (*MavenMatcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository.Name == "maven"
}

// Query implements driver.Matcher.
func (*MavenMatcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{}
}

// Vulnerable implements driver.Matcher.
func (*MavenMatcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	// if the vuln is not associated with any package,
	// return not vulnerable.
	if vuln.Package == nil {
		return false, nil
	}

	v, err := maven.NewVersion(record.Package.Version)
	if err != nil {
		return false, nil
	}

	spec, err := maven.NewRequirements(vuln.Package.Version)
	if err != nil {
		return false, nil
	}

	if spec.Check(v) {
		return true, nil
	}
	return false, nil
}

package snyk

import (
	"context"

	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Matcher = (*PythonMatcher)(nil)
)

// PythonMatcher attempts to correlate discovered python packages with reported
// vulnerabilities.
type PythonMatcher struct{}

// Name implements driver.PythonMatcher.
func (*PythonMatcher) Name() string { return "snyk-python" }

// Filter implements driver.PythonMatcher.
func (*PythonMatcher) Filter(record *claircore.IndexRecord) bool {
	return record.Package.NormalizedVersion.Kind == "pep440"
}

// Query implements driver.PythonMatcher.
func (*PythonMatcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{}
}

// Vulnerable implements driver.PythonMatcher.
func (*PythonMatcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	// if the vuln is not associated with any package,
	// return not vulnerable.
	if vuln.Package == nil {
		return false, nil
	}

	v, err := pep440.Parse(record.Package.Version)
	if err != nil {
		return false, nil
	}

	spec, err := pep440.NewSpecifiers(vuln.Package.Version)
	if err != nil {
		return false, nil
	}

	if spec.Check(v) {
		return true, nil
	}
	return false, nil
}

package crda

import (
  "context"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Matcher       = (*Matcher)(nil)
	_ driver.RemoteMatcher = (*Matcher)(nil)
)

// Matcher attempts to correlate discovered python packages with reported
// vulnerabilities.
type Matcher struct{}

// Name implements driver.Matcher.
func (*Matcher) Name() string { return "crda-python" }

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Package.NormalizedVersion.Kind == "pep440"
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	panic("unreachable")
}

// Vulnerable implements driver.Matcher.
func (*Matcher) Vulnerable(record *claircore.IndexRecord, vuln *claircore.Vulnerability) bool {
	// RemoteMatcher can match Package and Vulnerability.
	panic("unreachable")
}

// QueryRemoteMatcher implements driver.RemoteMatcher.
func (*Matcher) QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "crda/matcher/RemoteMatcher.QueryRemoteMatcher").
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().
		Int("records", len(records)).
		Msg("interest")
  return QueryRemoteMatcher(ctx, records)
}

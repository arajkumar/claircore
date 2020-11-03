// Package defaults sets updater defaults.
//
// Importing this package registers default updaters via its init function.
package matcher

import (
	"context"
	"sync"
	"time"

	"github.com/quay/claircore/crda"
)

var (
	once   sync.Once
	regerr error
)

func init() {
	ctx, done := context.WithTimeout(context.Background(), 1*time.Minute)
	defer done()
	once.Do(func() { regerr = inner(ctx) })
}

// Error reports if an error was encountered when initializing the default
// updaters.
func MatcherError() error {
	return regerr
}

func inner(ctx context.Context) error {

	//Register crda
	rf, err := crda.NewFactory(ctx)
	if err != nil {
		return err
	}
	Register("crda", rf)

	return nil
}

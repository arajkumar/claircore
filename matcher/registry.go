// Package matcher holds a registry of default matchers.
//
// A set of in-tree updaters can be added by using the defaults package's Set
// function.
package matcher

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/quay/claircore/libvuln/driver"
)

var pkg = struct {
	sync.Mutex
	fs map[string]driver.MatcherSetFactory
}{
	fs: make(map[string]driver.MatcherSetFactory),
}

// Register registers an MatcherSetFactory.
//
// Register will panic if the same name is used twice.
func Register(name string, f driver.MatcherSetFactory) {
	pkg.Lock()
	defer pkg.Unlock()
	if _, ok := pkg.fs[name]; ok {
		panic("")
	}
	pkg.fs[name] = f
}

// Registered returns a new map populated with the registered MatcherSetFactories.
func Registered() map[string]driver.MatcherSetFactory {
	pkg.Lock()
	defer pkg.Unlock()
	r := make(map[string]driver.MatcherSetFactory, len(pkg.fs))
	for k, v := range pkg.fs {
		r[k] = v
	}
	return r
}

// Configure calls the Configure method on all the passed-in
// MatcherSetFactories.
func Configure(ctx context.Context, fs map[string]driver.MatcherSetFactory, cfg map[string]driver.MatcherConfigUnmarshaler, c *http.Client) error {
	errd := false
	var b strings.Builder
	b.WriteString("matchers: errors configuring factories:")
	if c == nil {
		c = http.DefaultClient
	}

	for name, fac := range fs {
		f, fOK := fac.(driver.ConfigurableMatcher)
		cf, cfOK := cfg[name]
		if fOK && cfOK {
			if err := f.ConfigureMatcher(ctx, cf, c); err != nil {
				errd = true
				b.WriteString("\n\t")
				b.WriteString(err.Error())
			}
		}
	}

	if errd {
		return errors.New(b.String())
	}
	return nil
}

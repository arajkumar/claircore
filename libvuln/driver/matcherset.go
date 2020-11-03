package driver

import (
	"context"
	"fmt"
	"regexp"
)

// ErrExists is an error returned if the matchers
// already exists in the set.
type MatcherErrExists struct {
	Matcher []string
}

func (e MatcherErrExists) MatcherError() string {
	return fmt.Sprintf("reused names: %v", e.Matcher)
}

// MatcherSetFactory is used to construct matchers at run-time.
type MatcherSetFactory interface {
	MatcherSet(context.Context) (MatcherSet, error)
}

type MatcherSetFactoryFunc func(context.Context) (MatcherSet, error)

func (m MatcherSetFactoryFunc) MatcherSet(ctx context.Context) (MatcherSet, error) {
	return m(ctx)
}

// StaticSet creates an MatcherSetFunc returning the provided set.
func StaticMatcherSet(m MatcherSet) MatcherSetFactory {
	return MatcherSetFactoryFunc(func(_ context.Context) (MatcherSet, error) {
		return m, nil
	})
}

// MatcherSet holds a deduplicated set of matchers.
type MatcherSet struct {
	set map[string]Matcher
}

// NewMatcherSet returns an initialized UpdaterSet.
func NewMatcherSet() MatcherSet {
	return MatcherSet{
		set: map[string]Matcher{},
	}
}

// Add will add an Updater to the set.
//
// An error will be reported if a matcher with the same name already exists.
func (s *MatcherSet) Add(m Matcher) error {
	if _, ok := s.set[m.Name()]; ok {
		return ErrExists{[]string{m.Name()}}
	}

	s.set[m.Name()] = m
	return nil
}

// Merge will merge the MatcherSet provided as argument
// into the MatcherSet provided as the function receiver.
//
// If a matcher exists in the target set an error
// specifying which matcherss could not be merged is returned.
func (s *MatcherSet) Merge(set MatcherSet) error {
	exists := make([]string, 0, len(set.set))
	for n := range set.set {
		if _, ok := s.set[n]; ok {
			exists = append(exists, n)
		}
	}

	if len(exists) > 0 {
		return ErrExists{exists}
	}

	for n, u := range set.set {
		s.set[n] = u
	}
	return nil
}

// Matchers returns the matchers within the set as slice.
func (s *MatcherSet) Matchers() []Matcher {
	m := make([]Matcher, 0, len(s.set))
	for _, v := range s.set {
		m = append(m, v)
	}
	return m
}

// RegexFilter will remove any matchers from the set whose reported names do not
// match the provided regexp string.
func (s *MatcherSet) RegexFilter(regex string) error {
	re, err := regexp.Compile(regex)
	if err != nil {
		return fmt.Errorf("regex failed to compile: %v", err)
	}
	for name, m := range s.set {
		if !re.MatchString(m.Name()) {
			delete(s.set, name)
		}
	}
	return nil
}

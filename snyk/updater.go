// Package snyk provides an updater for importing pyup vulnerability
// information.
package snyk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/snyk/vulntransformer"
)

const defaultURL = `https://snyk.io/partners/api/v4/vulndb/feed.json`

var (
	_ driver.Updater = (*Updater)(nil)
)

type VulnTransformers map[string]vulntransformer.VulnTransformer

// Updater reads a pyup formatted json database for vulnerabilities.
//
// The zero value is not safe to use.
type Updater struct {
	url          *url.URL
	client       *http.Client
	transformers VulnTransformers
	// jwt auth params
	iss string
	psk string
}

// NewUpdater returns a configured Updater or reports an error.
func NewUpdater(transformers VulnTransformers, opt ...Option) (*Updater, error) {
	if len(transformers) < 1 {
		return nil, fmt.Errorf("vuln transformers is empty")
	}

	u := Updater{transformers: transformers}
	for _, f := range opt {
		if err := f(&u); err != nil {
			return nil, err
		}
	}

	if u.url == nil {
		var err error
		u.url, err = url.Parse(defaultURL)
		if err != nil {
			return nil, err
		}
	}
	if u.client == nil {
		u.client = http.DefaultClient
	}

	return &u, nil
}

// Option controls the configuration of an Updater.
type Option func(*Updater) error

// WithAuthParams sets the iss and psk that the updater should use to generate
// JWT Bearer Authorization for http requests.
func WithAuthParams(iss string, psk string) Option {
	return func(u *Updater) error {
		u.iss = iss
		u.psk = psk
		return nil
	}
}

// WithClient sets the http.Client that the updater should use for requests.
//
// If not passed to NewUpdater, http.DefaultClient will be used.
func WithClient(c *http.Client) Option {
	return func(u *Updater) error {
		u.client = c
		return nil
	}
}

// WithURL sets the URL the updater should fetch.
//
// The URL should point to a gzip compressed tarball containing a properly
// formatted json object in a file named `insecure_full.json`.
//
// If not passed to NewUpdater, the master branch of github.com/snyk/safety-db
// will be fetched.
func WithURL(uri string) Option {
	u, err := url.Parse(uri)
	return func(up *Updater) error {
		if err != nil {
			return err
		}
		up.url = u
		return nil
	}
}

// Name implements driver.Updater.
func (*Updater) Name() string { return "snyk" }

func (u *Updater) getAuthToken() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": u.iss,
		"iat": time.Now().UTC().Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	return token.SignedString([]byte(u.psk))
}

// Fetch implements driver.Updater.
func (u *Updater) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "snyk/Updater.Fetch"))
	zlog.Info(ctx).Str("database", u.url.String()).Msg("starting fetch")

	token, err := u.getAuthToken()
	if err != nil {
		return nil, "", err
	}

	req := http.Request{
		Method: http.MethodGet,
		Header: http.Header{
			"User-Agent":    {"claircore/snyk/Updater"},
			"Authorization": {fmt.Sprintf("Bearer %s", token)},
		},
		URL:        u.url,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       u.url.Host,
	}
	if hint != "" {
		zlog.Debug(ctx).
			Str("hint", string(hint)).
			Msg("using hint")
		req.Header.Set("if-none-match", string(hint))
	}

	res, err := u.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, hint, err
	}
	switch res.StatusCode {
	case http.StatusNotModified:
		return nil, hint, driver.Unchanged
	case http.StatusOK:
		// break
	default:
		return nil, hint, fmt.Errorf("snyk: fetcher got unexpected HTTP response: %d (%s)", res.StatusCode, res.Status)
	}
	zlog.Debug(ctx).Msg("request ok")

	if t := res.Header.Get("etag"); t != "" {
		zlog.Debug(ctx).
			Str("hint", t).
			Msg("using new hint")
		hint = driver.Fingerprint(t)
	}
	return res.Body, hint, nil
}

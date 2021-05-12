// Package snyk provides an updater for importing pyup vulnerability
// information.
package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/snyk/vulntransformer"
)

// Parse implements driver.Updater.
func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "snyk/Updater.Parse"))
	zlog.Info(ctx).Msg("parse start")
	defer r.Close()
	defer zlog.Info(ctx).Msg("parse done")

	var ret []*claircore.Vulnerability
	// r is a large JSON, attempt stream parsing.
	dec := json.NewDecoder(r)
	// read {
	_, err := dec.Token()
	if err != nil {
		return nil, err
	}
	var mungeCt int
	for dec.More() {
		// read "<language>":
		langToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		lang, ok := langToken.(string)
		if !ok {
			return ret, fmt.Errorf("unexpected token type %#v", lang)
		}
		tx, repoOk := u.transformers[lang]
		if !repoOk {
			zlog.Info(ctx).Str("lang", lang).Msg("skip language")
		}
		// read [
		_, err = dec.Token()
		if err != nil {
			return nil, err
		}
		// read vulnerabilities.
		for dec.More() {
			var e vulntransformer.Vulnerability
			err := dec.Decode(&e)
			if err != nil {
				return nil, err
			}
			// consume the stream though it is useless.
			if !repoOk {
				continue
			}
			v, err := tx.VulnTransform(ctx, &e)
			if err != nil {
				zlog.Warn(ctx).
					Str("package", e.PackageName).
					Str("version", strings.Join(e.VulnerableVersions, ",")).
					Str("hashes", strings.Join(e.HashesRange, ",")).
					Msg("malformed database entry")
				mungeCt++
			}
			ret = append(ret, v...)
		}
		// read ]
		_, err = dec.Token()
		if err != nil {
			return nil, err
		}
	}
	// read }
	_, err = dec.Token()
	if err != nil {
		return nil, err
	}
	if mungeCt > 0 {
		zlog.Debug(ctx).
			Int("count", mungeCt).
			Msg("munged bounds on some vulnerabilities 😬")
	}
	zlog.Debug(ctx).
		Int("count", len(ret)).
		Msg("found vulnerabilities")
	return ret, nil
}

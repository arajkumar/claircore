// Package snyk provides an updater for importing pyup vulnerability
// information.
package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
)

type entry struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	PackageName         string   `json:"package"`
	Severity            string   `json:"severity"`
	URL                 string   `json:"url"`
	VulnerabileVersions []string `json:"vulnerableVersions"`
}

// Parse implements driver.Updater.
func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "snyk/Updater.Parse"))
	zlog.Info(ctx).Msg("parse start")
	defer r.Close()
	defer zlog.Info(ctx).Msg("parse done")

	var ret []*claircore.Vulnerability
	// r has a large JSON, do a stream parsing.
	dec := json.NewDecoder(r)
	// read {
	_, err := dec.Token()
	if err != nil {
		return nil, err
	}
	for dec.More() {
		// read "ecosystem":
		langToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		lang, ok := langToken.(string)
		if !ok {
			return ret, fmt.Errorf("unexpected token type %#v", lang)
		}
		repo, repoOk := u.langToRepo[lang]
		// read [
		_, err = dec.Token()
		if err != nil {
			return nil, err
		}
		// read vulnerabilities.
		for dec.More() {
			var e entry
			err := dec.Decode(&e)
			if err != nil {
				return nil, err
			}
			if !repoOk {
				zlog.Error(ctx).Str("lang", lang).Msg("unexpected lang")
				continue
			}
			for _, vv := range e.VulnerabileVersions {
				v := claircore.Vulnerability{
					Name:        e.ID,
					Description: e.Description,
					Repo:        repo,
					Package: &claircore.Package{
						Name:    e.PackageName,
						Version: vv,
						Kind:    claircore.BINARY,
					},
				}
				ret = append(ret, &v)
			}
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
	zlog.Debug(ctx).
		Int("count", len(ret)).
		Msg("found vulnerabilities")
	return ret, nil
}

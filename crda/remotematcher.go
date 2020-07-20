package crda

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
)

var (
	urlTemplate = url.URL{
		Scheme:   "https",
		Host:     "f8a-analytics-2445582058137.production.gw.apicast.io",
		Path:     "/api/v2/component-analyses/pypi/%s/%s",
		RawQuery: "user_key=9e7da76708fe374d8c10fa752e72989f",
	}
)

// Build struct to model CRDA V2 ComponentAnalysis response which
// delivers Snyk sourced Vulnerability information.
type Vulnerability struct {
	ID   string `json:"vendor_cve_ids"`
	CVSS string `json:"cvss"`
}

type Analyses struct {
	Vulnerabilities []Vulnerability `json:"vulnerability"`
}

type VulnReport struct {
	RecommendedVersion string   `json:"recommended_versions"`
	Severity           string   `json:"severity"`
	Message            string   `json:"message"`
	Analyses           Analyses `json:"component_analyses"`
	// To map back to input
	record *claircore.IndexRecord
}

func componentAnalyses(ctx context.Context, record *claircore.IndexRecord, c chan VulnReport) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "crda/remotematcher/componentAnalyses").
		Logger()
	reqUrl := urlTemplate
	reqUrl.Path = fmt.Sprintf(reqUrl.Path, record.Package.Name, record.Package.Version)
	req := http.Request{
		Method:     http.MethodGet,
		Header:     http.Header{"User-Agent": {"claircore/crda/RemoteMatcher"}},
		URL:        &reqUrl,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       reqUrl.Host,
	}
	// Per request shouldn't go beyound 10s.
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	log.Debug().
		Str("package", record.Package.Name).
		Str("version", record.Package.Version).
		Msg("restful")
		// Fixme: Use configurable http client.
	res, err := http.DefaultClient.Do(req.WithContext(tctx))
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		log.Error().
			Err(err).
			Str("package", record.Package.Name).
			Str("version", record.Package.Version).
			Msg("restful")
		c <- VulnReport{record: record}
	} else {
		var vulnReport VulnReport
		data, _ := ioutil.ReadAll(res.Body)
		err = json.Unmarshal(data, &vulnReport)
		if err != nil {
			log.Error().
				Err(err).
				Str("package", record.Package.Name).
				Str("version", record.Package.Version).
				Msg("unmarshal")
			c <- VulnReport{record: record}
		}
		vulnReport.record = record
		c <- vulnReport
	}
}

func QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "crda/remotematcher/QueryRemoteMatcher").
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().
		Int("records", len(records)).
		Msg("packages")

	ch := make(chan VulnReport)
	for _, record := range records {
		go componentAnalyses(ctx, record, ch)
	}

	results := make(map[string][]*claircore.Vulnerability)
	resultCount := 0
	for r := range ch {
		resultCount++
		// A package can have multiple vulnerability for a version.
		for _, vuln := range r.Analyses.Vulnerabilities {
			results[r.record.Package.ID] = append(results[r.record.Package.ID], &claircore.Vulnerability{
				ID:                 vuln.ID,
				Updater:            "Code Ready Analytics",
				Name:               vuln.ID,
				Description:        fmt.Sprintf("%s cvss: %s", r.Message, vuln.CVSS),
				Links:              fmt.Sprintf("https://snyk.io/vuln/%s", vuln.ID),
				Severity:           r.Severity,
				NormalizedSeverity: NormalizeSeverity(r.Severity),
				FixedInVersion:     r.RecommendedVersion,
				Package:            r.record.Package,
			})
			log.Debug().
				Str("package", r.record.Package.Name).
				Str("version", r.record.Package.Version).
				Str("id", vuln.ID).
				Msg("vulns")
		}
		// Got result for all records.
		if resultCount >= len(records) {
			close(ch)
		}
	}
	log.Debug().
		Int("vulnerabilities", len(results)).
		Msg("query")
	return results, nil
}

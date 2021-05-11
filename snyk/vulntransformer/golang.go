package vulntransformer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/python"
)

const (
	defaultGolangProxyHost = "https://proxy.golang.org"
	defaultProxyEndPoint   = "%s/%s/@v/%s.info"
)

type golang struct {
	client *http.Client
}

// Option controls the configuration of an GoVulnTransformer.
type Option func(*golang) error

func NewGoVulnTransformer(opt ...Option) (*golang, error) {
	g := golang{}
	for _, f := range opt {
		if err := f(&g); err != nil {
			return nil, err
		}
	}
	if g.client == nil {
		g.client = http.DefaultClient
	}
	return &g, nil
}

// WithClient sets the http.Client that the matcher should use for requests.
//
// If not passed to NewMatcher, http.DefaultClient will be used.
func WithClient(c *http.Client) Option {
	return func(g *golang) error {
		g.client = c
		return nil
	}
}

func addCommaConstraint(r string) string {
	tokens := strings.Split(r, " ")
	versions := make([]string, 0, len(tokens)+1) // add extra cap for comma.
	versions = append(versions, tokens[0])
	for _, t := range tokens[1:] {
		t = strings.TrimSpace(t)
		switch {
		case t == "":
			continue
		case strings.HasPrefix(t, ">"),
			strings.HasPrefix(t, "<"),
			strings.HasPrefix(t, "="),
			strings.HasPrefix(t, "*"):
			versions = append(versions, ",", t)
		default:
			versions = append(versions, t)
		}
	}
	return strings.Join(versions, "")
}

func addCommaConstraints(ranges []string) []string {
	ret := make([]string, 0, len(ranges))
	for _, r := range ranges {
		ret = append(ret, addCommaConstraint(r))
	}
	return ret
}

type Info struct {
	Version string    // version string
	Time    time.Time // commit time
}

func (g *golang) fetchVersionInfo(ctx context.Context, pkg, hash string) (*Info, error) {
	// A request shouldn't go beyound 5s.
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	url := fmt.Sprintf(defaultProxyEndPoint, defaultGolangProxyHost, pkg, hash)
	req, err := http.NewRequestWithContext(tctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "claircore/crda/RemoteMatcher")
	req.Header.Set("Content-Type", "application/json")
	res, err := g.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	var info Info
	data, _ := ioutil.ReadAll(res.Body)
	err = json.Unmarshal(data, &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func guessModPath(pkg string) []string {
	guessedMods := make([]string, 0, strings.Count(pkg, "/"))
	pkgElements := strings.Split(pkg, "/")
	for i, _ := range pkgElements {
		guessedMods = append(guessedMods, strings.Join(pkgElements[:len(pkgElements)-i], "/"))
	}
	return guessedMods
}

func (i Info) String(hash string) string {
	// already has Version in the form of v0.0.0-time-hash
	if strings.Count(i.Version, "-") == 3 {
		return i.Version
	}
	// format equvalent to golang pseudo version.
	// e.g.
	// curl -vv https://proxy.golang.org/aahframe.work/@v/881dc9f71d1f7a4e8a9a39df9c5c081d3a2da1ec.info
	return fmt.Sprintf("%s-%04d%02d%02d%02d%02d%02d-%s", i.Version, i.Time.Year(), i.Time.Month(), i.Time.Day(), i.Time.Hour(), i.Time.Minute(), i.Time.Second(), hash[0:12])
}

func (g *golang) fetchPseudoVersion(ctx context.Context, pkg, hash string) (string, error) {
	mods := guessModPath(pkg)
	for _, m := range mods {
		info, err := g.fetchVersionInfo(ctx, m, hash)
		if err == nil {
			return info.String(hash), nil
		}
	}
	return "", nil
}

func (g *golang) convertToPseudoVersionRange(ctx context.Context, pkg string, hashesRange []string) ([]string, error) {
	ret := make([]string, 0, len(hashesRange))
	for _, h := range hashesRange {
		v, _ := g.fetchPseudoVersion(ctx, pkg, h)
		ret = append(ret, v)
	}
	return ret, nil
}

func unifiedVersionRangeGolang(ranges []string) string {
	return strings.Join(ranges, "||")
}

func (g *golang) VulnTransform(ctx context.Context, e *Vulnerability) ([]*claircore.Vulnerability, error) {
	pseudoRanges, err := g.convertToPseudoVersionRange(ctx, e.PackageName, e.HashesRange)
	v := claircore.Vulnerability{
		Name:        e.ID,
		Description: e.Description,
		Repo:        &python.Repository,
		Package: &claircore.Package{
			Name:    e.PackageName,
			Version: unifiedVersionRangeGolang(append(addCommaConstraints(e.VulnerableVersions), pseudoRanges...)),
			Kind:    claircore.BINARY,
		},
		FixedInVersion: strings.Join(e.InitiallyFixedIn, ", "),
		Updater:        "snyk-golang",
	}
	return []*claircore.Vulnerability{&v}, err
}

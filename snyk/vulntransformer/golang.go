package vulntransformer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/python"
	"github.com/quay/zlog"
)

const (
	defaultGoProxyURL    = "https://proxy.golang.org"
	defaultProxyEndPoint = "%s/%s/@v/%s.info"
)

type golang struct {
	client *http.Client
	url    *url.URL
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

	if g.url == nil {
		var err error
		g.url, err = url.Parse(defaultGoProxyURL)
		if err != nil {
			return nil, err
		}
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

// WithGoProxyURL sets the server host name that the matcher should use for requests.
//
// If not passed to NewGoVulnTransformer, defaultGoProxyURL will be used.
func WithGoProxyURL(url *url.URL) Option {
	return func(g *golang) error {
		g.url = url
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
	// A request shouldn't go beyound 10s.
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	url := fmt.Sprintf(defaultProxyEndPoint, g.url.String(), pkg, hash)
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
	var trimmedHash string
	if len(hash) >= 12 {
		trimmedHash = hash[0:12]
	} else {
		trimmedHash = hash
	}
	// format equvalent to golang pseudo version.
	// e.g.
	// curl -vv https://proxy.golang.org/aahframe.work/@v/881dc9f71d1f7a4e8a9a39df9c5c081d3a2da1ec.info
	return fmt.Sprintf("%s-%04d%02d%02d%02d%02d%02d-%s", i.Version, i.Time.Year(), i.Time.Month(), i.Time.Day(), i.Time.Hour(), i.Time.Minute(), i.Time.Second(), trimmedHash)
}

func trimConstraints(hash string) string {
	trimed := make([]rune, 0, len(hash))
	for _, h := range hash {
		switch h {
		case '<', '>', '=', '*':
			continue
		default:
			trimed = append(trimed, h)
		}
	}
	return string(trimed)
}

func (g *golang) fetchPseudoVersion(ctx context.Context, pkg, hashConstraint string) (string, error) {
	mods := guessModPath(pkg)
	hashes := strings.Split(hashConstraint, ",")
	for _, h := range hashes {
		h = trimConstraints(h)
		// TODO: try happyEyeBall
		for _, m := range mods {
			info, err := g.fetchVersionInfo(ctx, m, h)
			if err == nil {
				hashConstraint = strings.ReplaceAll(hashConstraint, h, info.String(h))
				break
			}
		}
	}
	return hashConstraint, nil
}

// func (g *golang) fetchPseudoVersion(ctx context.Context, pkg, hashConstraint string) (string, error) {
// 	mods := guessModPath(pkg)
// 	hashes := strings.Split(hashConstraint, ",")
// 	type I struct {
// 		h    string
// 		info *Info
// 	}
// 	ctrlC := make(chan I, len(hashes))
// 	errorC := make(chan error, len(hashes)*len(mods)) // max len(mods) no of errors are possible.
// 	defer close(errorC)
// 	defer close(ctrlC)
// 	for _, h := range hashes {
// 		h = trimConstraints(h)
// 		for _, m := range mods {
// 			go func(m, h string) {
// 				info, err := g.fetchVersionInfo(ctx, m, h)
// 				if err != nil {
// 					errorC <- err
// 				} else {
// 					ctrlC <- I{h: h, info: info}
// 				}
// 			}(m, h)
// 		}
// 	}
// 	for i := range ctrlC {
// 		hashConstraint = strings.ReplaceAll(hashConstraint, i.h, i.info.String(i.h))
// 	}
// 	return hashConstraint, nil
// }

func (g *golang) convertToPseudoVersionRange(ctx context.Context, pkg string, hashesRange []string) ([]string, error) {
	ret := make([]string, 0, len(hashesRange))
	for _, h := range hashesRange {
		v, _ := g.fetchPseudoVersion(ctx, pkg, addCommaConstraint(h))
		ret = append(ret, v)
	}
	return ret, nil
}

func unifiedVersionRangeGolang(ranges []string) string {
	return strings.Join(ranges, "||")
}

func (g *golang) VulnTransform(ctx context.Context, e *Vulnerability) ([]*claircore.Vulnerability, error) {
	zlog.Debug(ctx).
		Str("ID", e.ID).
		Msg("golang ingestion")
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

// Package java contains components for interrogating java packages in
// container layers.
package java

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"runtime/trace"
	"strings"

	"github.com/magiconair/properties"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for directories that seem like wheels or eggs, and looks at the
// metadata recorded there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "java" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Scan attempts to find wheel or egg info directories and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	log := zerolog.Ctx(ctx).With().
		Str("component", "java/Scanner.Scan").
		Str("version", ps.Version()).
		Str("layer", layer.Hash.String()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rd, ok := r.(interface {
		io.ReadCloser
		io.Seeker
	})
	if !ok {
		return nil, errors.New("java: cannot seek on returned layer Reader")
	}

	var ret []*claircore.Package
	tr := tar.NewReader(rd)
	var h *tar.Header
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		switch {
		case h.Typeflag != tar.TypeReg:
			// Should we chase symlinks with the correct name?
			continue
		case strings.HasSuffix(h.Name, `.jar`):
			log.Debug().Str("file", h.Name).Msg("found jar")
		case strings.HasSuffix(h.Name, `.war`):
			log.Debug().Str("file", h.Name).Msg("found war")
		default:
			continue
		}
		packages, err := getPackagesFromJar(log, tr, h.Name, h.Size, false)
		if err != nil {
			return nil, err
		}
		ret = append(ret, packages...)
	}
	if err != io.EOF {
		return nil, err
	}
	return ret, nil
}

func getPackagesFromJar(log zerolog.Logger, reader io.Reader, name string, size int64, isNestedJar bool) ([]*claircore.Package, error) {
	archive, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	zp, err := zip.NewReader(bytes.NewReader(archive), size)
	if err != nil {
		return nil, err
	}
	var ret []*claircore.Package
	for _, f := range zp.File {
		isJar := false
		switch {
		case strings.HasSuffix(f.Name, `.jar`) && !isNestedJar:
			log.Debug().Str("container", name).Str("file", f.Name).Msg("found jar inside war")
			isJar = true
		case strings.HasSuffix(f.Name, `pom.properties`):
			log.Debug().Str("file", name).Msg("found pom.properties")
		default:
			continue
		}
		pomProps, err := f.Open()
		if err != nil {
			return nil, err
		}
		if isJar {
			pkgsFromNestedJar, err := getPackagesFromJar(log, pomProps, name+"@"+f.Name, int64(f.UncompressedSize64), true)
			if err != nil {
				log.Debug().Err(err).Msg("nested getPackagesFromJar failed")
				return nil, err
			}
			ret = append(ret, pkgsFromNestedJar...)
			continue
		}
		pomPropsBytes, err := ioutil.ReadAll(pomProps)
		if err != nil {
			return nil, err
		}
		props, err := properties.Load(pomPropsBytes, properties.UTF8)
		if err != nil {
			return nil, err
		}
		// pom.properties format for each maven jar
		type PomProperties struct {
			Version    string `properties:"version"`
			GroupID    string `properties:"groupId"`
			ArtifactID string `properties:"artifactId"`
		}
		var pomProperties PomProperties
		if err := props.Decode(&pomProperties); err != nil {
			return nil, err
		}
		ret = append(ret, &claircore.Package{
			Name:           pomProperties.GroupID + ":" + pomProperties.ArtifactID,
			Version:        pomProperties.Version,
			PackageDB:      "maven:" + name,
			Kind:           claircore.BINARY,
			RepositoryHint: Repository.URI,
		})
	}
	return ret, nil
}

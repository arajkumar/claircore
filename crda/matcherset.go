package crda

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/rs/zerolog"
)

const URL = "https://f8a-analytics-preview-2445582058137.production.gw.apicast.io/?user_key=3e42fa66f65124e6b1266a23431e3d08"

func NewFactory(ctx context.Context, opts ...FactoryOption) (*Factory, error) {
	f := Factory{
		client: http.DefaultClient,
	}

	f.url = URL

	for _, o := range opts {
		if err := o(&f); err != nil {
			return nil, err
		}
	}
	return &f, nil
}

type Factory struct {
	url    string
	client *http.Client
}

type FactoryConfig struct {
	URL string `json:"url", yaml:"url"`
}

func (f *Factory) ConfigureMatcher(ctx context.Context, cfg driver.MatcherConfigUnmarshaler, c *http.Client) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "crda/Factory.Configure").
		Logger()
	var fc FactoryConfig

	if err := cfg(&fc); err != nil {
		return err
	}
	log.Debug().Msg("loaded incoming config")

	if fc.URL != "" {
		log.Info().
			Str("url", fc.URL).
			Msg("configured manifest URL")
		f.url = fc.URL
	}

	if c != nil {
		log.Info().
			Msg("configured HTTP client")
		f.client = c
	}

	return nil
}

func (f *Factory) MatcherSet(_ context.Context) (driver.MatcherSet, error) {
	us := driver.NewMatcherSet()
	py, err := NewMatcher(WithURL(f.url), WithClient(f.client))
	if err != nil {
		return us, fmt.Errorf("failed to create crda matcher: %v", err)
	}
	err = us.Add(py)
	if err != nil {
		return us, err
	}
	return us, nil
}

// A FactoryOption is used with New to configure a Factory.
type FactoryOption func(*Factory) error

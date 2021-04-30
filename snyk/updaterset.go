package snyk

import (
	"context"
	"fmt"
	"os"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/snyk/vulntransformer"
)

func UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	transformers := VulnTransformers{
		"python": &vulntransformer.Python{},
	}
	py, err := NewUpdater(transformers, WithAuthParams(os.Getenv("SNYK_ISS"), os.Getenv("SNYK_PSK")))
	if err != nil {
		return us, fmt.Errorf("failed to create snyk updater: %v", err)
	}
	err = us.Add(py)
	if err != nil {
		return us, err
	}
	return us, nil
}

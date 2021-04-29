package snyk

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/python"
)

func UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	langToRepo := map[string]*claircore.Repository{
		"python": &python.Repository,
	}
	py, err := NewUpdater(langToRepo)
	if err != nil {
		return us, fmt.Errorf("failed to create snyk updater: %v", err)
	}
	err = us.Add(py)
	if err != nil {
		return us, err
	}
	return us, nil
}

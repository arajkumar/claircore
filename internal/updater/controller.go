package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/distlock"
)

// Controller is a control structure for fetching, parsing, and updating a vulnstore.
type Controller struct {
	*Opts
}

// Opts are options used to create an Updater
type Opts struct {
	// an embedded updater interface
	driver.Updater
	// a unique name for this controller. must be unique between controllers
	Name string
	// store for persistence
	Store vulnstore.Updater
	// update interval
	Interval time.Duration
	// lock to ensure only process updating
	Lock distlock.Locker
	// immediately update on construction
	UpdateOnStart bool
}

// New is a constructor for an Controller
func New(opts *Opts) *Controller {
	return &Controller{
		Opts: opts,
	}
}

// Start begins a long running update controller. cancel ctx to stop.
func (u *Controller) Start(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/updater/Controller").
		Str("name", u.Name).
		Dur("interval", u.Interval).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("controller running")
	go u.start(ctx)
	return nil
}

// start implements the event loop of an updater controller
func (u *Controller) start(ctx context.Context) {
	t := time.NewTicker(u.Interval)
	defer t.Stop()

	if u.UpdateOnStart {
		u.Update(ctx)
	}

	for {
		select {
		case <-t.C:
			u.Update(ctx)
		case <-ctx.Done():
			log.Printf("updater %v is exiting due to context cancelation: %v", u.Name, ctx.Err())
			return
		}
	}
}

// Update triggers an update procedure. exported to make testing easier.
func (u *Controller) Update(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/updater/Controller.Update").
		Str("updater", u.Updater.Name()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("looking for updates")
	// attempt to get distributed lock. if we cannot another updater is currently updating the vulnstore
	locked, err := u.tryLock(ctx)
	if err != nil {
		log.Error().
			Err(err).
			Msg("unexpected error while trying lock")
		return err
	}
	if !locked {
		log.Debug().Msg("another process is updating. waiting till next update interval")
		return nil
	}
	defer u.Lock.Unlock()

	// create update operation id for this update
	UOID := uuid.New().String()
	log.Info().Str("update_operation_id", UOID).Msg("generated uoid")

	// retreive previous fingerprint. GetUpdateOperations will
	// return update operations in descending order
	var prevFP driver.Fingerprint
	allOUs, err := u.Store.GetUpdateOperations(ctx, []string{u.Updater.Name()})
	if err != nil {
		return err
	}
	OUs := allOUs[u.Updater.Name()]
	if len(OUs) > 0 {
		prevFP = OUs[0].Fingerprint
	}

	// Fetch the vulnerability database. if the fetcher
	// determines no update is necessary a driver.Unchanged
	// error will be returned
	vulnDB, newFP, err := u.Fetch(ctx, prevFP)
	if err != nil {
		return err
	}
	// just to be defensive. if no error is returned this should not happen
	if vulnDB != nil {
		defer vulnDB.Close()
	}

	// parse the vulndb
	vulns, err := u.Parse(ctx, vulnDB)
	if err != nil {
		return fmt.Errorf("failed to parse the fetched vulnerability database: %v", err)
	}

	// update the vulnstore
	err = u.Store.UpdateVulnerabilities(ctx, u.Updater.Name(), UOID, newFP, vulns)
	if err != nil {
		return fmt.Errorf("failed to update vulnerabilities: %v", err)
	}

	log.Info().Msg("successfully updated the vulnstore")
	return nil
}

// lock attempts to acquire a distributed lock
func (u *Controller) tryLock(ctx context.Context) (bool, error) {
	// attempt lock acquisiton
	ok, err := u.Lock.TryLock(ctx, u.Name)
	if err != nil {
		return false, fmt.Errorf("experienced an unexpected error when acquiring lock %v", err)
	}
	// did not acquire, another process is updating the database. bail
	return ok, err
}

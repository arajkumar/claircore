package dastore

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
)

// store implements all interfaces in the vulnstore package
type Store struct {
}

//function using interface of vulnerability
func (s Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	// filter out the python packages by looping for the records
	//change.....................
	fmt.Printf("Connection made ")
	vulns, err := get(ctx, records, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilites: %v", err)
	}
	return vulns, err
}

/*func (s *Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) int {
	fmt.Println("hi got connected")

	return 1
}*/

package cognitoidp

import (
	"context"
	"strings"

	"stackd/internal/awsctx"
)

// publicClient resolves an app client named by a public (IAM-free) request.
// A regional endpoint binds the lookup to its Region. An unsigned request to a
// regionless local endpoint resolves the bearer client ID in the partition; an
// ambiguous ID fails closed instead of selecting another account's client.
func publicClient(r Reader, id string) (ClientRecord, error) {
	m := awsctx.FromContext(r.Context())
	if !m.EndpointRegionImplicit {
		return r.ClientByID(m.Partition, m.Region, id)
	}
	rows, err := r.ClientsByID(m.Partition, id)
	if err != nil {
		return ClientRecord{}, err
	}
	if len(rows) != 1 {
		return ClientRecord{}, ErrNotFound
	}
	return rows[0], nil
}

// publicPoolRegion is the Region of a pool named by a public token or path.
// User pool IDs carry their Region; only a regionless endpoint uses it.
func publicPoolRegion(ctx context.Context, poolID string) string {
	m := awsctx.FromContext(ctx)
	if m.EndpointRegionImplicit {
		if region, _, ok := strings.Cut(poolID, "_"); ok {
			return region
		}
	}
	return m.Region
}

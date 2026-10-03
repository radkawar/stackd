package appsync

import (
	"context"

	api "stackd/internal/awsapi/appsync"
)

// DataSources executes a resolved request through the authoritative service owner.
// Implementations must not retain caller authority or bypass destination commands.
type DataSources interface {
	Execute(context.Context, APIRecord, api.DataSource, map[string]any) (any, error)
}

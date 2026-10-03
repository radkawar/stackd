package lambda

import (
	"context"

	runtime "stackd/compute/lambda"
	"stackd/internal/awswire"
)

// RoleProvider checks the deploying caller's PassRole and Lambda trust, then
// issues local execution-role credentials for real runtime environments.
// Implementations join the caller's IAM authority transaction where supplied.
type RoleProvider interface {
	Validate(ctx context.Context, roleARN, functionARN string) *awswire.Error
	Assume(ctx context.Context, roleARN, functionARN, sessionName string) (runtime.Credentials, *awswire.Error)
}

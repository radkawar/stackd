package servicecatalogappregistry

import (
	"context"
	"slices"
	"strings"
)

// ApplicationRoles supplies the current IAM service-linked-role session used by
// AppRegistry to manage its Resource Groups. Only application create and update
// ensure the role exists; other operations must use the current role.
type ApplicationRoles interface {
	Context(ctx context.Context, applicationARN string, ensure bool) (context.Context, error)
}

// ApplicationRoleDependency identifies an application that still owns resources
// managed through the account's AppRegistry service-linked role.
type ApplicationRoleDependency struct{ Region, ARN string }

// WithApplicationRoleUsage holds all regional application ownership stable while
// IAM decides service-linked-role deletion. The writable shared transaction lets
// IAM commit its decision without releasing the resource-ownership fence.
func (s *Service) WithApplicationRoleUsage(ctx context.Context, partition, accountID string, fn func(context.Context, []ApplicationRoleDependency) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		applications, err := tx.AccountApplications(partition, accountID)
		if err != nil {
			return err
		}
		dependencies := make([]ApplicationRoleDependency, len(applications))
		for i, application := range applications {
			dependencies[i] = ApplicationRoleDependency{Region: application.Region, ARN: application.ARN}
		}
		slices.SortFunc(dependencies, func(a, b ApplicationRoleDependency) int {
			if n := strings.Compare(a.Region, b.Region); n != 0 {
				return n
			}
			return strings.Compare(a.ARN, b.ARN)
		})
		return fn(tx.Context(), dependencies)
	})
}

package eks

import "context"

// ClusterRoleDependency is an extant EKS resource using the service-linked role.
type ClusterRoleDependency struct{ Region, ARN string }

// WithClusterRoleUsage keeps the all-region resource set stable while IAM checks
// role deletion. Creating/deleting clusters uses this same repository boundary.
func (s *Service) WithClusterRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []ClusterRoleDependency) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		clusters, err := tx.AllClusters()
		if err != nil {
			return err
		}
		var dependencies []ClusterRoleDependency
		for _, c := range clusters {
			if c.Key.Partition == partition && c.Key.AccountID == account {
				dependencies = append(dependencies, ClusterRoleDependency{Region: c.Key.Region, ARN: c.Key.ARN()})
			}
		}
		return fn(tx.Context(), dependencies)
	})
}

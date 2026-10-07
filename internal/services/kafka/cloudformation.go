package kafka

import "context"

type cloudFormationOwnerKey struct{}
type cloudFormationOwner struct{ Kind, StackID, LogicalID, Token string }

const (
	cloudFormationCluster       = "Cluster"
	cloudFormationConfiguration = "Configuration"
)

// WithCloudFormationConfigurationOwner attaches controller authority to the
// existing creation transaction; this metadata never crosses an AWS response.
func WithCloudFormationConfigurationOwner(ctx context.Context, stackID, logicalID, token string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{cloudFormationConfiguration, stackID, logicalID, token})
}

// WithCloudFormationClusterOwner binds one exact CloudFormation incarnation to
// cluster commands. CreateCluster persists it with the new cluster row; every
// other cluster command treats a cluster carrying another claim as absent, so
// public tags or a same-name recreation can never satisfy the fence.
func WithCloudFormationClusterOwner(ctx context.Context, stackID, logicalID, token string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{cloudFormationCluster, stackID, logicalID, token})
}

func cloudFormationOwnerFor(ctx context.Context, kind string) (cloudFormationOwner, bool) {
	owner, ok := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	return owner, ok && owner.Kind == kind
}

// cloudFormationForeignCluster reports whether a fenced command must not see v.
// An empty fenced token never matches, including unowned direct-API clusters.
func cloudFormationForeignCluster(ctx context.Context, v ClusterRecord) bool {
	owner, ok := cloudFormationOwnerFor(ctx, cloudFormationCluster)
	return ok && (owner.Token == "" || v.OwnerStackID != owner.StackID || v.OwnerLogicalID != owner.LogicalID || v.OwnerToken != owner.Token)
}

// CloudFormationOwner is a native row's private CloudFormation incarnation
// claim. It is never accepted from or rendered by an MSK API or tag.
type CloudFormationOwner struct{ StackID, LogicalID, Token string }

// CloudFormationConfigurationOwnership uses the same scoped DescribeConfiguration
// authority as the public command. It does not grant import or claim authority.
func (s *Service) CloudFormationConfigurationOwnership(ctx context.Context, arn string) (CloudFormationOwner, error) {
	var owner CloudFormationOwner
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.configuration(ctx, r, arn, "DescribeConfiguration")
		if err != nil {
			return err
		}
		owner = CloudFormationOwner{v.OwnerStackID, v.OwnerLogicalID, v.OwnerToken}
		return nil
	})
	if err != nil {
		return CloudFormationOwner{}, wireError(err)
	}
	return owner, nil
}

package dynamodb

import (
	"context"
	"slices"
	"time"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

const ReplicationServicePrincipal = "replication.dynamodb.amazonaws.com"
const ReplicationServiceRoleName = "AWSServiceRoleForDynamoDBReplication"

// ServiceRoles provisions IAM's protected replication role in the resource
// transaction. IAM authorizes creation only when the account lacks the role.
type ServiceRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

// ReplicationIdentity supplies a current trust-authorized service-role session.
// DynamoDB remains the authority for current table/resource-policy evaluation.
type ReplicationIdentity interface {
	Context(context.Context, TableKey) (context.Context, error)
}

// RegionAccess supplies the owning account's current destination opt-in state.
type RegionAccess interface {
	RegionEnabled(context.Context, string, string, time.Time) (bool, error)
}

func regionalContext(ctx context.Context, region string) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.Region = region
	return awsctx.WithMetadata(ctx, metadata)
}

func (s *Service) replicaRegion(ctx context.Context, scope Scope, region string) error {
	if scope.Partition != "aws" {
		// TODO: Comeback capture noncommercial DynamoDB replication availability
		// and exact service-linked role templates before enabling those partitions.
		return unsupported("DynamoDB replication in this partition is not implemented.")
	}
	if !slices.ContainsFunc(awscatalog.CommercialRegions(), func(candidate awscatalog.CommercialRegion) bool { return candidate.Name == region }) {
		return invalidTable("Invalid AWS Region: " + region)
	}
	if s.regions == nil || s.roles == nil || s.replicationIdentity == nil {
		return unsupported("DynamoDB replication requires account Region and IAM role providers.")
	}
	enabled, err := s.regions.RegionEnabled(ctx, scope.AccountID, region, s.clock.Now())
	if err != nil {
		return err
	}
	if !enabled {
		return invalidTable("The replica Region is not enabled for this account.")
	}
	return nil
}

// WithReplicaRoleUsage keeps membership stable while IAM checks whether the
// account's service-linked replication role is still required.
func (s *Service) WithReplicaRoleUsage(ctx context.Context, partition, accountID string, fn func(context.Context, []TableKey) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		tables, err := tx.ReplicaTables("")
		if err != nil {
			return err
		}
		var keys []TableKey
		for _, table := range tables {
			if table.Key.Partition == partition && table.Key.AccountID == accountID {
				keys = append(keys, table.Key)
			}
		}
		return fn(tx.Context(), keys)
	})
}

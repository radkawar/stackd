package dynamodb

import (
	"context"

	api "stackd/internal/awsapi/dynamodb"
)

// ReplicaScaling owns regional configuration through scaling service commands.
// Admission removes policies as the forwarded caller; creation and completed
// billing transitions install settings under the replication role.
type ReplicaScaling interface {
	PrepareReplica(context.Context, TableKey, TableKey, *api.TableDescription) error
	ConfigureReplica(context.Context, TableKey, *api.TableDescription, int32) error
	ResetReplicaPolicies(context.Context, TableKey, *api.TableDescription) error
	DescribeReplica(context.Context, TableKey, *api.ReplicaAutoScalingDescription, bool) error
	// UpdateReplica receives the admitted caller and the replication-role session
	// separately: native policy removal and configuration have different actors.
	UpdateReplica(caller, role context.Context, key TableKey, index string, read bool, update *api.AutoScalingSettingsUpdate) error
}

func (s *Service) prepareReplicaScaling(ctx context.Context, source, target *TableRecord) error {
	if source.Data.BillingModeSummary != nil && value(source.Data.BillingModeSummary.BillingMode) == "PAY_PER_REQUEST" {
		return nil
	}
	if s.replicaScaling == nil {
		return unsupported("Provisioned DynamoDB replicas require Application Auto Scaling integration.")
	}
	service, err := s.replicationIdentity.Context(ctx, source.Key)
	if err != nil {
		return err
	}
	return s.replicaScaling.PrepareReplica(service, source.Key, target.Key, &source.Data)
}

func (s *Service) configureReplicaScaling(ctx context.Context, table *TableRecord) error {
	if s.replicaScaling == nil {
		return unsupported("Provisioned DynamoDB replicas require Application Auto Scaling integration.")
	}
	service, err := s.replicationIdentity.Context(ctx, table.Key)
	if err != nil {
		return err
	}
	return s.replicaScaling.ConfigureReplica(service, table.Key, &table.Data, tableCapacityLimit)
}

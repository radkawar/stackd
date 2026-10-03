package dynamodb

import (
	"context"
	"slices"

	api "stackd/internal/awsapi/dynamodb"
)

func (s *Service) describeTableReplicaAutoScaling(ctx context.Context, tx Transaction, in *api.DescribeTableReplicaAutoScalingInput) (*api.DescribeTableReplicaAutoScalingOutput, error) {
	table, members, err := s.replicaScalingTables(ctx, tx, value(in.TableName), "DescribeTableReplicaAutoScaling")
	if err != nil {
		return nil, err
	}
	description, err := s.replicaAutoScalingDescription(ctx, &table, members)
	if err != nil {
		return nil, err
	}
	return &api.DescribeTableReplicaAutoScalingOutput{TableAutoScalingDescription: description}, nil
}

func (s *Service) updateTableReplicaAutoScaling(ctx context.Context, in *api.UpdateTableReplicaAutoScalingInput) (*api.UpdateTableReplicaAutoScalingOutput, error) {
	if err := validateReplicaScalingUpdate(in); err != nil {
		return nil, err
	}
	var members []TableRecord
	var changes []replicaScalingChange
	var description *api.TableAutoScalingDescription
	// Admission and the returned pre-update projection share one snapshot.
	// Scaling effects then commit independently, including on partial failure.
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		table, peers, err := s.replicaScalingTables(tx.Context(), tx, value(in.TableName), "UpdateTableReplicaAutoScaling")
		if err != nil {
			return err
		}
		members = peers
		changes, err = planReplicaScalingChanges(in, members)
		if err != nil {
			return err
		}
		description, err = s.replicaAutoScalingDescription(tx.Context(), &table, members)
		return err
	}); err != nil {
		return nil, err
	}
	var firstErr error
	for _, member := range members {
		role, err := s.replicationIdentity.Context(ctx, member.Key)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, change := range changes {
			if change.key != member.Key {
				continue
			}
			if err := s.replicaScaling.UpdateReplica(ctx, role, change.key, change.index, change.read, change.settings); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return &api.UpdateTableReplicaAutoScalingOutput{TableAutoScalingDescription: description}, nil
}

// A change binds a supplied setting to an existing global-table member and
// dimension. Membership and billing validation finish before any scaling effect.
type replicaScalingChange struct {
	key      TableKey
	index    string
	read     bool
	settings *api.AutoScalingSettingsUpdate
}

func planReplicaScalingChanges(in *api.UpdateTableReplicaAutoScalingInput, members []TableRecord) ([]replicaScalingChange, error) {
	var changes []replicaScalingChange
	add := func(member TableRecord, index string, read bool, settings *api.AutoScalingSettingsUpdate) error {
		if settings == nil {
			return nil
		}
		if index != "" && !slices.ContainsFunc(member.Data.GlobalSecondaryIndexes, func(candidate api.GlobalSecondaryIndexDescription) bool {
			return value(candidate.IndexName) == index
		}) {
			return failure("ResourceNotFoundException", "Global secondary index does not exist: "+index)
		}
		if !provisionedTable(&member) && (settings.AutoScalingDisabled == nil || !bool(*settings.AutoScalingDisabled)) {
			return invalidTable("The table's billing mode must be PROVISIONED to enable auto scaling.")
		}
		changes = append(changes, replicaScalingChange{key: member.Key, index: index, read: read, settings: settings})
		return nil
	}
	for _, member := range members {
		if err := add(member, "", false, in.ProvisionedWriteCapacityAutoScalingUpdate); err != nil {
			return nil, err
		}
		for _, index := range in.GlobalSecondaryIndexUpdates {
			if err := add(member, value(index.IndexName), false, index.ProvisionedWriteCapacityAutoScalingUpdate); err != nil {
				return nil, err
			}
		}
	}
	for _, replica := range in.ReplicaUpdates {
		position := slices.IndexFunc(members, func(member TableRecord) bool { return member.Key.Region == value(replica.RegionName) })
		if position == -1 {
			return nil, failure("ResourceNotFoundException", "Global table replica does not exist in Region: "+value(replica.RegionName))
		}
		member := members[position]
		if err := add(member, "", true, replica.ReplicaProvisionedReadCapacityAutoScalingUpdate); err != nil {
			return nil, err
		}
		for _, index := range replica.ReplicaGlobalSecondaryIndexUpdates {
			if err := add(member, value(index.IndexName), true, index.ProvisionedReadCapacityAutoScalingUpdate); err != nil {
				return nil, err
			}
		}
	}
	return changes, nil
}

func (s *Service) replicaScalingTables(ctx context.Context, r Reader, selector, action string) (TableRecord, []TableRecord, error) {
	table, err := s.controlTable(ctx, r, selector, action, nil)
	if err != nil {
		return TableRecord{}, nil, err
	}
	if table.Replica.GroupID == "" {
		return TableRecord{}, nil, failure("ResourceNotFoundException", "Global table with name: '"+table.Key.Name+"' does not exist.")
	}
	if s.replicaScaling == nil || s.replicationIdentity == nil {
		return TableRecord{}, nil, unsupported("DynamoDB replica scaling requires Application Auto Scaling and IAM role integration.")
	}
	members, err := r.ReplicaTables(table.Replica.GroupID)
	return table, members, err
}

func (s *Service) replicaAutoScalingDescription(ctx context.Context, table *TableRecord, members []TableRecord) (*api.TableAutoScalingDescription, error) {
	out := &api.TableAutoScalingDescription{TableName: table.Data.TableName, TableStatus: table.Data.TableStatus, Replicas: api.ReplicaAutoScalingDescriptionList{}}
	for _, member := range members {
		status := api.ReplicaStatus(value(member.Data.TableStatus))
		if member.Replica.UnauthorizedAt != nil {
			status = api.ReplicaStatusREPLICATION_NOT_AUTHORIZED
		}
		replica := api.ReplicaAutoScalingDescription{RegionName: new(api.RegionName(member.Key.Region)), ReplicaStatus: &status, GlobalSecondaryIndexes: api.ReplicaGlobalSecondaryIndexAutoScalingDescriptionList{}}
		for _, index := range member.Data.GlobalSecondaryIndexes {
			replica.GlobalSecondaryIndexes = append(replica.GlobalSecondaryIndexes, api.ReplicaGlobalSecondaryIndexAutoScalingDescription{IndexName: index.IndexName, IndexStatus: index.IndexStatus})
		}
		service, err := s.replicationIdentity.Context(ctx, member.Key)
		if err != nil {
			return nil, err
		}
		if err := s.replicaScaling.DescribeReplica(service, member.Key, &replica, !provisionedTable(&member)); err != nil {
			return nil, err
		}
		out.Replicas = append(out.Replicas, replica)
	}
	return out, nil
}

func validateReplicaScalingUpdate(in *api.UpdateTableReplicaAutoScalingInput) error {
	if in.ProvisionedWriteCapacityAutoScalingUpdate == nil && len(in.GlobalSecondaryIndexUpdates) == 0 && len(in.ReplicaUpdates) == 0 {
		return invalidTable("At least one update parameter must be specified.")
	}
	validate := func(settings *api.AutoScalingSettingsUpdate) error {
		if settings == nil {
			return nil
		}
		if settings.AutoScalingDisabled != nil && bool(*settings.AutoScalingDisabled) {
			if settings.MinimumUnits != nil || settings.MaximumUnits != nil || settings.ScalingPolicyUpdate != nil {
				return invalidTable("MinimumUnits, MaximumUnits and ScalingPolicyUpdate must be omitted when disabling auto scaling.")
			}
		} else if settings.MinimumUnits == nil || settings.MaximumUnits == nil || settings.ScalingPolicyUpdate == nil {
			return invalidTable("MinimumUnits, MaximumUnits and ScalingPolicyUpdate are required unless auto scaling is being disabled.")
		}
		return nil
	}
	if err := validate(in.ProvisionedWriteCapacityAutoScalingUpdate); err != nil {
		return err
	}
	validateIndex := func(name *api.IndexName, settings *api.AutoScalingSettingsUpdate) error {
		if name == nil {
			// The Smithy member is optional, but native requests without the
			// index selector fail before table lookup with this modeled error.
			return failure("InternalServerError", "Internal server error", 500)
		}
		if settings == nil {
			return invalidTable("At least one update parameter must be specified for the global secondary index.")
		}
		return validate(settings)
	}
	for _, index := range in.GlobalSecondaryIndexUpdates {
		if err := validateIndex(index.IndexName, index.ProvisionedWriteCapacityAutoScalingUpdate); err != nil {
			return err
		}
	}
	for _, replica := range in.ReplicaUpdates {
		if replica.ReplicaProvisionedReadCapacityAutoScalingUpdate == nil && len(replica.ReplicaGlobalSecondaryIndexUpdates) == 0 {
			return invalidTable("At least one update parameter must be specified for the replica Region.")
		}
		if err := validate(replica.ReplicaProvisionedReadCapacityAutoScalingUpdate); err != nil {
			return err
		}
		for _, index := range replica.ReplicaGlobalSecondaryIndexUpdates {
			if err := validateIndex(index.IndexName, index.ProvisionedReadCapacityAutoScalingUpdate); err != nil {
				return err
			}
		}
	}
	return nil
}

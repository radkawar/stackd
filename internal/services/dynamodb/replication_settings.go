package dynamodb

import (
	"context"
	"slices"

	api "stackd/internal/awsapi/dynamodb"
)

// hasGlobalTableSettings identifies settings whose ordinary UpdateTable form
// synchronizes all members, replacing any replica override of the changed field.
func hasGlobalTableSettings(in *api.UpdateTableInput) bool {
	return in.BillingMode != nil || in.ProvisionedThroughput != nil || in.OnDemandThroughput != nil || in.TableClass != nil || len(in.GlobalSecondaryIndexUpdates) != 0
}

func hasTableSettings(in *api.UpdateTableInput) bool {
	return hasGlobalTableSettings(in) || in.DeletionProtectionEnabled != nil || in.StreamSpecification != nil || in.SSESpecification != nil || in.WarmThroughput != nil || in.VectorIndexUpdates != nil
}

func (s *Service) updateGlobalTableSettings(ctx context.Context, tx Transaction, table TableRecord, in *api.UpdateTableInput) (*TableRecord, error) {
	if in.StreamSpecification != nil && in.StreamSpecification.StreamEnabled != nil && !*in.StreamSpecification.StreamEnabled {
		return nil, invalidTable("Streams cannot be disabled on a global table replica")
	}
	changed, err := s.updateTableSettings(ctx, tx, table, in)
	if err != nil || !hasGlobalTableSettings(in) {
		return changed, err
	}
	members, err := tx.ReplicaTables(table.Replica.GroupID)
	if err != nil {
		return nil, err
	}
	// The caller needs UpdateTable only on the source. Service-owned pending
	// updates are authorized as the replication SLR when the controller applies
	// them. Admission still shares the regional limits and validation owner.
	for _, peer := range members {
		if peer.Key == table.Key {
			continue
		}
		settings := api.CloneUpdateTableInput(*in)
		settings.TableName = new(api.TableArn(peer.Key.Name))
		settings.DeletionProtectionEnabled = nil
		settings.StreamSpecification = nil
		settings.MultiRegionConsistency = nil
		peer.Replica.SettingsPending = true
		if _, err := s.updateTableSettings(regionalContext(ctx, peer.Key.Region), tx, peer, &settings); err != nil {
			return nil, err
		}
	}
	if !provisionedTable(&table) && value(in.BillingMode) == "PROVISIONED" {
		if s.replicaScaling == nil {
			return nil, unsupported("Provisioned DynamoDB replicas require Application Auto Scaling integration.")
		}
		for _, member := range members {
			if err := s.replicaScaling.ResetReplicaPolicies(ctx, member.Key, &member.Data); err != nil {
				return nil, err
			}
		}
	}
	return changed, nil
}

// replicaCreateInput derives a native regional CreateTable request, rather than
// copying a description or inheriting region-owned tags, recovery, or policies.
func replicaCreateInput(source *TableRecord, override api.UpdateReplicationGroupMemberAction) (api.CreateTableInput, error) {
	settings, err := replicaOverrideInput(source, override)
	if err != nil {
		return api.CreateTableInput{}, err
	}
	stream := source.Data.StreamSpecification
	if stream == nil || stream.StreamEnabled == nil || !*stream.StreamEnabled {
		stream = &api.StreamSpecification{StreamEnabled: new(api.StreamEnabled(true)), StreamViewType: new(api.StreamViewTypeNEW_AND_OLD_IMAGES)}
	}
	in := api.CreateTableInput{
		TableName:            new(api.TableArn(source.Key.Name)),
		AttributeDefinitions: source.Data.AttributeDefinitions,
		KeySchema:            source.Data.KeySchema,
		BillingMode:          new(api.BillingModePROVISIONED),
		StreamSpecification:  stream,
	}
	if source.Data.BillingModeSummary != nil {
		in.BillingMode = source.Data.BillingModeSummary.BillingMode
	}
	if value(in.BillingMode) == "PROVISIONED" {
		in.ProvisionedThroughput = capacityFromDescription(source.Data.ProvisionedThroughput)
	}
	if source.Data.OnDemandThroughput != nil {
		in.OnDemandThroughput = mergeOnDemand(source.Data.OnDemandThroughput, &api.OnDemandThroughput{})
	}
	if source.Data.TableClassSummary != nil {
		in.TableClass = source.Data.TableClassSummary.TableClass
	}
	if settings.TableClass != nil {
		in.TableClass = settings.TableClass
	}
	if settings.ProvisionedThroughput != nil {
		in.ProvisionedThroughput = settings.ProvisionedThroughput
	}
	if settings.OnDemandThroughput != nil {
		if in.OnDemandThroughput == nil {
			in.OnDemandThroughput = &api.OnDemandThroughput{}
		}
		in.OnDemandThroughput.MaxReadRequestUnits = settings.OnDemandThroughput.MaxReadRequestUnits
	}
	for _, index := range source.Data.LocalSecondaryIndexes {
		in.LocalSecondaryIndexes = append(in.LocalSecondaryIndexes, api.LocalSecondaryIndex{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection})
	}
	for _, index := range source.Data.GlobalSecondaryIndexes {
		next := api.GlobalSecondaryIndex{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection}
		if value(in.BillingMode) == "PROVISIONED" {
			next.ProvisionedThroughput = capacityFromDescription(index.ProvisionedThroughput)
		}
		if index.OnDemandThroughput != nil {
			next.OnDemandThroughput = mergeOnDemand(index.OnDemandThroughput, &api.OnDemandThroughput{})
		}
		for _, change := range settings.GlobalSecondaryIndexUpdates {
			if value(change.Update.IndexName) != value(index.IndexName) {
				continue
			}
			if change.Update.ProvisionedThroughput != nil {
				next.ProvisionedThroughput = change.Update.ProvisionedThroughput
			}
			if change.Update.OnDemandThroughput != nil {
				if next.OnDemandThroughput == nil {
					next.OnDemandThroughput = &api.OnDemandThroughput{}
				}
				next.OnDemandThroughput.MaxReadRequestUnits = change.Update.OnDemandThroughput.MaxReadRequestUnits
			}
		}
		in.GlobalSecondaryIndexes = append(in.GlobalSecondaryIndexes, next)
	}
	return api.CloneCreateTableInput(in), nil
}

// Replica overrides use the authoritative generated action shape. Write capacity
// is retained from the destination while only the requested read value changes.
func replicaOverrideInput(table *TableRecord, in api.UpdateReplicationGroupMemberAction) (api.UpdateTableInput, error) {
	out := api.UpdateTableInput{TableName: new(api.TableArn(table.Key.Name)), TableClass: in.TableClassOverride}
	if in.KMSMasterKeyId != nil {
		return out, unsupported("Explicit DynamoDB encryption configuration is not implemented.")
	}
	mode := "PROVISIONED"
	if table.Data.BillingModeSummary != nil {
		mode = value(table.Data.BillingModeSummary.BillingMode)
	}
	if in.ProvisionedThroughputOverride != nil {
		if mode != "PROVISIONED" || in.ProvisionedThroughputOverride.ReadCapacityUnits == nil {
			return out, invalidTable("ProvisionedThroughputOverride requires provisioned capacity and ReadCapacityUnits")
		}
		out.ProvisionedThroughput = capacityFromDescription(table.Data.ProvisionedThroughput)
		if out.ProvisionedThroughput == nil {
			return out, invalidTable("The replica has no provisioned throughput to override")
		}
		out.ProvisionedThroughput.ReadCapacityUnits = in.ProvisionedThroughputOverride.ReadCapacityUnits
	}
	if in.OnDemandThroughputOverride != nil {
		if mode != "PAY_PER_REQUEST" || in.OnDemandThroughputOverride.MaxReadRequestUnits == nil {
			return out, invalidTable("OnDemandThroughputOverride requires on-demand capacity and MaxReadRequestUnits")
		}
		out.OnDemandThroughput = &api.OnDemandThroughput{MaxReadRequestUnits: in.OnDemandThroughputOverride.MaxReadRequestUnits}
	}
	seen := make(map[string]bool, len(in.GlobalSecondaryIndexes))
	for _, override := range in.GlobalSecondaryIndexes {
		name := value(override.IndexName)
		if seen[name] {
			return out, invalidTable("Only one override per index is allowed: " + name)
		}
		seen[name] = true
		position := slices.IndexFunc(table.Data.GlobalSecondaryIndexes, func(index api.GlobalSecondaryIndexDescription) bool { return value(index.IndexName) == name })
		if position < 0 {
			return out, invalidTable("The table does not have the specified index: " + name)
		}
		index := table.Data.GlobalSecondaryIndexes[position]
		update := api.UpdateGlobalSecondaryIndexAction{IndexName: index.IndexName}
		if override.ProvisionedThroughputOverride != nil {
			if mode != "PROVISIONED" || override.ProvisionedThroughputOverride.ReadCapacityUnits == nil {
				return out, invalidTable("Index ProvisionedThroughputOverride requires provisioned capacity and ReadCapacityUnits")
			}
			update.ProvisionedThroughput = capacityFromDescription(index.ProvisionedThroughput)
			if update.ProvisionedThroughput == nil {
				return out, invalidTable("The index has no provisioned throughput to override: " + name)
			}
			update.ProvisionedThroughput.ReadCapacityUnits = override.ProvisionedThroughputOverride.ReadCapacityUnits
		}
		if override.OnDemandThroughputOverride != nil {
			if mode != "PAY_PER_REQUEST" || override.OnDemandThroughputOverride.MaxReadRequestUnits == nil {
				return out, invalidTable("Index OnDemandThroughputOverride requires on-demand capacity and MaxReadRequestUnits")
			}
			update.OnDemandThroughput = &api.OnDemandThroughput{MaxReadRequestUnits: override.OnDemandThroughputOverride.MaxReadRequestUnits}
		}
		if update.ProvisionedThroughput == nil && update.OnDemandThroughput == nil {
			return out, invalidTable("At least one read throughput override must be specified for index: " + name)
		}
		out.GlobalSecondaryIndexUpdates = append(out.GlobalSecondaryIndexUpdates, api.GlobalSecondaryIndexUpdate{Update: &update})
	}
	return api.CloneUpdateTableInput(out), nil
}

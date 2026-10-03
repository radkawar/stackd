package dynamodb

import (
	"slices"

	api "stackd/internal/awsapi/dynamodb"
)

// engineUpdateApplied recognizes completion after a restart between the native
// mutation and the retained control-plane commit. Only this controller writes
// these physical table configurations; no second receipt protocol is needed.
func engineUpdateApplied(table *api.TableDescription, in *api.UpdateTableInput) bool {
	if in.BillingMode != nil {
		mode := "PROVISIONED"
		if table.BillingModeSummary != nil {
			mode = value(table.BillingModeSummary.BillingMode)
		}
		if mode != value(in.BillingMode) {
			return false
		}
	}
	if !engineCapacityMatches(table.ProvisionedThroughput, in.ProvisionedThroughput) {
		return false
	}
	if in.DeletionProtectionEnabled != nil {
		enabled := table.DeletionProtectionEnabled != nil && bool(*table.DeletionProtectionEnabled)
		if enabled != bool(*in.DeletionProtectionEnabled) {
			return false
		}
	}
	if in.StreamSpecification != nil {
		actual := table.StreamSpecification
		enabled := actual != nil && actual.StreamEnabled != nil && bool(*actual.StreamEnabled)
		requested := bool(*in.StreamSpecification.StreamEnabled)
		if enabled != requested {
			return false
		}
		if enabled && value(actual.StreamViewType) != value(in.StreamSpecification.StreamViewType) {
			return false
		}
	}
	for _, update := range in.GlobalSecondaryIndexUpdates {
		name := ""
		switch {
		case update.Create != nil:
			name = value(update.Create.IndexName)
		case update.Update != nil:
			name = value(update.Update.IndexName)
		case update.Delete != nil:
			name = value(update.Delete.IndexName)
		}
		actual := tableIndex(table, name)
		switch {
		case update.Create != nil:
			if actual == nil {
				return false
			}
		case update.Delete != nil:
			if actual != nil {
				return false
			}
		case update.Update != nil:
			if actual == nil || !engineCapacityMatches(actual.ProvisionedThroughput, update.Update.ProvisionedThroughput) {
				return false
			}
		}
	}
	return true
}
func engineCapacityMatches(actual *api.ProvisionedThroughputDescription, wanted *api.ProvisionedThroughput) bool {
	return wanted == nil || actual != nil && actual.ReadCapacityUnits != nil && actual.WriteCapacityUnits != nil && int64(*actual.ReadCapacityUnits) == int64(*wanted.ReadCapacityUnits) && int64(*actual.WriteCapacityUnits) == int64(*wanted.WriteCapacityUnits)
}

func tableIndex(table *api.TableDescription, name string) *api.GlobalSecondaryIndexDescription {
	for i := range table.GlobalSecondaryIndexes {
		if value(table.GlobalSecondaryIndexes[i].IndexName) == name {
			return &table.GlobalSecondaryIndexes[i]
		}
	}
	return nil
}

// Strip Go-owned controls without mutating the retained, admitted intent.
// Pure index maximum changes have no native Update action at all.
func engineUpdateInput(input *api.UpdateTableInput, observed *api.TableDescription) api.UpdateTableInput {
	in := *input
	in.TableClass = nil
	in.DeletionProtectionEnabled = nil
	in.OnDemandThroughput = nil
	in.ReplicaUpdates = nil
	in.MultiRegionConsistency = nil
	in.GlobalTableWitnessUpdates = nil
	in.GlobalTableSettingsReplicationMode = nil
	omitUpdate := func(change api.GlobalSecondaryIndexUpdate) bool {
		if change.Update == nil {
			return false
		}
		if change.Update.OnDemandThroughput != nil {
			return true
		}
		// Local retains stale index capacity while on-demand and rejects an
		// unchanged index member when switching back. The Go control plane has
		// already validated the public transition; this native member is done.
		index := tableIndex(observed, value(change.Update.IndexName))
		return index != nil && engineCapacityMatches(index.ProvisionedThroughput, change.Update.ProvisionedThroughput)
	}
	if !slices.ContainsFunc(in.GlobalSecondaryIndexUpdates, func(change api.GlobalSecondaryIndexUpdate) bool {
		return change.Create != nil && change.Create.OnDemandThroughput != nil || omitUpdate(change)
	}) {
		return in
	}
	updates := make(api.GlobalSecondaryIndexUpdateList, 0, len(in.GlobalSecondaryIndexUpdates))
	for _, change := range in.GlobalSecondaryIndexUpdates {
		if omitUpdate(change) {
			continue
		}
		if change.Create != nil && change.Create.OnDemandThroughput != nil {
			create := *change.Create
			create.OnDemandThroughput = nil
			change.Create = &create
		}
		updates = append(updates, change)
	}
	in.GlobalSecondaryIndexUpdates = updates
	return in
}

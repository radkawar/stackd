package dynamodb

import (
	"context"
	"slices"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
)

// updateTable admits only transitions the native engine can complete; even an
// on-demand maximum change mirrors capacity the engine must enforce.
func (s *Service) updateTable(ctx context.Context, tx Transaction, table TableRecord, in *api.UpdateTableInput) (*TableRecord, error) {
	if err := s.requireEngine(); err != nil {
		return nil, err
	}
	if in.GlobalTableSettingsReplicationMode != nil || in.GlobalTableWitnessUpdates != nil || in.MultiRegionConsistency != nil && value(in.MultiRegionConsistency) != "EVENTUAL" {
		// TODO: Comeback implement MRSC and multi-account global tables
		// with their distinct consistency, witness and authorization contracts.
		return nil, unsupported("This DynamoDB global table consistency or settings mode is not implemented.")
	}
	if in.ReplicaUpdates != nil {
		return s.updateReplicas(ctx, tx, table, in)
	}
	if table.Replica.GroupID != "" {
		return s.updateGlobalTableSettings(ctx, tx, table, in)
	}
	return s.updateTableSettings(ctx, tx, table, in)
}

// updateTableSettings is the shared regional admission path for ordinary table
// changes and settings propagated by the global-table owner.
func (s *Service) updateTableSettings(ctx context.Context, tx Transaction, table TableRecord, in *api.UpdateTableInput) (*TableRecord, error) {
	if err := checkResourceOwner(ctx, tx, table.Key); err != nil {
		return nil, err
	}
	var err error
	if err = transitionAvailable(table); err != nil {
		return nil, err
	}
	if in.SSESpecification != nil {
		return nil, unsupported("Explicit DynamoDB encryption configuration is not implemented.")
	}
	if in.VectorIndexUpdates != nil {
		return nil, unsupported("DynamoDB vector indexes are not implemented.")
	}
	if in.WarmThroughput != nil {
		return nil, unsupported("Explicit DynamoDB warm-throughput configuration is not implemented.")
	}
	if in.TableClass == nil && in.BillingMode == nil && in.DeletionProtectionEnabled == nil && in.ProvisionedThroughput == nil && in.OnDemandThroughput == nil && in.StreamSpecification == nil && len(in.GlobalSecondaryIndexUpdates) == 0 {
		return nil, invalidTable("At least one property must be specified to update the table")
	}
	onDemandOnly := in.TableClass == nil && in.BillingMode == nil && in.DeletionProtectionEnabled == nil && in.ProvisionedThroughput == nil && in.StreamSpecification == nil
	mode := "PROVISIONED"
	if table.Data.BillingModeSummary != nil {
		mode = value(table.Data.BillingModeSummary.BillingMode)
	}
	oldMode := mode
	if in.BillingMode != nil {
		mode = value(in.BillingMode)
	}
	if err = validateCapacity(mode, in.ProvisionedThroughput, in.BillingMode != nil && mode == "PROVISIONED"); err != nil {
		return nil, err
	}
	if err = validateOnDemand(mode, in.OnDemandThroughput, true); err != nil {
		return nil, err
	}
	if in.OnDemandThroughput != nil && in.OnDemandThroughput.MaxReadRequestUnits == nil && in.OnDemandThroughput.MaxWriteRequestUnits == nil {
		// Independently reproduced native behavior for an empty table update.
		return nil, failure("InternalFailure", "", 500)
	}
	projected := api.CreateTableInput{TableName: new(api.TableArn(table.Key.Name)), BillingMode: new(api.BillingMode(mode)), KeySchema: api.CloneKeySchema(table.Data.KeySchema), AttributeDefinitions: api.CloneAttributeDefinitions(table.Data.AttributeDefinitions), TableClass: in.TableClass, StreamSpecification: in.StreamSpecification}
	if mode == "PROVISIONED" {
		projected.ProvisionedThroughput = capacityFromDescription(table.Data.ProvisionedThroughput)
		if in.ProvisionedThroughput != nil {
			projected.ProvisionedThroughput = new(api.CloneProvisionedThroughput(*in.ProvisionedThroughput))
		}
	}
	for _, index := range table.Data.LocalSecondaryIndexes {
		projected.LocalSecondaryIndexes = append(projected.LocalSecondaryIndexes, api.LocalSecondaryIndex{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection})
	}
	for _, index := range table.Data.GlobalSecondaryIndexes {
		next := api.GlobalSecondaryIndex{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection}
		if mode == "PROVISIONED" {
			next.ProvisionedThroughput = capacityFromDescription(index.ProvisionedThroughput)
		}
		projected.GlobalSecondaryIndexes = append(projected.GlobalSecondaryIndexes, next)
	}
	currentDefs, err := attributeMap(table.Data.AttributeDefinitions)
	if err != nil {
		return nil, err
	}
	updateDefs, err := attributeMap(in.AttributeDefinitions)
	if err != nil {
		return nil, err
	}
	for _, attribute := range in.AttributeDefinitions {
		name := value(attribute.AttributeName)
		if kind, ok := currentDefs[name]; ok {
			if kind != value(attribute.AttributeType) {
				return nil, invalidTable("Cannot change the type of an existing key attribute: " + name)
			}
		} else {
			projected.AttributeDefinitions = append(projected.AttributeDefinitions, attribute)
		}
	}
	seen := map[string]bool{}
	structuralChanges := 0
	for _, change := range in.GlobalSecondaryIndexUpdates {
		count := 0
		name := ""
		if change.Create != nil {
			count++
			name = value(change.Create.IndexName)
		}
		if change.Update != nil {
			count++
			name = value(change.Update.IndexName)
		}
		if change.Delete != nil {
			count++
			name = value(change.Delete.IndexName)
		}
		if count != 1 {
			return nil, invalidTable("Each GlobalSecondaryIndexUpdate must contain exactly one Create, Update, or Delete action")
		}
		if seen[name] {
			return nil, invalidTable("Only one update per index is allowed: " + name)
		}
		seen[name] = true
		position := slices.IndexFunc(projected.GlobalSecondaryIndexes, func(index api.GlobalSecondaryIndex) bool { return value(index.IndexName) == name })
		switch {
		case change.Create != nil:
			structuralChanges++
			if position >= 0 {
				return nil, failure("ValidationException", "Attempting to create an index which already exists")
			}
			index := change.Create
			projected.GlobalSecondaryIndexes = append(projected.GlobalSecondaryIndexes, api.GlobalSecondaryIndex{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection, ProvisionedThroughput: index.ProvisionedThroughput, OnDemandThroughput: index.OnDemandThroughput, WarmThroughput: index.WarmThroughput})
		case change.Delete != nil:
			structuralChanges++
			if position < 0 {
				return nil, invalidTable("Attempting to delete an index which does not exist: " + name)
			}
			projected.GlobalSecondaryIndexes = slices.Delete(projected.GlobalSecondaryIndexes, position, position+1)
		case change.Update != nil:
			if position < 0 {
				return nil, invalidTable("The table does not have the specified index: " + name)
			}
			index := change.Update
			if index.WarmThroughput != nil {
				return nil, unsupported("Explicit index warm-throughput configuration is not implemented.")
			}
			if index.ProvisionedThroughput == nil && (index.OnDemandThroughput == nil || index.OnDemandThroughput.MaxReadRequestUnits == nil && index.OnDemandThroughput.MaxWriteRequestUnits == nil) {
				return nil, invalidTable("ProvisionedThroughput or OnDemandThroughput must be specified for the index update")
			}
			if err = validateCapacity(mode, index.ProvisionedThroughput, false); err != nil {
				return nil, err
			}
			if err = validateOnDemand(mode, index.OnDemandThroughput, true); err != nil {
				return nil, err
			}
			onDemandOnly = onDemandOnly && index.ProvisionedThroughput == nil
			projected.GlobalSecondaryIndexes[position].ProvisionedThroughput = index.ProvisionedThroughput
		}
	}
	if structuralChanges > 1 {
		return nil, invalidTable("Only one global secondary index can be created or deleted in a single operation")
	}
	// Existing attributes belonging only to a removed index disappear; newly supplied
	// unused definitions are invalid rather than silently ignored.
	used := map[string]bool{}
	for _, key := range projected.KeySchema {
		used[value(key.AttributeName)] = true
	}
	for _, index := range projected.LocalSecondaryIndexes {
		for _, key := range index.KeySchema {
			used[value(key.AttributeName)] = true
		}
	}
	for _, index := range projected.GlobalSecondaryIndexes {
		for _, key := range index.KeySchema {
			used[value(key.AttributeName)] = true
		}
	}
	for name := range updateDefs {
		if !used[name] {
			return nil, invalidTable("AttributeDefinitions contains an attribute that is not used in a key schema: " + name)
		}
	}
	projected.AttributeDefinitions = slices.DeleteFunc(projected.AttributeDefinitions, func(attribute api.AttributeDefinition) bool { return !used[value(attribute.AttributeName)] })
	if err = validateCreate(&projected); err != nil {
		return nil, err
	}
	if err = validateAccountCapacity(tx, table.Key, &projected); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	if err = validateThroughputUpdates(&table.Data, in, now); err != nil {
		return nil, err
	}
	if oldMode != mode && mode == "PAY_PER_REQUEST" {
		if err = validateOnDemandSwitch(tx, table.Key, now); err != nil {
			return nil, err
		}
	}
	if onDemandOnly && structuralChanges == 0 && !table.Replica.SettingsPending && !(table.Replica.GroupID != "" && hasGlobalTableSettings(in)) {
		updateOnDemand(&table.Data, in)
		if err = tx.PutTable(table); err != nil {
			return nil, err
		}
		return &table, nil
	}
	if in.StreamSpecification != nil && bool(*in.StreamSpecification.StreamEnabled) && table.Data.StreamSpecification != nil && table.Data.StreamSpecification.StreamEnabled != nil && bool(*table.Data.StreamSpecification.StreamEnabled) {
		return nil, invalidTable("Stream is already enabled")
	}
	if in.StreamSpecification != nil {
		table.Data.StreamSpecification = nil
		if bool(*in.StreamSpecification.StreamEnabled) {
			table.Data.StreamSpecification = new(api.CloneStreamSpecification(*in.StreamSpecification))
			if err = s.assignStreamIdentity(tx, &table); err != nil {
				return nil, err
			}
		}
	}
	pending := api.CloneUpdateTableInput(*in)
	table.PendingUpdate = &pending
	table.UpdateAcceptedAt = now
	table.Data.TableStatus = new(api.TableStatusUPDATING)
	for _, change := range in.GlobalSecondaryIndexUpdates {
		if change.Create != nil {
			index := change.Create
			table.Data.GlobalSecondaryIndexes = append(table.Data.GlobalSecondaryIndexes, newIndexDescription(table.Key, api.GlobalSecondaryIndex{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection, ProvisionedThroughput: index.ProvisionedThroughput, OnDemandThroughput: index.OnDemandThroughput}))
			table.Data.GlobalSecondaryIndexes[len(table.Data.GlobalSecondaryIndexes)-1].Backfilling = new(api.Backfilling(true))
		} else {
			name := ""
			status := api.IndexStatusUPDATING
			if change.Update != nil {
				name = value(change.Update.IndexName)
			} else {
				name = value(change.Delete.IndexName)
				status = api.IndexStatusDELETING
			}
			for i := range table.Data.GlobalSecondaryIndexes {
				index := &table.Data.GlobalSecondaryIndexes[i]
				if value(index.IndexName) == name {
					index.IndexStatus = new(status)
				}
			}
		}
	}
	if structuralChanges > 0 {
		table.Data.AttributeDefinitions = api.CloneAttributeDefinitions(projected.AttributeDefinitions)
		slices.SortFunc(table.Data.AttributeDefinitions, func(a, b api.AttributeDefinition) int {
			return strings.Compare(value(a.AttributeName), value(b.AttributeName))
		})
	}
	if err = tx.PutTable(table); err != nil {
		return nil, err
	}
	return &table, nil
}

func capacityFromDescription(in *api.ProvisionedThroughputDescription) *api.ProvisionedThroughput {
	if in == nil || in.ReadCapacityUnits == nil || in.WriteCapacityUnits == nil {
		return nil
	}
	return &api.ProvisionedThroughput{ReadCapacityUnits: new(api.PositiveLongObject(*in.ReadCapacityUnits)), WriteCapacityUnits: new(api.PositiveLongObject(*in.WriteCapacityUnits))}
}

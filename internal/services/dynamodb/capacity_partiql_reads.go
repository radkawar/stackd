package dynamodb

import (
	"context"

	api "stackd/internal/awsapi/dynamodb"
)

func readCapacityUnits(size int, consistent, transaction bool) float64 {
	units := float64(max(1, (size+4095)/4096))
	if transaction {
		return units * 2
	}
	if !consistent {
		return units / 2
	}
	return units
}

func statementReadResult(table *TableRecord, index string, global bool, tableUnits, indexUnits float64, transaction bool) *api.ConsumedCapacity {
	part := func(units float64) api.Capacity {
		capacity := api.Capacity{CapacityUnits: new(api.ConsumedCapacityUnits(units))}
		if transaction {
			capacity.ReadCapacityUnits = new(api.ConsumedCapacityUnits(units))
		}
		return capacity
	}
	capacity := &api.ConsumedCapacity{TableName: new(api.TableArn(table.PhysicalName)), CapacityUnits: new(api.ConsumedCapacityUnits(tableUnits + indexUnits)), Table: new(part(tableUnits))}
	if transaction {
		capacity.ReadCapacityUnits = new(api.ConsumedCapacityUnits(tableUnits + indexUnits))
	}
	if index != "" {
		indexes := api.SecondaryIndexesCapacityMap{api.IndexName(index): part(indexUnits)}
		if global {
			capacity.GlobalSecondaryIndexes = indexes
		} else {
			capacity.LocalSecondaryIndexes = indexes
		}
	}
	return capacity
}

// statementReadCapacity measures a native unfiltered, unprojected companion
// statement while the caller holds the database mutation gate. It uses the same
// native traversal, Limit and evaluated cursor, including filtered-empty pages.
// Local 3.3.1 leaves requestHash unset, allowing the original validated cursor
// on this companion. The public pagination envelope still binds the original
// statement and parameters; the original execution owns public validation.
func (s *Service) statementReadCapacity(ctx context.Context, statement *dataStatement, in *api.ExecuteStatementInput, transaction bool) (*api.ConsumedCapacity, error) {
	return s.statementReadCapacityPage(ctx, statement, in, transaction, nil, nil)
}

func (s *Service) statementReadCapacityPage(ctx context.Context, statement *dataStatement, in *api.ExecuteStatementInput, transaction bool, out *api.ExecuteStatementOutput, conditions api.KeyConditions) (*api.ConsumedCapacity, error) {
	table := statement.table
	indexName := statement.parsed.Index()
	consistent := in.ConsistentRead != nil && bool(*in.ConsistentRead)
	schema := table.Data.KeySchema
	var projection *api.Projection
	var global bool
	for _, index := range table.Data.LocalSecondaryIndexes {
		if value(index.IndexName) == indexName {
			schema, projection = index.KeySchema, index.Projection
		}
	}
	for _, index := range table.Data.GlobalSecondaryIndexes {
		if value(index.IndexName) == indexName {
			schema, projection, global = index.KeySchema, index.Projection, true
		}
	}
	fetchTable := projection != nil && !global && !indexProjectsAttributes(table.Data.KeySchema, schema, projection, statement.access.ProjectedAttributes)
	if out == nil {
		conditions = statement.parsed.CapacityConditions(schema, statement.parameters)
		text, parameters := statement.parsed.CapacityReadStatement(table.PhysicalName, schema, conditions)
		measurement := &api.ExecuteStatementInput{Statement: new(api.PartiQLStatement(text)), Parameters: parameters, ConsistentRead: in.ConsistentRead, Limit: in.Limit, NextToken: in.NextToken}
		out = new(api.ExecuteStatementOutput)
		if err := s.callEngine(ctx, table, "ExecuteStatement", measurement, out); err != nil {
			return nil, err
		}
	}
	partition := api.AttributeName(dataPartitionKey(table, indexName))
	// TODO: Comeback model physical scan overhead and empty query-partition visits.
	bytesByPartition := make(map[string]int)
	if conditions != nil && in.NextToken == nil && (out.NextToken == nil || len(out.LastEvaluatedKey) == 0) {
		// A completed multi-key query also visits missing partitions. Each has
		// the documented minimum, even though no item can identify it below.
		for _, attribute := range conditions[partition].AttributeValueList {
			key, _ := dataCanonicalScalar(attribute)
			bytesByPartition[key] = 0
		}
	}
	var scanBytes int
	var fetches []capacityWrite
	for _, item := range out.Items {
		image := api.AttributeMap(item)
		size := itemSize(image)
		if projection != nil {
			size = itemSize(capacityProjection(table.Data.KeySchema, schema, projection, image))
		}
		if conditions == nil {
			scanBytes += size
		} else {
			key, _ := dataCanonicalScalar(image[partition])
			bytesByPartition[key] += size
		}
		if fetchTable {
			fetches = append(fetches, capacityWrite{table: table, key: capacityKey(table.Data.KeySchema, image), readBefore: true})
		}
	}
	var units float64
	if conditions == nil || len(bytesByPartition) == 0 {
		units = readCapacityUnits(scanBytes, consistent, transaction)
	} else {
		for _, size := range bytesByPartition {
			units += readCapacityUnits(size, consistent, transaction)
		}
	}
	if projection == nil {
		return statementReadResult(table, "", false, units, 0, transaction), nil
	}
	var tableUnits float64
	if len(fetches) != 0 {
		var plan dataPlan
		if err := plan.add(&table, statement.selector); err != nil {
			return nil, err
		}
		if err := s.collectCapacityImages(ctx, &plan, fetches, false); err != nil {
			return nil, err
		}
		for _, fetch := range fetches {
			tableUnits += readCapacityUnits(itemSize(fetch.before), consistent, transaction)
		}
	}
	// Physical-partition search overhead is absent from Local's storage model.
	// This reports evaluated bytes and documented minima, not invented AWS
	// physical partition counts; that native topology remains unobservable.
	return statementReadResult(table, indexName, global, tableUnits, units, transaction), nil
}

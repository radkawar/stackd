package glue

import (
	"context"
	"reflect"
	"strconv"

	api "stackd/internal/awsapi/glue"
)

// publishCrawl enters ordinary catalog commands under the live execution role.
// Replaying a retained claim after restart does not create duplicate partitions.
func (s *Service) publishCrawl(ctx context.Context, row CrawlerRecord, tables []crawlerDerivedTable, run *CrawlRecord) error {
	database := new(api.NameString(value(row.Crawler.DatabaseName)))
	seen := make(map[string]bool, len(tables))
	updateBehavior, deleteBehavior := "UPDATE_IN_DATABASE", "DEPRECATE_IN_DATABASE"
	if policy := row.Crawler.SchemaChangePolicy; policy != nil {
		if policy.UpdateBehavior != nil {
			updateBehavior = value(policy.UpdateBehavior)
		}
		if policy.DeleteBehavior != nil {
			deleteBehavior = value(policy.DeleteBehavior)
		}
	}
	for _, derived := range tables {
		if err := ctx.Err(); err != nil {
			return err
		}
		table := derived.Table
		name := value(table.Name)
		if seen[name] {
			return failure("InvalidInputException", "Crawler targets produced duplicate table names.")
		}
		seen[name] = true
		table.StorageDescriptor = catalogStorageDescriptor(table.StorageDescriptor)
		existing, rejected := runCommand(s, ctx, "GetTable", &api.GetTableInput{DatabaseName: database, Name: table.Name}, s.getTable)
		if rejected != nil && rejected.Code != "EntityNotFoundException" {
			return rejected
		}
		if rejected != nil {
			if _, rejected = runCommand(s, ctx, "CreateTable", &api.CreateTableInput{DatabaseName: database, TableInput: &table}, s.createTable); rejected != nil {
				return rejected
			}
			run.TablesCreated++
		} else if updateBehavior != "LOG" {
			if existing.Table == nil {
				return failure("InternalServiceException", "Catalog returned no table.", 500)
			}
			old := existing.Table
			// Preserve application metadata while replacing the crawler-owned schema.
			for k, v := range old.Parameters {
				if _, ok := table.Parameters[k]; !ok && k != "DEPRECATED_BY_CRAWLER" {
					table.Parameters[k] = v
				}
			}
			table.Owner, table.Description, table.Retention = old.Owner, old.Description, old.Retention
			if !reflect.DeepEqual(old.StorageDescriptor, table.StorageDescriptor) || !reflect.DeepEqual(old.PartitionKeys, table.PartitionKeys) || !reflect.DeepEqual(old.Parameters, table.Parameters) {
				if _, rejected = runCommand(s, ctx, "UpdateTable", &api.UpdateTableInput{DatabaseName: database, TableInput: &table}, s.updateTable); rejected != nil {
					return rejected
				}
				run.TablesUpdated++
			}
		}
		for _, partition := range derived.Partitions {
			if err := ctx.Err(); err != nil {
				return err
			}
			partition.StorageDescriptor = catalogStorageDescriptor(partition.StorageDescriptor)
			old, rejected := runCommand(s, ctx, "GetPartition", &api.GetPartitionInput{DatabaseName: database, TableName: table.Name, PartitionValues: partition.Values}, s.getPartition)
			if rejected != nil && rejected.Code != "EntityNotFoundException" {
				return rejected
			}
			if rejected != nil {
				out, rejected := runCommand(s, ctx, "BatchCreatePartition", &api.BatchCreatePartitionInput{DatabaseName: database, TableName: table.Name, PartitionInputList: api.PartitionInputList{partition}}, s.batchCreatePartition)
				if rejected != nil {
					return rejected
				}
				if len(out.Errors) > 0 {
					detail := out.Errors[0].ErrorDetail
					if detail != nil && value(detail.ErrorCode) != "AlreadyExistsException" {
						return failure(value(detail.ErrorCode), value(detail.ErrorMessage))
					}
				} else {
					run.PartitionsCreated++
				}
			} else if updateBehavior != "LOG" && old.Partition != nil && !reflect.DeepEqual(old.Partition.StorageDescriptor, partition.StorageDescriptor) {
				if _, rejected := runCommand(s, ctx, "UpdatePartition", &api.UpdatePartitionInput{DatabaseName: database, TableName: table.Name, PartitionValueList: api.BoundedPartitionValueList(partition.Values), PartitionInput: &partition}, s.updatePartition); rejected != nil {
					return rejected
				}
			}
		}
		if deleteBehavior == "DELETE_FROM_DATABASE" && len(table.PartitionKeys) > 0 {
			if err := s.deleteMissingCrawlerPartitions(ctx, database, table.Name, derived.Partitions); err != nil {
				return err
			}
		}
	}
	if deleteBehavior == "LOG" {
		return nil
	}
	var next *api.Token
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		out, rejected := runCommand(s, ctx, "GetTables", &api.GetTablesInput{DatabaseName: database, NextToken: next}, s.getTables)
		if rejected != nil {
			return rejected
		}
		for _, old := range out.TableList {
			if string(old.Parameters["UPDATED_BY_CRAWLER"]) != row.Key.Name || seen[value(old.Name)] {
				continue
			}
			if deleteBehavior == "DELETE_FROM_DATABASE" {
				if _, rejected := runCommand(s, ctx, "DeleteTable", &api.DeleteTableInput{DatabaseName: database, Name: old.Name}, s.deleteTable); rejected != nil {
					return rejected
				}
				continue
			}
			if _, already := old.Parameters["DEPRECATED_BY_CRAWLER"]; already {
				continue
			}
			old.Parameters["DEPRECATED_BY_CRAWLER"] = api.ParametersMapValue(strconv.FormatInt(s.clock.Now().UnixMilli(), 10))
			input := api.TableInput{Name: old.Name, Description: old.Description, Owner: old.Owner, Retention: old.Retention, TableType: old.TableType, StorageDescriptor: old.StorageDescriptor, PartitionKeys: old.PartitionKeys, Parameters: old.Parameters}
			if _, rejected := runCommand(s, ctx, "UpdateTable", &api.UpdateTableInput{DatabaseName: database, TableInput: &input}, s.updateTable); rejected != nil {
				return rejected
			}
		}
		if out.NextToken == nil {
			break
		}
		next = out.NextToken
	}
	return nil
}

func (s *Service) deleteMissingCrawlerPartitions(ctx context.Context, database, name *api.NameString, partitions []api.PartitionInput) error {
	present := make(map[string]bool, len(partitions))
	for _, partition := range partitions {
		present[partitionValuesKey(partition.Values)] = true
	}
	var next *api.Token
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		out, rejected := runCommand(s, ctx, "GetPartitions", &api.GetPartitionsInput{DatabaseName: database, TableName: name, NextToken: next}, s.getPartitions)
		if rejected != nil {
			return rejected
		}
		for _, partition := range out.Partitions {
			if present[partitionValuesKey(partition.Values)] {
				continue
			}
			if _, rejected := runCommand(s, ctx, "DeletePartition", &api.DeletePartitionInput{DatabaseName: database, TableName: name, PartitionValues: partition.Values}, s.deletePartition); rejected != nil {
				return rejected
			}
		}
		if out.NextToken == nil {
			return nil
		}
		next = out.NextToken
	}
}

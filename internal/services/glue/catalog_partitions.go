package glue

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"strconv"

	api "stackd/internal/awsapi/glue"
)

func partitionValuesKey(values api.ValueStringList) string {
	data, _ := json.Marshal(values)
	return string(data)
}
func validatePartitionValues(table TableRecord, values api.ValueStringList) error {
	if len(values) != len(table.Table.PartitionKeys) {
		return failure("InvalidInputException", "The number of partition values must match the number of partition keys.")
	}
	return nil
}
func partitionDescription(key TableKey, input *api.PartitionInput) api.Partition {
	return api.Partition{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), TableName: new(api.NameString(key.TableName)), Values: input.Values, StorageDescriptor: catalogStorageDescriptor(input.StorageDescriptor), Parameters: input.Parameters, LastAccessTime: input.LastAccessTime, LastAnalyzedTime: input.LastAnalyzedTime}
}
func (s *Service) createPartitionRecord(tx Transaction, table TableRecord, input *api.PartitionInput) error {
	if input == nil {
		return failure("InvalidInputException", "PartitionInput is required.")
	}
	if err := validatePartitionValues(table, input.Values); err != nil {
		return err
	}
	key := PartitionKey{TableKey: table.Key, Values: partitionValuesKey(input.Values)}
	if _, err := tx.Partition(key); err == nil {
		return failure("AlreadyExistsException", "Partition already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	record := PartitionRecord{Key: key, Partition: partitionDescription(table.Key, input)}
	record.Partition.CreationTime = new(s.clock.Now().UTC())
	return tx.PutPartition(record)
}
func (s *Service) partitionTable(ctx context.Context, tx Transaction, action string, key TableKey) (TableRecord, error) {
	if err := s.authorizeTable(ctx, tx, action, key); err != nil {
		return TableRecord{}, err
	}
	return tx.Table(key)
}
func (s *Service) createPartition(ctx context.Context, tx Transaction, in *api.CreatePartitionInput) (*api.CreatePartitionOutput, error) {
	table, err := s.partitionTable(ctx, tx, "CreatePartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName))
	if err != nil {
		return nil, err
	}
	return &api.CreatePartitionOutput{}, s.createPartitionRecord(tx, table, in.PartitionInput)
}
func (s *Service) getPartition(ctx context.Context, tx Transaction, in *api.GetPartitionInput) (*api.GetPartitionOutput, error) {
	table, err := s.partitionTable(ctx, tx, "GetPartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName))
	if err != nil {
		return nil, err
	}
	if err := validatePartitionValues(table, in.PartitionValues); err != nil {
		return nil, err
	}
	record, err := tx.Partition(PartitionKey{TableKey: table.Key, Values: partitionValuesKey(in.PartitionValues)})
	if err != nil {
		return nil, err
	}
	return &api.GetPartitionOutput{Partition: &record.Partition}, nil
}
func (s *Service) getPartitions(ctx context.Context, tx Transaction, in *api.GetPartitionsInput) (*api.GetPartitionsOutput, error) {
	table, err := s.partitionTable(ctx, tx, "GetPartitions", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName))
	if err != nil {
		return nil, err
	}
	if in.TransactionId != nil || in.QueryAsOfTime != nil {
		return nil, unsupported("Transactional partition snapshots are not supported.")
	}
	predicate, err := compilePartitionExpression(value(in.Expression), table.Table.PartitionKeys)
	if err != nil {
		return nil, err
	}
	segment, total := int32(0), int32(1)
	if in.Segment != nil {
		if in.Segment.SegmentNumber == nil || in.Segment.TotalSegments == nil {
			return nil, failure("InvalidInputException", "Both segment fields are required.")
		}
		segment, total = int32(*in.Segment.SegmentNumber), int32(*in.Segment.TotalSegments)
		if total < 1 || segment < 0 || segment >= total {
			return nil, failure("InvalidInputException", "Invalid segment number.")
		}
	}
	binding := catalogPageBinding("GetPartitions", table.Key.ARN(), value(in.Expression), strconv.Itoa(int(segment)), strconv.Itoa(int(total)))
	after, err := catalogPageAfter(in.NextToken, binding)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Partitions(table.Key)
	if err != nil {
		return nil, err
	}
	out := &api.GetPartitionsOutput{Partitions: api.PartitionList{}}
	limit := catalogPageSize(in.MaxResults)
	for _, row := range rows {
		if row.Key.Values <= after {
			continue
		}
		if total > 1 {
			h := fnv.New32a()
			_, _ = h.Write([]byte(row.Key.Values))
			if int32(h.Sum32()%uint32(total)) != segment {
				continue
			}
		}
		matches, err := predicate(row.Partition.Values)
		if err != nil {
			return nil, err
		}
		if !matches {
			continue
		}
		if len(out.Partitions) == limit {
			out.NextToken = catalogNextToken(binding, partitionValuesKey(out.Partitions[len(out.Partitions)-1].Values))
			break
		}
		if in.ExcludeColumnSchema != nil && bool(*in.ExcludeColumnSchema) && row.Partition.StorageDescriptor != nil {
			row.Partition.StorageDescriptor.Columns = nil
		}
		out.Partitions = append(out.Partitions, row.Partition)
	}
	return out, nil
}
func (s *Service) updatePartitionRecord(tx Transaction, table TableRecord, old api.ValueStringList, input *api.PartitionInput) error {
	if input == nil {
		return failure("InvalidInputException", "PartitionInput is required.")
	}
	if err := validatePartitionValues(table, old); err != nil {
		return err
	}
	if err := validatePartitionValues(table, input.Values); err != nil {
		return err
	}
	key := PartitionKey{TableKey: table.Key, Values: partitionValuesKey(old)}
	record, err := tx.Partition(key)
	if err != nil {
		return err
	}
	next := PartitionKey{TableKey: table.Key, Values: partitionValuesKey(input.Values)}
	if next != key {
		if _, err := tx.Partition(next); err == nil {
			return failure("AlreadyExistsException", "Target partition already exists.")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	partition := partitionDescription(table.Key, input)
	partition.CreationTime = record.Partition.CreationTime
	updated := PartitionRecord{CFNOwner: record.CFNOwner, Key: next, Partition: partition}
	if err := updatePartitionStatistics(tx, table, key, updated); err != nil {
		return err
	}
	if next != key {
		if err := tx.DeletePartition(key); err != nil {
			return err
		}
	}
	return tx.PutPartition(updated)
}
func (s *Service) updatePartition(ctx context.Context, tx Transaction, in *api.UpdatePartitionInput) (*api.UpdatePartitionOutput, error) {
	table, err := s.partitionTable(ctx, tx, "UpdatePartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName))
	if err != nil {
		return nil, err
	}
	return &api.UpdatePartitionOutput{}, s.updatePartitionRecord(tx, table, api.ValueStringList(in.PartitionValueList), in.PartitionInput)
}
func deletePartitionRecord(tx Transaction, table TableRecord, values api.ValueStringList) error {
	if err := validatePartitionValues(table, values); err != nil {
		return err
	}
	key := PartitionKey{TableKey: table.Key, Values: partitionValuesKey(values)}
	if _, err := tx.Partition(key); err != nil {
		return err
	}
	return deletePartitionContents(tx, key)
}
func (s *Service) deletePartition(ctx context.Context, tx Transaction, in *api.DeletePartitionInput) (*api.DeletePartitionOutput, error) {
	table, err := s.partitionTable(ctx, tx, "DeletePartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName))
	if err != nil {
		return nil, err
	}
	return &api.DeletePartitionOutput{}, deletePartitionRecord(tx, table, in.PartitionValues)
}
func (s *Service) batchCreatePartition(ctx context.Context, tx Transaction, in *api.BatchCreatePartitionInput) (*api.BatchCreatePartitionOutput, error) {
	table, err := s.partitionTable(ctx, tx, "BatchCreatePartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName))
	if err != nil {
		return nil, err
	}
	// AWS rejects the entire batch for structural partition-value arity errors.
	for _, input := range in.PartitionInputList {
		if err := validatePartitionValues(table, input.Values); err != nil {
			return nil, err
		}
	}
	out := &api.BatchCreatePartitionOutput{Errors: api.PartitionErrors{}}
	event := CatalogEvent{Scope: table.Key.Scope, CatalogID: table.Key.CatalogID, DatabaseName: table.Key.Name, TableName: table.Key.TableName, Operation: "BatchCreatePartition"}
	for _, input := range in.PartitionInputList {
		if err := s.createPartitionRecord(tx, table, &input); err != nil {
			if !errors.Is(err, ErrNotFound) && wireError(err).StatusCode >= 500 {
				return nil, err
			}
			out.Errors = append(out.Errors, api.PartitionError{PartitionValues: input.Values, ErrorDetail: catalogErrorDetail(err)})
		} else if s.catalogEvents != nil {
			event.ChangedPartitions = append(event.ChangedPartitions, catalogEventValues(input.Values))
		}
	}
	if len(event.ChangedPartitions) > 0 {
		if err := s.publishCatalogEvent(ctx, event); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Service) batchGetPartition(ctx context.Context, tx Transaction, in *api.BatchGetPartitionInput) (*api.BatchGetPartitionOutput, error) {
	table, err := s.partitionTable(ctx, tx, "BatchGetPartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName))
	if err != nil {
		return nil, err
	}
	out := &api.BatchGetPartitionOutput{Partitions: api.PartitionList{}, UnprocessedKeys: api.BatchGetPartitionValueList{}}
	seen := map[string]bool{}
	for _, input := range in.PartitionsToGet {
		if err := validatePartitionValues(table, input.Values); err != nil {
			return nil, err
		}
		encoded := partitionValuesKey(input.Values)
		if seen[encoded] {
			continue
		}
		seen[encoded] = true
		row, err := tx.Partition(PartitionKey{TableKey: table.Key, Values: encoded})
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out.Partitions = append(out.Partitions, row.Partition)
	}
	return out, nil
}
func (s *Service) batchUpdatePartition(ctx context.Context, tx Transaction, in *api.BatchUpdatePartitionInput) (*api.BatchUpdatePartitionOutput, error) {
	table, err := s.partitionTable(ctx, tx, "BatchUpdatePartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName))
	if err != nil {
		return nil, err
	}
	for _, input := range in.Entries {
		if input.PartitionInput == nil {
			return nil, failure("InvalidInputException", "PartitionInput is required.")
		}
		if err := validatePartitionValues(table, input.PartitionInput.Values); err != nil {
			return nil, err
		}
		if err := validatePartitionValues(table, api.ValueStringList(input.PartitionValueList)); err != nil {
			return nil, err
		}
	}
	out := &api.BatchUpdatePartitionOutput{Errors: api.BatchUpdatePartitionFailureList{}}
	event := CatalogEvent{Scope: table.Key.Scope, CatalogID: table.Key.CatalogID, DatabaseName: table.Key.Name, TableName: table.Key.TableName, Operation: "BatchUpdatePartition"}
	for _, input := range in.Entries {
		if err := s.updatePartitionRecord(tx, table, api.ValueStringList(input.PartitionValueList), input.PartitionInput); err != nil {
			if wireError(err).StatusCode >= 500 {
				return nil, err
			}
			out.Errors = append(out.Errors, api.BatchUpdatePartitionFailureEntry{PartitionValueList: input.PartitionValueList, ErrorDetail: catalogErrorDetail(err)})
		} else if s.catalogEvents != nil {
			event.ChangedPartitions = append(event.ChangedPartitions, catalogEventValues(input.PartitionInput.Values))
		}
	}
	if len(event.ChangedPartitions) > 0 {
		if err := s.publishCatalogEvent(ctx, event); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Service) batchDeletePartition(ctx context.Context, tx Transaction, in *api.BatchDeletePartitionInput) (*api.BatchDeletePartitionOutput, error) {
	table, err := s.partitionTable(ctx, tx, "BatchDeletePartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName))
	if err != nil {
		return nil, err
	}
	for _, input := range in.PartitionsToDelete {
		if err := validatePartitionValues(table, input.Values); err != nil {
			return nil, err
		}
	}
	out := &api.BatchDeletePartitionOutput{Errors: api.PartitionErrors{}}
	event := CatalogEvent{Scope: table.Key.Scope, CatalogID: table.Key.CatalogID, DatabaseName: table.Key.Name, TableName: table.Key.TableName, Operation: "BatchDeletePartition"}
	for _, input := range in.PartitionsToDelete {
		if err := deletePartitionRecord(tx, table, input.Values); err != nil {
			if wireError(err).StatusCode >= 500 {
				return nil, err
			}
			out.Errors = append(out.Errors, api.PartitionError{PartitionValues: input.Values, ErrorDetail: catalogErrorDetail(err)})
		} else if s.catalogEvents != nil {
			event.ChangedPartitions = append(event.ChangedPartitions, catalogEventValues(input.Values))
		}
	}
	if len(event.ChangedPartitions) > 0 {
		if err := s.publishCatalogEvent(ctx, event); err != nil {
			return nil, err
		}
	}
	return out, nil
}

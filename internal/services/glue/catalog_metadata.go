package glue

import (
	"context"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/glue"
)

func (s *Service) createIndex(tx Transaction, table TableRecord, input api.PartitionIndex) error {
	key := PartitionIndexKey{TableKey: table.Key, IndexName: value(input.IndexName)}
	if _, err := tx.PartitionIndex(key); err == nil {
		return failure("AlreadyExistsException", "Partition index already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	indexes, err := tx.PartitionIndexes(table.Key)
	if err != nil {
		return err
	}
	if len(indexes) >= 3 {
		return failure("ResourceNumberLimitExceededException", "A table can have at most three partition indexes.")
	}
	if len(input.Keys) == 0 {
		return failure("InvalidInputException", "Partition index keys cannot be empty.")
	}
	descriptor := api.PartitionIndexDescriptor{IndexName: input.IndexName, IndexStatus: new(api.PartitionIndexStatusACTIVE), Keys: api.KeySchemaElementList{}}
	seen := map[string]bool{}
	positions := []int{}
	for _, key := range input.Keys {
		name := string(key)
		if seen[name] {
			return failure("InvalidInputException", "Duplicate partition index key.")
		}
		seen[name] = true
		found := false
		for i, column := range table.Table.PartitionKeys {
			if value(column.Name) == name {
				descriptor.Keys = append(descriptor.Keys, api.KeySchemaElement{Name: column.Name, Type: new(api.ColumnTypeString(value(column.Type)))})
				positions = append(positions, i)
				found = true
				break
			}
		}
		if !found {
			return failure("InvalidInputException", "Partition index keys must refer to table partition keys.")
		}
	}
	partitions, err := tx.Partitions(table.Key)
	if err != nil {
		return err
	}
	invalid := api.BackfillErroredPartitionsList{}
	for _, partition := range partitions {
		for j, i := range positions {
			if i >= len(partition.Partition.Values) {
				invalid = append(invalid, api.PartitionValueList{Values: partition.Partition.Values})
				break
			}
			_, err := partitionComparator(value(descriptor.Keys[j].Type), partitionToken{text: string(partition.Partition.Values[i]), quoted: true})
			if err != nil {
				invalid = append(invalid, api.PartitionValueList{Values: partition.Partition.Values})
				break
			}
		}
	}
	if len(invalid) > 0 {
		descriptor.IndexStatus = new(api.PartitionIndexStatusFAILED)
		descriptor.BackfillErrors = api.BackfillErrors{{Code: new(api.BackfillErrorCodeINVALID_PARTITION_TYPE_DATA_ERROR), Partitions: invalid}}
	}
	return tx.PutPartitionIndex(PartitionIndexRecord{Key: key, Index: descriptor})
}
func (s *Service) createPartitionIndex(ctx context.Context, tx Transaction, in *api.CreatePartitionIndexInput) (*api.CreatePartitionIndexOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName)
	table, err := s.partitionTable(ctx, tx, "CreatePartitionIndex", key)
	if err != nil {
		return nil, err
	}
	if in.PartitionIndex == nil {
		return nil, failure("InvalidInputException", "PartitionIndex is required.")
	}
	return &api.CreatePartitionIndexOutput{}, s.createIndex(tx, table, *in.PartitionIndex)
}
func (s *Service) getPartitionIndexes(ctx context.Context, tx Transaction, in *api.GetPartitionIndexesInput) (*api.GetPartitionIndexesOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName)
	if _, err := s.partitionTable(ctx, tx, "GetPartitionIndexes", key); err != nil {
		return nil, err
	}
	binding := catalogPageBinding("GetPartitionIndexes", key.ARN())
	after, err := catalogPageAfter(in.NextToken, binding)
	if err != nil {
		return nil, err
	}
	rows, err := tx.PartitionIndexes(key)
	if err != nil {
		return nil, err
	}
	out := &api.GetPartitionIndexesOutput{PartitionIndexDescriptorList: api.PartitionIndexDescriptorList{}}
	for _, row := range rows {
		if row.Key.IndexName > after {
			out.PartitionIndexDescriptorList = append(out.PartitionIndexDescriptorList, row.Index)
		}
	}
	return out, nil
}
func (s *Service) deletePartitionIndex(ctx context.Context, tx Transaction, in *api.DeletePartitionIndexInput) (*api.DeletePartitionIndexOutput, error) {
	table := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName)
	if _, err := s.partitionTable(ctx, tx, "DeletePartitionIndex", table); err != nil {
		return nil, err
	}
	key := PartitionIndexKey{TableKey: table, IndexName: value(in.IndexName)}
	if _, err := tx.PartitionIndex(key); err != nil {
		return nil, err
	}
	return &api.DeletePartitionIndexOutput{}, tx.DeletePartitionIndex(key)
}
func functionKey(ctx context.Context, id *api.CatalogIdString, db, name *api.NameString) FunctionKey {
	return FunctionKey{DatabaseKey: databaseKey(ctx, id, db), FunctionName: strings.ToLower(value(name))}
}
func (s *Service) authorizeFunction(ctx context.Context, tx Reader, action string, key FunctionKey) error {
	return s.authorizeCatalog(ctx, tx, action, key.CatalogKey, key.DatabaseKey.ARN(), key.ARN())
}
func functionDescription(key FunctionKey, in *api.UserDefinedFunctionInput) api.UserDefinedFunction {
	return api.UserDefinedFunction{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), FunctionName: new(api.NameString(key.FunctionName)), ClassName: in.ClassName, FunctionType: in.FunctionType, OwnerName: in.OwnerName, OwnerType: in.OwnerType, ResourceUris: in.ResourceUris}
}
func (s *Service) createUserDefinedFunction(ctx context.Context, tx Transaction, in *api.CreateUserDefinedFunctionInput) (*api.CreateUserDefinedFunctionOutput, error) {
	if in.FunctionInput == nil || value(in.FunctionInput.FunctionName) == "" {
		return nil, failure("InvalidInputException", "FunctionName is required.")
	}
	key := functionKey(ctx, in.CatalogId, in.DatabaseName, in.FunctionInput.FunctionName)
	if err := s.authorizeFunction(ctx, tx, "CreateUserDefinedFunction", key); err != nil {
		return nil, err
	}
	if _, err := tx.Database(key.DatabaseKey); err != nil {
		return nil, err
	}
	if _, err := tx.Function(key); err == nil {
		return nil, failure("AlreadyExistsException", "Function already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	record := FunctionRecord{Key: key, Function: functionDescription(key, in.FunctionInput)}
	record.Function.CreateTime = new(s.clock.Now().UTC())
	return &api.CreateUserDefinedFunctionOutput{}, tx.PutFunction(record)
}
func (s *Service) getUserDefinedFunction(ctx context.Context, tx Transaction, in *api.GetUserDefinedFunctionInput) (*api.GetUserDefinedFunctionOutput, error) {
	key := functionKey(ctx, in.CatalogId, in.DatabaseName, in.FunctionName)
	if err := s.authorizeFunction(ctx, tx, "GetUserDefinedFunction", key); err != nil {
		return nil, err
	}
	record, err := tx.Function(key)
	if err != nil {
		return nil, err
	}
	return &api.GetUserDefinedFunctionOutput{UserDefinedFunction: &record.Function}, nil
}
func (s *Service) updateUserDefinedFunction(ctx context.Context, tx Transaction, in *api.UpdateUserDefinedFunctionInput) (*api.UpdateUserDefinedFunctionOutput, error) {
	key := functionKey(ctx, in.CatalogId, in.DatabaseName, in.FunctionName)
	if err := s.authorizeFunction(ctx, tx, "UpdateUserDefinedFunction", key); err != nil {
		return nil, err
	}
	record, err := tx.Function(key)
	if err != nil {
		return nil, err
	}
	if in.FunctionInput == nil || strings.ToLower(value(in.FunctionInput.FunctionName)) != key.FunctionName {
		return nil, failure("InvalidInputException", "Function name cannot be changed.")
	}
	updated := functionDescription(key, in.FunctionInput)
	updated.CreateTime = record.Function.CreateTime
	record.Function = updated
	return &api.UpdateUserDefinedFunctionOutput{}, tx.PutFunction(record)
}
func (s *Service) deleteUserDefinedFunction(ctx context.Context, tx Transaction, in *api.DeleteUserDefinedFunctionInput) (*api.DeleteUserDefinedFunctionOutput, error) {
	key := functionKey(ctx, in.CatalogId, in.DatabaseName, in.FunctionName)
	if err := s.authorizeFunction(ctx, tx, "DeleteUserDefinedFunction", key); err != nil {
		return nil, err
	}
	if _, err := tx.Function(key); err != nil {
		return nil, err
	}
	return &api.DeleteUserDefinedFunctionOutput{}, tx.DeleteFunction(key)
}
func (s *Service) getUserDefinedFunctions(ctx context.Context, tx Transaction, in *api.GetUserDefinedFunctionsInput) (*api.GetUserDefinedFunctionsOutput, error) {
	key := databaseKey(ctx, in.CatalogId, in.DatabaseName)
	if err := s.authorizeCatalog(ctx, tx, "GetUserDefinedFunctions", key.CatalogKey); err != nil {
		return nil, err
	}
	var databases []DatabaseRecord
	if in.DatabaseName != nil {
		if err := s.authorizeDatabase(ctx, tx, "GetUserDefinedFunctions", key); err != nil {
			return nil, err
		}
		row, err := tx.Database(key)
		if err != nil {
			return nil, err
		}
		databases = []DatabaseRecord{row}
	} else {
		var err error
		databases, err = tx.Databases(key.CatalogKey)
		if err != nil {
			return nil, err
		}
	}
	filter, err := catalogNameFilter(value(in.Pattern))
	if err != nil {
		return nil, err
	}
	binding := catalogPageBinding("GetUserDefinedFunctions", key.ARN(), value(in.Pattern), value(in.FunctionType))
	after, err := catalogPageAfter(in.NextToken, binding)
	if err != nil {
		return nil, err
	}
	rows := []FunctionRecord{}
	for _, database := range databases {
		found, err := tx.Functions(database.Key)
		if err != nil {
			return nil, err
		}
		rows = append(rows, found...)
	}
	slices.SortFunc(rows, func(a, b FunctionRecord) int {
		return strings.Compare(a.Key.Name+"\x00"+a.Key.FunctionName, b.Key.Name+"\x00"+b.Key.FunctionName)
	})
	out := &api.GetUserDefinedFunctionsOutput{UserDefinedFunctions: api.UserDefinedFunctionList{}}
	limit := catalogPageSize(in.MaxResults)
	last := ""
	for _, row := range rows {
		cursor := row.Key.Name + "\x00" + row.Key.FunctionName
		if cursor <= after || filter != nil && !filter.MatchString(row.Key.FunctionName) || in.FunctionType != nil && value(row.Function.FunctionType) != value(in.FunctionType) {
			continue
		}
		if err := s.authorizeFunction(ctx, tx, "GetUserDefinedFunctions", row.Key); err != nil {
			if wireError(err).Code == "AccessDeniedException" {
				continue
			}
			return nil, err
		}
		if len(out.UserDefinedFunctions) == limit {
			out.NextToken = catalogNextToken(binding, last)
			break
		}
		out.UserDefinedFunctions = append(out.UserDefinedFunctions, row.Function)
		last = cursor
	}
	return out, nil
}

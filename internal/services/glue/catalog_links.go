package glue

import (
	"context"
	"errors"
	"strings"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
)

// Resource links keep their own identity and permissions. The AWS Glue API
// follows at most one database or table link, with operation-specific rules:
// https://docs.aws.amazon.com/lake-formation/latest/dg/resource-links-glue-apis.html
// These helpers select command resources; they do not create another catalog.
type catalogRoute struct {
	ctx                     context.Context
	input, output           any
	hasOutput, followTables bool
}

func linkContext(ctx context.Context, region string) context.Context {
	if region == "" {
		return ctx
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Region = region
	return awsctx.WithMetadata(ctx, metadata)
}
func databaseLinkKey(source DatabaseKey, target *api.DatabaseIdentifier) (DatabaseKey, error) {
	if target == nil || value(target.DatabaseName) == "" {
		return DatabaseKey{}, failure("InvalidInputException", "A database link requires a target database name.")
	}
	catalog := value(target.CatalogId)
	if catalog == "" {
		catalog = source.CatalogID
	}
	account, _, _ := strings.Cut(catalog, ":")
	scope := source.Scope
	scope.AccountID = account
	if target.Region != nil {
		scope.Region = value(target.Region)
	}
	return DatabaseKey{CatalogKey: CatalogKey{Scope: scope, CatalogID: catalog}, Name: strings.ToLower(value(target.DatabaseName))}, nil
}
func tableLinkKey(source TableKey, target *api.TableIdentifier) (TableKey, error) {
	if target == nil || value(target.DatabaseName) == "" || value(target.Name) == "" {
		return TableKey{}, failure("InvalidInputException", "A table link requires target database and table names.")
	}
	db, err := databaseLinkKey(source.DatabaseKey, &api.DatabaseIdentifier{CatalogId: target.CatalogId, DatabaseName: target.DatabaseName, Region: target.Region})
	if err != nil {
		return TableKey{}, err
	}
	return TableKey{DatabaseKey: db, TableName: strings.ToLower(value(target.Name))}, nil
}
func catalogInputKeys(ctx context.Context, input any) (DatabaseKey, string, bool) {
	switch in := input.(type) {
	case *api.GetDatabaseInput:
		return databaseKey(ctx, in.CatalogId, in.Name), "", true
	case *api.UpdateDatabaseInput:
		return databaseKey(ctx, in.CatalogId, in.Name), "", true
	case *api.CreateTableInput:
		if in.TableInput != nil {
			return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableInput.Name)), true
		}
	case *api.UpdateTableInput:
		if in.TableInput != nil {
			name := in.TableInput.Name
			if in.Name != nil {
				name = in.Name
			}
			return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(name)), true
		}
	case *api.GetTableInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.Name)), true
	case *api.DeleteTableInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.Name)), true
	case *api.GetTablesInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), "", true
	case *api.BatchDeleteTableInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), "", true
	case *api.GetTableVersionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.GetTableVersionsInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.DeleteTableVersionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.CreatePartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.GetPartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.GetPartitionsInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.UpdatePartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.DeletePartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.BatchCreatePartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.BatchGetPartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.BatchUpdatePartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.BatchDeletePartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.CreateUserDefinedFunctionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), "", true
	case *api.GetUserDefinedFunctionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), "", true
	case *api.GetUserDefinedFunctionsInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), "", in.DatabaseName != nil
	case *api.UpdateUserDefinedFunctionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), "", true
	case *api.DeleteUserDefinedFunctionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), "", true
	case *api.GetColumnStatisticsForTableInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.UpdateColumnStatisticsForTableInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.DeleteColumnStatisticsForTableInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.GetColumnStatisticsForPartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.UpdateColumnStatisticsForPartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	case *api.DeleteColumnStatisticsForPartitionInput:
		return databaseKey(ctx, in.CatalogId, in.DatabaseName), strings.ToLower(value(in.TableName)), true
	}
	return DatabaseKey{}, "", false
}
func (s *Service) routeCatalogCommand(ctx context.Context, tx Reader, action string, input any) (catalogRoute, error) {
	route := catalogRoute{ctx: ctx, input: input, followTables: action == "GetTables"}
	db, name, selected := catalogInputKeys(ctx, input)
	if !selected {
		return route, nil
	}
	originalName := name
	record, err := tx.Database(db)
	if errors.Is(err, ErrNotFound) {
		return route, nil
	}
	if err != nil {
		return route, err
	}
	dbLinked := record.Database.TargetDatabase != nil
	if dbLinked {
		if err := s.authorizeDatabase(ctx, tx, action, db); err != nil {
			return route, err
		}
		if in, ok := input.(*api.UpdateDatabaseInput); ok && in.DatabaseInput != nil && in.DatabaseInput.TargetDatabase != nil {
			return route, failure("InvalidInputException", "A database resource link target cannot be changed.")
		}
		target, err := databaseLinkKey(db, record.Database.TargetDatabase)
		if err != nil {
			return route, err
		}
		targetCtx := linkContext(ctx, target.Region)
		if err := s.authorizeDatabase(targetCtx, tx, action, target); err != nil {
			if action == "GetDatabase" && wireError(err).Code == "AccessDeniedException" {
				return route, nil
			}
			return route, err
		}
		targetRecord, err := tx.Database(target)
		if err != nil {
			return route, err
		}
		if targetRecord.Database.TargetDatabase != nil {
			return route, failure("InvalidInputException", "Resource link chains are not supported.")
		}
		if in, ok := input.(*api.CreateTableInput); ok && in.TableInput != nil && in.TableInput.TargetTable != nil {
			return route, failure("InvalidInputException", "A table resource link cannot be created through a database resource link.")
		}
		db = target
		route.ctx = targetCtx
		route.followTables = false
	}
	followTable := name != "" && action != "CreateTable" && action != "DeleteTable" && action != "DeleteTableVersion"
	if followTable {
		key := TableKey{DatabaseKey: db, TableName: name}
		table, err := tx.Table(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return route, err
		}
		if err == nil && table.Table.TargetTable != nil {
			if err := s.authorizeTable(route.ctx, tx, action, key); err != nil {
				return route, err
			}
			if in, ok := input.(*api.UpdateTableInput); ok && in.TableInput != nil && in.TableInput.TargetTable != nil {
				return route, failure("InvalidInputException", "A table resource link target cannot be changed.")
			}
			readTable := action == "GetTable" || action == "GetTableVersion" || action == "GetTableVersions"
			if dbLinked && !readTable {
				switch action {
				case "GetPartition":
					route.output = &api.GetPartitionOutput{}
					route.hasOutput = true
					return route, nil
				case "GetPartitions":
					route.output = &api.GetPartitionsOutput{Partitions: api.PartitionList{}}
					route.hasOutput = true
					return route, nil
				case "BatchGetPartition":
					route.output = &api.BatchGetPartitionOutput{Partitions: api.PartitionList{}, UnprocessedKeys: api.BatchGetPartitionValueList{}}
					route.hasOutput = true
					return route, nil
				}
				return route, failure("InvalidInputException", "This operation cannot follow both database and table resource links.")
			}
			if !dbLinked {
				target, err := tableLinkKey(key, table.Table.TargetTable)
				if err != nil {
					return route, err
				}
				route.ctx = linkContext(route.ctx, target.Region)
				if err := s.authorizeTable(route.ctx, tx, action, target); err != nil {
					return route, err
				}
				targetTable, err := tx.Table(target)
				if err != nil {
					return route, err
				}
				if targetTable.Table.TargetTable != nil {
					return route, failure("InvalidInputException", "Resource link chains are not supported.")
				}
				db, name = target.DatabaseKey, target.TableName
			}
		}
	}
	if db != record.Key || name != originalName {
		route.input = rewriteCatalogInput(input, db, name)
	}
	return route, nil
}
func rewriteCatalogInput(input any, key DatabaseKey, table string) any {
	id, name, tableName := new(api.CatalogIdString(key.CatalogID)), new(api.NameString(key.Name)), new(api.NameString(table))
	switch in := input.(type) {
	case *api.GetDatabaseInput:
		v := *in
		v.CatalogId, v.Name = id, name
		return &v
	case *api.UpdateDatabaseInput:
		v := *in
		v.CatalogId, v.Name = id, name
		if in.DatabaseInput != nil {
			body := *in.DatabaseInput
			body.Name = name
			body.TargetDatabase = nil
			v.DatabaseInput = &body
		}
		return &v
	case *api.CreateTableInput:
		v := *in
		v.CatalogId, v.DatabaseName = id, name
		return &v
	case *api.GetTableInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.Name = id, name, tableName
		return &v
	case *api.GetTablesInput:
		v := *in
		v.CatalogId, v.DatabaseName = id, name
		return &v
	case *api.UpdateTableInput:
		v := *in
		v.CatalogId, v.DatabaseName = id, name
		if in.Name != nil {
			v.Name = tableName
		}
		if in.TableInput != nil {
			body := *in.TableInput
			body.Name = tableName
			body.TargetTable = nil
			v.TableInput = &body
		}
		return &v
	case *api.DeleteTableInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.Name = id, name, tableName
		return &v
	case *api.BatchDeleteTableInput:
		v := *in
		v.CatalogId, v.DatabaseName = id, name
		return &v
	case *api.GetTableVersionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.GetTableVersionsInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.DeleteTableVersionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.CreatePartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.GetPartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.GetPartitionsInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.UpdatePartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.DeletePartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.BatchCreatePartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.BatchGetPartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.BatchUpdatePartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.BatchDeletePartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.CreateUserDefinedFunctionInput:
		v := *in
		v.CatalogId, v.DatabaseName = id, name
		return &v
	case *api.GetUserDefinedFunctionInput:
		v := *in
		v.CatalogId, v.DatabaseName = id, name
		return &v
	case *api.GetUserDefinedFunctionsInput:
		v := *in
		v.CatalogId, v.DatabaseName = id, name
		return &v
	case *api.UpdateUserDefinedFunctionInput:
		v := *in
		v.CatalogId, v.DatabaseName = id, name
		return &v
	case *api.DeleteUserDefinedFunctionInput:
		v := *in
		v.CatalogId, v.DatabaseName = id, name
		return &v
	case *api.GetColumnStatisticsForTableInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.UpdateColumnStatisticsForTableInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.DeleteColumnStatisticsForTableInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.GetColumnStatisticsForPartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.UpdateColumnStatisticsForPartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	case *api.DeleteColumnStatisticsForPartitionInput:
		v := *in
		v.CatalogId, v.DatabaseName, v.TableName = id, name, tableName
		return &v
	}
	return input
}
func (s *Service) followCatalogResult(tx Reader, route catalogRoute, output any) error {
	switch out := output.(type) {
	case *api.GetDatabasesOutput:
		for i, db := range out.DatabaseList {
			if db.TargetDatabase == nil {
				continue
			}
			source := databaseKey(route.ctx, db.CatalogId, db.Name)
			target, err := databaseLinkKey(source, db.TargetDatabase)
			if err != nil {
				return err
			}
			ctx := linkContext(route.ctx, target.Region)
			if err := s.authorizeDatabase(ctx, tx, "GetDatabases", target); err != nil {
				if wireError(err).Code == "AccessDeniedException" {
					continue
				}
				return err
			}
			record, err := tx.Database(target)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if record.Database.TargetDatabase == nil {
				out.DatabaseList[i] = record.Database
			}
		}
	case *api.GetTablesOutput:
		if !route.followTables {
			return nil
		}
		for i, table := range out.TableList {
			if table.TargetTable == nil {
				continue
			}
			source := tableKey(route.ctx, table.CatalogId, table.DatabaseName, table.Name)
			target, err := tableLinkKey(source, table.TargetTable)
			if err != nil {
				return err
			}
			ctx := linkContext(route.ctx, target.Region)
			if err := s.authorizeTable(ctx, tx, "GetTables", target); err != nil {
				return err
			}
			record, err := tx.Table(target)
			if err != nil {
				return err
			}
			if record.Table.TargetTable != nil {
				return failure("InvalidInputException", "Resource link chains are not supported.")
			}
			out.TableList[i] = record.Table
		}
	}
	return nil
}

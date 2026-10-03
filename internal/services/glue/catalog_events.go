package glue

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/glue"
)

type CatalogEvent struct {
	Scope                                         Scope
	CatalogID, DatabaseName, TableName, Operation string
	ChangedTables                                 []string
	ChangedPartitions                             [][]string
}
type CatalogEvents interface {
	PublishCatalog(context.Context, CatalogEvent) error
}

func catalogEventValues(values api.ValueStringList) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}
func (s *Service) publishCatalogCall(ctx context.Context, action string, input any) error {
	if s.catalogEvents == nil {
		return nil
	}
	var id *api.CatalogIdString
	var db, table *api.NameString
	event := CatalogEvent{Operation: action}
	switch in := input.(type) {
	case *api.CreateDatabaseInput:
		id = in.CatalogId
		db = in.DatabaseInput.Name
	case *api.DeleteDatabaseInput:
		id = in.CatalogId
		db = in.Name
	case *api.CreateTableInput:
		id = in.CatalogId
		db = in.DatabaseName
		event.ChangedTables = []string{value(in.TableInput.Name)}
	case *api.DeleteTableInput:
		id = in.CatalogId
		db = in.DatabaseName
		event.ChangedTables = []string{value(in.Name)}
	case *api.UpdateTableInput:
		id = in.CatalogId
		db = in.DatabaseName
		table = in.TableInput.Name
	case *api.CreatePartitionInput:
		id = in.CatalogId
		db = in.DatabaseName
		table = in.TableName
		event.ChangedPartitions = [][]string{catalogEventValues(in.PartitionInput.Values)}
	case *api.UpdatePartitionInput:
		id = in.CatalogId
		db = in.DatabaseName
		table = in.TableName
		event.ChangedPartitions = [][]string{catalogEventValues(in.PartitionInput.Values)}
	case *api.DeletePartitionInput:
		id = in.CatalogId
		db = in.DatabaseName
		table = in.TableName
		event.ChangedPartitions = [][]string{catalogEventValues(in.PartitionValues)}
	default:
		return nil
	}
	key := catalogKey(ctx, id)
	event.Scope = key.Scope
	event.CatalogID = key.CatalogID
	event.DatabaseName = value(db)
	event.TableName = value(table)
	return s.publishCatalogEvent(ctx, event)
}

func (s *Service) publishCatalogEvent(ctx context.Context, event CatalogEvent) error {
	if s.catalogEvents == nil {
		return nil
	}
	event.DatabaseName = strings.ToLower(event.DatabaseName)
	event.TableName = strings.ToLower(event.TableName)
	for i, name := range event.ChangedTables {
		event.ChangedTables[i] = strings.ToLower(name)
	}
	return s.catalogEvents.PublishCatalog(ctx, event)
}

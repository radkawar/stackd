// Package glue owns the Data Catalog and Glue execution control plane.
package glue

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/glue"
)

var ErrNotFound = errors.New("glue resource not found")

type Scope struct{ Partition, AccountID, Region string }
type ResourceKey struct {
	Scope
	Name string
}

func (k ResourceKey) ARN(kind string) string {
	return "arn:" + k.Partition + ":glue:" + k.Region + ":" + k.AccountID + ":" + kind + "/" + k.Name
}

type CatalogKey struct {
	Scope
	CatalogID string
}

func (k CatalogKey) ARN() string {
	path := strings.TrimPrefix(k.CatalogID, k.AccountID)
	return "arn:" + k.Partition + ":glue:" + k.Region + ":" + k.AccountID + ":catalog" + strings.ReplaceAll(path, ":", "/")
}
func (k CatalogKey) ResourceARN(kind, name string) string {
	path := strings.TrimPrefix(k.CatalogID, k.AccountID)
	path = strings.TrimPrefix(strings.ReplaceAll(path, ":", "/"), "/")
	if path != "" {
		name = path + "/" + name
	}
	return ResourceKey{Scope: k.Scope, Name: name}.ARN(kind)
}

type DatabaseKey struct {
	CatalogKey
	Name string
}

func (k DatabaseKey) ARN() string { return k.CatalogKey.ResourceARN("database", k.Name) }

type TableKey struct {
	DatabaseKey
	TableName string
}

func (k TableKey) ARN() string { return k.CatalogKey.ResourceARN("table", k.Name+"/"+k.TableName) }

type PartitionKey struct {
	TableKey
	Values string
}
type FunctionKey struct {
	DatabaseKey
	FunctionName string
}

func (k FunctionKey) ARN() string {
	return k.CatalogKey.ResourceARN("userDefinedFunction", k.Name+"/"+k.FunctionName)
}

type TableVersionKey struct {
	TableKey
	Version int64
}
type PartitionIndexKey struct {
	TableKey
	IndexName string
}
type ColumnStatisticsKey struct {
	TableKey
	ColumnName string
}
type PartitionColumnStatisticsKey struct {
	PartitionKey
	ColumnName string
}

type CatalogRecord struct {
	CFNOwner string
	Key      CatalogKey
	Catalog  api.Catalog
	Tags     map[string]string
}
type DatabaseRecord struct {
	CFNOwner string
	Key      DatabaseKey
	Database api.Database
	Tags     map[string]string
}
type TableRecord struct {
	CFNOwner string
	Key      TableKey
	Table    api.Table
	Version  int64
}
type TableVersionRecord struct {
	Key   TableVersionKey
	Table api.Table
}
type PartitionRecord struct {
	CFNOwner  string
	Key       PartitionKey
	Partition api.Partition
}
type FunctionRecord struct {
	Key      FunctionKey
	Function api.UserDefinedFunction
}
type PartitionIndexRecord struct {
	Key   PartitionIndexKey
	Index api.PartitionIndexDescriptor
}
type ColumnStatisticsRecord struct {
	Key        ColumnStatisticsKey
	Statistics api.ColumnStatistics
}
type PartitionColumnStatisticsRecord struct {
	Key        PartitionColumnStatisticsKey
	Statistics api.ColumnStatistics
}
type ResourcePolicyRecord struct {
	Scope            Scope
	Policy           authorization.BoundPolicy
	Hash             string
	Created, Updated time.Time
}
type CatalogImportRecord struct {
	Key    CatalogKey
	Status api.CatalogImportStatus
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	Catalog(CatalogKey) (CatalogRecord, error)
	Catalogs(Scope) ([]CatalogRecord, error)
	Database(DatabaseKey) (DatabaseRecord, error)
	Databases(CatalogKey) ([]DatabaseRecord, error)
	ForeignDatabases(Scope) ([]DatabaseRecord, error)
	Table(TableKey) (TableRecord, error)
	Tables(DatabaseKey) ([]TableRecord, error)
	TableVersion(TableVersionKey) (TableVersionRecord, error)
	TableVersions(TableKey) ([]TableVersionRecord, error)
	Partition(PartitionKey) (PartitionRecord, error)
	Partitions(TableKey) ([]PartitionRecord, error)
	Function(FunctionKey) (FunctionRecord, error)
	Functions(DatabaseKey) ([]FunctionRecord, error)
	PartitionIndex(PartitionIndexKey) (PartitionIndexRecord, error)
	PartitionIndexes(TableKey) ([]PartitionIndexRecord, error)
	ColumnStatistics(ColumnStatisticsKey) (ColumnStatisticsRecord, error)
	PartitionColumnStatistics(PartitionColumnStatisticsKey) (PartitionColumnStatisticsRecord, error)
	PartitionStatistics(PartitionKey) ([]PartitionColumnStatisticsRecord, error)
	ResourcePolicy(Scope) (ResourcePolicyRecord, error)
	CatalogImport(CatalogKey) (CatalogImportRecord, error)
	JobsReader
	CrawlersReader
	RegistryReader
	WorkflowsReader
}
type Transaction interface {
	Reader
	PutCatalog(CatalogRecord) error
	DeleteCatalog(CatalogKey) error
	PutDatabase(DatabaseRecord) error
	DeleteDatabase(DatabaseKey) error
	PutTable(TableRecord) error
	DeleteTable(TableKey) error
	PutTableVersion(TableVersionRecord) error
	DeleteTableVersion(TableVersionKey) error
	PutPartition(PartitionRecord) error
	DeletePartition(PartitionKey) error
	PutFunction(FunctionRecord) error
	DeleteFunction(FunctionKey) error
	PutPartitionIndex(PartitionIndexRecord) error
	DeletePartitionIndex(PartitionIndexKey) error
	PutColumnStatistics(ColumnStatisticsRecord) error
	DeleteColumnStatistics(ColumnStatisticsKey) error
	PutPartitionColumnStatistics(PartitionColumnStatisticsRecord) error
	DeletePartitionColumnStatistics(PartitionColumnStatisticsKey) error
	DeletePartitionStatistics(PartitionKey) error
	DeletePartitionColumnStatisticsForColumn(ColumnStatisticsKey) error
	PutResourcePolicy(ResourcePolicyRecord) error
	DeleteResourcePolicy(Scope) error
	PutCatalogImport(CatalogImportRecord) error
	JobsWriter
	CrawlersWriter
	RegistryWriter
	WorkflowsWriter
}

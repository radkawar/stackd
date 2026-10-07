// Package athena owns Athena controls and durable SQL execution intent.
package athena

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/athena"
	"stackd/internal/awsctx"
)

var ErrNotFound = errors.New("athena resource not found")

type Scope struct{ Partition, AccountID, Region string }
type ResourceKey struct {
	Scope
	Name string
}

func (k ResourceKey) ARN(kind string) string {
	return "arn:" + k.Partition + ":athena:" + k.Region + ":" + k.AccountID + ":" + kind + "/" + k.Name
}

type StatementKey struct {
	WorkGroup ResourceKey
	Name      string
}

type WorkGroupRecord struct {
	CFNOwner string
	Key      ResourceKey
	Data     api.WorkGroup
	Tags     map[string]string
}
type CatalogRecord struct {
	CFNOwner string
	Key      ResourceKey
	Data     api.DataCatalog
	Tags     map[string]string
}
type NamedQueryRecord struct {
	CFNOwner           string
	Key                ResourceKey
	Data               api.NamedQuery
	Token, Fingerprint string
}
type PreparedStatementRecord struct {
	CFNOwner string
	Key      StatementKey
	Data     api.PreparedStatement
}

// QueryRecord retains public execution metadata, not result rows. S3 remains
// authoritative for result bytes. Caller is authenticated nonsecret identity,
// not a second credential store. Version fences cancellation and stale workers.
type QueryRecord struct {
	Key                ResourceKey
	Data               api.QueryExecution
	Token, Fingerprint string
	Caller             awsctx.Metadata
	ParentEventID      string
	Version            int64
	Due                time.Time
	Started            *time.Time
	EngineID           string
	Columns            api.ColumnInfoList
	UpdateCount        int64
	PublishMetrics     bool
	RequesterPays      bool
	BytesCutoff        int64
}

type ResourceQuery struct {
	Scope            Scope
	WorkGroup, After string
	Limit            int
}

// Repository participates in the shared memory or native SQL transaction domain.
// Native engine and S3 effects must never run inside these callbacks.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	WorkGroup(ResourceKey) (WorkGroupRecord, error)
	WorkGroups(ResourceQuery) ([]WorkGroupRecord, error)
	Catalog(ResourceKey) (CatalogRecord, error)
	Catalogs(ResourceQuery) ([]CatalogRecord, error)
	NamedQuery(ResourceKey) (NamedQueryRecord, error)
	NamedQueryByToken(Scope, string) (NamedQueryRecord, error)
	NamedQueries(ResourceQuery) ([]NamedQueryRecord, error)
	PreparedStatement(StatementKey) (PreparedStatementRecord, error)
	PreparedStatements(ResourceQuery) ([]PreparedStatementRecord, error)
	Query(ResourceKey) (QueryRecord, error)
	QueryByToken(Scope, string) (QueryRecord, error)
	Queries(ResourceQuery) ([]QueryRecord, error)
	NextQuery() (QueryRecord, error)
	ActiveQueries() ([]QueryRecord, error)
}
type Transaction interface {
	Reader
	PutWorkGroup(WorkGroupRecord) error
	// DeleteWorkGroup removes its query history and token/column/caller children.
	// The command must first quiesce native handles and remove named/prepared queries.
	DeleteWorkGroup(ResourceKey) error
	PutCatalog(CatalogRecord) error
	DeleteCatalog(ResourceKey) error
	PutNamedQuery(NamedQueryRecord) error
	DeleteNamedQuery(ResourceKey) error
	PutPreparedStatement(PreparedStatementRecord) error
	DeletePreparedStatement(StatementKey) error
	PutQuery(QueryRecord) error
}

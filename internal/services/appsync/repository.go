package appsync

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/appsync"
)

var ErrNotFound = errors.New("AppSync resource not found")
var ErrConflict = errors.New("AppSync resource conflict")

type Key struct{ Partition, AccountID, Region, ID string }

func (k Key) ARN() string {
	return "arn:" + k.Partition + ":appsync:" + k.Region + ":" + k.AccountID + ":apis/" + k.ID
}

type APIRecord struct {
	Key             Key
	API             api.GraphqlApi
	Schema          string
	SchemaStatus    string
	SchemaDetails   []byte
	SchemaOwnership string
	Ownership       string
}
type DataSourceRecord struct {
	API        Key
	DataSource api.DataSource
	Ownership  string
}
type ResolverRecord struct {
	API       Key
	Resolver  api.Resolver
	Ownership string
}
type FunctionRecord struct {
	API       Key
	Function  api.FunctionConfiguration
	Ownership string
}
type APIKeyRecord struct {
	API       Key
	Key       api.ApiKey
	Ownership string
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	API(Key) (APIRecord, error)
	APIByID(string) (APIRecord, error)
	APIs() ([]APIRecord, error)
	DataSources(Key) ([]DataSourceRecord, error)
	Resolvers(Key) ([]ResolverRecord, error)
	Functions(Key) ([]FunctionRecord, error)
	APIKeys(Key) ([]APIKeyRecord, error)
}
type Transaction interface {
	Reader
	PutAPI(APIRecord) error
	DeleteAPI(Key) error
	PutDataSource(DataSourceRecord) error
	DeleteDataSource(Key, string) error
	PutResolver(ResolverRecord) error
	DeleteResolver(Key, string, string) error
	PutFunction(FunctionRecord) error
	DeleteFunction(Key, string) error
	PutAPIKey(APIKeyRecord) error
	DeleteAPIKey(Key, string) error
}

// Dependency checks are shared by memory and SQL so ordinary owner writes cannot
// publish dangling data source or pipeline references.
func CheckFunctionReferences(r Reader, p FunctionRecord) error {
	_, e := findDataSource(r, p.API, value(p.Function.DataSourceName))
	return e
}
func CheckResolverReferences(r Reader, p ResolverRecord) error {
	if value(p.Resolver.Kind) == "PIPELINE" {
		if value(p.Resolver.DataSourceName) != "" {
			return ErrConflict
		}
		if p.Resolver.PipelineConfig != nil {
			for _, id := range p.Resolver.PipelineConfig.Functions {
				if _, e := findFunction(r, p.API, string(id)); e != nil {
					return e
				}
			}
		}
		return nil
	}
	_, e := findDataSource(r, p.API, value(p.Resolver.DataSourceName))
	return e
}
func CheckDeleteDataSource(r Reader, k Key, name string) error {
	resolvers, e := r.Resolvers(k)
	if e != nil {
		return e
	}
	for _, v := range resolvers {
		if value(v.Resolver.DataSourceName) == name {
			return ErrConflict
		}
	}
	functions, e := r.Functions(k)
	if e != nil {
		return e
	}
	for _, v := range functions {
		if value(v.Function.DataSourceName) == name {
			return ErrConflict
		}
	}
	return nil
}
func CheckDeleteFunction(r Reader, k Key, id string) error {
	resolvers, e := r.Resolvers(k)
	if e != nil {
		return e
	}
	for _, v := range resolvers {
		if v.Resolver.PipelineConfig != nil {
			for _, f := range v.Resolver.PipelineConfig.Functions {
				if string(f) == id {
					return ErrConflict
				}
			}
		}
	}
	return nil
}

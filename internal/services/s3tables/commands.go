package s3tables

import (
	"context"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awswire"
)

func registerOperations(s *Service) {
	bind(s, "CreateTableBucket", s.CreateTableBucket)
	bind(s, "GetTableBucket", s.GetTableBucket)
	bind(s, "ListTableBuckets", s.ListTableBuckets)
	bind(s, "DeleteTableBucket", s.DeleteTableBucket)
	bind(s, "CreateNamespace", s.CreateNamespace)
	bind(s, "GetNamespace", s.GetNamespace)
	bind(s, "ListNamespaces", s.ListNamespaces)
	bind(s, "DeleteNamespace", s.DeleteNamespace)
	bind(s, "GetTable", s.GetTable)
	bind(s, "ListTables", s.ListTables)
	bind(s, "DeleteTable", s.DeleteTable)
	bind(s, "RenameTable", s.RenameTable)
	bind(s, "GetTableMetadataLocation", s.GetTableMetadataLocation)
	bind(s, "UpdateTableMetadataLocation", s.UpdateTableMetadataLocation)
	bind(s, "CreateTable", s.CreateTable)
}
func (s *Service) CreateTableBucket(ctx context.Context, in *api.CreateTableBucketInput) (*api.CreateTableBucketOutput, *awswire.Error) {
	return command(s, ctx, "CreateTableBucket", in, s.createTableBucket)
}
func (s *Service) GetTableBucket(ctx context.Context, in *api.GetTableBucketInput) (*api.GetTableBucketOutput, *awswire.Error) {
	return command(s, ctx, "GetTableBucket", in, s.getTableBucket)
}
func (s *Service) ListTableBuckets(ctx context.Context, in *api.ListTableBucketsInput) (*api.ListTableBucketsOutput, *awswire.Error) {
	return command(s, ctx, "ListTableBuckets", in, s.listTableBuckets)
}
func (s *Service) DeleteTableBucket(ctx context.Context, in *api.DeleteTableBucketInput) (*api.DeleteTableBucketOutput, *awswire.Error) {
	return command(s, ctx, "DeleteTableBucket", in, s.deleteTableBucket)
}
func (s *Service) CreateNamespace(ctx context.Context, in *api.CreateNamespaceInput) (*api.CreateNamespaceOutput, *awswire.Error) {
	return command(s, ctx, "CreateNamespace", in, s.createNamespace)
}
func (s *Service) GetNamespace(ctx context.Context, in *api.GetNamespaceInput) (*api.GetNamespaceOutput, *awswire.Error) {
	return command(s, ctx, "GetNamespace", in, s.getNamespace)
}
func (s *Service) ListNamespaces(ctx context.Context, in *api.ListNamespacesInput) (*api.ListNamespacesOutput, *awswire.Error) {
	return command(s, ctx, "ListNamespaces", in, s.listNamespaces)
}
func (s *Service) DeleteNamespace(ctx context.Context, in *api.DeleteNamespaceInput) (*api.DeleteNamespaceOutput, *awswire.Error) {
	return command(s, ctx, "DeleteNamespace", in, s.deleteNamespace)
}
func (s *Service) GetTable(ctx context.Context, in *api.GetTableInput) (*api.GetTableOutput, *awswire.Error) {
	return command(s, ctx, "GetTable", in, s.getTable)
}
func (s *Service) ListTables(ctx context.Context, in *api.ListTablesInput) (*api.ListTablesOutput, *awswire.Error) {
	return command(s, ctx, "ListTables", in, s.listTables)
}
func (s *Service) DeleteTable(ctx context.Context, in *api.DeleteTableInput) (*api.DeleteTableOutput, *awswire.Error) {
	return command(s, ctx, "DeleteTable", in, s.deleteTable)
}
func (s *Service) RenameTable(ctx context.Context, in *api.RenameTableInput) (*api.RenameTableOutput, *awswire.Error) {
	return command(s, ctx, "RenameTable", in, s.renameTable)
}
func (s *Service) GetTableMetadataLocation(ctx context.Context, in *api.GetTableMetadataLocationInput) (*api.GetTableMetadataLocationOutput, *awswire.Error) {
	return command(s, ctx, "GetTableMetadataLocation", in, s.getTableMetadataLocation)
}
func (s *Service) UpdateTableMetadataLocation(ctx context.Context, in *api.UpdateTableMetadataLocationInput) (*api.UpdateTableMetadataLocationOutput, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	prepared, rejected := s.PrepareTableMetadataUpdate(ctx, in)
	if rejected != nil {
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err = s.recordCall(completion, "UpdateTableMetadataLocation", in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	return s.PublishTableMetadataUpdate(ctx, in, prepared)
}

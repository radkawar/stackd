package integrations

import (
	"context"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/athena"
)

// AthenaGlueCommands is Glue's ordinary generated command edge. Athena never
// keeps a shadow metastore or bypasses catalog IAM/resource policy evaluation.
type AthenaGlueCommands interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}
type AthenaGlue struct{ Glue AthenaGlueCommands }

var _ athena.Catalog = AthenaGlue{}

func (a AthenaGlue) command(ctx context.Context, name string, input any) (any, *awswire.Error) {
	if a.Glue == nil {
		return nil, &awswire.Error{Code: "InternalServerException", Message: "Glue catalog is not configured", StatusCode: 500}
	}
	model, _ := awscatalog.LookupService("glue")
	operation, _ := model.Operation(name)
	return a.Glue.ExecuteCommand(awsctx.WithViaService(ctx, "athena.amazonaws.com"), awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
}
func (a AthenaGlue) GetDatabase(ctx context.Context, in *api.GetDatabaseInput) (*api.GetDatabaseOutput, *awswire.Error) {
	out, err := a.command(ctx, "GetDatabase", in)
	if err != nil {
		return nil, err
	}
	result, ok := out.(*api.GetDatabaseOutput)
	if !ok {
		return nil, athenaGlueOutputError()
	}
	return result, nil
}
func (a AthenaGlue) GetDatabases(ctx context.Context, in *api.GetDatabasesInput) (*api.GetDatabasesOutput, *awswire.Error) {
	out, err := a.command(ctx, "GetDatabases", in)
	if err != nil {
		return nil, err
	}
	result, ok := out.(*api.GetDatabasesOutput)
	if !ok {
		return nil, athenaGlueOutputError()
	}
	return result, nil
}
func (a AthenaGlue) GetTable(ctx context.Context, in *api.GetTableInput) (*api.GetTableOutput, *awswire.Error) {
	out, err := a.command(ctx, "GetTable", in)
	if err != nil {
		return nil, err
	}
	result, ok := out.(*api.GetTableOutput)
	if !ok {
		return nil, athenaGlueOutputError()
	}
	return result, nil
}
func (a AthenaGlue) GetTables(ctx context.Context, in *api.GetTablesInput) (*api.GetTablesOutput, *awswire.Error) {
	out, err := a.command(ctx, "GetTables", in)
	if err != nil {
		return nil, err
	}
	result, ok := out.(*api.GetTablesOutput)
	if !ok {
		return nil, athenaGlueOutputError()
	}
	return result, nil
}
func athenaGlueOutputError() *awswire.Error {
	return &awswire.Error{Code: "InternalServerException", Message: "Glue returned an unexpected catalog response", StatusCode: 500}
}

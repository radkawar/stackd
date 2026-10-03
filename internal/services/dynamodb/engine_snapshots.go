package dynamodb

import (
	"context"
	"errors"

	engine "stackd/engine/dynamodb"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awscatalog"
)

// createNativeSnapshot is shared by on-demand and continuous baselines. Its
// caller excludes source mutations until the paginated native copy completes.
func createNativeSnapshot(ctx context.Context, db engine.Database, input *api.CreateTableInput, source string) (bool, error) {
	model, _ := awscatalog.LookupService("dynamodb")
	var created api.CreateTableOutput
	if err := nativeCall(ctx, db, model, "CreateTable", input, &created, nil); err != nil && !engineCode(err, "ResourceInUseException") {
		return false, err
	}
	var observed api.DescribeTableOutput
	if err := nativeCall(ctx, db, model, "DescribeTable", &api.DescribeTableInput{TableName: input.TableName}, &observed, nil); err != nil {
		return false, err
	}
	if observed.Table == nil {
		return false, errors.New("native snapshot DescribeTable omitted table")
	}
	if value(observed.Table.TableStatus) != "ACTIVE" {
		return false, nil
	}
	if err := copyNativeTable(ctx, db, db, source, value(input.TableName)); err != nil {
		return false, err
	}
	return true, nil
}

func deleteNativeTable(ctx context.Context, db engine.Database, physicalName string) (bool, error) {
	model, _ := awscatalog.LookupService("dynamodb")
	name := new(api.TableArn(physicalName))
	var deleted api.DeleteTableOutput
	if err := nativeCall(ctx, db, model, "DeleteTable", &api.DeleteTableInput{TableName: name}, &deleted, nil); err != nil {
		if engineCode(err, "ResourceNotFoundException") {
			return true, nil
		}
		return false, err
	}
	var observed api.DescribeTableOutput
	err := nativeCall(ctx, db, model, "DescribeTable", &api.DescribeTableInput{TableName: name}, &observed, nil)
	if engineCode(err, "ResourceNotFoundException") {
		return true, nil
	}
	return false, err
}

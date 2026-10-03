package integrations

import (
	"context"
	"errors"
	"math"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
	aas "stackd/internal/services/applicationautoscaling"
	"stackd/internal/services/dynamodb"
)

// DynamoDBScaling enters the table owner's authorized, audited command boundary.
// No capacity is retained by the adapter or inferred from an accepted update.
type DynamoDBScaling interface {
	DescribeTable(context.Context, *api.DescribeTableInput) (*api.DescribeTableOutput, *awswire.Error)
	UpdateCapacity(context.Context, *api.UpdateTableInput) (*api.UpdateTableOutput, *awswire.Error)
}

func dynamoDBCapacityUnits(units *api.NonNegativeLongObject) (int32, error) {
	if units == nil || *units < 1 || *units > math.MaxInt32 {
		return 0, &awswire.Error{Code: "ValidationException", Message: "Provisioned capacity is outside the scalable capacity range", StatusCode: 400}
	}
	return int32(*units), nil
}

func (a *ApplicationScaling) dynamoDBThroughput(ctx context.Context, key aas.TargetKey) (*api.ProvisionedThroughputDescription, error) {
	if a.DynamoDB == nil {
		return nil, &awswire.Error{Code: "InternalServiceException", Message: "DynamoDB scaling resource integration is unavailable", StatusCode: 500}
	}
	parts := strings.Split(key.ResourceID, "/")
	out, rejected := a.DynamoDB.DescribeTable(ctx, &api.DescribeTableInput{TableName: new(api.TableArn(parts[1]))})
	if rejected != nil {
		if rejected.Code == "ResourceNotFoundException" {
			return nil, aas.ErrNotFound
		}
		return nil, rejected
	}
	if out.Table == nil || out.Table.TableStatus != nil && *out.Table.TableStatus == "DELETING" {
		return nil, aas.ErrNotFound
	}
	if mode := out.Table.BillingModeSummary; mode != nil && mode.BillingMode != nil && *mode.BillingMode == "PAY_PER_REQUEST" {
		return nil, &awswire.Error{Code: "ValidationException", Message: "Validation failed for scalable target. Reason: PAY_PER_REQUEST table mode is not scalable.", StatusCode: 400}
	}
	throughput := out.Table.ProvisionedThroughput
	if len(parts) == 4 {
		throughput = nil
		for _, index := range out.Table.GlobalSecondaryIndexes {
			if index.IndexName != nil && string(*index.IndexName) == parts[3] && (index.IndexStatus == nil || *index.IndexStatus != "DELETING") {
				throughput = index.ProvisionedThroughput
				break
			}
		}
	}
	if throughput == nil {
		return nil, aas.ErrNotFound
	}
	return throughput, nil
}

func (a *ApplicationScaling) setDynamoDBCapacity(ctx context.Context, key aas.TargetKey, count int32) error {
	current, err := a.dynamoDBThroughput(ctx, key)
	if errors.Is(err, aas.ErrNotFound) {
		return &awswire.Error{Code: "ValidationException", Message: "DynamoDB table or global secondary index does not exist: " + key.ResourceID, StatusCode: 400}
	}
	if err != nil {
		return err
	}
	// UpdateTable requires both dimensions. Read the untouched dimension from
	// the real engine in this transaction, never from the other scalable target.
	if current.ReadCapacityUnits == nil || current.WriteCapacityUnits == nil {
		return aas.ErrNotFound
	}
	throughput := &api.ProvisionedThroughput{ReadCapacityUnits: new(api.PositiveLongObject(*current.ReadCapacityUnits)), WriteCapacityUnits: new(api.PositiveLongObject(*current.WriteCapacityUnits))}
	if strings.HasSuffix(key.Dimension, ":ReadCapacityUnits") {
		throughput.ReadCapacityUnits = new(api.PositiveLongObject(count))
	} else {
		throughput.WriteCapacityUnits = new(api.PositiveLongObject(count))
	}
	parts := strings.Split(key.ResourceID, "/")
	input := &api.UpdateTableInput{TableName: new(api.TableArn(parts[1]))}
	if len(parts) == 4 {
		input.GlobalSecondaryIndexUpdates = api.GlobalSecondaryIndexUpdateList{{Update: &api.UpdateGlobalSecondaryIndexAction{IndexName: new(api.IndexName(parts[3])), ProvisionedThroughput: throughput}}}
	} else {
		input.ProvisionedThroughput = throughput
	}
	_, rejected := a.DynamoDB.UpdateCapacity(ctx, input)
	if rejected != nil {
		return rejected
	}
	return nil
}

// ObserveTableCapacity joins the table owner's transaction after real engine
// observation. A deleted table or index does not deregister its scaling targets.
func (a *ApplicationScaling) ObserveTableCapacity(ctx context.Context, key dynamodb.TableKey, table *api.TableDescription) error {
	if table == nil || table.TableStatus == nil || *table.TableStatus != "ACTIVE" {
		return nil
	}
	if mode := table.BillingModeSummary; mode != nil && mode.BillingMode != nil && *mode.BillingMode == "PAY_PER_REQUEST" {
		return nil
	}
	target := aas.TargetKey{Scope: aas.Scope{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region}, Namespace: "dynamodb", ResourceID: "table/" + key.Name}
	if err := a.observeDynamoDBThroughput(ctx, target, "table", table.ProvisionedThroughput); err != nil {
		return err
	}
	for _, index := range table.GlobalSecondaryIndexes {
		if index.IndexName == nil || index.IndexStatus == nil || *index.IndexStatus != "ACTIVE" {
			continue
		}
		target.ResourceID = "table/" + key.Name + "/index/" + string(*index.IndexName)
		if err := a.observeDynamoDBThroughput(ctx, target, "index", index.ProvisionedThroughput); err != nil {
			return err
		}
	}
	return nil
}

func (a *ApplicationScaling) observeDynamoDBThroughput(ctx context.Context, key aas.TargetKey, resourceType string, throughput *api.ProvisionedThroughputDescription) error {
	if throughput == nil {
		return nil
	}
	for _, dimension := range []struct {
		name  string
		units *api.NonNegativeLongObject
	}{{"ReadCapacityUnits", throughput.ReadCapacityUnits}, {"WriteCapacityUnits", throughput.WriteCapacityUnits}} {
		// Capacity outside AAS's int32 domain cannot satisfy any retained
		// request, but must not reject an otherwise valid DynamoDB observation.
		if dimension.units == nil || *dimension.units < 1 || *dimension.units > math.MaxInt32 {
			continue
		}
		count := int32(*dimension.units)
		key.Dimension = "dynamodb:" + resourceType + ":" + dimension.name
		if err := a.Scaling.ObserveCapacity(ctx, key, count, count); err != nil {
			return err
		}
	}
	return nil
}

// PrepareReplica keeps scaling configuration in its owning service while
// DynamoDB supplies the current table/index membership and replication identity.
func (a *ApplicationScaling) PrepareReplica(ctx context.Context, source, target dynamodb.TableKey, table *api.TableDescription) error {
	return a.Scaling.CopyDynamoDBReplica(ctx, target.Region, dynamoDBScalingResources(source.Name, table))
}

// ConfigureReplica applies native billing-transition defaults after the table
// owner observes real provisioned capacity. Quota admission remains with DynamoDB.
func (a *ApplicationScaling) ConfigureReplica(ctx context.Context, key dynamodb.TableKey, table *api.TableDescription, maximum int32) error {
	resource := "table/" + key.Name
	configure := func(resource string, throughput *api.ProvisionedThroughputDescription) error {
		return a.Scaling.ConfigureDynamoDBReplica(ctx, resource, int32(*throughput.ReadCapacityUnits), int32(*throughput.WriteCapacityUnits), maximum)
	}
	if err := configure(resource, table.ProvisionedThroughput); err != nil {
		return err
	}
	for _, index := range table.GlobalSecondaryIndexes {
		if err := configure(resource+"/index/"+string(*index.IndexName), index.ProvisionedThroughput); err != nil {
			return err
		}
	}
	return nil
}

// ResetReplicaPolicies retains the caller's authority while recording DynamoDB
// as the native forwarding service. Targets and their tags remain registered.
func (a *ApplicationScaling) ResetReplicaPolicies(ctx context.Context, key dynamodb.TableKey, table *api.TableDescription) error {
	return a.Scaling.ResetDynamoDBReplicaPolicies(replicaScalingCaller(ctx, key), dynamoDBScalingResources(key.Name, table))
}

func dynamoDBScalingResources(name string, table *api.TableDescription) []string {
	resources := make([]string, 1, len(table.GlobalSecondaryIndexes)+1)
	resources[0] = "table/" + name
	for _, index := range table.GlobalSecondaryIndexes {
		resources = append(resources, resources[0]+"/index/"+string(*index.IndexName))
	}
	return resources
}

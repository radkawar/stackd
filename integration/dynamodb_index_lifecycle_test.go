package stackd_test

import (
	"bytes"
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	engine "stackd/engine/dynamodb"
)

type nativeIndexCountRuntime struct {
	engine.Runtime
	updates atomic.Int32
}

type nativeIndexCountDatabase struct {
	engine.Database
	owner *nativeIndexCountRuntime
}

func (r *nativeIndexCountRuntime) Open(ctx context.Context, spec engine.Specification) (engine.Database, error) {
	database, err := r.Runtime.Open(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &nativeIndexCountDatabase{Database: database, owner: r}, nil
}

func (d *nativeIndexCountDatabase) Request(ctx context.Context, target string, body []byte) (engine.Response, error) {
	if target == "DynamoDB_20120810.UpdateTable" {
		d.owner.updates.Add(1)
	}
	return d.Database.Request(ctx, target, body)
}

func TestDynamoDBNativeIndexLifecycleAndInterruptedReopen(t *testing.T) {
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 to exercise pinned DynamoDB Local")
	}
	dockerClient, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dockerClient.Close)
	runtime, err := engine.NewDocker(t.Context(), engine.DockerConfig{Client: dockerClient})
	if err != nil {
		t.Fatal(err)
	}
	counted := &nativeIndexCountRuntime{Runtime: runtime}
	owned := &dynamoReplayRuntime{Runtime: counted}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		for _, spec := range owned.specifications() {
			if err := runtime.Remove(ctx, spec); err != nil {
				t.Errorf("remove exact owned native database %s: %v", spec.ID, err)
			}
		}
	})
	clients, reopen := retainedCloud(t, "sqlite", stackd.Config{Clock: clock.NewManual(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)), DynamoDBRuntime: owned})
	api := dynamoClient(clients, "test", "test", clients.server.Client())
	name := "native-index-transition"
	_, err = api.CreateTable(t.Context(), &dynamodb.CreateTableInput{TableName: aws.String(name), BillingMode: types.BillingModeProvisioned, ProvisionedThroughput: &types.ProvisionedThroughput{ReadCapacityUnits: aws.Int64(5), WriteCapacityUnits: aws.Int64(5)}, AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS}}, KeySchema: []types.KeySchemaElement{{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if _, err := api.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(name)}); err != nil {
			t.Errorf("delete owned table: %v", err)
			return
		}
		if err := dynamoWaitAbsent(ctx, api, name); err != nil {
			t.Errorf("signed table absence: %v", err)
		}
	}()
	if err := dynamoWaitActive(t.Context(), api, name); err != nil {
		t.Fatal(err)
	}
	payload := []byte("native-index-payload\x00\xff")
	_, err = api.PutItem(t.Context(), &dynamodb.PutItemInput{TableName: aws.String(name), Item: map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: "native"}, "group": &types.AttributeValueMemberS{Value: "proof"}, "payload": &types.AttributeValueMemberB{Value: payload}}})
	if err != nil {
		t.Fatal(err)
	}
	committed := owned.failAfterCommit("UpdateTable")
	_, err = api.UpdateTable(t.Context(), &dynamodb.UpdateTableInput{TableName: aws.String(name), AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS}, {AttributeName: aws.String("group"), AttributeType: types.ScalarAttributeTypeS}}, GlobalSecondaryIndexUpdates: []types.GlobalSecondaryIndexUpdate{{Create: &types.CreateGlobalSecondaryIndexAction{IndexName: aws.String("by-group"), KeySchema: []types.KeySchemaElement{{AttributeName: aws.String("group"), KeyType: types.KeyTypeHash}}, Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll}, ProvisionedThroughput: &types.ProvisionedThroughput{ReadCapacityUnits: aws.Int64(2), WriteCapacityUnits: aws.Int64(2)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-committed:
	case <-time.After(30 * time.Second):
		t.Fatal("real native index update was not reached")
	}
	clients = reopen()
	api = dynamoClient(clients, "test", "test", clients.server.Client())
	waitIndex := func(present bool, read, write int64) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for {
			description, err := api.DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: aws.String(name)})
			if err != nil {
				t.Fatal(err)
			}
			indexes := description.Table.GlobalSecondaryIndexes
			if !present && len(indexes) == 0 && description.Table.TableStatus == types.TableStatusActive {
				return
			}
			if present && len(indexes) == 1 && indexes[0].IndexStatus == types.IndexStatusActive && aws.ToInt64(indexes[0].ProvisionedThroughput.ReadCapacityUnits) == read && aws.ToInt64(indexes[0].ProvisionedThroughput.WriteCapacityUnits) == write {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("native GSI did not settle: %+v", description.Table)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	checkBytes := func() {
		t.Helper()
		out, err := api.Query(t.Context(), &dynamodb.QueryInput{TableName: aws.String(name), IndexName: aws.String("by-group"), KeyConditionExpression: aws.String("#g = :g"), ExpressionAttributeNames: map[string]string{"#g": "group"}, ExpressionAttributeValues: map[string]types.AttributeValue{":g": &types.AttributeValueMemberS{Value: "proof"}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Items) != 1 {
			t.Fatalf("native GSI rows = %d", len(out.Items))
		}
		value, ok := out.Items[0]["payload"].(*types.AttributeValueMemberB)
		if !ok || !bytes.Equal(value.Value, payload) {
			t.Fatal("native GSI binary bytes differ")
		}
	}
	waitIndex(true, 2, 2)
	checkBytes()
	if got := counted.updates.Load(); got != 1 {
		t.Fatalf("reopen repeated native index creation: %d", got)
	}
	_, err = api.UpdateTable(t.Context(), &dynamodb.UpdateTableInput{TableName: aws.String(name), GlobalSecondaryIndexUpdates: []types.GlobalSecondaryIndexUpdate{{Update: &types.UpdateGlobalSecondaryIndexAction{IndexName: aws.String("by-group"), ProvisionedThroughput: &types.ProvisionedThroughput{ReadCapacityUnits: aws.Int64(3), WriteCapacityUnits: aws.Int64(4)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	waitIndex(true, 3, 4)
	checkBytes()
	_, err = api.UpdateTable(t.Context(), &dynamodb.UpdateTableInput{TableName: aws.String(name), GlobalSecondaryIndexUpdates: []types.GlobalSecondaryIndexUpdate{{Delete: &types.DeleteGlobalSecondaryIndexAction{IndexName: aws.String("by-group")}}}})
	if err != nil {
		t.Fatal(err)
	}
	waitIndex(false, 0, 0)
	clients = reopen()
	api = dynamoClient(clients, "test", "test", clients.server.Client())
	waitIndex(false, 0, 0)
	out, err := api.GetItem(t.Context(), &dynamodb.GetItemInput{TableName: aws.String(name), ConsistentRead: aws.Bool(true), Key: map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: "native"}}})
	if err != nil {
		t.Fatal(err)
	}
	value, ok := out.Item["payload"].(*types.AttributeValueMemberB)
	if !ok || !bytes.Equal(value.Value, payload) {
		t.Fatal("native index deletion/reopen changed base binary bytes")
	}
	if got := counted.updates.Load(); got != 3 {
		t.Fatalf("native index mutations=%d, want one create, update and delete", got)
	}
}

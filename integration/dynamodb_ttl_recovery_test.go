package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	streamtypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
)

// Only the failure boundary is injected. Every successful response and every
// item/stream effect comes from the real engine, including the refreshed expiry.
// The failed database handle remains unavailable until the service is reopened.
type ttlFailureRuntime struct {
	dynamoengine.Runtime
	mu       sync.Mutex
	mode     string
	fired    bool
	boundary chan error
}

type ttlFailureDatabase struct {
	dynamoengine.Database
	owner  *ttlFailureRuntime
	mu     sync.Mutex
	failed bool
}

func (r *ttlFailureRuntime) Open(ctx context.Context, spec dynamoengine.Specification) (dynamoengine.Database, error) {
	db, err := r.Runtime.Open(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &ttlFailureDatabase{Database: db, owner: r}, nil
}

func (d *ttlFailureDatabase) Request(ctx context.Context, target string, body []byte) (dynamoengine.Response, error) {
	d.mu.Lock()
	failed := d.failed
	d.mu.Unlock()
	if failed {
		return dynamoengine.Response{}, errors.New("injected native handle failure until reopen")
	}
	var candidate struct {
		TableName           string
		Key                 json.RawMessage
		ConditionExpression string
	}
	if !strings.HasSuffix(target, ".DeleteItem") {
		return d.Database.Request(ctx, target, body)
	}
	if err := json.Unmarshal(body, &candidate); err != nil {
		return dynamoengine.Response{}, err
	}
	if candidate.ConditionExpression != "#ttl = :seen" {
		return d.Database.Request(ctx, target, body)
	}
	d.owner.mu.Lock()
	trip := !d.owner.fired
	d.owner.fired = true
	d.owner.mu.Unlock()
	if !trip {
		return d.Database.Request(ctx, target, body)
	}
	var effectErr error
	if d.owner.mode == "after" {
		response, err := d.Database.Request(ctx, target, body)
		effectErr = err
		if err == nil && response.StatusCode != 200 {
			effectErr = fmt.Errorf("native deletion HTTP %d: %s", response.StatusCode, response.Body)
		}
	} else if d.owner.mode == "refreshed" {
		// A native update after Scan invalidates the retained conditional candidate.
		input, err := json.Marshal(map[string]any{"TableName": candidate.TableName, "Key": candidate.Key, "UpdateExpression": "SET #expiry = :future", "ExpressionAttributeNames": map[string]string{"#expiry": "expiry"}, "ExpressionAttributeValues": map[string]any{":future": map[string]string{"N": "2000000000"}}})
		if err != nil {
			effectErr = err
		} else {
			response, err := d.Database.Request(ctx, "DynamoDB_20120810.UpdateItem", input)
			effectErr = err
			if err == nil && response.StatusCode != 200 {
				effectErr = fmt.Errorf("native expiry refresh HTTP %d: %s", response.StatusCode, response.Body)
			}
		}
	}
	d.mu.Lock()
	d.failed = true
	d.mu.Unlock()
	d.owner.boundary <- effectErr
	return dynamoengine.Response{}, errors.New("injected TTL external-write boundary failure")
}

func TestDynamoDBTTLNativeRecovery(t *testing.T) {
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 to exercise pinned DynamoDB Local")
	}
	compute, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(compute.Close)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: compute})
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, mode := range []string{"before", "after", "refreshed"} {
			t.Run(backend+"/"+mode, func(t *testing.T) { dynamoTTLRecovery(t, runtime, backend, mode) })
		}
	}
}

func dynamoTTLRecovery(t *testing.T, runtime dynamoengine.Runtime, backend, mode string) {
	t.Helper()
	origin := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	source := clock.NewManual(origin.Add(-time.Minute))
	observed := &dynamoReplayRuntime{Runtime: runtime}
	fault := &ttlFailureRuntime{Runtime: observed, mode: mode, boundary: make(chan error, 1)}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		for _, spec := range observed.specifications() {
			if err := runtime.Remove(ctx, spec); err != nil {
				t.Errorf("remove owned database: %v", err)
			}
		}
	})
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source, DynamoDBRuntime: fault})
	client := dynamoClient(clients, "test", "test", clients.server.Client())
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	const table = "ttl-recovery"
	key := map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: "same-key"}}
	create := func() string {
		t.Helper()
		_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{TableName: aws.String(table), BillingMode: types.BillingModePayPerRequest, AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS}}, KeySchema: []types.KeySchemaElement{{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash}}, StreamSpecification: &types.StreamSpecification{StreamEnabled: aws.Bool(true), StreamViewType: types.StreamViewTypeNewAndOldImages}})
		if err != nil {
			t.Fatal(err)
		}
		if err := dynamoWaitActive(ctx, client, table); err != nil {
			t.Fatal(err)
		}
		out, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
		if err != nil {
			t.Fatal(err)
		}
		return aws.ToString(out.Table.LatestStreamArn)
	}
	arn := create()
	advanceClock(t, source, time.Minute)
	put := func(expiry string) {
		t.Helper()
		_, err := client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(table), Item: map[string]types.AttributeValue{"pk": key["pk"], "expiry": &types.AttributeValueMemberN{Value: expiry}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	put(strconv.FormatInt(origin.Add(-time.Minute).Unix(), 10))
	if _, err := client.UpdateContinuousBackups(ctx, &dynamodb.UpdateContinuousBackupsInput{TableName: aws.String(table), PointInTimeRecoverySpecification: &types.PointInTimeRecoverySpecification{PointInTimeRecoveryEnabled: aws.Bool(true), RecoveryPeriodInDays: aws.Int32(1)}}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, time.Second)
	ttlAt := source.Now()
	_, err := client.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{TableName: aws.String(table), TimeToLiveSpecification: &types.TimeToLiveSpecification{AttributeName: aws.String("expiry"), Enabled: aws.Bool(true)}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-fault.boundary:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("TTL worker did not reach the native failure boundary", ctx.Err())
	}
	if err := source.Advance(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	clients = reopen()
	client = dynamoClient(clients, "test", "test", clients.server.Client())
	streams := func() *dynamodbstreams.Client {
		return dynamodbstreams.New(dynamodbstreams.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
	}
	wantTTL := 1
	if mode == "refreshed" {
		wantTTL = 0
		// A normal write cannot pass until the old no-record candidate is cleared.
		out, err := client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: key, ConsistentRead: aws.Bool(true)})
		if err != nil {
			t.Fatal(err)
		}
		if expiry, ok := out.Item["expiry"].(*types.AttributeValueMemberN); !ok || expiry.Value != "2000000000" {
			t.Fatalf("conditional recovery deleted the refreshed item: %#v", out.Item)
		}
	}
	afterExpiry := ""
	if mode == "refreshed" {
		afterExpiry = "2000000000"
	}
	for _, point := range []struct {
		name, expiry string
		at           time.Time
	}{
		{"before", strconv.FormatInt(origin.Add(-time.Minute).Unix(), 10), origin},
		{"after", afterExpiry, ttlAt},
	} {
		target := table + "-pitr-" + point.name
		if _, err := client.RestoreTableToPointInTime(ctx, &dynamodb.RestoreTableToPointInTimeInput{SourceTableName: aws.String(table), TargetTableName: aws.String(target), RestoreDateTime: &point.at}); err != nil {
			t.Fatal(err)
		}
		if err := dynamoWaitActive(ctx, client, target); err != nil {
			t.Fatal(err)
		}
		item, err := client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(target), Key: key, ConsistentRead: aws.Bool(true)})
		if err != nil {
			t.Fatal(err)
		}
		if point.expiry == "" {
			if len(item.Item) != 0 {
				t.Fatalf("restored TTL deletion resurrected an item: %#v", item.Item)
			}
		} else if expiry, ok := item.Item["expiry"].(*types.AttributeValueMemberN); !ok || expiry.Value != point.expiry {
			t.Fatalf("restored %s TTL boundary: %#v, want expiry %s", point.name, item.Item, point.expiry)
		}
	}
	// Reuse the very same key, then delete as a customer. Pending ownership must
	// never survive to tag this later REMOVE, even after another repository reopen.
	put("2000000000")
	if _, err := client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(table), Key: key}); err != nil {
		t.Fatal(err)
	}
	removes := dynamoTTLRemoves(t, ctx, streams(), arn, wantTTL+1)
	var ttlID string
	for _, record := range removes {
		if record.UserIdentity == nil {
			continue
		}
		if wantTTL == 0 || ttlID != "" || aws.ToString(record.UserIdentity.Type) != "Service" || aws.ToString(record.UserIdentity.PrincipalId) != "dynamodb.amazonaws.com" {
			t.Fatalf("incorrect TTL attribution: %#v", record)
		}
		if !record.Dynamodb.ApproximateCreationDateTime.Equal(ttlAt) {
			t.Fatalf("TTL origin moved across reopen: %v want %v", record.Dynamodb.ApproximateCreationDateTime, ttlAt)
		}
		ttlID = aws.ToString(record.EventID)
	}
	if wantTTL == 1 && ttlID == "" {
		t.Fatal("native TTL REMOVE lost its service identity after reopen")
	}
	clients = reopen()
	client = dynamoClient(clients, "test", "test", clients.server.Client())
	again := dynamoTTLRemoves(t, ctx, streams(), arn, wantTTL+1)
	for i := range removes {
		if aws.ToString(again[i].EventID) != aws.ToString(removes[i].EventID) || aws.ToString(again[i].Dynamodb.SequenceNumber) != aws.ToString(removes[i].Dynamodb.SequenceNumber) {
			t.Fatal("recovery duplicated or replaced native record identity")
		}
	}
	if mode != "after" {
		return
	}
	// Replacement is exercised through supported public control transitions,
	// which must resolve pending TTL work before changing the native incarnation.
	for _, enabled := range []bool{false, true} {
		spec := &types.StreamSpecification{StreamEnabled: aws.Bool(enabled)}
		if enabled {
			spec.StreamViewType = types.StreamViewTypeNewAndOldImages
		}
		if _, err := client.UpdateTable(ctx, &dynamodb.UpdateTableInput{TableName: aws.String(table), StreamSpecification: spec}); err != nil {
			t.Fatal(err)
		}
		if err := dynamoWaitActive(ctx, client, table); err != nil {
			t.Fatal(err)
		}
	}
	out, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
	if err != nil {
		t.Fatal(err)
	}
	rotated := aws.ToString(out.Table.LatestStreamArn)
	if rotated == arn {
		t.Fatal("stream replacement reused the old generation")
	}
	assertCustomerRemoval := func(streamARN string) {
		t.Helper()
		put("2000000000")
		if _, err := client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(table), Key: key}); err != nil {
			t.Fatal(err)
		}
		if records := dynamoTTLRemoves(t, ctx, streams(), streamARN, 1); records[0].UserIdentity != nil {
			t.Fatal("replacement generation inherited old TTL ownership")
		}
	}
	assertCustomerRemoval(rotated)
	if _, err := client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(table)}); err != nil {
		t.Fatal(err)
	}
	if err := dynamoWaitAbsent(ctx, client, table); err != nil {
		t.Fatal(err)
	}
	replacement := create()
	if replacement == arn || replacement == rotated {
		t.Fatal("table replacement reused an old stream generation")
	}
	assertCustomerRemoval(replacement)
}

func dynamoTTLRemoves(t *testing.T, ctx context.Context, client *dynamodbstreams.Client, arn string, count int) []streamtypes.Record {
	t.Helper()
	for {
		out, err := client.DescribeStream(ctx, &dynamodbstreams.DescribeStreamInput{StreamArn: aws.String(arn)})
		if err != nil {
			t.Fatal(err)
		}
		var removes []streamtypes.Record
		ids := map[string]bool{}
		for _, shard := range out.StreamDescription.Shards {
			iterator, err := client.GetShardIterator(ctx, &dynamodbstreams.GetShardIteratorInput{StreamArn: aws.String(arn), ShardId: shard.ShardId, ShardIteratorType: streamtypes.ShardIteratorTypeTrimHorizon})
			if err != nil {
				t.Fatal(err)
			}
			for next := iterator.ShardIterator; next != nil; {
				page, err := client.GetRecords(ctx, &dynamodbstreams.GetRecordsInput{ShardIterator: next})
				if err != nil {
					t.Fatal(err)
				}
				for _, record := range page.Records {
					id := aws.ToString(record.EventID)
					if id == "" || ids[id] {
						t.Fatalf("missing or duplicate native event ID: %q", id)
					}
					ids[id] = true
					if record.EventName == streamtypes.OperationTypeRemove {
						removes = append(removes, record)
					}
				}
				if len(page.Records) == 0 {
					break
				}
				next = page.NextShardIterator
			}
		}
		if len(removes) >= count {
			if len(removes) != count {
				t.Fatalf("native REMOVE count %d want %d", len(removes), count)
			}
			return removes
		}
		select {
		case <-ctx.Done():
			t.Fatalf("native REMOVE count %d want %d: %v", len(removes), count, ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

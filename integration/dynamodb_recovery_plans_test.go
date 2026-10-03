package stackd_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
	dynamostore "stackd/storage/dynamodb"
)

// The barrier is after a real planning View has released its repository lock.
// Control requests can then change PITR before the queued mutation takes the
// data gate. No metadata or native response is fabricated by the wrapper.
type dynamoPlanRepository struct {
	dynamostore.Repository
	mu      sync.Mutex
	barrier *dynamoPlanBarrier
}

type dynamoPlanBarrier struct {
	reached chan struct{}
	resume  chan struct{}
}

type dynamoPlanRequest struct{}

type dynamoPlanReader struct {
	dynamostore.Reader
	reads int
}

func (r *dynamoPlanReader) Table(key dynamostore.TableKey) (dynamostore.TableRecord, error) {
	table, err := r.Reader.Table(key)
	if err == nil && (key.Name == "queued-first" || key.Name == "queued-second") {
		r.reads++
	}
	return table, err
}

func (r *dynamoPlanRepository) View(ctx context.Context, fn func(dynamostore.Reader) error) error {
	if marked, _ := ctx.Value(dynamoPlanRequest{}).(bool); !marked {
		return r.Repository.View(ctx, fn)
	}
	var reads int
	err := r.Repository.View(ctx, func(reader dynamostore.Reader) error {
		observed := &dynamoPlanReader{Reader: reader}
		err := fn(observed)
		reads = observed.reads
		return err
	})
	if err != nil || reads < 4 {
		return err
	}
	r.mu.Lock()
	barrier := r.barrier
	r.barrier = nil
	r.mu.Unlock()
	if barrier == nil {
		return nil
	}
	close(barrier.reached)
	select {
	case <-barrier.resume:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestDynamoDBRecoveryQueuedPlans(t *testing.T) {
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
		for _, operation := range []string{"TransactWriteItems", "BatchExecuteStatement", "ExecuteTransaction"} {
			t.Run(backend+"/"+operation, func(t *testing.T) {
				dynamoRecoveryQueuedPlans(t, runtime, backend, operation)
			})
		}
	}
}

func dynamoRecoveryQueuedPlans(t *testing.T, runtime dynamoengine.Runtime, backend, operation string) {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	owned := &dynamoReplayRuntime{Runtime: runtime}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		for _, spec := range owned.specifications() {
			if err := runtime.Remove(ctx, spec); err != nil {
				t.Errorf("remove owned database: %v", err)
			}
		}
	})
	var repository *dynamoPlanRepository
	clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source, DynamoDBRuntime: owned}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		repository = &dynamoPlanRepository{Repository: config.Storage.DynamoDB}
		config.Storage.DynamoDB = repository
		cloud, err := stackd.New(config)
		if err != nil {
			t.Fatal(err)
		}
		return cloud, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Header.Get("X-Amz-Target") == "DynamoDB_20120810."+operation {
				request = request.WithContext(context.WithValue(request.Context(), dynamoPlanRequest{}, true))
			}
			cloud.ServeHTTP(w, request)
		}))
	})
	client := dynamoClient(clients, "test", "test", clients.server.Client())
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	tables := []string{"queued-first", "queued-second"}
	item := func(key, payload string) map[string]types.AttributeValue {
		return map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: key}, "payload": &types.AttributeValueMemberS{Value: payload}}
	}
	putAll := func(payload string) {
		t.Helper()
		for _, table := range tables {
			for _, key := range []string{"one", "two"} {
				if _, err := client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(table), Item: item(key, payload)}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, table := range tables {
		_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{TableName: aws.String(table), BillingMode: types.BillingModePayPerRequest, AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS}}, KeySchema: []types.KeySchemaElement{{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := dynamoWaitActive(ctx, client, table); err != nil {
			t.Fatal(err)
		}
	}
	advanceClock(t, source, time.Minute)
	putAll("seed")
	setRecovery := func(enabled bool) {
		t.Helper()
		advanceClock(t, source, time.Second)
		for _, table := range tables {
			_, err := client.UpdateContinuousBackups(ctx, &dynamodb.UpdateContinuousBackupsInput{TableName: aws.String(table), PointInTimeRecoverySpecification: &types.PointInTimeRecoverySpecification{PointInTimeRecoveryEnabled: aws.Bool(enabled), RecoveryPeriodInDays: aws.Int32(1)}})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	write := func(payload string) error {
		var transaction []types.TransactWriteItem
		var batch []types.BatchStatementRequest
		var statements []types.ParameterizedStatement
		for _, table := range tables {
			for i, key := range []string{"one", "two"} {
				selector := table
				if i == 1 {
					selector = "arn:aws:dynamodb:us-east-1:000000000000:table/" + table
				}
				transaction = append(transaction, types.TransactWriteItem{Put: &types.Put{TableName: aws.String(selector), Item: item(key, payload)}})
				statement := fmt.Sprintf("UPDATE \"%s\" SET \"payload\"=? WHERE \"pk\"=?", table)
				parameters := []types.AttributeValue{&types.AttributeValueMemberS{Value: payload}, &types.AttributeValueMemberS{Value: key}}
				batch = append(batch, types.BatchStatementRequest{Statement: &statement, Parameters: parameters})
				statements = append(statements, types.ParameterizedStatement{Statement: &statement, Parameters: parameters})
			}
		}
		switch operation {
		case "TransactWriteItems":
			_, err := client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: transaction})
			return err
		case "ExecuteTransaction":
			_, err := client.ExecuteTransaction(ctx, &dynamodb.ExecuteTransactionInput{TransactStatements: statements})
			return err
		default:
			out, err := client.BatchExecuteStatement(ctx, &dynamodb.BatchExecuteStatementInput{Statements: batch})
			if err != nil {
				return err
			}
			if len(out.Responses) != len(batch) {
				return fmt.Errorf("batch returned %d responses for %d statements", len(out.Responses), len(batch))
			}
			for _, response := range out.Responses {
				if response.Error != nil {
					return fmt.Errorf("batch rejected statement: %s: %s", response.Error.Code, aws.ToString(response.Error.Message))
				}
			}
			return nil
		}
	}
	queue := func(payload string, controls func()) {
		t.Helper()
		barrier := &dynamoPlanBarrier{reached: make(chan struct{}), resume: make(chan struct{})}
		repository.mu.Lock()
		repository.barrier = barrier
		repository.mu.Unlock()
		var resume sync.Once
		defer resume.Do(func() { close(barrier.resume) })
		done := make(chan error, 1)
		go func() { done <- write(payload) }()
		select {
		case <-barrier.reached:
		case err := <-done:
			t.Fatalf("write did not reach planning barrier: %v", err)
		case <-ctx.Done():
			t.Fatal("planning did not reach repository boundary", ctx.Err())
		}
		controls()
		advanceClock(t, source, time.Second)
		resume.Do(func() { close(barrier.resume) })
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("queued write did not finish", ctx.Err())
		}
	}
	assertRestore := func(payload string) {
		t.Helper()
		at := source.Now()
		advanceClock(t, source, time.Second)
		putAll("later-" + payload)
		for _, table := range tables {
			target := table + "-" + payload
			_, err := client.RestoreTableToPointInTime(ctx, &dynamodb.RestoreTableToPointInTimeInput{SourceTableName: &table, TargetTableName: &target, RestoreDateTime: &at})
			if err != nil {
				t.Fatal(err)
			}
			if err := dynamoWaitActive(ctx, client, target); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"one", "two"} {
				out, err := client.GetItem(ctx, &dynamodb.GetItemInput{TableName: &target, Key: map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: key}}, ConsistentRead: aws.Bool(true)})
				if err != nil {
					t.Fatal(err)
				}
				if want := item(key, payload); !reflect.DeepEqual(out.Item, want) {
					t.Fatalf("%s restored %s/%s = %#v, want %#v", operation, target, key, out.Item, want)
				}
			}
		}
	}
	queue("enabled", func() { setRecovery(true) })
	assertRestore("enabled")
	queue("disabled", func() { setRecovery(false) })
	setRecovery(true)
	assertRestore("disabled")
	queue("rotated", func() {
		setRecovery(false)
		setRecovery(true)
	})
	assertRestore("rotated")
}

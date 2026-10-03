package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
)

// Record even failed Open attempts so cleanup owns partially prepared resources.
// An explicitly armed failure drops a real committed response, never a native call.
type dynamoReplayRuntime struct {
	dynamoengine.Runtime
	mu      sync.Mutex
	owned   map[string]dynamoengine.Specification
	paused  []string
	failure *dynamoCommitFailure
}

func (r *dynamoReplayRuntime) Open(ctx context.Context, spec dynamoengine.Specification) (dynamoengine.Database, error) {
	r.mu.Lock()
	if r.owned == nil {
		r.owned = map[string]dynamoengine.Specification{}
	}
	r.owned[spec.ID] = spec
	r.mu.Unlock()
	db, err := r.Runtime.Open(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &dynamoCommitFailureDatabase{Database: db, owner: r}, nil
}

func (r *dynamoReplayRuntime) specifications() []dynamoengine.Specification {
	r.mu.Lock()
	defer r.mu.Unlock()
	specs := make([]dynamoengine.Specification, 0, len(r.owned))
	for _, spec := range r.owned {
		specs = append(specs, spec)
	}
	return specs
}

type dynamoCommitFailure struct {
	operation string
	reached   chan struct{}
}

type dynamoCommitFailureDatabase struct {
	dynamoengine.Database
	owner       *dynamoReplayRuntime
	unavailable atomic.Bool
}

func (r *dynamoReplayRuntime) failAfterCommit(operation string) <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failure = &dynamoCommitFailure{operation: operation, reached: make(chan struct{})}
	return r.failure.reached
}

func (d *dynamoCommitFailureDatabase) Request(ctx context.Context, target string, body []byte) (dynamoengine.Response, error) {
	if d.unavailable.Load() {
		return dynamoengine.Response{}, errors.New("native handle unavailable after committed response loss")
	}
	response, err := d.Database.Request(ctx, target, body)
	if err != nil || response.StatusCode != http.StatusOK {
		return response, err
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	failure := d.owner.failure
	if failure == nil || target != "DynamoDB_20120810."+failure.operation {
		return response, nil
	}
	d.owner.failure = nil
	d.unavailable.Store(true)
	close(failure.reached)
	return dynamoengine.Response{}, errors.New("native committed response lost")
}

// setPaused suspends the real owned engines, rather than replacing native calls.
func (r *dynamoReplayRuntime) setPaused(ctx context.Context, client *docker.Client, paused bool) error {
	if !paused {
		var result error
		for _, id := range r.paused {
			result = errors.Join(result, client.JSON(ctx, http.MethodPost, "/containers/"+id+"/unpause", nil, nil))
		}
		r.paused = nil
		return result
	}
	for _, spec := range r.specifications() {
		filter, _ := json.Marshal(map[string][]string{"label": {"stackd.dynamodb.id=" + spec.ID}})
		var containers []struct{ ID string }
		if err := client.JSON(ctx, http.MethodGet, "/containers/json?filters="+url.QueryEscape(string(filter)), nil, &containers); err != nil {
			return err
		}
		for _, container := range containers {
			if err := client.JSON(ctx, http.MethodPost, "/containers/"+container.ID+"/pause", nil, nil); err != nil {
				return err
			}
			r.paused = append(r.paused, container.ID)
		}
	}
	if len(r.paused) == 0 {
		return errors.New("no owned native engine to pause")
	}
	return nil
}

func dynamoWaitActive(ctx context.Context, client *dynamodb.Client, table string) error {
	return dynamodb.NewTableExistsWaiter(client, func(options *dynamodb.TableExistsWaiterOptions) {
		options.MinDelay = 100 * time.Millisecond
		options.MaxDelay = 500 * time.Millisecond
	}).Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)}, 60*time.Second)
}

func dynamoWaitAbsent(ctx context.Context, client *dynamodb.Client, table string) error {
	return dynamodb.NewTableNotExistsWaiter(client, func(options *dynamodb.TableNotExistsWaiterOptions) {
		options.MinDelay = 100 * time.Millisecond
		options.MaxDelay = 500 * time.Millisecond
	}).Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)}, 60*time.Second)
}

// The controller describes a newly created target outside the mutation gate.
// Suspend that request, not the database: source writes still reach the real
// engine while both restores remain pending at the same service instant.
type dynamoRestoreBarrierRuntime struct {
	dynamoengine.Runtime
	mu      sync.Mutex
	barrier *dynamoRestoreBarrier
}

type dynamoRestoreBarrier struct {
	table   string
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

type dynamoRestoreBarrierDatabase struct {
	dynamoengine.Database
	owner *dynamoRestoreBarrierRuntime
}

func (r *dynamoRestoreBarrierRuntime) Open(ctx context.Context, spec dynamoengine.Specification) (dynamoengine.Database, error) {
	db, err := r.Runtime.Open(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &dynamoRestoreBarrierDatabase{Database: db, owner: r}, nil
}

func (r *dynamoRestoreBarrierRuntime) setPaused(paused bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if paused {
		if r.barrier == nil {
			r.barrier = &dynamoRestoreBarrier{reached: make(chan struct{}), release: make(chan struct{})}
		}
	} else if r.barrier != nil {
		close(r.barrier.release)
		r.barrier = nil
	}
}

func (r *dynamoRestoreBarrierRuntime) pending() *dynamoRestoreBarrier {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.barrier
}

func (d *dynamoRestoreBarrierDatabase) Request(ctx context.Context, target string, body []byte) (dynamoengine.Response, error) {
	barrier := d.owner.pending()
	if barrier == nil || target != "DynamoDB_20120810.CreateTable" && target != "DynamoDB_20120810.DescribeTable" {
		return d.Database.Request(ctx, target, body)
	}
	var input struct {
		TableName              string
		GlobalSecondaryIndexes []json.RawMessage
	}
	if err := json.Unmarshal(body, &input); err != nil {
		return dynamoengine.Response{}, err
	}
	if target == "DynamoDB_20120810.CreateTable" {
		response, err := d.Database.Request(ctx, target, body)
		// This fixture's restored targets have a GSI; its private recovery
		// baseline does not. Match schema, never a private physical-name prefix.
		if err == nil && response.StatusCode == 200 && len(input.GlobalSecondaryIndexes) != 0 {
			d.owner.mu.Lock()
			if barrier.table == "" {
				barrier.table = input.TableName
			}
			d.owner.mu.Unlock()
		}
		return response, err
	}
	d.owner.mu.Lock()
	block := barrier.table != "" && barrier.table == input.TableName
	d.owner.mu.Unlock()
	if block {
		barrier.once.Do(func() { close(barrier.reached) })
		select {
		case <-ctx.Done():
			return dynamoengine.Response{}, ctx.Err()
		case <-barrier.release:
		}
	}
	return d.Database.Request(ctx, target, body)
}

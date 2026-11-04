package integrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/cloudformation"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sqs"
	"stackd/storage/sqlite"
	cfnsqlite "stackd/storage/sqlite/cloudformation"
)

// Hold the real child resource result before its deployment commit so native
// busy admission cannot race unrelated ownership reads or controller recovery.
func TestCloudFormationStackNativeOwnershipRecoveryAndIsolation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			now := clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))
			repository := cloudformation.NewMemoryRepository(nil)
			queueRepository := sqs.NewMemoryRepository(nil)
			path := filepath.Join(t.TempDir(), "nested-owner.sqlite")
			var db *sql.DB
			var owner *cloudformation.Service
			var queues *sqs.Service
			var commands StepFunctionsCommands
			var handler cloudformation.ResourceHandler
			var boundary *cfnStackQueueResultBarrier
			open := func() {
				t.Helper()
				var store cloudformation.Repository = repository
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					store = cfnsqlite.New(db)
				}
				queues = sqs.NewWithConfig(sqs.Config{Repository: queueRepository, Clock: now})
				owner = cloudformation.New(cloudformation.Config{Repository: store, Clock: now})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"cloudformation": owner, "sqs": queues})
				handlers := CloudFormationMessagingHandlers(commands)
				boundary = &cfnStackQueueResultBarrier{cfnSQSQueue: cfnSQSQueue{commands}, entered: make(chan cloudformation.ResourceRequest, 1), resume: make(chan struct{})}
				handlers["AWS::SQS::Queue"] = boundary
				for kind, h := range CloudFormationStackHandlers(commands) {
					handlers[kind] = h
				}
				owner.SetHandlers(handlers)
				handler = handlers["AWS::CloudFormation::Stack"]
			}
			closeOwners := func() {
				_ = owner.Close()
				_ = queues.Close()
				if db != nil {
					_ = db.Close()
					db = nil
				}
			}
			open()
			t.Cleanup(closeOwners)
			body := `{"Resources":{"Queue":{"Type":"AWS::SQS::Queue"}}}`
			parent, err := cfnComputeCall[api.CreateStackOutput](ctx, commands, "cloudformation", "CreateStack", map[string]any{"StackName": "owner-parent", "TemplateBody": body, "ClientRequestToken": "parent-source-token"})
			if err != nil {
				t.Fatal(err)
			}
			r := cloudformation.ResourceRequest{Type: "AWS::CloudFormation::Stack", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, StackID: cfnComputeValue(parent.StackId), StackName: "owner-parent", LogicalID: "Child", Token: "owned-incarnation", OperationToken: "source-operation", Properties: cloudformation.Properties{"TemplateBody": body}}
			created, err := handler.Create(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			queueCreated, err := boundary.wait(ctx)
			if err != nil || queueCreated.StackID != r.PhysicalID || queueCreated.PhysicalID == "" {
				t.Fatalf("child did not reach its real resource-result boundary: %+v %v", queueCreated, err)
			}
			if ready, err := handler.(cloudformation.ResourceStabilizer).Stabilize(ctx, r); err != nil || ready {
				t.Fatalf("pending native source job became fake-complete: ready=%v err=%v", ready, err)
			}
			closeOwners()
			open()
			recovered, err := handler.Create(ctx, r)
			if err != nil || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("exact-token recovery lost native child identity: %v %v", recovered, err)
			}
			queueRecovered, err := boundary.wait(ctx)
			if err != nil || queueRecovered.StackID != r.PhysicalID || queueRecovered.Token != queueCreated.Token || queueRecovered.PhysicalID != queueCreated.PhysicalID {
				t.Fatalf("recovered deployment lost its admitted native queue: %+v want=%+v err=%v", queueRecovered, queueCreated, err)
			}
			reader := handler.(cloudformation.ResourceReader)
			model, err := reader.Read(ctx, r)
			if err != nil || model["ParentId"] != r.StackID || model["RootId"] != r.StackID {
				t.Fatalf("retained owner/root metadata lost after reopen: %v %v", model, err)
			}
			wrong := r
			wrong.Token = "another-incarnation"
			if _, err := reader.Read(ctx, wrong); err == nil {
				t.Fatal("foreign incarnation read an owned child through the trusted adapter")
			}
			if err := handler.Delete(ctx, wrong); err == nil {
				t.Fatal("foreign incarnation was allowed to delete an owned child")
			}
			changed := r
			changed.Properties = cloudformation.Properties{"TemplateBody": `{"Resources":{"Queue":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"changed-source"}}}}`}
			if _, err := handler.Create(ctx, changed); err == nil {
				t.Fatal("changed create request reused its exact retained operation token")
			}
			direct := r
			direct.CloudControl = true
			if _, err := reader.Read(ctx, direct); err != nil {
				t.Fatalf("ordinary direct CC/native scope could not read an actual child: %v", err)
			}
			var pending *cloudformation.ResourcePendingError
			if err := handler.Delete(ctx, r); !errors.As(err, &pending) {
				t.Fatalf("busy actual child was not retained as pending admission: %v", err)
			}
			close(boundary.resume)
			// A fixed clock keeps each synchronous resource/finalization commit
			// due in this drain, regardless of background driver scheduling.
			if drained, err := owner.JobDriver().RunDue(ctx, 100); err != nil || drained.More {
				t.Fatalf("released native child did not drain: %+v %v", drained, err)
			}
			if ready, err := handler.(cloudformation.ResourceStabilizer).Stabilize(ctx, r); err != nil || !ready {
				t.Fatalf("released native child did not complete: ready=%v err=%v", ready, err)
			}
			grandchild := r
			grandchild.StackID = r.PhysicalID
			grandchild.StackName = model["StackName"].(string)
			grandchild.LogicalID = "Grandchild"
			grandchild.Token = "grandchild-incarnation"
			grandchild.PhysicalID = ""
			result, err := handler.Create(ctx, grandchild)
			if err != nil {
				t.Fatal(err)
			}
			grandchild.PhysicalID = result.PhysicalID
			grandModel, err := reader.Read(ctx, grandchild)
			if err != nil || grandModel["ParentId"] != r.PhysicalID || grandModel["RootId"] != r.StackID {
				t.Fatalf("multi-level child lost its actual root: %v %v", grandModel, err)
			}
			// Matching a pre-existing root's name and template is never proof
			// that this parent incarnation created that native stack.
			collision := r
			collision.LogicalID = "Unowned"
			collision.Token = "unowned-attempt"
			collision.PhysicalID = ""
			name := cfnComputeName(collision, "StackName", 128)
			if _, err := cfnComputeCall[api.CreateStackOutput](ctx, commands, "cloudformation", "CreateStack", map[string]any{"StackName": name, "TemplateBody": body}); err != nil {
				t.Fatal(err)
			}
			if _, err := handler.Create(ctx, collision); err == nil {
				t.Fatal("matching native root name/template was adopted as a child")
			}
			if err := handler.(cloudformation.ResourceDeletionPolicyValidator).ValidateDeletionPolicy("Snapshot"); err == nil {
				t.Fatal("nested stack admitted unsupported snapshot deletion")
			}
		})
	}
}

// The native SQS owner has committed, but CloudFormation has not published the
// resource result. Cancellation leaves the genuine RUNNING intent for replay.
// Embedding the real adapter preserves its read/recovery/validation contracts.
type cfnStackQueueResultBarrier struct {
	cfnSQSQueue
	entered     chan cloudformation.ResourceRequest
	resume      chan struct{}
	enteredOnce sync.Once
}

func (b *cfnStackQueueResultBarrier) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result, err := b.cfnSQSQueue.Create(ctx, r)
	if err != nil || r.StackName == "owner-parent" {
		return result, err
	}
	r.PhysicalID = result.PhysicalID
	b.enteredOnce.Do(func() { b.entered <- r })
	select {
	case <-b.resume:
		return result, nil
	case <-ctx.Done():
		return result, ctx.Err()
	}
}

func (b *cfnStackQueueResultBarrier) wait(ctx context.Context) (cloudformation.ResourceRequest, error) {
	select {
	case r := <-b.entered:
		return r, nil
	case <-ctx.Done():
		return cloudformation.ResourceRequest{}, ctx.Err()
	}
}

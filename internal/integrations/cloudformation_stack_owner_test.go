package integrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	api "stackd/internal/awsapi/cloudformation"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sqs"
	"stackd/storage/sqlite"
	cfnsqlite "stackd/storage/sqlite/cloudformation"
)

// Admission-only cases intentionally keep the actual source jobs pending. The
// public consumer suite separately drains those same owners through real effects.
func TestCloudFormationStackNativeOwnershipRecoveryAndIsolation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			repository := cloudformation.NewMemoryRepository(nil)
			path := filepath.Join(t.TempDir(), "nested-owner.sqlite")
			var db *sql.DB
			var owner *cloudformation.Service
			var queues *sqs.Service
			var commands StepFunctionsCommands
			var handler cloudformation.ResourceHandler
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
				queues = sqs.NewWithConfig(sqs.Config{})
				owner = cloudformation.New(cloudformation.Config{Repository: store})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"cloudformation": owner, "sqs": queues})
				handlers := CloudFormationMessagingHandlers(commands)
				for kind, h := range CloudFormationStackHandlers(commands) {
					handlers[kind] = h
				}
				owner.SetHandlers(handlers)
				handler = handlers["AWS::CloudFormation::Stack"]
			}
			close := func() {
				_ = owner.Close()
				_ = queues.Close()
				if db != nil {
					_ = db.Close()
					db = nil
				}
			}
			open()
			t.Cleanup(close)
			body := `{"Resources":{"Queue":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"native-owned-source"}}}}`
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
			if ready, err := handler.(cloudformation.ResourceStabilizer).Stabilize(ctx, r); err != nil || ready {
				t.Fatalf("pending native source job became fake-complete: ready=%v err=%v", ready, err)
			}
			close()
			open()
			recovered, err := handler.Create(ctx, r)
			if err != nil || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("exact-token recovery lost native child identity: %v %v", recovered, err)
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

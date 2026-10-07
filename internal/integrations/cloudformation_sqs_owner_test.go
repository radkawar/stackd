package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sqs"
	"stackd/storage/sqlite"
	sqlsqs "stackd/storage/sqlite/sqs"
)

func sqsPrivateFixture(t *testing.T, persistent bool) (context.Context, cloudformation.ResourceRequest, *clock.Manual, func() StepFunctionsCommands) {
	t.Helper()
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	r := cloudformation.ResourceRequest{StackID: "private-stack", StackName: "private", LogicalID: "Queue", Token: "original-token", Type: "AWS::SQS::Queue", Scope: cloudformation.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Properties: cloudformation.Properties{"QueueName": "private-queue"}}
	path := filepath.Join(t.TempDir(), "sqs.sqlite")
	manual := clock.NewManual(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
	var service *sqs.Service
	var db *sql.DB
	var repository sqs.Repository = sqs.NewMemoryRepository(nil)
	closeOwner := func() {
		if service != nil {
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			service = nil
		}
		if db != nil {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = nil
		}
	}
	t.Cleanup(closeOwner)
	reopen := func() StepFunctionsCommands {
		closeOwner()
		if persistent {
			var err error
			db, err = sqlite.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			repository = sqlsqs.New(db)
		}
		service = sqs.NewWithConfig(sqs.Config{Repository: repository, Clock: manual})
		return NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sqs": service})
	}
	return ctx, r, manual, reopen
}

func TestSQSPrivateOwnersRejectCounterfeitQueueAndPolicyIncarnations(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "memory"
		if persistent {
			name = "sqlite"
		}
		t.Run(name, func(t *testing.T) {
			ctx, r, manual, reopen := sqsPrivateFixture(t, persistent)
			commands := reopen()
			h := cfnSQSQueue{commands}
			r.CloudControl = true
			created, err := h.Create(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.CloudControl, r.PhysicalID = false, created.PhysicalID
			policy := r
			policy.LogicalID, policy.Token, policy.Type, policy.PhysicalID = "Inline", "policy-token", "AWS::SQS::QueueInlinePolicy", ""
			policy.Properties = cloudformation.Properties{"Queue": created.PhysicalID, "PolicyDocument": cfnSQSPublishPolicy(created.Attributes["Arn"].(string), "Allow")}
			inline := cfnSQSQueueInlinePolicy{commands}
			if _, err := inline.Create(ctx, policy); err != nil {
				t.Fatal(err)
			}
			policy.PhysicalID = created.PhysicalID
			public, err := h.tags(ctx, created.PhysicalID)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{cfnMessagingOwnerTag, cfnMessagingTokenTag, cfnMessagingPolicyTag} {
				if _, exists := public[key]; exists {
					t.Fatalf("private claim exposed as %q", key)
				}
			}
			commands = reopen()
			h, inline = cfnSQSQueue{commands}, cfnSQSQueueInlinePolicy{commands}
			if recovered, err := h.RecoverCreation(ctx, r); err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("queue recovery: %+v %v", recovered, err)
			}
			if recovered, err := inline.RecoverCreation(ctx, policy); err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("policy recovery: %+v %v", recovered, err)
			}
			if replayed, err := h.Create(ctx, r); err != nil || replayed.PhysicalID != created.PhysicalID {
				t.Fatalf("queue replay: %+v %v", replayed, err)
			}
			if _, err := inline.Create(ctx, policy); err != nil {
				t.Fatal(err)
			}
			counterfeit := map[string]string{cfnMessagingOwnerTag: cfnMessagingOwner(r), cfnMessagingTokenTag: cfnMessagingHash(r.Token), cfnMessagingPolicyTag: cfnSQSPolicyOwner(policy)}
			if err := h.tag(ctx, created.PhysicalID, counterfeit); err != nil {
				t.Fatal(err)
			}
			if err := h.untag(ctx, created.PhysicalID, cfnMessagingKeys(counterfeit)); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Read(ctx, r); err != nil {
				t.Fatalf("customer untag relinquished private queue claim: %v", err)
			}
			if _, err := inline.Read(ctx, policy); err != nil {
				t.Fatalf("customer untag relinquished private policy claim: %v", err)
			}
			if err := cfnMessagingExec(ctx, commands, "sqs", "DeleteQueue", &api.DeleteQueueInput{QueueUrl: new(api.String(created.PhysicalID))}); err != nil {
				t.Fatal(err)
			}
			if err := manual.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			if _, err := cfnMessagingCall[api.CreateQueueOutput](ctx, commands, "sqs", "CreateQueue", &api.CreateQueueInput{QueueName: new(api.String("private-queue")), Tags: cfnSQSNativeTags(counterfeit)}); err != nil {
				t.Fatal(err)
			}
			doc, _ := cfnMessagingPolicy(policy.Properties["PolicyDocument"].(map[string]any))
			if err := cfnMessagingExec(ctx, commands, "sqs", "SetQueueAttributes", &api.SetQueueAttributesInput{QueueUrl: new(api.String(created.PhysicalID)), Attributes: api.QueueAttributeMap{"Policy": api.String(doc)}}); err != nil {
				t.Fatal(err)
			}
			if out, err := h.Create(ctx, r); err == nil || out.PhysicalID != "" {
				t.Fatalf("counterfeit queue adopted: %+v %v", out, err)
			}
			if out, err := h.RecoverCreation(ctx, r); err == nil || out.PhysicalID != "" {
				t.Fatalf("counterfeit queue recovered: %+v %v", out, err)
			}
			if _, err := h.Read(ctx, r); err == nil {
				t.Fatal("foreign queue passed owned read")
			}
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"QueueName": "private-queue", "DelaySeconds": 5}
			if _, err := h.Update(ctx, r); err == nil {
				t.Fatal("stale queue updated recreated row")
			}
			if err := h.Delete(ctx, r); err == nil {
				t.Fatal("stale queue deleted recreated row")
			}
			if out, err := inline.Create(ctx, policy); err == nil || out.PhysicalID != "" {
				t.Fatalf("counterfeit policy adopted: %+v %v", out, err)
			}
			if _, err := inline.Read(ctx, policy); err == nil {
				t.Fatal("counterfeit policy passed owned read")
			}
			if err := inline.Delete(ctx, policy); err != nil {
				t.Fatal(err)
			}
			direct := r
			direct.CloudControl = true
			if _, err := h.Read(ctx, direct); err != nil {
				t.Fatalf("native CC read blocked: %v", err)
			}
			if _, err := h.Update(ctx, direct); err != nil {
				t.Fatalf("native CC update blocked: %v", err)
			}
			if out, err := h.Create(ctx, direct); err == nil || out.PhysicalID != "" {
				t.Fatalf("CC create bypassed private claim: %+v %v", out, err)
			}
			policy.CloudControl = true
			if err := inline.Delete(ctx, policy); err != nil {
				t.Fatalf("untagged native CC policy delete blocked: %v", err)
			}
			if err := h.Delete(ctx, direct); err != nil {
				t.Fatalf("native CC queue delete blocked: %v", err)
			}
		})
	}
}
func cfnSQSPublishPolicy(arn, effect string) map[string]any {
	return map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": effect, "Principal": "*", "Action": "sqs:SendMessage", "Resource": arn}}}
}

type sqsPrivateCommandHook struct {
	awscommands.CommandExecutor
	before func(awsapi.DecodedRequest)
}

func (h *sqsPrivateCommandHook) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	if h.before != nil {
		h.before(request)
	}
	return h.CommandExecutor.ExecuteCommand(ctx, request)
}

func TestSQSQueueMutationAtomicallyRejectsForeignRecreation(t *testing.T) {
	ctx, r, manual, reopen := sqsPrivateFixture(t, false)
	commands := reopen()
	created, err := (cfnSQSQueue{commands}).Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID, r.Previous = created.PhysicalID, r.Properties
	r.Properties = cloudformation.Properties{"QueueName": "private-queue", "DelaySeconds": 5}
	hook := &sqsPrivateCommandHook{CommandExecutor: commands.providers["sqs"].executor}
	armed := true
	hook.before = func(request awsapi.DecodedRequest) {
		if !armed || request.Operation.Name != "SetQueueAttributes" {
			return
		}
		armed = false
		if err := cfnMessagingExec(ctx, commands, "sqs", "DeleteQueue", &api.DeleteQueueInput{QueueUrl: new(api.String(created.PhysicalID))}); err != nil {
			t.Fatal(err)
		}
		if err := manual.Advance(time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := cfnMessagingCall[api.CreateQueueOutput](ctx, commands, "sqs", "CreateQueue", &api.CreateQueueInput{QueueName: new(api.String("private-queue"))}); err != nil {
			t.Fatal(err)
		}
	}
	hooked := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sqs": hook})
	if _, err := (cfnSQSQueue{hooked}).Update(ctx, r); err == nil {
		t.Fatal("check-before-mutation race updated foreign native incarnation")
	}
	live, err := (cfnSQSQueue{commands}).Read(ctx, cloudformation.ResourceRequest{CloudControl: true, PhysicalID: created.PhysicalID, Scope: r.Scope})
	if err != nil || live["DelaySeconds"] == int64(5) {
		t.Fatalf("foreign row changed: %+v %v", live, err)
	}
}

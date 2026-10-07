package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sns"
	"stackd/storage/sqlite"
	sqlsns "stackd/storage/sqlite/sns"
)

func snsPrivateFixture(t *testing.T, persistent bool) (context.Context, cloudformation.ResourceRequest, func() StepFunctionsCommands) {
	t.Helper()
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	r := cloudformation.ResourceRequest{StackID: "private-stack", StackName: "private", LogicalID: "Topic", Token: "original-token", Type: "AWS::SNS::Topic", Scope: cloudformation.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Properties: cloudformation.Properties{"TopicName": "private-topic"}}
	path := filepath.Join(t.TempDir(), "sns.sqlite")
	var service *sns.Service
	var db *sql.DB
	var repository sns.Repository = sns.NewMemoryRepository(nil)
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
			repository = sqlsns.New(db)
		}
		service = sns.New(sns.Config{Repository: repository})
		return NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sns": service})
	}
	return ctx, r, reopen
}

func TestSNSPrivateOwnersRejectCounterfeitTopicAndPolicyIncarnations(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "memory"
		if persistent {
			name = "sqlite"
		}
		t.Run(name, func(t *testing.T) {
			ctx, r, reopen := snsPrivateFixture(t, persistent)
			commands := reopen()
			h := cfnSNSTopic{commands}
			r.CloudControl = true
			created, err := h.Create(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.CloudControl, r.PhysicalID = false, created.PhysicalID
			policy := r
			policy.LogicalID, policy.Token, policy.Type, policy.PhysicalID = "Inline", "policy-token", "AWS::SNS::TopicInlinePolicy", ""
			policy.Properties = cloudformation.Properties{"TopicArn": created.PhysicalID, "PolicyDocument": cfnSNSPublishPolicy(created.PhysicalID, "Allow")}
			inline := cfnSNSTopicInlinePolicy{commands}
			if _, err := inline.Create(ctx, policy); err != nil {
				t.Fatal(err)
			}
			policy.PhysicalID = created.PhysicalID
			public, err := h.tags(ctx, created.PhysicalID)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{cfnMessagingOwnerTag, cfnMessagingTokenTag, cfnMessagingPolicyTag, "stackd:cloudformation:policy-id", "stackd:cloudformation:policy-type"} {
				if _, exists := public[key]; exists {
					t.Fatalf("private claim exposed as %q", key)
				}
			}
			// Reopening must preserve both independently owned native claims.
			commands = reopen()
			h, inline = cfnSNSTopic{commands}, cfnSNSTopicInlinePolicy{commands}
			if recovered, err := h.RecoverCreation(ctx, r); err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("topic recovery: %+v %v", recovered, err)
			}
			if recovered, err := inline.RecoverCreation(ctx, policy); err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("policy recovery: %+v %v", recovered, err)
			}
			if replayed, err := h.Create(ctx, r); err != nil || replayed.PhysicalID != created.PhysicalID {
				t.Fatalf("topic replay: %+v %v", replayed, err)
			}
			if _, err := inline.Create(ctx, policy); err != nil {
				t.Fatal(err)
			}
			counterfeit := map[string]string{cfnMessagingOwnerTag: cfnMessagingOwner(r), cfnMessagingTokenTag: cfnMessagingHash(r.Token), cfnMessagingPolicyTag: cfnSNSPolicyMarker(policy), "stackd:cloudformation:policy-id": created.PhysicalID, "stackd:cloudformation:policy-type": policy.Type}
			if err := h.tag(ctx, created.PhysicalID, counterfeit); err != nil {
				t.Fatal(err)
			}
			if err := h.untag(ctx, created.PhysicalID, cfnMessagingKeys(counterfeit)); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Read(ctx, r); err != nil {
				t.Fatalf("customer untag relinquished private topic claim: %v", err)
			}
			if _, err := inline.Read(ctx, policy); err != nil {
				t.Fatalf("customer untag relinquished private policy claim: %v", err)
			}
			// Native deletion/recreation has the same ARN, tags and policy payload,
			// but neither old owner may adopt or mutate that foreign incarnation.
			if err := cfnMessagingExec(ctx, commands, "sns", "DeleteTopic", &api.DeleteTopicInput{TopicArn: new(api.TopicARN(created.PhysicalID))}); err != nil {
				t.Fatal(err)
			}
			if _, err := cfnMessagingCall[api.CreateTopicOutput](ctx, commands, "sns", "CreateTopic", &api.CreateTopicInput{Name: new(api.TopicName("private-topic")), Tags: cfnSNSNativeTags(counterfeit)}); err != nil {
				t.Fatal(err)
			}
			doc, _ := cfnMessagingPolicy(policy.Properties["PolicyDocument"].(map[string]any))
			if err := h.set(ctx, created.PhysicalID, "Policy", doc); err != nil {
				t.Fatal(err)
			}
			if out, err := h.Create(ctx, r); err == nil || out.PhysicalID != "" {
				t.Fatalf("counterfeit topic adopted: %+v %v", out, err)
			}
			if out, err := h.RecoverCreation(ctx, r); err == nil || out.PhysicalID != "" {
				t.Fatalf("counterfeit topic recovered: %+v %v", out, err)
			}
			if _, err := h.Read(ctx, r); err == nil {
				t.Fatal("foreign topic passed owned read")
			}
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"TopicName": "private-topic", "DisplayName": "stale-write"}
			if _, err := h.Update(ctx, r); err == nil {
				t.Fatal("stale topic updated recreated row")
			}
			if err := h.Delete(ctx, r); err == nil {
				t.Fatal("stale topic deleted recreated row")
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
			cfnSNSCheckPolicy(t, ctx, commands, created.PhysicalID, policy.Properties["PolicyDocument"].(map[string]any))
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
				t.Fatalf("native CC topic delete blocked: %v", err)
			}
		})
	}
}

type snsPrivateCommandHook struct {
	awscommands.CommandExecutor
	before func(awsapi.DecodedRequest)
}

func (h *snsPrivateCommandHook) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	if h.before != nil {
		h.before(request)
	}
	return h.CommandExecutor.ExecuteCommand(ctx, request)
}

func TestSNSTopicMutationAtomicallyRejectsForeignRecreation(t *testing.T) {
	ctx, base, r := cfnSNSPolicyFixture(t)
	created, err := (cfnSNSTopic{base}).Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID, r.Previous = created.PhysicalID, r.Properties
	r.Properties = cloudformation.Properties{"TopicName": "policy-consumer", "DisplayName": "stale"}
	provider := base.providers["sns"]
	hook := &snsPrivateCommandHook{CommandExecutor: provider.executor}
	armed := true
	hook.before = func(request awsapi.DecodedRequest) {
		if !armed || request.Operation.Name != "SetTopicAttributes" {
			return
		}
		armed = false
		if err := cfnMessagingExec(ctx, base, "sns", "DeleteTopic", &api.DeleteTopicInput{TopicArn: new(api.TopicARN(created.PhysicalID))}); err != nil {
			t.Fatal(err)
		}
		if _, err := cfnMessagingCall[api.CreateTopicOutput](ctx, base, "sns", "CreateTopic", &api.CreateTopicInput{Name: new(api.TopicName("policy-consumer")), Tags: cfnSNSNativeTags(map[string]string{cfnMessagingOwnerTag: cfnMessagingOwner(r), cfnMessagingTokenTag: cfnMessagingHash(r.Token)})}); err != nil {
			t.Fatal(err)
		}
	}
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sns": hook})
	if _, err := (cfnSNSTopic{commands}).Update(ctx, r); err == nil {
		t.Fatal("check-before-mutation race updated foreign native incarnation")
	}
	live, _, err := (cfnSNSTopic{base}).observe(ctx, created.PhysicalID)
	if err != nil || live.Attributes["DisplayName"] != "" {
		t.Fatalf("foreign row changed: %+v %v", live, err)
	}
}

func TestSNSTopicPostAdmissionFailureReturnsRecoverableNativeIdentity(t *testing.T) {
	ctx, r, reopen := snsPrivateFixture(t, true)
	commands := reopen()
	r.Properties["Subscription"] = []any{map[string]any{"Protocol": "sqs", "Endpoint": "not-an-arn"}}
	h := cfnSNSTopic{commands}
	created, err := h.Create(ctx, r)
	if err == nil || created.PhysicalID == "" {
		t.Fatalf("lost admitted topic identity: %+v %v", created, err)
	}
	commands = reopen()
	h = cfnSNSTopic{commands}
	if recovered, err := h.RecoverCreation(ctx, r); err != nil || recovered.PhysicalID != created.PhysicalID {
		t.Fatalf("post-error reopening recovery: %+v %v", recovered, err)
	}
	if replayed, err := h.Create(ctx, r); err == nil || replayed.PhysicalID != created.PhysicalID {
		t.Fatalf("post-error exact replay: %+v %v", replayed, err)
	}
	r.PhysicalID = created.PhysicalID
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
}

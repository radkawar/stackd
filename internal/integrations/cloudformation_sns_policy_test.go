package integrations

import (
	"context"
	"fmt"
	"testing"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sns"
)

func cfnSNSPolicyFixture(t *testing.T) (context.Context, StepFunctionsCommands, cloudformation.ResourceRequest) {
	t.Helper()
	service := sns.New(sns.Config{})
	t.Cleanup(func() { _ = service.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sns": service})
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	r := cloudformation.ResourceRequest{StackID: "stack-one", StackName: "policy-stack", LogicalID: "Topic", Token: "topic-incarnation", Scope: cloudformation.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Properties: cloudformation.Properties{"TopicName": "policy-consumer"}}
	return ctx, commands, r
}
func cfnSNSPublishPolicy(arn, effect string) map[string]any {
	return map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": effect, "Principal": "*", "Action": "sns:Publish", "Resource": arn}}}
}
func cfnSNSObservePolicy(t *testing.T, ctx context.Context, commands StepFunctionsCommands, arn string) string {
	t.Helper()
	out, err := cfnMessagingCall[api.GetTopicAttributesOutput](ctx, commands, "sns", "GetTopicAttributes", &api.GetTopicAttributesInput{TopicArn: new(api.TopicARN(arn))})
	if err != nil {
		t.Fatal(err)
	}
	return string(out.Attributes["Policy"])
}
func cfnSNSCheckPolicy(t *testing.T, ctx context.Context, commands StepFunctionsCommands, arn string, expected map[string]any) {
	t.Helper()
	doc, err := cfnMessagingPolicy(expected)
	if err != nil {
		t.Fatal(err)
	}
	if live := cfnSNSObservePolicy(t, ctx, commands, arn); !cfnMessagingEqualJSON(live, doc) {
		t.Fatalf("live SNS policy = %s, want %s", live, doc)
	}
}

func TestSNSInlinePolicyCollisionRecoveryUpdateRollbackAndRemoval(t *testing.T) {
	ctx, commands, topicRequest := cfnSNSPolicyFixture(t)
	handlers := CloudFormationMessagingHandlers(commands)
	topic := handlers["AWS::SNS::Topic"]
	created, err := topic.Create(ctx, topicRequest)
	if err != nil {
		t.Fatal(err)
	}
	arn := created.PhysicalID
	inline := handlers["AWS::SNS::TopicInlinePolicy"]
	if inline == nil || handlers["AWS::SNS::TopicPolicy"] == nil || handlers["AWS::SNS::Subscription"] == nil {
		t.Fatal("SNS owner handlers are missing from the consumer registry")
	}
	allow := cfnSNSPublishPolicy(arn, "Allow")
	r := topicRequest
	r.LogicalID, r.Token, r.Type = "Inline", "inline-incarnation", "AWS::SNS::TopicInlinePolicy"
	r.Properties = cloudformation.Properties{"TopicArn": arn, "PolicyDocument": allow}
	result, err := inline.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if result.PhysicalID != arn || result.Ref != arn || len(result.Attributes) != 0 {
		t.Fatalf("inline identity = %#v", result)
	}
	if recovered, err := inline.Create(ctx, r); err != nil || recovered.PhysicalID != arn {
		t.Fatalf("same-incarnation recovery = %#v, %v", recovered, err)
	}
	r.PhysicalID = arn
	other := r
	other.Token = "other-incarnation"
	if _, err := inline.Create(ctx, other); err == nil {
		t.Fatal("different incarnation adopted the live policy")
	}
	if err := inline.Delete(ctx, other); err == nil {
		t.Fatal("different incarnation deleted the live policy")
	}
	// Even the same logical identity and token cannot move across resource types.
	other = r
	other.Type, other.PhysicalID = "AWS::SNS::TopicPolicy", ""
	other.Properties = cloudformation.Properties{"Topics": []string{arn}, "PolicyDocument": allow}
	if _, err := handlers[other.Type].Create(ctx, other); err == nil {
		t.Fatal("TopicPolicy overwrote an inline claim")
	}
	cfnSNSCheckPolicy(t, ctx, commands, arn, allow)
	read := inline.(cloudformation.ResourceReader)
	model, err := read.Read(ctx, r)
	if err != nil || model["TopicArn"] != arn {
		t.Fatalf("live inline read = %#v, %v", model, err)
	}
	listed, err := read.List(ctx, r)
	if err != nil || len(listed) != 1 || listed[0].Identifier != arn {
		t.Fatalf("live inline list = %#v, %v", listed, err)
	}
	// An ordinary topic update must preserve the separate policy claim.
	topicRequest.PhysicalID = arn
	topicRequest.Previous = topicRequest.Properties
	topicRequest.Properties = cloudformation.Properties{"TopicName": "policy-consumer", "DisplayName": "updated", "Tags": []any{map[string]any{"Key": "customer", "Value": "value"}}}
	if _, err := topic.Update(ctx, topicRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := inline.(cloudformation.ResourceResultReader).Result(ctx, r); err != nil {
		t.Fatal(err)
	}
	before := r.Properties
	deny := cfnSNSPublishPolicy(arn, "Deny")
	r.Previous, r.Properties = before, cloudformation.Properties{"TopicArn": arn, "PolicyDocument": deny}
	if _, err := inline.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	cfnSNSCheckPolicy(t, ctx, commands, arn, deny)
	r.Previous, r.Properties = r.Properties, before
	if _, err := inline.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	cfnSNSCheckPolicy(t, ctx, commands, arn, allow)
	if err := inline.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := inline.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if live := cfnSNSObservePolicy(t, ctx, commands, arn); !cfnMessagingEqualJSON(live, cfnSNSTopicDefaultPolicy(arn)) {
		t.Fatalf("removal did not restore native default: %s", live)
	}
	if _, err := read.Read(ctx, r); !cfnMessagingMissing(err, "NotFoundException") {
		t.Fatalf("removed inline policy remains visible: %v", err)
	}
	// The reverse collision is independently enforced by the same SNS owner.
	policy := handlers["AWS::SNS::TopicPolicy"]
	result, err = policy.Create(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	other.PhysicalID = result.PhysicalID
	if _, err := inline.Create(ctx, r); err == nil {
		t.Fatal("inline resource overwrote a TopicPolicy claim")
	}
	if model, err := policy.(cloudformation.ResourceReader).Read(ctx, other); err != nil || model["Id"] != result.PhysicalID {
		t.Fatalf("live TopicPolicy read = %#v, %v", model, err)
	}
	if err := policy.Delete(ctx, other); err != nil {
		t.Fatal(err)
	}
}

func TestSNSNativePolicyWritesRelinquishClaimsAndIsolateStaleCleanup(t *testing.T) {
	for _, action := range []string{"SetTopicAttributes", "AddPermission", "RemovePermission", "CloudControlUpdate", "CloudControlDelete"} {
		t.Run(action, func(t *testing.T) {
			ctx, commands, topicRequest := cfnSNSPolicyFixture(t)
			created, err := (cfnSNSTopic{commands}).Create(ctx, topicRequest)
			if err != nil {
				t.Fatal(err)
			}
			arn := created.PhysicalID
			allow := cfnSNSPublishPolicy(arn, "Allow")
			// Keep a second statement so native RemovePermission is valid.
			allow["Statement"] = append(allow["Statement"].([]any), map[string]any{"Sid": "Native", "Effect": "Allow", "Principal": "*", "Action": "sns:Subscribe", "Resource": arn})
			r := topicRequest
			r.LogicalID, r.Token = "Inline", "inline-incarnation"
			r.Properties = cloudformation.Properties{"TopicArn": arn, "PolicyDocument": allow}
			h := cfnSNSTopicInlinePolicy{commands}
			if _, err := h.Create(ctx, r); err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = arn
			switch action {
			case "SetTopicAttributes":
				doc, _ := cfnMessagingPolicy(allow)
				// An equal native write is still native authority, not recovery.
				if err := (cfnSNSTopic{commands}).set(ctx, arn, "Policy", doc); err != nil {
					t.Fatal(err)
				}
			case "AddPermission":
				if err := cfnMessagingExec(ctx, commands, "sns", action, &api.AddPermissionInput{TopicArn: new(api.TopicARN(arn)), Label: new(api.Label("Added")), AWSAccountId: api.DelegatesList{"222222222222"}, ActionName: api.ActionsList{"Publish"}}); err != nil {
					t.Fatal(err)
				}
			case "RemovePermission":
				if err := cfnMessagingExec(ctx, commands, "sns", action, &api.RemovePermissionInput{TopicArn: new(api.TopicARN(arn)), Label: new(api.Label("Native"))}); err != nil {
					t.Fatal(err)
				}
			case "CloudControlUpdate":
				direct := r
				direct.CloudControl, direct.Token = true, "native-update"
				direct.Previous, direct.Properties = r.Properties, cloudformation.Properties{"TopicArn": arn, "PolicyDocument": cfnSNSPublishPolicy(arn, "Deny")}
				if _, err := h.Update(ctx, direct); err != nil {
					t.Fatal(err)
				}
			case "CloudControlDelete":
				direct := r
				direct.CloudControl, direct.Token = true, "native-delete"
				if err := h.Delete(ctx, direct); err != nil {
					t.Fatal(err)
				}
			}
			live := cfnSNSObservePolicy(t, ctx, commands, arn)
			if err := h.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
			if after := cfnSNSObservePolicy(t, ctx, commands, arn); !cfnMessagingEqualJSON(after, live) {
				t.Fatalf("stale cleanup overwrote the native policy: %s -> %s", live, after)
			}
			r.Previous = r.Properties
			if _, err := h.Update(ctx, r); err == nil {
				t.Fatal("stack update reacquired a relinquished claim")
			}
			if !cfnMessagingEqualJSON(live, cfnSNSTopicDefaultPolicy(arn)) {
				recovery := r
				recovery.PhysicalID, recovery.Previous = "", nil
				if _, err := h.Create(ctx, recovery); err == nil {
					t.Fatal("create recovery adopted an unrelated policy by matching its topic or document")
				}
			}
		})
	}
}

func TestSNSPolicyPublishEffectsAndNegativeScope(t *testing.T) {
	ctx, commands, topicRequest := cfnSNSPolicyFixture(t)
	created, err := (cfnSNSTopic{commands}).Create(ctx, topicRequest)
	if err != nil {
		t.Fatal(err)
	}
	arn := created.PhysicalID
	foreign := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "222222222222", Region: "us-east-1", PrincipalARN: "arn:aws:iam::222222222222:root", PrincipalID: "222222222222"})
	publish := func() error {
		_, err := cfnMessagingCall[api.PublishOutput](foreign, commands, "sns", "Publish", &api.PublishInput{TopicArn: new(api.TopicARN(arn)), Message: new(api.Message("real publication"))})
		return err
	}
	if err := publish(); err == nil {
		t.Fatal("native default allowed a foreign publication")
	}
	r := topicRequest
	r.LogicalID, r.Token = "Inline", "inline-incarnation"
	r.Properties = cloudformation.Properties{"TopicArn": arn, "PolicyDocument": cfnSNSPublishPolicy(arn, "Allow")}
	h := cfnSNSTopicInlinePolicy{commands}
	if _, err := h.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = arn
	if err := publish(); err != nil {
		t.Fatalf("live policy grant did not permit publication: %v", err)
	}
	for _, scope := range []cloudformation.Scope{{Partition: "aws", Account: "222222222222", Region: "us-east-1"}, {Partition: "aws", Account: "111111111111", Region: "us-west-2"}, {Partition: "aws-cn", Account: "111111111111", Region: "us-east-1"}} {
		other := r
		other.Scope = scope
		if _, err := h.Create(ctx, other); err == nil {
			t.Fatalf("scope mismatch was accepted: %#v", scope)
		}
		if err := h.Delete(ctx, other); err == nil {
			t.Fatalf("scope mismatch deleted a policy: %#v", scope)
		}
	}
	r.Previous, r.Properties = r.Properties, cloudformation.Properties{"TopicArn": arn, "PolicyDocument": cfnSNSPublishPolicy(arn, "Deny")}
	if _, err := h.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := publish(); err == nil {
		t.Fatal("policy update did not deny foreign publication")
	}
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := publish(); err == nil {
		t.Fatal("policy removal left a foreign publication grant")
	}
}

func TestSNSMultiTopicPolicyFailedCreateRollsBackActualEffects(t *testing.T) {
	ctx, commands, topicRequest := cfnSNSPolicyFixture(t)
	var arns []string
	for i := range 2 {
		r := topicRequest
		r.LogicalID, r.Properties = fmt.Sprintf("Topic%d", i), cloudformation.Properties{"TopicName": fmt.Sprintf("policy-consumer-%d", i)}
		result, err := (cfnSNSTopic{commands}).Create(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		arns = append(arns, result.PhysicalID)
	}
	r := topicRequest
	r.LogicalID, r.Token, r.Type = "Policy", "policy-incarnation", "AWS::SNS::TopicPolicy"
	// SNS accepts the first target and rejects the second mismatched Resource.
	r.Properties = cloudformation.Properties{"Topics": arns, "PolicyDocument": cfnSNSPublishPolicy(arns[0], "Allow")}
	h := cfnSNSTopicPolicy{commands}
	result, err := h.Create(ctx, r)
	if err == nil {
		t.Fatal("SNS accepted a policy referring to another topic")
	}
	r.PhysicalID = result.PhysicalID
	if err := h.Delete(ctx, r); err != nil {
		t.Fatalf("failed-create rollback: %v", err)
	}
	for _, arn := range arns {
		if live := cfnSNSObservePolicy(t, ctx, commands, arn); !cfnMessagingEqualJSON(live, cfnSNSTopicDefaultPolicy(arn)) {
			t.Fatalf("rollback left policy effects on %s: %s", arn, live)
		}
	}
}

func TestSNSInlinePolicyRecoveryAcrossOwnerRestart(t *testing.T) {
	repository := sns.NewMemoryRepository(nil)
	service := sns.New(sns.Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sns": service})
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	r := cloudformation.ResourceRequest{StackID: "restart-stack", StackName: "restart", LogicalID: "Topic", Token: "topic-incarnation", Scope: cloudformation.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Properties: cloudformation.Properties{"TopicName": "restart-topic"}}
	topic, err := (cfnSNSTopic{commands}).Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.LogicalID, r.Token = "Policy", "policy-incarnation"
	r.Properties = cloudformation.Properties{"TopicArn": topic.PhysicalID, "PolicyDocument": cfnSNSPublishPolicy(topic.PhysicalID, "Allow")}
	if _, err := (cfnSNSTopicInlinePolicy{commands}).Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	restarted := sns.New(sns.Config{Repository: repository})
	t.Cleanup(func() { _ = restarted.Close() })
	restartedCommands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sns": restarted})
	h := cfnSNSTopicInlinePolicy{restartedCommands}
	if recovered, err := h.Create(ctx, r); err != nil || recovered.PhysicalID != topic.PhysicalID {
		t.Fatalf("owner restart recovery = %#v, %v", recovered, err)
	}
	other := r
	other.Token = "new-incarnation"
	if _, err := h.Create(ctx, other); err == nil {
		t.Fatal("owner restart lost the persisted incarnation claim")
	}
	r.PhysicalID = topic.PhysicalID
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if live := cfnSNSObservePolicy(t, ctx, restartedCommands, topic.PhysicalID); !cfnMessagingEqualJSON(live, cfnSNSTopicDefaultPolicy(topic.PhysicalID)) {
		t.Fatalf("restarted owner removal did not remove the policy: %s", live)
	}
}

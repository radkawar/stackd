package integrations

import (
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awscommands"
	"stackd/internal/services/cloudformation"
)

func TestSNSPrivatePolicyFenceRejectsRecreationDuringNativeMutation(t *testing.T) {
	for _, remove := range []bool{false, true} {
		name := "update"
		if remove {
			name = "delete"
		}
		t.Run(name, func(t *testing.T) {
			ctx, base, r := cfnSNSPolicyFixture(t)
			created, err := (cfnSNSTopic{base}).Create(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.LogicalID, r.Token, r.Type = "Inline", "inline-token", "AWS::SNS::TopicInlinePolicy"
			r.Properties = cloudformation.Properties{"TopicArn": created.PhysicalID, "PolicyDocument": cfnSNSPublishPolicy(created.PhysicalID, "Allow")}
			if _, err := (cfnSNSTopicInlinePolicy{base}).Create(ctx, r); err != nil {
				t.Fatal(err)
			}
			r.PhysicalID, r.Previous = created.PhysicalID, r.Properties
			r.Properties = cloudformation.Properties{"TopicArn": created.PhysicalID, "PolicyDocument": cfnSNSPublishPolicy(created.PhysicalID, "Deny")}
			hook := &snsPrivateCommandHook{CommandExecutor: base.providers["sns"].executor}
			armed := true
			hook.before = func(request awsapi.DecodedRequest) {
				if !armed || request.Operation.Name != "SetTopicAttributes" {
					return
				}
				armed = false
				if err := cfnMessagingExec(ctx, base, "sns", "DeleteTopic", &api.DeleteTopicInput{TopicArn: new(api.TopicARN(created.PhysicalID))}); err != nil {
					t.Fatal(err)
				}
				foreign, _ := cfnMessagingPolicy(cfnSNSPublishPolicy(created.PhysicalID, "Allow"))
				if _, err := cfnMessagingCall[api.CreateTopicOutput](ctx, base, "sns", "CreateTopic", &api.CreateTopicInput{Name: new(api.TopicName("policy-consumer")), Attributes: api.TopicAttributesMap{"Policy": api.AttributeValue(foreign)}, Tags: cfnSNSNativeTags(map[string]string{cfnMessagingPolicyTag: cfnSNSPolicyMarker(r)})}); err != nil {
					t.Fatal(err)
				}
			}
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sns": hook})
			h := cfnSNSTopicInlinePolicy{commands}
			if remove {
				if err := h.Delete(ctx, r); err == nil {
					t.Fatal("stale policy deleted foreign incarnation during race")
				}
			} else {
				if _, err := h.Update(ctx, r); err == nil {
					t.Fatal("stale policy updated foreign incarnation during race")
				}
			}
			if armed {
				t.Fatal("native policy mutation hook was not reached")
			}
			cfnSNSCheckPolicy(t, ctx, base, created.PhysicalID, cfnSNSPublishPolicy(created.PhysicalID, "Allow"))
		})
	}
}

func TestSNSCloudControlPolicyCreateAlwaysClaimsAndCannotCrossTypes(t *testing.T) {
	ctx, commands, topic := cfnSNSPolicyFixture(t)
	created, err := (cfnSNSTopic{commands}).Create(ctx, topic)
	if err != nil {
		t.Fatal(err)
	}
	r := topic
	r.LogicalID, r.Token, r.Type, r.CloudControl = "Inline", "cc-create-token", "AWS::SNS::TopicInlinePolicy", true
	r.Properties = cloudformation.Properties{"TopicArn": created.PhysicalID, "PolicyDocument": cfnSNSPublishPolicy(created.PhysicalID, "Allow")}
	inline := cfnSNSTopicInlinePolicy{commands}
	if _, err := inline.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if recovered, err := inline.RecoverCreation(ctx, r); err != nil || recovered.PhysicalID != created.PhysicalID {
		t.Fatalf("CC CREATE did not privately claim: %+v %v", recovered, err)
	}
	other := r
	other.Token = "other-token"
	if out, err := inline.Create(ctx, other); err == nil || out.PhysicalID != "" {
		t.Fatalf("CC CREATE overwrote existing claim: %+v %v", out, err)
	}
	other.Type = "AWS::SNS::TopicPolicy"
	other.Properties = cloudformation.Properties{"Topics": []string{created.PhysicalID}, "PolicyDocument": cfnSNSPublishPolicy(created.PhysicalID, "Allow")}
	if out, err := (cfnSNSTopicPolicy{commands}).Create(ctx, other); err == nil || out.PhysicalID != "" {
		t.Fatalf("CC CREATE crossed policy resource types: %+v %v", out, err)
	}
}

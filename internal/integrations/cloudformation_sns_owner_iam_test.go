package integrations

import (
	"testing"

	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
)

func TestSNSPrivateOwnerDoesNotBypassCurrentIAM(t *testing.T) {
	ctx, commands, r := cfnSNSPolicyFixture(t)
	h := cfnSNSTopic{commands}
	created, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID, r.Previous = created.PhysicalID, r.Properties
	r.Properties = cloudformation.Properties{"TopicName": "policy-consumer", "DisplayName": "denied"}
	m := awsctx.FromContext(ctx)
	m.HasSessionPolicy = true
	m.SessionPolicies = []string{`{"Statement":[{"Effect":"Allow","Action":"sns:*","Resource":"*"},{"Effect":"Deny","Action":["sns:SetTopicAttributes","sns:TagResource","sns:UntagResource","sns:DeleteTopic"],"Resource":"*"}]}`}
	denied := awsctx.WithMetadata(ctx, m)
	if _, err := h.Update(denied, r); err == nil {
		t.Fatal("private topic ownership bypassed current IAM update deny")
	}
	if err := h.Delete(denied, r); err == nil {
		t.Fatal("private topic ownership bypassed current IAM delete deny")
	}
	live, _, err := h.observe(ctx, r.PhysicalID)
	if err != nil || live.Attributes["DisplayName"] != "" {
		t.Fatalf("denied update changed topic: %+v %v", live, err)
	}
	policy := r
	policy.LogicalID, policy.Token, policy.Type, policy.PhysicalID = "Inline", "policy-token", "AWS::SNS::TopicInlinePolicy", ""
	policy.Properties = cloudformation.Properties{"TopicArn": created.PhysicalID, "PolicyDocument": cfnSNSPublishPolicy(created.PhysicalID, "Allow")}
	inline := cfnSNSTopicInlinePolicy{commands}
	if _, err := inline.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	policy.PhysicalID = created.PhysicalID
	if err := inline.Delete(denied, policy); err == nil {
		t.Fatal("private policy ownership bypassed current IAM delete deny")
	}
	policy.Previous = policy.Properties
	policy.Properties = cloudformation.Properties{"TopicArn": created.PhysicalID, "PolicyDocument": cfnSNSPublishPolicy(created.PhysicalID, "Deny")}
	if _, err := inline.Update(denied, policy); err == nil {
		t.Fatal("private policy ownership bypassed current IAM update deny")
	}
	cfnSNSCheckPolicy(t, ctx, commands, created.PhysicalID, cfnSNSPublishPolicy(created.PhysicalID, "Allow"))
	m.SessionPolicies = []string{`{"Statement":[{"Effect":"Allow","Action":"sns:*","Resource":"*"},{"Effect":"Deny","Action":"sns:GetTopicAttributes","Resource":"*"}]}`}
	denied = awsctx.WithMetadata(ctx, m)
	if recovered, err := h.RecoverCreation(denied, r); err == nil || recovered.PhysicalID != "" {
		t.Fatalf("topic recovery bypassed current read IAM: %+v %v", recovered, err)
	}
	if recovered, err := inline.RecoverCreation(denied, policy); err == nil || recovered.PhysicalID != "" {
		t.Fatalf("policy recovery bypassed current read IAM: %+v %v", recovered, err)
	}
}

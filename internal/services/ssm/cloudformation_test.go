package ssm

import (
	"context"
	"testing"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
)

// literalBinder stores documents without principal resolution; principal
// binding is not the behavior under test.
type literalBinder struct{}

func (literalBinder) BindResourcePolicy(_ context.Context, document string, _ authorization.ResourcePolicyOptions) (authorization.BoundPolicy, error) {
	return authorization.BoundPolicy{Document: document}, nil
}
func (literalBinder) RenderResourcePolicy(_ context.Context, bound authorization.BoundPolicy) (string, error) {
	return bound.Document, nil
}

func TestCloudFormationResourcePolicyClaims(t *testing.T) {
	s := New(Config{Clock: clock.Real{}, PolicyBinder: literalBinder{}})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	if _, err := runCommand(s, ctx, "PutParameter", &api.PutParameterRequest{Name: new(api.PSParameterName("/shared")), Value: new(api.PSParameterValue("v")), Type: new(api.ParameterType("String")), Tier: new(api.ParameterTier("Advanced"))}, s.putParameter); err != nil {
		t.Fatal(err)
	}
	arn := "arn:aws:ssm:us-east-1:123456789012:parameter/shared"
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"ssm:GetParameter","Resource":"` + arn + `"}]}`
	put := func(ctx context.Context, id, hash string) (*api.PutResourcePolicyResponse, error) {
		in := &api.PutResourcePolicyRequest{ResourceArn: new(api.ResourceArnString(arn)), Policy: new(api.Policy(document))}
		if id != "" {
			in.PolicyId, in.PolicyHash = new(api.PolicyId(id)), new(api.PolicyHash(hash))
		}
		out, err := runCommand(s, ctx, "PutResourcePolicy", in, s.putResourcePolicy)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	// A native policy with an identical document is never adopted.
	native, err := put(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	mine := WithCloudFormationResourcePolicyOwner(ctx, "stack-resource:token-one")
	first, err := put(mine, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if value(first.PolicyId) == value(native.PolicyId) {
		t.Fatal("a claimed create adopted a native policy with the same document")
	}
	retried, err := put(mine, "", "")
	if err != nil || value(retried.PolicyId) != value(first.PolicyId) {
		t.Fatalf("exact-token retry must recover its policy: %+v %v", retried, err)
	}
	listed, rejected := runCommand(s, mine, "GetResourcePolicies", &api.GetResourcePoliciesRequest{ResourceArn: new(api.ResourceArnString(arn))}, s.getResourcePolicies)
	if rejected != nil || len(listed.Policies) != 1 || value(listed.Policies[0].PolicyId) != value(first.PolicyId) {
		t.Fatalf("claimed reads must expose only the claimed policy: %+v %v", listed, rejected)
	}
	other := WithCloudFormationResourcePolicyOwner(ctx, "stack-resource:token-two")
	if _, err := put(other, value(native.PolicyId), value(native.PolicyHash)); err == nil {
		t.Fatal("a claim updated a policy it does not own")
	}
	_, rejected = runCommand(s, other, "DeleteResourcePolicy", &api.DeleteResourcePolicyRequest{ResourceArn: new(api.ResourceArnString(arn)), PolicyId: first.PolicyId, PolicyHash: first.PolicyHash}, s.deleteResourcePolicy)
	readTestError(t, rejected, "ResourcePolicyConflictException")
	// Public updates keep the creating incarnation's claim.
	if _, err := put(ctx, value(first.PolicyId), value(first.PolicyHash)); err != nil {
		t.Fatal(err)
	}
	if again, err := put(mine, "", ""); err != nil || value(again.PolicyId) != value(first.PolicyId) {
		t.Fatalf("public update dropped the incarnation claim: %+v %v", again, err)
	}
	all, rejected := runCommand(s, ctx, "GetResourcePolicies", &api.GetResourcePoliciesRequest{ResourceArn: new(api.ResourceArnString(arn))}, s.getResourcePolicies)
	if rejected != nil || len(all.Policies) != 2 {
		t.Fatalf("unclaimed reads list every policy: %+v %v", all, rejected)
	}
}

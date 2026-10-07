package integrations

import (
	"context"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	iamowner "stackd/internal/services/iam"
	"testing"
)

func cfnIAMOwnerFixture(t *testing.T) (context.Context, StepFunctionsCommands) {
	t.Helper()
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-2", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	owner := iamowner.New()
	t.Cleanup(func() { _ = owner.Close() })
	return ctx, NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"iam": owner})
}
func cfnIAMOwnerRequest(kind, logical string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{Type: "AWS::IAM::" + kind, StackID: "arn:aws:cloudformation:us-east-2:123456789012:stack/identities/native", StackName: "identities", LogicalID: logical, Token: logical + "-incarnation", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-2"}, Properties: p}
}

// Exercise actual credential issuance, not a mocked create response. Recovery
// must retain one credential, while public discovery never becomes a secret API.
func TestIAMAccessKeyRecoveryRetainsSecretAndRejectsForeignDelete(t *testing.T) {
	ctx, commands := cfnIAMOwnerFixture(t)
	if err := cfnComputeRun(ctx, commands, "iam", "CreateUser", map[string]any{"UserName": "credential-owner"}); err != nil {
		t.Fatal(err)
	}
	h := cfnIAMAccessKey{commands}
	r := cfnIAMOwnerRequest("AccessKey", "Key", cloudformation.Properties{"UserName": "credential-owner"})
	first, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := first.Attributes["SecretAccessKey"].(string)
	if secret == "" || second.PhysicalID != first.PhysicalID || second.Attributes["SecretAccessKey"] != secret {
		t.Fatal("credential recovery changed its native incarnation or secret")
	}
	keys, err := cfnComputeCall[api.ListAccessKeysOutput](ctx, commands, "iam", "ListAccessKeys", map[string]any{"UserName": "credential-owner"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.AccessKeyMetadata) != 1 {
		t.Fatal("recovery issued another credential")
	}
	r.PhysicalID = first.PhysicalID
	r.Previous = r.Properties
	r.Properties = cloudformation.Properties{"UserName": "credential-owner", "Status": "Inactive"}
	updated, err := h.Update(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Attributes["SecretAccessKey"] != secret {
		t.Fatal("status update lost the creation-only GetAtt secret")
	}
	model, err := h.Read(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := model["SecretAccessKey"]; exists {
		t.Fatal("public resource read disclosed credential material")
	}
	if model["Status"] != "Inactive" {
		t.Fatal("resource read echoed stale status")
	}
	foreign := r
	foreign.Token = "foreign-incarnation"
	if err := h.Delete(ctx, foreign); err == nil {
		t.Fatal("foreign incarnation deleted a credential")
	}
	recovery := r
	recovery.PhysicalID = ""
	if err := h.Delete(ctx, recovery); err != nil {
		t.Fatal(err)
	}
	keys, err = cfnComputeCall[api.ListAccessKeysOutput](ctx, commands, "iam", "ListAccessKeys", map[string]any{"UserName": "credential-owner"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.AccessKeyMetadata) != 0 {
		t.Fatal("rollback recovery left its credential behind")
	}
}

func TestIAMEmptyMembershipClaimsSurviveMoveAndCannotAdoptExternalGrant(t *testing.T) {
	ctx, commands := cfnIAMOwnerFixture(t)
	for _, group := range []string{"original-group", "destination-group"} {
		if err := cfnComputeRun(ctx, commands, "iam", "CreateGroup", map[string]any{"GroupName": group}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cfnComputeRun(ctx, commands, "iam", "CreateUser", map[string]any{"UserName": "external-member"}); err != nil {
		t.Fatal(err)
	}
	if err := cfnComputeRun(ctx, commands, "iam", "AddUserToGroup", map[string]any{"GroupName": "original-group", "UserName": "external-member"}); err != nil {
		t.Fatal(err)
	}
	h := cfnIAMUserToGroupAddition{commands}
	collision := cfnIAMOwnerRequest("UserToGroupAddition", "Collision", cloudformation.Properties{"GroupName": "original-group", "Users": []any{"external-member"}})
	failed, err := h.Create(ctx, collision)
	if err == nil {
		t.Fatal("create adopted an external membership")
	}
	collision.PhysicalID = failed.PhysicalID
	if err := h.Delete(ctx, collision); err != nil {
		t.Fatal(err)
	}
	group, err := cfnComputeCall[api.GetGroupOutput](ctx, commands, "iam", "GetGroup", map[string]any{"GroupName": "original-group"})
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Users) != 1 {
		t.Fatal("failed-create rollback removed an external membership")
	}
	r := cfnIAMOwnerRequest("UserToGroupAddition", "Empty", cloudformation.Properties{"GroupName": "original-group", "Users": []any{}})
	created, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = created.PhysicalID
	model, err := h.Read(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if model["GroupName"] != "original-group" {
		t.Fatal("empty membership claim was not persisted by its native owner")
	}
	r.Previous = r.Properties
	r.Properties = cloudformation.Properties{"GroupName": "destination-group", "Users": []any{}}
	moved, err := h.Update(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if moved.PhysicalID != created.PhysicalID {
		t.Fatal("in-place membership move replaced its aggregate identifier")
	}
	rows, err := h.List(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Properties["GroupName"] != "destination-group" {
		t.Fatal("membership move retained an obsolete native claim")
	}
	refreshed, err := h.Result(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := cfnComputeCall[api.GetGroupOutput](ctx, commands, "iam", "GetGroup", map[string]any{"GroupName": "destination-group"})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Attributes["Id"] != cfnComputeValue(destination.Group.GroupId) {
		t.Fatal("GetAtt Id was not refreshed from the actual destination group")
	}
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	group, err = cfnComputeCall[api.GetGroupOutput](ctx, commands, "iam", "GetGroup", map[string]any{"GroupName": "original-group"})
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Users) != 1 {
		t.Fatal("membership lifecycle destroyed an unrelated grant")
	}
}

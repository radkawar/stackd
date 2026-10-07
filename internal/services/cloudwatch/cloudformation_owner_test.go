package cloudwatch

import (
	"context"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func TestCloudFormationDashboardNativeUpdateAndRecreation(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	call := func(ctx context.Context, action string, input any) (any, *awswire.Error) {
		model, _ := awscatalog.LookupService("cloudwatch")
		operation, _ := model.Operation(action)
		return service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
	}
	success := func(ctx context.Context, action string, input any) any {
		t.Helper()
		out, wire := call(ctx, action, input)
		if wire != nil {
			t.Fatalf("%s: %v", action, wire)
		}
		return out
	}
	expected := map[string]string{"stackd:cloudformation:stack-id": "stack", "stackd:cloudformation:logical-id": "Dashboard", "stackd:cloudformation:incarnation": "first"}
	tags := api.TagList{}
	for key, value := range expected {
		tags = append(tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(value))})
	}
	name := new(api.DashboardName("owned-dashboard"))
	initial := &api.PutDashboardInput{DashboardName: name, DashboardBody: new(api.DashboardBody(`{"widgets":[]}`)), Tags: tags}
	success(WithCloudFormationOwner(ctx, "first", true), "PutDashboard", initial)
	changed := &api.PutDashboardInput{DashboardName: name, DashboardBody: new(api.DashboardBody(`{"widgets":[{"type":"text","x":0,"y":0,"width":6,"height":2,"properties":{"markdown":"native-change"}}]}`))}
	success(ctx, "PutDashboard", changed)
	_ = service.Close()
	service = New(Config{Repository: repository})
	owned := WithCloudFormationOwner(ctx, "first", false)
	success(owned, "PutDashboard", changed)
	out := success(ctx, "GetDashboard", &api.GetDashboardInput{DashboardName: name}).(*api.GetDashboardOutput)
	if value(out.DashboardBody) != value(changed.DashboardBody) {
		t.Fatalf("native dashboard update was not retained: %s", value(out.DashboardBody))
	}
	if _, wire := call(WithCloudFormationOwner(ctx, "different-cc-creation", true), "PutDashboard", initial); wire == nil || wire.Code != "AccessDeniedException" {
		t.Fatalf("CloudControl create adopted an existing dashboard: %v", wire)
	}
	success(ctx, "DeleteDashboards", &api.DeleteDashboardsInput{DashboardNames: api.DashboardNames{"owned-dashboard"}})
	if _, wire := call(owned, "PutDashboard", changed); wire == nil || wire.Code != "ResourceNotFoundException" {
		t.Fatalf("CFN update recreated a missing dashboard: %v", wire)
	}
	success(ctx, "PutDashboard", initial)
	if _, wire := call(owned, "DeleteDashboards", &api.DeleteDashboardsInput{DashboardNames: api.DashboardNames{"owned-dashboard"}}); wire == nil || wire.Code != "AccessDeniedException" {
		t.Fatalf("stale CFN deleted a native recreation: %v", wire)
	}
	success(ctx, "GetDashboard", &api.GetDashboardInput{DashboardName: name})
}

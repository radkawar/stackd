package integrations

import (
	"context"
	"strings"
	"testing"

	"stackd/internal/awsapi"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/signer"
)

func TestCloudControlSignerForeignARNDoesNotUseLocalNamesake(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	owner := signer.New(signer.Config{})
	h := cfnSignerProfile{commands: NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"signer": owner})}
	r := cloudformation.ResourceRequest{Type: "AWS::Signer::SigningProfile", StackID: "signer-stack", StackName: "signer", LogicalID: "Profile", Token: "original", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Properties: cloudformation.Properties{"ProfileName": "local_profile", "PlatformId": cfnSignerLambdaPlatform, "Tags": []any{map[string]any{"Key": "purpose", "Value": "original"}}}}
	created, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = created.PhysicalID
	r.CloudControl = true
	for _, tc := range []struct{ name, arn string }{
		{"partition", strings.Replace(created.PhysicalID, "arn:aws:", "arn:aws-cn:", 1)},
		{"account", strings.Replace(created.PhysicalID, "123456789012", "999999999999", 1)},
		{"region", strings.Replace(created.PhysicalID, "us-east-1", "us-west-2", 1)},
		{"service", strings.Replace(created.PhysicalID, ":signer:", ":lambda:", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			foreign := r
			foreign.PhysicalID = tc.arn
			if _, err := h.Read(ctx, foreign); err == nil {
				t.Fatal("foreign ARN read local profile")
			}
			foreign.Previous = r.Properties
			foreign.Properties = cloudformation.Properties{"ProfileName": "local_profile", "PlatformId": cfnSignerLambdaPlatform, "Tags": map[string]string{"purpose": "foreign"}}
			if _, err := h.Update(ctx, foreign); err == nil {
				t.Fatal("foreign ARN updated local profile")
			}
			if err := h.Delete(ctx, foreign); err == nil {
				t.Fatal("foreign ARN canceled local profile")
			}
			p, err := h.current(ctx, r)
			if err != nil {
				t.Fatal("local profile lost", err)
			}
			if cfnComputeValue(p.Status) != "Active" || cfnSignerTags(p.Tags)["purpose"] != "original" {
				t.Fatalf("local profile changed: %+v", p)
			}
		})
	}
}

func TestSignerCreateReplayRetainsCanceledIncarnation(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	owner := signer.New(signer.Config{})
	h := cfnSignerProfile{commands: NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"signer": owner})}
	r := cloudformation.ResourceRequest{Type: "AWS::Signer::SigningProfile", StackID: "signer-stack", StackName: "signer", LogicalID: "Profile", Token: "original", Properties: cloudformation.Properties{"ProfileName": "replay_profile", "PlatformId": cfnSignerLambdaPlatform}}
	created, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = created.PhysicalID
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	replay, err := h.Create(ctx, r)
	if err == nil || replay.PhysicalID != created.PhysicalID {
		t.Fatalf("canceled incarnation lost: %+v %v", replay, err)
	}
}

type cfnSignerTestExecutor func(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)

func (f cfnSignerTestExecutor) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	return f(ctx, r)
}

func TestSignerCreateFailureRetainsNativeAdmission(t *testing.T) {
	for _, lostPut := range []bool{false, true} {
		t.Run(map[bool]string{false: "read_failure", true: "lost_put_reply"}[lostPut], func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			owner := signer.New(signer.Config{})
			admitted := false
			executor := cfnSignerTestExecutor(func(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
				if admitted && !lostPut && r.Operation.Name == "GetSigningProfile" {
					return nil, &awswire.Error{Code: "AccessDeniedException", Message: "post-admission read denied", StatusCode: 403}
				}
				out, err := owner.ExecuteCommand(ctx, r)
				if err == nil && r.Operation.Name == "PutSigningProfile" {
					admitted = true
					if lostPut {
						return nil, &awswire.Error{Code: "RequestTimeout", Message: "native admission reply lost", StatusCode: 504}
					}
				}
				return out, err
			})
			h := cfnSignerProfile{commands: NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"signer": executor})}
			r := cloudformation.ResourceRequest{Type: "AWS::Signer::SigningProfile", StackID: "signer-stack", StackName: "signer", LogicalID: "Profile", Token: "original", Properties: cloudformation.Properties{"ProfileName": "admitted_profile", "PlatformId": cfnSignerLambdaPlatform}}
			result, err := h.Create(ctx, r)
			if err == nil || result.PhysicalID != "arn:aws:signer:us-east-1:123456789012:/signing-profiles/admitted_profile" {
				t.Fatalf("native admission lost: %+v %v", result, err)
			}
			r.PhysicalID = result.PhysicalID
			native := cfnSignerProfile{commands: NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"signer": owner})}
			if err := native.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := native.Read(ctx, r); err == nil {
				t.Fatal("rollback failed to cancel admitted profile")
			}
		})
	}
}

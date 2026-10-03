package iam_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

func TestSimulateCustomPolicyAggregateAndBoundary(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	denyPrivate := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/private/*"}}`
	out, err := c.SimulateCustomPolicy(ctx, &sdkiam.SimulateCustomPolicyInput{
		ActionNames: []string{"s3:GetObject", "s3:PutObject"}, PolicyInputList: []string{allowRead, denyPrivate},
		ResourceArns: []string{"arn:aws:s3:::example/public/file", "arn:aws:s3:::example/private/file"}, MaxItems: aws.Int32(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.IsTruncated || len(out.EvaluationResults) != 1 {
		t.Fatalf("simulation pagination: %+v", out)
	}
	get := out.EvaluationResults[0]
	if aws.ToString(get.EvalActionName) != "s3:GetObject" || get.EvalDecision != types.PolicyEvaluationDecisionTypeExplicitDeny || len(get.ResourceSpecificResults) != 2 {
		t.Fatalf("aggregate decision: %+v", get)
	}
	if get.ResourceSpecificResults[0].EvalResourceDecision != types.PolicyEvaluationDecisionTypeAllowed || get.ResourceSpecificResults[1].EvalResourceDecision != types.PolicyEvaluationDecisionTypeExplicitDeny {
		t.Fatalf("resource decisions: %+v", get.ResourceSpecificResults)
	}
	boundary := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/public/*"}}`
	out, err = c.SimulateCustomPolicy(ctx, &sdkiam.SimulateCustomPolicyInput{
		ActionNames: []string{"s3:GetObject"}, PolicyInputList: []string{allowRead}, PermissionsBoundaryPolicyInputList: []string{boundary},
		ResourceArns: []string{"arn:aws:s3:::example/public/file", "arn:aws:s3:::example/private/file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	get = out.EvaluationResults[0]
	if get.EvalDecision != types.PolicyEvaluationDecisionTypeImplicitDeny || get.PermissionsBoundaryDecisionDetail == nil || get.PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary {
		t.Fatalf("boundary aggregate: %+v", get)
	}
	if !get.ResourceSpecificResults[0].PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary || get.ResourceSpecificResults[1].PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary {
		t.Fatalf("boundary resources: %+v", get.ResourceSpecificResults)
	}
}

func TestSimulateCustomPolicyContextAndActionValidation(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	conditional := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`
	input := &sdkiam.SimulateCustomPolicyInput{ActionNames: []string{"s3:GetObject"}, PolicyInputList: []string{conditional}}
	out, err := c.SimulateCustomPolicy(ctx, input)
	if err != nil || out.EvaluationResults[0].EvalDecision != types.PolicyEvaluationDecisionTypeImplicitDeny {
		t.Fatalf("missing context: %+v, %v", out, err)
	}
	input.ContextEntries = []types.ContextEntry{{ContextKeyName: aws.String("aws:MultiFactorAuthPresent"), ContextKeyType: types.ContextKeyTypeEnumBoolean, ContextKeyValues: []string{"true"}}}
	out, err = c.SimulateCustomPolicy(ctx, input)
	if err != nil || out.EvaluationResults[0].EvalDecision != types.PolicyEvaluationDecisionTypeAllowed {
		t.Fatalf("provided context: %+v, %v", out, err)
	}
	input.ResourcePolicy = aws.String(trustEC2)
	_, err = c.SimulateCustomPolicy(ctx, input)
	requireCode(t, err, "InvalidInput")
	input.ResourcePolicy = nil
	input.ActionNames = []string{"s3:*"}
	out, err = c.SimulateCustomPolicy(ctx, input)
	if err != nil || out.EvaluationResults[0].EvalDecision != types.PolicyEvaluationDecisionTypeImplicitDeny {
		t.Fatalf("literal wildcard action: %+v %v", out, err)
	}
	input.ActionNames = []string{"s3:GetObject"}
	input.PolicyInputList = []string{`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/${aws:username}/*"}}`}
	input.ResourceArns = []string{"arn:aws:s3:::example/alice/file"}
	input.ContextEntries = nil
	out, err = c.SimulateCustomPolicy(ctx, input)
	if err != nil || out.EvaluationResults[0].EvalDecision != types.PolicyEvaluationDecisionTypeImplicitDeny {
		t.Fatalf("missing policy variable: %+v, %v", out, err)
	}
	input.ContextEntries = []types.ContextEntry{{ContextKeyName: aws.String("aws:username"), ContextKeyType: types.ContextKeyTypeEnumString, ContextKeyValues: []string{"alice"}}}
	out, err = c.SimulateCustomPolicy(ctx, input)
	if err != nil || out.EvaluationResults[0].EvalDecision != types.PolicyEvaluationDecisionTypeAllowed {
		t.Fatalf("resolved policy variable: %+v, %v", out, err)
	}
}

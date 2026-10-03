package authorization_test

import (
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func TestNonNullContextCannotInventVerifiedClaims(t *testing.T) {
	const grant = `{"Statement":{"Effect":"Allow","Action":"lambda:RemovePermission","Resource":"*"}}`
	evaluator := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: grant}}}}, nil)
	ctx := awsctx.WithMetadata(t.Context(), metadata(false))
	for _, key := range []string{"aws:PrincipalARN", "aws:PrincipalTag/missing", "aws:SourceIdentity", "aws:MultiFactorAuthPresent", "aws:SecureTransport", "aws:PrincipalServiceNamesList", "ec2:SourceInstanceARN", "idp.example:sub"} {
		t.Run(key, func(t *testing.T) {
			request := authorization.Request{Action: "lambda:RemovePermission", ResourceARN: "*", Context: map[string][]string{key: {}}}
			if err := evaluator.Authorize(ctx, request); err == nil {
				t.Fatal("service-owned empty set fabricated a verified identity claim")
			}
		})
	}
}

func TestNonNullServiceContextPreservesCurrentConditionDenials(t *testing.T) {
	const grant = `{"Statement":{"Effect":"Allow","Action":"lambda:RemovePermission","Resource":"*","Condition":{"Null":{"lambda:Principal":"false"},"ForAllValues:StringEquals":{"lambda:Principal":["arn:aws:iam::123456789012:root","s3.amazonaws.com"]}}}}`
	evaluator := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: grant}}}}, nil)
	ctx := awsctx.WithMetadata(t.Context(), metadata(false))
	request := authorization.Request{Action: "lambda:RemovePermission", ResourceARN: "*"}
	if err := evaluator.Authorize(ctx, request); err == nil {
		t.Fatal("absent principal context bypassed the Null guard")
	}
	request.Context = map[string][]string{"lambda:Principal": nil}
	if err := evaluator.Authorize(ctx, request); err == nil {
		t.Fatal("nil principal context bypassed the Null guard")
	}
	request.Context = map[string][]string{"LaMbDa:PrInCiPaL": {}}
	if err := evaluator.Authorize(ctx, request); err != nil {
		t.Fatalf("authoritative non-null empty set did not satisfy the captured set/presence contract: %v", err)
	}
	request.Context = map[string][]string{"lambda:Principal": {"sns.amazonaws.com"}}
	if err := evaluator.Authorize(ctx, request); err == nil {
		t.Fatal("present-empty support bypassed a mismatching principal value")
	}
}

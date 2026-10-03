package authorization_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func TestNativeFederatedResourceAdmissionDoesNotBecomeRoleTrust(t *testing.T) {
	for _, filename := range []string{"resource_policy_federation_native.json", "resource_policy_federation_shapes_native.json"} {
		data, err := os.ReadFile("../../testdata/lambda/" + filename)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Account string `json:"account"`
			Cases   []struct {
				Label     string                               `json:"label"`
				Operation string                               `json:"operation"`
				Request   struct{ Policy, ResourceArn string } `json:"request"`
				Error     struct{ Code string }                `json:"error"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		ctx := awsctx.WithMetadata(t.Context(), metadata(false))
		for _, observation := range fixture.Cases {
			if observation.Operation != "put_resource_policy" || (!strings.HasPrefix(observation.Label, "federated-") && observation.Label != "principal-empty-object") {
				continue
			}
			t.Run(observation.Label, func(t *testing.T) {
				document := strings.ReplaceAll(observation.Request.Policy, fixture.Account, account)
				resource := strings.ReplaceAll(observation.Request.ResourceArn, fixture.Account, account)
				evaluator := authorization.New(identitySource{}, nil)
				bound, err := evaluator.BindResourcePolicy(ctx, document, authorization.ResourcePolicyOptions{AllowFederatedPrincipals: true})
				if observation.Error.Code != "" {
					if !errors.Is(err, policy.ErrInvalidPolicy) {
						t.Fatalf("native-rejected principal shape admitted: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := evaluator.BindResourcePolicy(ctx, document, authorization.ResourcePolicyOptions{}); !errors.Is(err, authorization.ErrInvalidPrincipal) {
					t.Fatalf("default service admission changed: %v", err)
				}
				if err := authorization.ValidateResourcePolicy([]byte(document)); err == nil {
					t.Fatal("default validation admitted a federated resource principal")
				}
				request := authorization.Request{Action: "lambda:InvokeFunction", ResourceARN: resource, ResourcePolicies: []authorization.BoundPolicy{bound}}
				if err := evaluator.Authorize(ctx, request); err == nil {
					t.Fatal("federated selector granted permissions to AWS credentials")
				}
				evaluator = authorization.New(identitySource{set: authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Statement":{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}}`}}}}, nil)
				if err := evaluator.Authorize(ctx, request); err != nil {
					t.Fatalf("opaque selector invalidated an independent identity grant or became role trust: %v", err)
				}
			})
		}
	}
}

func TestFederatedResourceOptInPreservesTrustAndAWSPrincipalAdmission(t *testing.T) {
	evaluator := authorization.New(identitySource{}, nil)
	ctx := awsctx.WithMetadata(t.Context(), metadata(false))
	for _, principal := range []string{"*", "not a principal", "issuer.stackd.invalid", "cognito-identity.amazonaws.com"} {
		encoded, err := json.Marshal(principal)
		if err != nil {
			t.Fatal(err)
		}
		trust := `{"Statement":{"Effect":"Allow","Principal":{"Federated":` + string(encoded) + `},"Action":"sts:AssumeRoleWithWebIdentity"}}`
		if _, err := evaluator.BindTrustPolicy(ctx, trust); err == nil {
			t.Fatalf("trust provider admission bypassed for %q", principal)
		}
	}
	mixed := `{"Statement":{"Effect":"Allow","Principal":{"Federated":"issuer.stackd.invalid","AWS":"` + userARN + `"},"Action":"lambda:InvokeFunction","Resource":"*"}}`
	if _, err := evaluator.BindResourcePolicy(ctx, mixed, authorization.ResourcePolicyOptions{AllowFederatedPrincipals: true}); !errors.Is(err, authorization.ErrInvalidPrincipal) {
		t.Fatalf("federated admission bypassed current IAM principal binding: %v", err)
	}
}

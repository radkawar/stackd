package organizations_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestOrganizationsResourcePolicyReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/iam/organizations_resource_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			client := organizationsInputClient(t, endpoint)
			createOrg(t, client)
			member := createAccount(t, client, "delegated")
			org, err := client.DescribeOrganization(t.Context(), &sdk.DescribeOrganizationInput{})
			if err != nil {
				t.Fatal(err)
			}
			target, err := client.CreatePolicy(t.Context(), &sdk.CreatePolicyInput{Name: aws.String("OWNED_NAME"), Description: aws.String("Owned delegation probe"), Type: types.PolicyTypeServiceControlPolicy, Content: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			replacements := strings.NewReplacer("RESOURCE_POLICY_ID", "CAPTURED_RESOURCE", "222222222222", member, "ORGANIZATION_ID", *org.Organization.Id, "POLICY_ID", *target.Policy.PolicySummary.Id)
			type observation struct {
				Case, Action, Code string
				Status             int
				Input              sdk.PutResourcePolicyInput
				Document           json.RawMessage
				Output             struct {
					ResourcePolicy *types.ResourcePolicy
					Tags           []types.Tag
					Reason         string
				}
			}
			var fixture struct {
				Initial               string
				Lifecycle, Validation []observation
			}
			if err := json.Unmarshal([]byte(replacements.Replace(string(raw))), &fixture); err != nil {
				t.Fatal(err)
			}
			_, err = client.DescribeResourcePolicy(t.Context(), &sdk.DescribeResourcePolicyInput{})
			requireCode(t, err, fixture.Initial)
			checkError := func(t *testing.T, err error, row observation) {
				t.Helper()
				if row.Code == "Success" {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				requireCode(t, err, row.Code)
				var response *smithyhttp.ResponseError
				if !errors.As(err, &response) || response.HTTPStatusCode() != row.Status {
					t.Fatalf("status: %v, want %d", err, row.Status)
				}
				if row.Output.Reason != "" {
					var invalid *types.InvalidInputException
					var constraint *types.ConstraintViolationException
					reason := ""
					if errors.As(err, &invalid) {
						reason = string(invalid.Reason)
					}
					if errors.As(err, &constraint) {
						reason = string(constraint.Reason)
					}
					if reason != row.Output.Reason {
						t.Fatalf("reason = %q, want %q", reason, row.Output.Reason)
					}
				}
			}
			var rpID string
			checkPolicy := func(t *testing.T, got, want *types.ResourcePolicy) {
				t.Helper()
				if got == nil || got.ResourcePolicySummary == nil || got.Content == nil {
					t.Fatalf("missing resource policy: %+v", got)
				}
				summary := got.ResourcePolicySummary
				if rpID == "" {
					rpID = aws.ToString(summary.Id)
				}
				if !strings.HasPrefix(rpID, "rp-") || aws.ToString(summary.Id) != rpID {
					t.Fatalf("resource policy identity changed: %+v", summary)
				}
				expectedARN := strings.ReplaceAll(aws.ToString(want.ResourcePolicySummary.Arn), "CAPTURED_RESOURCE", rpID)
				if aws.ToString(summary.Arn) != expectedARN {
					t.Fatalf("ARN = %q, want %q", aws.ToString(summary.Arn), expectedARN)
				}
				var a, b any
				if err := json.Unmarshal([]byte(*got.Content), &a); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(*want.Content), &b); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(a, b) {
					t.Fatalf("stored policy = %s, want %s", *got.Content, *want.Content)
				}
			}
			for i, row := range fixture.Lifecycle {
				t.Run(fmt.Sprintf("lifecycle/%02d/%s", i, row.Action), func(t *testing.T) {
					var got *types.ResourcePolicy
					switch row.Action {
					case "PutResourcePolicy":
						out, callErr := client.PutResourcePolicy(t.Context(), &row.Input)
						err = callErr
						if out != nil {
							got = out.ResourcePolicy
						}
					case "DescribeResourcePolicy":
						out, callErr := client.DescribeResourcePolicy(t.Context(), &sdk.DescribeResourcePolicyInput{})
						err = callErr
						if out != nil {
							got = out.ResourcePolicy
						}
					case "DeleteResourcePolicy":
						_, err = client.DeleteResourcePolicy(t.Context(), &sdk.DeleteResourcePolicyInput{})
					case "ListTagsForResource":
						out, callErr := client.ListTagsForResource(t.Context(), &sdk.ListTagsForResourceInput{ResourceId: &rpID})
						err = callErr
						if out != nil && !reflect.DeepEqual(out.Tags, row.Output.Tags) {
							t.Fatalf("tags = %+v, want %+v", out.Tags, row.Output.Tags)
						}
					default:
						t.Fatalf("unhandled capture %s", row.Action)
					}
					checkError(t, err, row)
					if got != nil {
						checkPolicy(t, got, row.Output.ResourcePolicy)
					}
				})
			}
			rpID = ""
			var current *types.ResourcePolicy
			for _, row := range fixture.Validation {
				t.Run("validation/"+row.Case, func(t *testing.T) {
					out, err := client.PutResourcePolicy(t.Context(), &sdk.PutResourcePolicyInput{Content: aws.String(string(row.Document))})
					checkError(t, err, row)
					if err == nil {
						checkPolicy(t, out.ResourcePolicy, row.Output.ResourcePolicy)
						current = out.ResourcePolicy
					}
					stored, err := client.DescribeResourcePolicy(t.Context(), &sdk.DescribeResourcePolicyInput{})
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(stored.ResourcePolicy, current) {
						t.Fatal("rejected update changed delegation state")
					}
				})
			}
		})
	}
}

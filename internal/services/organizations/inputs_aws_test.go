package organizations_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awscatalog"
	"stackd/internal/gateway"
)

func TestOrganizationsInputsReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/iam/organizations_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Action                          string
			Input                           map[string]json.RawMessage
			Code, Reason, Name, Description string
			Status                          int
			Tags                            []types.Tag
			UnitCount                       int `json:"unit_count"`
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			client := organizationsInputClient(t, endpoint)
			root := createOrg(t, client)
			unit, err := client.CreateOrganizationalUnit(t.Context(), &sdk.CreateOrganizationalUnitInput{ParentId: &root, Name: aws.String("OWNED_NAME")})
			if err != nil {
				t.Fatal(err)
			}
			id := unit.OrganizationalUnit.Id
			policy, err := client.CreatePolicy(t.Context(), &sdk.CreatePolicyInput{Name: aws.String("OWNED_NAME"), Description: aws.String("initial"),
				Type: types.PolicyTypeServiceControlPolicy, Content: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			policyID := policy.Policy.PolicySummary.Id
			for i, row := range fixture.Observations {
				t.Run(fmt.Sprintf("%02d/%s", i+1, row.Action), func(t *testing.T) {
					parameters := map[string]any{}
					switch row.Action {
					case "UpdateOrganizationalUnit":
						parameters["OrganizationalUnitId"] = *id
					case "UpdatePolicy":
						parameters["PolicyId"] = *policyID
					case "TagResource", "UntagResource":
						parameters["ResourceId"] = *id
					case "ListOrganizationalUnitsForParent":
						parameters["ParentId"] = *id
					default:
						t.Fatalf("unknown capture action %q", row.Action)
					}
					for k, v := range row.Input {
						parameters[k] = v
					}
					option := func(o *sdk.Options) { o.APIOptions = append(o.APIOptions, organizationsJSONInput(t, parameters)) }
					var callErr error
					var units *sdk.ListOrganizationalUnitsForParentOutput
					switch row.Action {
					case "UpdateOrganizationalUnit":
						_, callErr = client.UpdateOrganizationalUnit(t.Context(), &sdk.UpdateOrganizationalUnitInput{OrganizationalUnitId: id}, option)
					case "UpdatePolicy":
						_, callErr = client.UpdatePolicy(t.Context(), &sdk.UpdatePolicyInput{PolicyId: policyID}, option)
					case "TagResource":
						_, callErr = client.TagResource(t.Context(), &sdk.TagResourceInput{ResourceId: id, Tags: []types.Tag{}}, option)
					case "UntagResource":
						_, callErr = client.UntagResource(t.Context(), &sdk.UntagResourceInput{ResourceId: id, TagKeys: []string{}}, option)
					case "ListOrganizationalUnitsForParent":
						units, callErr = client.ListOrganizationalUnitsForParent(t.Context(), &sdk.ListOrganizationalUnitsForParentInput{ParentId: id}, option)
					}
					if row.Code == "Success" {
						if callErr != nil {
							t.Fatal(callErr)
						}
					} else {
						requireCode(t, callErr, row.Code)
						var invalid *types.InvalidInputException
						if !errors.As(callErr, &invalid) || string(invalid.Reason) != row.Reason {
							t.Fatalf("error = %v, want Reason %q", callErr, row.Reason)
						}
						var response *smithyhttp.ResponseError
						if !errors.As(callErr, &response) || response.HTTPStatusCode() != row.Status {
							t.Fatalf("error = %v, want status %d", callErr, row.Status)
						}
					}
					switch row.Action {
					case "UpdateOrganizationalUnit":
						got, err := client.DescribeOrganizationalUnit(t.Context(), &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: id})
						if err != nil {
							t.Fatal(err)
						}
						if aws.ToString(got.OrganizationalUnit.Name) != row.Name {
							t.Fatalf("stored name = %q, want %q", aws.ToString(got.OrganizationalUnit.Name), row.Name)
						}
					case "UpdatePolicy":
						got, err := client.DescribePolicy(t.Context(), &sdk.DescribePolicyInput{PolicyId: policyID})
						if err != nil {
							t.Fatal(err)
						}
						summary := got.Policy.PolicySummary
						if aws.ToString(summary.Name) != row.Name || aws.ToString(summary.Description) != row.Description {
							t.Fatalf("stored policy name/description = %q/%q, want %q/%q", aws.ToString(summary.Name), aws.ToString(summary.Description), row.Name, row.Description)
						}
					case "TagResource", "UntagResource":
						got, err := client.ListTagsForResource(t.Context(), &sdk.ListTagsForResourceInput{ResourceId: id})
						if err != nil {
							t.Fatal(err)
						}
						slices.SortFunc(got.Tags, func(a, b types.Tag) int { return strings.Compare(aws.ToString(a.Key), aws.ToString(b.Key)) })
						if !reflect.DeepEqual(got.Tags, row.Tags) {
							t.Fatalf("stored tags = %#v, want %#v", got.Tags, row.Tags)
						}
					case "ListOrganizationalUnitsForParent":
						if units != nil && (len(units.OrganizationalUnits) != row.UnitCount || units.NextToken != nil) {
							t.Fatalf("page = %#v, want %d units and no token", units, row.UnitCount)
						}
					}
				})
			}
		})
	}
}

// Keep SDK operation selection, signing and output/error decoding while replaying
// nulls and malformed inputs that client-side validation would otherwise reject.
func organizationsJSONInput(t *testing.T, value map[string]any) func(*middleware.Stack) error {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return func(stack *middleware.Stack) error {
		return stack.Build.Add(middleware.BuildMiddlewareFunc("OrganizationsCaptureInput", func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
			request := in.Request.(*smithyhttp.Request)
			request, err := request.SetStream(bytes.NewReader(body))
			if err != nil {
				return middleware.BuildOutput{}, middleware.Metadata{}, err
			}
			request.ContentLength = int64(len(body))
			in.Request = request
			return next.HandleBuild(ctx, in)
		}), middleware.Before)
	}
}

func organizationsInputClient(t *testing.T, endpoint string) *sdk.Client {
	t.Helper()
	service := organizationsOnly(nil)
	var client *sdk.Client
	if endpoint == "standalone" {
		client = fixedClient(t, service, orgRoot(managementID, "aws"))
	} else {
		t.Cleanup(func() { _ = service.Close() })
		model, _ := awscatalog.LookupService("organizations")
		registry := &gateway.Registry{}
		if err := registry.Register(gateway.Service{Name: "organizations", SigningName: "organizations", Protocol: gateway.JSON11,
			TargetPrefix: "AWSOrganizationsV20161128", Provider: service, Model: &model, Decode: api.DecodeRequest}); err != nil {
			t.Fatal(err)
		}
		handler, err := gateway.New(registry, gateway.Config{AccountID: managementID})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		client = sdk.New(sdk.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL),
			Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	}

	return client
}

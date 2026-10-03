package organizations_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

func TestEffectivePolicyWireAWS(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/iam/organizations_effective_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case   string
			Input  map[string]any
			Output struct{ Reason string }
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			client := organizationsInputClient(t, endpoint)
			for _, row := range capture.Observations {
				if row.Case != "missing-kind" && !strings.HasPrefix(row.Case, "invalid-kind-") {
					continue
				}
				t.Run(row.Case, func(t *testing.T) {
					_, err := client.DescribeEffectivePolicy(t.Context(), &sdk.DescribeEffectivePolicyInput{PolicyType: types.EffectivePolicyTypeTagPolicy}, func(o *sdk.Options) { o.APIOptions = append(o.APIOptions, organizationsJSONInput(t, row.Input)) })
					var invalid *types.InvalidInputException
					if !errors.As(err, &invalid) || string(invalid.Reason) != row.Output.Reason {
						t.Fatalf("input error = %v; want reason %s", err, row.Output.Reason)
					}
				})
			}
		})
	}
}

func TestEffectivePolicyValidationWireAWS(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/iam/organizations_policy_validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case, Action, Code string
			Input              map[string]any
			Output             struct{ Reason string }
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			client := organizationsInputClient(t, endpoint)
			for _, row := range capture.Observations {
				if row.Code != "InvalidInputException" || row.Case == "bad-token" || row.Case == "empty-token" {
					continue
				}
				t.Run(row.Case, func(t *testing.T) {
					_, err := client.ListEffectivePolicyValidationErrors(t.Context(), &sdk.ListEffectivePolicyValidationErrorsInput{AccountId: new("111111111111"), PolicyType: types.EffectivePolicyTypeTagPolicy}, func(o *sdk.Options) { o.APIOptions = append(o.APIOptions, organizationsJSONInput(t, row.Input)) })
					var invalid *types.InvalidInputException
					if !errors.As(err, &invalid) || string(invalid.Reason) != row.Output.Reason {
						t.Fatalf("wire error = %v; want %s", err, row.Output.Reason)
					}
				})
			}
		})
	}
}

package stackd_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func TestAPIGatewayNativeHTTPLogging(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real Gateway logging runtimes")
	}
	var fixture, settings gatewayLoggingFixture
	awsReadFixture(t, "apigateway/http_logs.json", &fixture)
	awsReadFixture(t, "apigateway/http_log_settings.json", &settings)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newGatewayLoggingReplay(t, fixture, backend)
			for _, row := range fixture.Observations {
				if strings.HasPrefix(row.Label, "inventory-") || strings.Contains(row.Label, "ready-") || row.Operation == "CreateFunction" && row.Result.Code != "Success" {
					continue
				}
				if row.Service == "logs" && row.Operation != "CreateLogGroup" {
					continue
				}
				r.call(row)
				if row.Label == "get-full-format" {
					break
				}
			}
			account, err := apigateway.NewFromConfig(r.config(r.owner)).GetAccount(t.Context(), &apigateway.GetAccountInput{})
			if err != nil || aws.ToString(account.CloudwatchRoleArn) != "" {
				t.Fatalf("HTTP delivery required or changed regional role: %v %v", account, err)
			}
			group := fixture.Owned["access_groups"].([]any)[0].(map[string]any)["name"].(string)
			r.httpDeliveryPolicy(group)
			// Reopen enabled settings before the real client traffic, then prove
			// access IDs against both the response and Python's Runtime API ID.
			r.clients = r.reopen()
			r.call(r.row("get-full-format"))
			for index, row := range fixture.HTTP {
				if !strings.HasPrefix(row.Label, "full-") {
					continue
				}
				r.http(index)
				correlation := fixture.RequestCorrelations[row.Label]
				if row.Label != "full-unmatched" && len(correlation.AccessEventKeys) == 0 {
					t.Fatalf("%s lacks captured access evidence", row.Label)
				}
				for _, key := range correlation.LambdaEventKeys {
					r.application(fixture.LogEvents[key])
				}
				for _, key := range correlation.AccessEventKeys {
					r.access(group, fixture.LogEvents[key])
				}
				// Native unmatched404 has bounded absence, not a universal
				// prohibition on logging. No immediate absence assertion here.
			}
			// Fresh admission, denied CreateLogDelivery and missing groups were
			// exercised above using the native operator and assumed deny role.
			// The new native supplement supplies successful partial updates;
			// replay them on this same deployed, already exercised API.
			r.bindings[settings.Owned["http_api"].(string)] = r.bindings[fixture.Owned["http_api"].(string)]
			var nativeGroups []string
			for _, row := range settings.Observations {
				if row.Operation == "CreateLogGroup" {
					nativeGroups = append(nativeGroups, row.Input["logGroupName"].(string))
				}
			}
			for index, native := range nativeGroups {
				local := fixture.Owned["access_groups"].([]any)[index].(map[string]any)["name"].(string)
				r.bindings[native] = local
			}
			for _, row := range settings.Observations {
				if row.Operation != "UpdateStage" && row.Operation != "GetStage" && row.Operation != "DeleteAccessLogSettings" {
					continue
				}
				r.call(row)
				if row.Label == "read-after-delete" {
					r.retain([]string{group}, []gatewaySDKObservation{row})
				}
			}
			// Resource and worker/container cleanup also runs on fatal failures
			// through retainedCloud/newLambdaDockerStack's registered cleanup.
			for _, row := range fixture.Observations {
				if row.Service == "apigatewayv2" && (strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "absence-")) {
					r.call(row)
				}
			}
		})
	}
}

func (r *gatewayLoggingReplay) httpDeliveryPolicy(group string) {
	t := r.t
	t.Helper()
	// Compare the actual native resource-policy statement, not a handcrafted
	// permission echo. This is the policy that authorizes real subsequent writes.
	var expected map[string]any
	for _, row := range r.fixture.Observations {
		if row.Operation != "DescribeResourcePolicies" || row.Result.Code != "Success" {
			continue
		}
		encoded, err := json.Marshal(row.Result.Output)
		if err != nil {
			t.Fatal(err)
		}
		var native cloudwatchlogs.DescribeResourcePoliciesOutput
		awsDecodeJSON(t, encoded, &native)
		for _, policy := range native.ResourcePolicies {
			if strings.Contains(aws.ToString(policy.PolicyDocument), group) {
				awsDecodeJSON(t, []byte(aws.ToString(policy.PolicyDocument)), &expected)
				break
			}
		}
		if expected != nil {
			break
		}
	}
	if expected == nil {
		t.Fatal("native HTTP fixture lacks its activated delivery policy")
	}
	arn := "arn:aws:logs:" + r.fixture.Region + ":" + r.fixture.Account + ":log-group:" + group
	out, err := r.logs().DescribeResourcePolicies(t.Context(), &cloudwatchlogs.DescribeResourcePoliciesInput{ResourceArn: &arn, PolicyScope: "RESOURCE"})
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range out.ResourcePolicies {
		var got map[string]any
		awsDecodeJSON(t, []byte(aws.ToString(policy.PolicyDocument)), &got)
		if reflect.DeepEqual(got, expected) {
			return
		}
	}
	t.Fatalf("HTTP delivery policy does not match native permissions: got=%v native=%v", out.ResourcePolicies, expected)
}

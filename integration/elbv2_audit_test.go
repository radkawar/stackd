package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestELBv2NativeManagementAudit(t *testing.T) {
	var capture nativeControlAuditCapture
	awsReadFixture(t, "elbv2/management_audit.json", &capture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: capture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			config := func() aws.Config {
				return aws.Config{Region: capture.Region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1}
			}
			vpc, err := ec2.NewFromConfig(config()).CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: new("10.242.0.0/16")})
			if err != nil {
				t.Fatal(err)
			}
			bindings := map[string]string{}
			for _, call := range capture.Calls {
				if call.Operation == "CreateTargetGroup" {
					var input elasticloadbalancingv2.CreateTargetGroupInput
					awsDecodeJSON(t, call.Input, &input)
					bindings[aws.ToString(input.VpcId)] = aws.ToString(vpc.Vpc.VpcId)
				}
			}
			for _, call := range capture.Calls {
				if !t.Run(call.Label, func(t *testing.T) {
					output, callErr := awstest.CallSDK(t.Context(), elasticloadbalancingv2.NewFromConfig(config()), call.Operation, ec2AuditReplace(t, call.Input, bindings))
					if call.Code == "Success" {
						if callErr != nil {
							t.Fatal(callErr)
						}
					} else {
						assertAPIError(t, callErr, call.Code)
					}
					if created, ok := output.(*elasticloadbalancingv2.CreateTargetGroupOutput); ok && callErr == nil {
						var native elasticloadbalancingv2.CreateTargetGroupOutput
						awsDecodeJSON(t, call.Output, &native)
						bindings[aws.ToString(native.TargetGroups[0].TargetGroupArn)] = aws.ToString(created.TargetGroups[0].TargetGroupArn)
						native.TargetGroups[0].TargetGroupArn = created.TargetGroups[0].TargetGroupArn
						native.TargetGroups[0].VpcId = vpc.Vpc.VpcId
						if !reflect.DeepEqual(created.TargetGroups, native.TargetGroups) {
							t.Fatalf("SDK creation output differs from native: got %#v native %#v", created.TargetGroups, native.TargetGroups)
						}
					}
					for _, row := range capture.History.Events {
						if row.Event["requestID"] != call.RequestID {
							continue
						}
						body, err := json.Marshal(row.Event)
						if err != nil {
							t.Fatal(err)
						}
						var want map[string]any
						awsDecodeJSON(t, ec2AuditReplace(t, body, bindings), &want)
						got := auditLookupRecord(t, cloudtrail.NewFromConfig(config()), nativeAuditRequestID(t, output, callErr), call.Operation)
						want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
						// Attribute order is not an AWS contract; compare keyed values.
						for _, event := range []map[string]any{got, want} {
							if attributes, ok := awsFixtureField(event, "responseElements.attributes").([]any); ok {
								slices.SortFunc(attributes, func(a, b any) int {
									return strings.Compare(a.(map[string]any)["key"].(string), b.(map[string]any)["key"].(string))
								})
							}
						}
						assertNativeAuditEvent(t, got, want, "")
						if !reflect.DeepEqual(got["apiVersion"], want["apiVersion"]) {
							t.Fatalf("API version differs: got %v native %v", got["apiVersion"], want["apiVersion"])
						}
						return
					}
					t.Fatal("native audit outcome missing for exact request", call.RequestID)
				}) {
					return
				}
				if call.Operation == "CreateTargetGroup" {
					c = reopen()
				}
			}
		})
	}
}

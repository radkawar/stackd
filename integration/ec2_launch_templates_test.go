package stackd_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

// These fixtures are independent AWS control calls correlated to exact native
// request IDs. Replay the state transitions and their audit documents against
// both repositories, replacing the controller midway through the sequence.
func TestEC2LaunchTemplateNativeFixtures(t *testing.T) {
	for _, file := range []string{"launch_templates.json", "launch_template_edges.json", "launch_template_deletion.json"} {
		t.Run(file, func(t *testing.T) {
			var fixture struct {
				Account, Region string
				Calls           []struct {
					Label, Operation, Code string
					Input, Output          json.RawMessage
					RequestID              string    `json:"request_id"`
					StartedAt              time.Time `json:"started_at"`
				}
				CloudTrail struct {
					Events []struct{ Event map[string]any }
				}
			}
			awsReadFixture(t, "ec2/"+file, &fixture)
			events := map[string]map[string]any{}
			for _, row := range fixture.CloudTrail.Events {
				if id, ok := row.Event["requestID"].(string); ok {
					events[id] = row.Event
				}
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					source := clock.NewManual(fixture.Calls[0].StartedAt.Truncate(time.Second))
					clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source})
					bindings := map[string]string{"arn:aws:iam::" + fixture.Account + ":user/Delegated": "arn:aws:iam::" + fixture.Account + ":root"}
					for index, row := range fixture.Calls {
						if index == len(fixture.Calls)/2 {
							clients = reopen()
						}
						if row.StartedAt.Truncate(time.Second).After(source.Now()) {
							source.Advance(row.StartedAt.Truncate(time.Second).Sub(source.Now()))
						}
						apiMatched := false
						if !t.Run(row.Label, func(t *testing.T) {
							event := events[row.RequestID]
							if event == nil {
								t.Fatalf("missing exact native management event for request %s", row.RequestID)
							}
							input := ec2AuditReplace(t, row.Input, bindings)
							// Botocore supplied idempotency tokens were captured by CloudTrail, not
							// in the user's pre-serialization parameters. Replay that same token.
							var params map[string]any
							if err := json.Unmarshal(input, &params); err != nil {
								t.Fatal(err)
							}
							if envelope, ok := event["requestParameters"].(map[string]any); ok {
								if token, ok := envelope["clientToken"].(string); ok {
									params["ClientToken"] = token
								}
								if request, ok := envelope[row.Operation+"Request"].(map[string]any); ok {
									if token, ok := request["ClientToken"].(string); ok {
										params["ClientToken"] = token
									}
								}
							}
							input, _ = json.Marshal(params)
							client := ec2.New(ec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
							actual, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
							if row.Code != "Success" {
								assertAPIError(t, err, row.Code)
							} else {
								if err != nil {
									t.Fatal(err)
								}
								expected := reflect.New(reflect.TypeOf(actual).Elem()).Interface()
								if err := json.Unmarshal(row.Output, expected); err != nil {
									t.Fatal(err)
								}
								want, got := ec2NetworkDocument(t, expected), ec2NetworkDocument(t, actual)
								bindLaunchTemplateIdentities(t, want, got, bindings)
								normalizeLaunchTemplateSDK(want)
								normalizeLaunchTemplateSDK(got)
								encoded, _ := json.Marshal(want)
								if err := json.Unmarshal(ec2AuditReplace(t, encoded, bindings), &want); err != nil {
									t.Fatal(err)
								}
								if !reflect.DeepEqual(want, got) {
									a, _ := json.MarshalIndent(got, "", "  ")
									b, _ := json.MarshalIndent(want, "", "  ")
									t.Fatalf("SDK response\ngot %s\nwant %s", a, b)
								}
							}
							apiMatched = true
							requestID := nativeAuditRequestID(t, actual, err)
							trail := cloudtrail.New(cloudtrail.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
							observed := auditLookupRecord(t, trail, requestID, row.Operation)
							normalizeLaunchTemplateAuditTime(observed)
							assertEC2AuditCapture(t, source.Now(), event, observed, requestID, err, bindings, normalizeLaunchTemplateAuditTime)
						}) && !apiMatched {
							return
						}
					}
				})
			}
		})
	}
}
func bindLaunchTemplateIdentities(t *testing.T, want, got any, bindings map[string]string) {
	t.Helper()
	switch value := want.(type) {
	case map[string]any:
		actual, _ := got.(map[string]any)
		for k, v := range value {
			if k == "LaunchTemplateId" {
				before, ok := v.(string)
				after, present := actual[k].(string)
				if ok && present {
					if old, exists := bindings[before]; exists && old != after {
						t.Fatalf("template identity changed %s => %s (was %s)", before, after, old)
					}
					bindings[before] = after
				}
			} else {
				bindLaunchTemplateIdentities(t, v, actual[k], bindings)
			}
		}
	case []any:
		actual, _ := got.([]any)
		for i, v := range value {
			if i < len(actual) {
				bindLaunchTemplateIdentities(t, v, actual[i], bindings)
			}
		}
	}
}
func normalizeLaunchTemplateSDK(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "CreateTime" && child != nil {
				if stamp, ok := child.(string); ok && !strings.HasPrefix(stamp, "1970-") {
					v[key] = "<resource-time>"
				}
			}
			if key == "NextToken" && child != nil {
				v[key] = "<cursor>"
			}
			normalizeLaunchTemplateSDK(child)
		}
	case []any:
		for _, child := range v {
			normalizeLaunchTemplateSDK(child)
		}
	}
}
func normalizeLaunchTemplateAuditTime(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "createTime" {
				if stamp, ok := child.(string); ok && !strings.HasPrefix(stamp, "1970-") {
					v[key] = "<resource-time>"
				}
			}
			normalizeLaunchTemplateAuditTime(child)
		}
	case []any:
		for _, child := range v {
			normalizeLaunchTemplateAuditTime(child)
		}
	}
}

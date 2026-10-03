package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestAPIGatewaySelectedAuditDelivery(t *testing.T) {
	var fixture struct {
		Steps []struct {
			Selector, Service, Operation string
			Input                        json.RawMessage
			Selected                     bool
		}
	}
	awsReadFixture(t, "apigateway/audit_delivery_workflow.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
			var cloud *stackd.Stack
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				var server *httptest.Server
				cloud, server = startPublicCloud(t, config)
				return cloud, server
			})
			controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
			trailNativeProvision(t, clients, controls, s3NativeLoad(t, "s3", "owned_object_delivery"), false)
			queueURL := trailNativeQueue(t, clients)
			if _, err := eventDeliveryClient(clients, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{
				Name: aws.String("native-cloudtrail"), State: eventtypes.RuleStateEnabled,
				EventPattern: aws.String(`{"source":["aws.apigateway"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["apigateway.amazonaws.com"],"eventName":["CreateRestApi","CreateApi"]}}`),
			}); err != nil {
				t.Fatal(err)
			}
			trails := trailNativeClient(clients)
			if _, err := trails.StartLogging(t.Context(), &cloudtrail.StartLoggingInput{Name: aws.String(controls.Identity["trail_name"])}); err != nil {
				t.Fatal(err)
			}
			wanted := map[string]string{}
			for _, step := range fixture.Steps {
				if _, err := trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: aws.String(controls.Identity["trail_name"]), EventSelectors: []trailtypes.EventSelector{{IncludeManagementEvents: aws.Bool(true), ReadWriteType: trailtypes.ReadWriteType(step.Selector)}}}); err != nil {
					t.Fatal(err)
				}
				creds := credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", "")
				var client any
				if step.Service == "apigateway" {
					client = apigateway.New(apigateway.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: creds, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				} else {
					client = apigatewayv2.New(apigatewayv2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: creds, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				}
				out, err := awstest.CallSDK(t.Context(), client, step.Operation, step.Input)
				if err != nil {
					t.Fatal(err)
				}
				id := nativeAuditRequestID(t, out, nil)
				if step.Selected {
					wanted[id] = step.Operation
				} else if messages := snsAdmissionReceive(t, cloud, clients.sqs(eventDeliveryAccount, "test", ""), queueURL); len(messages) != 0 {
					t.Fatalf("read-only selector admitted write: %v", messages)
				}
			}
			clients = reopen()
			seen := map[string]bool{}
			for _, message := range snsAdmissionReceive(t, cloud, clients.sqs(eventDeliveryAccount, "test", ""), queueURL) {
				var event struct {
					Source     string
					DetailType string `json:"detail-type"`
					Detail     struct {
						RequestID, EventSource, EventName, RecipientAccountID string
						ReadOnly                                              bool
						RequestParameters                                     map[string]any
					}
				}
				awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &event)
				operation, ok := wanted[event.Detail.RequestID]
				if !ok || event.Source != "aws.apigateway" || event.DetailType != "AWS API Call via CloudTrail" || event.Detail.EventSource != "apigateway.amazonaws.com" || event.Detail.EventName != operation || event.Detail.ReadOnly || event.Detail.RecipientAccountID != eventDeliveryAccount {
					t.Fatalf("unexpected selected audit event: %+v", event)
				}
				if operation == "CreateRestApi" {
					input, ok := event.Detail.RequestParameters["createRestApiInput"].(map[string]any)
					if !ok || input["name"] != "rest-selected" {
						t.Fatalf("REST audit wrapper lost: %v", event.Detail.RequestParameters)
					}
				} else if event.Detail.RequestParameters["name"] != "http-selected" {
					t.Fatalf("HTTP audit request lost: %v", event.Detail.RequestParameters)
				}
				seen[event.Detail.RequestID] = true
			}
			if len(seen) != len(wanted) {
				t.Fatalf("selected events missing after reopen: got %v want %v", seen, wanted)
			}
		})
	}
}

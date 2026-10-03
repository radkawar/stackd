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
)

func gatewayNativeAudits(t *testing.T) map[string]map[string]any {
	t.Helper()
	var fixture struct {
		Events []struct {
			Label string
			Event map[string]any
		}
	}
	awsReadFixture(t, "apigateway/cloudtrail_deployed.json", &fixture)
	records := make(map[string]map[string]any, len(fixture.Events))
	for _, row := range fixture.Events {
		records[row.Label] = row.Event
	}
	return records
}

func gatewayAudit(t *testing.T, clients cloudClients, fixture gatewayFixture, label, operation string, want map[string]any, output any, callErr error, bindings map[string]string) {
	t.Helper()
	if want == nil {
		return
	}
	trails := cloudtrail.New(cloudtrail.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
	got := auditLatestRecord(t, trails, operation)
	if got["requestID"] != nativeAuditRequestID(t, output, callErr) {
		t.Fatalf("%s: audit lost SDK request correlation", label)
	}
	normalized := gatewayClone(t, want)
	gatewaySubstitute(normalized, bindings)
	// Smithy SDK timestamps and native CloudTrail timestamps use different textual
	// formats. Match resource instants through the already-bound SDK response.
	dates := map[string]string{}
	for before, after := range bindings {
		native, err := time.Parse(time.RFC3339Nano, before)
		if err != nil {
			continue
		}
		local, err := time.Parse(time.RFC3339Nano, after)
		if err == nil {
			dates[native.UTC().Format(time.RFC3339)] = local.UTC().Format(time.RFC3339)
		}
	}
	gatewaySubstitute(normalized, dates)
	for _, field := range []string{"eventSource", "eventName", "awsRegion", "readOnly", "eventCategory", "managementEvent", "eventType", "recipientAccountId", "resources", "requestParameters", "responseElements", "errorCode", "additionalEventData", "errorMessage"} {
		expected, nativePresent := normalized[field]
		actual, present := got[field]
		if nativePresent != present {
			t.Fatalf("%s.%s: native presence=%t, actual=%t", label, field, nativePresent, present)
		}
		// Error prose is not an API contract; its presence and nonempty string are.
		if field == "errorMessage" && present {
			if text, ok := actual.(string); !ok || strings.TrimSpace(text) == "" {
				t.Fatalf("%s: missing error diagnosis", label)
			}
			continue
		}
		if field == "responseElements" && callErr != nil {
			if body, ok := expected.(map[string]any); ok && body["message"] != nil {
				actualBody, ok := actual.(map[string]any)
				if !ok {
					t.Fatalf("%s: native error response object missing", label)
				}
				text, ok := actualBody["message"].(string)
				if !ok || text == "" {
					t.Fatalf("%s: missing response error diagnosis", label)
				}
				body["message"] = text
			}
		}
		if !reflect.DeepEqual(expected, actual) {
			expectedJSON, _ := json.Marshal(expected)
			actualJSON, _ := json.Marshal(actual)
			t.Fatalf("%s.%s:\n native %s\n actual %s", label, field, expectedJSON, actualJSON)
		}
	}
	identity, _ := got["userIdentity"].(map[string]any)
	if identity["type"] != "Root" || identity["arn"] != "arn:aws:iam::"+fixture.Account+":root" {
		t.Fatalf("%s: audit lost authenticated local principal: %v", label, identity)
	}
}

package stackd_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

func cognitoNativeAudits(t *testing.T, name string) map[string]map[string]any {
	t.Helper()
	var fixture struct {
		Events []struct {
			Event  map[string]any
			Labels []string `json:"candidate_observation_labels"`
		}
	}
	awsReadFixture(t, "cognito/"+name+".json", &fixture)
	records := map[string]map[string]any{}
	for _, row := range fixture.Events {
		// The capture deliberately leaves ambiguous/redacted correlations unlabeled.
		if len(row.Labels) == 1 {
			records[row.Labels[0]] = row.Event
		}
	}
	return records
}

func (r *cognitoReplay) audit(t *testing.T, clients cloudClients, fixture cognitoLoginFixture, row cognitoObservation, want map[string]any, requestID string, now time.Time) {
	t.Helper()
	if want == nil {
		return
	}
	trails := cloudtrail.New(cloudtrail.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
	got := auditLatestRecord(t, trails, row.Operation)
	if got["requestID"] != requestID {
		t.Fatal("Cognito outcome lost SDK request correlation")
	}
	if got["eventTime"] != now.UTC().Format(time.RFC3339) {
		t.Fatal("Cognito outcome did not use service time")
	}
	for _, field := range []string{"eventSource", "eventName", "awsRegion", "readOnly", "eventCategory", "managementEvent", "eventType", "recipientAccountId", "resources", "requestParameters", "responseElements", "errorCode", "additionalEventData"} {
		native, nativePresent := want[field]
		actual, present := got[field]
		if nativePresent != present {
			t.Fatalf("%s: native field presence=%t, local=%t", field, nativePresent, present)
		}
		r.compare(t, "audit."+field, native, actual)
	}
	nativeIdentity := want["userIdentity"].(map[string]any)
	identity := got["userIdentity"].(map[string]any)
	if nativeIdentity["type"] == "Unknown" {
		if !reflect.DeepEqual(identity, nativeIdentity) {
			t.Fatalf("public Cognito call gained an IAM identity: %v", identity)
		}
	} else if row.Principal != "" {
		if identity["type"] != nativeIdentity["type"] {
			t.Fatalf("scoped Cognito call lost verified caller type: %v", identity)
		}
		for _, field := range []string{"arn", "principalId", "accountId"} {
			r.compare(t, "audit.userIdentity."+field, nativeIdentity[field], identity[field])
		}
	} else if identity["type"] != "Root" || identity["arn"] != "arn:aws:iam::"+fixture.Account+":root" {
		t.Fatalf("administrative Cognito call lost verified caller: %v", identity)
	}
}

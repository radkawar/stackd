package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type ebRoleAuditFixture struct {
	Account string
	Owned   struct {
		Bucket, Trail, Role string
		Buses, Queues       []string
	}
	Operations []struct {
		Label, Service, Operation string
		Input                     json.RawMessage
	}
	Records    []struct{ Event map[string]any }
	History    struct{ Events []map[string]any } `json:"history_supplement"`
	Deliveries []struct {
		Queue   string
		Message struct{ Body string }
	}
}

// Compare service-owned context and security projections, not provider request
// IDs, SDK user agents, generated credential IDs, or opaque session names.
func ebRoleAuditProjection(event map[string]any) map[string]any {
	out := make(map[string]any)
	for _, field := range []string{"eventSource", "eventName", "awsRegion", "readOnly", "eventCategory", "managementEvent", "eventType", "recipientAccountId", "resources", "apiVersion", "errorCode"} {
		out[field] = event[field]
	}
	identity, _ := event["userIdentity"].(map[string]any)
	out["identityType"], out["invokedBy"] = identity["type"], identity["invokedBy"]
	if identity["type"] == "IAMUser" {
		out["callerARN"], out["callerAccount"], out["callerName"] = identity["arn"], identity["accountId"], identity["userName"]
	} else {
		out["sourceIPAddress"], out["userAgent"] = event["sourceIPAddress"], event["userAgent"]
	}
	request, _ := event["requestParameters"].(map[string]any)
	switch event["eventName"] {
	case "PutEvents":
		out["requestParameters"] = request
		response, _ := event["responseElements"].(map[string]any)
		out["failedEntryCount"] = response["failedEntryCount"]
	case "SendMessage":
		context, _ := identity["sessionContext"].(map[string]any)
		issuer, _ := context["sessionIssuer"].(map[string]any)
		for _, field := range []string{"type", "arn", "accountId", "userName"} {
			out["issuer."+field] = issuer[field]
		}
		attributes, _ := context["attributes"].(map[string]any)
		out["mfaAuthenticated"] = attributes["mfaAuthenticated"]
		out["callerAccount"] = identity["accountId"]
		// The endpoint is local; the actual queue ARN is compared above.
		queue, _ := request["queueUrl"].(string)
		out["queueName"] = queue[strings.LastIndex(queue, "/")+1:]
		out["messageBody"] = request["messageBody"]
	case "AssumeRole":
		out["roleArn"], out["durationSeconds"] = request["roleArn"], request["durationSeconds"]
	}
	return out
}

func TestEventBridgeRoleNativeCloudTrailS3SDK(t *testing.T) {
	body, err := os.ReadFile("../testdata/aws/eventbridge/role_audit.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture ebRoleAuditFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.ReplaceAll(string(body), fixture.Account, eventDeliveryAccount))
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	native := make([]map[string]any, 0, len(fixture.Records)+len(fixture.History.Events))
	for _, row := range fixture.Records {
		native = append(native, ebRoleAuditProjection(row.Event))
	}
	for _, event := range fixture.History.Events {
		native = append(native, ebRoleAuditProjection(event))
	}

	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "role-audit.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 15, 20, 11, 0, 0, time.UTC))
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			trails, objects := trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			events, queues := eventDeliveryClient(c, eventDeliveryAccount), c.sqs(eventDeliveryAccount, "test", "")
			_, key, secret := c.user(t, eventDeliveryAccount, "Delegated")
			putUserPolicy(t, c.iam(eventDeliveryAccount, "test", ""), "Delegated", allow(`"events:PutEvents"`, "arn:aws:events:us-east-1:"+eventDeliveryAccount+":event-bus/"+fixture.Owned.Buses[0]))
			publisher := eventbridge.New(eventbridge.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), HTTPClient: c.server.Client(), RetryMaxAttempts: 1,
				Credentials: credentials.NewStaticCredentialsProvider(key, secret, "")})
			queueURLs := make(map[string]*string)
			published := make(map[string]map[string]any)
			messages := make(map[string]map[string]any)
			for _, row := range fixture.Operations {
				if row.Operation == "put_events" {
					continue
				}
				var client any
				switch row.Service {
				case "s3":
					client = objects
				case "cloudtrail":
					client = trails
				case "events":
					client = events
				case "iam":
					client = c.iam(eventDeliveryAccount, "test", "")
				case "sqs":
					client = queues
				default:
					t.Fatalf("unsupported native control service %s", row.Service)
				}
				var operation string
				for _, word := range strings.Split(row.Operation, "_") {
					operation += strings.ToUpper(word[:1]) + word[1:]
				}
				out, err := awstest.CallSDK(t.Context(), client, operation, row.Input, func(value any) {
					if input, ok := value.(*cloudtrail.PutEventSelectorsInput); ok {
						// Native STS evidence came from management-event history, not
						// these data-only objects. Select management legally in this
						// replay; Management eventSource=STS Equals is unsupported.
						input.AdvancedEventSelectors = append(input.AdvancedEventSelectors, trailtypes.AdvancedEventSelector{Name: aws.String("ServiceAssumptions"), FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}})
					}
				})
				if err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
				switch out := out.(type) {
				case *sqs.CreateQueueOutput:
					var input sqs.CreateQueueInput
					if err := json.Unmarshal(row.Input, &input); err != nil {
						t.Fatal(err)
					}
					queueURLs[aws.ToString(input.QueueName)] = out.QueueUrl
				case *eventbridge.PutTargetsOutput:
					if out.FailedEntryCount != 0 {
						t.Fatalf("%s: %+v", row.Label, out)
					}
				}
			}
			for _, row := range fixture.Operations {
				if row.Operation != "put_events" {
					continue
				}
				advanceClock(t, source, time.Minute)
				var input eventbridge.PutEventsInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				out, err := publisher.PutEvents(t.Context(), &input)
				if err != nil {
					t.Fatal(err)
				}
				if out.FailedEntryCount != 0 || len(out.Entries) != 1 || aws.ToString(out.Entries[0].EventId) == "" {
					t.Fatalf("%s: %+v", row.Label, out)
				}
				id := aws.ToString(out.Entries[0].EventId)
				var detail map[string]any
				if err := json.Unmarshal([]byte(aws.ToString(input.Entries[0].Detail)), &detail); err != nil {
					t.Fatal(err)
				}
				published[id] = detail
				trailNativeDrain(t, cloud)
				for _, queue := range fixture.Owned.Queues {
					received, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURLs[queue], MaxNumberOfMessages: 10})
					if err != nil {
						t.Fatal(err)
					}
					if len(received.Messages) != 1 {
						t.Fatalf("%s/%s delivered %d messages, want one", row.Label, queue, len(received.Messages))
					}
					message := received.Messages[0]
					var got map[string]any
					if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &got); err != nil {
						t.Fatal(err)
					}
					if got["id"] != id || !reflect.DeepEqual(got["detail"], detail) {
						t.Fatalf("%s lost publication: %#v", queue, got)
					}
					matched := false
					for _, delivery := range fixture.Deliveries {
						if !strings.HasSuffix(delivery.Queue, "/"+queue) {
							continue
						}
						var want map[string]any
						if err := json.Unmarshal([]byte(delivery.Message.Body), &want); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(want["detail"], detail) {
							continue
						}
						want["id"], want["time"] = got["id"], got["time"]
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("%s envelope: got %#v native %#v", queue, got, want)
						}
						matched = true
					}
					if !matched {
						t.Fatalf("no native delivery for %s/%s", row.Label, queue)
					}
					messages[aws.ToString(message.MessageId)] = map[string]any{"queue": queue, "md5": aws.ToString(message.MD5OfBody)}
					if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queueURLs[queue], ReceiptHandle: message.ReceiptHandle}); err != nil {
						t.Fatal(err)
					}
				}
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, cloud)
			logs := trailNativeRecords(t, trailNativeObjects(t, objects, fixture.Owned.Bucket, "owned/AWSLogs/"))
			assumptions := make(map[string]map[string]any)
			var sends []map[string]any
			seenPublications := make(map[string]bool)
			for _, event := range logs {
				name, _ := event["eventName"].(string)
				if name != "PutEvents" && name != "SendMessage" && name != "AssumeRole" {
					continue
				}
				projection := ebRoleAuditProjection(event)
				matched := false
				for _, want := range native {
					matched = matched || reflect.DeepEqual(projection, want)
				}
				if !matched {
					t.Errorf("%s has no native identity/resource/redaction projection: %#v", name, projection)
				}
				response, _ := event["responseElements"].(map[string]any)
				switch name {
				case "PutEvents":
					entries, _ := response["entries"].([]any)
					if len(entries) != 1 {
						t.Fatalf("unexpected PutEvents batch: %#v", event)
					}
					entry, _ := entries[0].(map[string]any)
					id, _ := entry["eventId"].(string)
					if published[id] == nil || seenPublications[id] {
						t.Fatalf("forwarding invented or duplicated a customer PutEvents audit: %#v", event)
					}
					seenPublications[id] = true
				case "AssumeRole":
					creds, _ := response["credentials"].(map[string]any)
					if creds["secretAccessKey"] != nil || creds["sessionToken"] != nil {
						t.Fatal("service assumption logged credential secrets")
					}
					accessKey, _ := creds["accessKeyId"].(string)
					role, _ := response["assumedRoleUser"].(map[string]any)
					request, _ := event["requestParameters"].(map[string]any)
					session, _ := request["roleSessionName"].(string)
					arn, _ := role["arn"].(string)
					if accessKey == "" || session == "" || arn != "arn:aws:sts::"+eventDeliveryAccount+":assumed-role/"+fixture.Owned.Role+"/"+session {
						t.Fatalf("unusable service assumption identity: %#v", event)
					}
					assumptions[accessKey] = role
				case "SendMessage":
					sends = append(sends, event)
				}
			}
			if len(seenPublications) != len(published) {
				t.Fatalf("source publication audits=%d want=%d", len(seenPublications), len(published))
			}
			seenMessages, sessions := make(map[string]bool), make(map[string]string)
			for _, event := range sends {
				identity, _ := event["userIdentity"].(map[string]any)
				accessKey, _ := identity["accessKeyId"].(string)
				role := assumptions[accessKey]
				if role == nil || role["arn"] != identity["arn"] || role["assumedRoleId"] != identity["principalId"] {
					t.Fatalf("destination audit cannot be traced to service assumption: %#v", event)
				}
				response, _ := event["responseElements"].(map[string]any)
				id, _ := response["messageId"].(string)
				message := messages[id]
				if message == nil || seenMessages[id] || message["md5"] != response["mD5OfMessageBody"] {
					t.Fatalf("audit does not describe an actual unique SQS delivery: %#v", event)
				}
				queue := message["queue"].(string)
				request, _ := event["requestParameters"].(map[string]any)
				queueURL, _ := request["queueUrl"].(string)
				if !strings.HasSuffix(queueURL, "/"+eventDeliveryAccount+"/"+queue) {
					t.Fatalf("audit names a different destination: %#v", event)
				}
				arn, _ := identity["arn"].(string)
				if previous := sessions[queue]; previous != "" && previous != arn {
					t.Fatalf("target session name changed across publications for %s", queue)
				}
				sessions[queue], seenMessages[id] = arn, true
			}
			if len(seenMessages) != len(fixture.Deliveries) || len(seenMessages) != len(messages) {
				t.Fatalf("destination audits=%d delivered=%d native=%d", len(seenMessages), len(messages), len(fixture.Deliveries))
			}
			if sessions[fixture.Owned.Queues[0]] == sessions[fixture.Owned.Queues[1]] {
				t.Fatal("distinct queue targets shared an opaque role session name")
			}
		})
	}
}

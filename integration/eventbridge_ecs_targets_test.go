package stackd_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/internal/awstest"
)

type eventBridgeECSCall struct {
	ID                                         int
	Label, Service, Operation, Code, InputJSON string
	Output                                     json.RawMessage
}
type eventBridgeECSFixture struct {
	Account, Region string
	Calls           []eventBridgeECSCall
}

func eventBridgeECSRead(t *testing.T) eventBridgeECSFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/eventbridge/ecs_targets.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture eventBridgeECSFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
func (f eventBridgeECSFixture) row(t *testing.T, id int) eventBridgeECSCall {
	t.Helper()
	for _, row := range f.Calls {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("missing native call %d", id)
	return eventBridgeECSCall{}
}
func (f eventBridgeECSFixture) call(t *testing.T, c cloudClients, id int, prepare ...func(any)) any {
	t.Helper()
	row := f.row(t, id)
	var client any
	switch row.Service {
	case "events":
		client = eventDeliveryClient(c, f.Account)
	case "iam":
		client = c.iam(f.Account, "test", "")
	case "sqs":
		client = c.sqs(f.Account, "test", "")
	case "ecs":
		client = ecs.New(ecs.Options{Region: f.Region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(f.Account, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	default:
		t.Fatalf("unsupported ECS fixture service %s", row.Service)
	}
	out, err := awstest.CallSDK(t.Context(), client, row.Operation, json.RawMessage(row.InputJSON), prepare...)
	if row.Code != "Success" {
		assertAPIError(t, err, row.Code)
		return nil
	}
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	if accepted, ok := out.(*eventbridge.PutTargetsOutput); ok && accepted.FailedEntryCount != 0 {
		t.Fatalf("%s: native accepted all targets, got %+v", row.Label, accepted)
	}
	return out
}

func TestEventBridgeECSNativeAtomicAdmission(t *testing.T) {
	fixture := eventBridgeECSRead(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account})
			fixture.call(t, clients, 19)
			fixture.call(t, clients, 20)
			// No roles or ECS resources exist: native accepts syntactically valid
			// references, independently of their current existence or trust.
			for _, id := range []int{37, 38, 39, 40, 41, 43, 44, 47, 48, 49, 50, 51, 52, 53, 98, 99, 100, 101, 102, 103, 104, 55, 86} {
				fixture.call(t, clients, id)
			}
			for _, id := range []int{176, 177, 178, 179, 180, 181, 182, 183, 184, 191, 192, 193, 194} {
				fixture.call(t, clients, id)
			}
			clients = reopen()
			got := fixture.call(t, clients, 87).(*eventbridge.ListTargetsByRuleOutput)
			var want eventbridge.ListTargetsByRuleOutput
			if err := json.Unmarshal(fixture.row(t, 87).Output, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Targets, want.Targets) {
				t.Fatalf("mixed invalid request changed retained target after reopen:\ngot %+v\nwant %+v", got.Targets, want.Targets)
			}
			arnTargets := fixture.call(t, clients, 185).(*eventbridge.ListTargetsByRuleOutput)
			var arnWant eventbridge.ListTargetsByRuleOutput
			if err := json.Unmarshal(fixture.row(t, 185).Output, &arnWant); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(arnTargets.Targets, arnWant.Targets) {
				t.Fatalf("retained ECS target identifier/defaults differ from AWS:\ngot %+v\nwant %+v", arnTargets.Targets, arnWant.Targets)
			}
			caller := fixture.call(t, clients, 88, func(v any) {
				v.(*iam.CreateRoleInput).AssumeRolePolicyDocument = aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + fixture.Account + `:root"},"Action":"sts:AssumeRole"}]}`)
			}).(*iam.CreateRoleOutput)
			fixture.call(t, clients, 89)
			session, err := clients.sts(fixture.Account, "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: caller.Role.Arn, RoleSessionName: aws.String("native-no-passrole")})
			if err != nil {
				t.Fatal(err)
			}
			sessionCredentials := session.Credentials
			callerEvents := eventbridge.New(eventbridge.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(aws.ToString(sessionCredentials.AccessKeyId), aws.ToString(sessionCredentials.SecretAccessKey), aws.ToString(sessionCredentials.SessionToken)), RetryMaxAttempts: 1})
			_, err = awstest.CallSDK(t.Context(), callerEvents, "PutTargets", json.RawMessage(fixture.row(t, 91).InputJSON))
			assertAPIError(t, err, fixture.row(t, 91).Code)
		})
	}
}

func TestEventBridgeECSNativeCurrentDenialAndInvalidOverride(t *testing.T) {
	fixture := eventBridgeECSRead(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account})
			for _, id := range []int{5, 6, 7, 8, 12, 18, 19, 20, 21, 22, 23} {
				fixture.call(t, clients, id)
			}
			queue := fixture.call(t, clients, 34).(*sqs.CreateQueueOutput).QueueUrl
			fixture.call(t, clients, 62, func(v any) { v.(*sqs.SetQueueAttributesInput).QueueUrl = queue })
			fixture.call(t, clients, 55)
			clients = reopen()
			// PutTargets does not freeze role permissions. Install the captured explicit
			// denial on the previously authorized invocation role after retention.
			var invocation eventbridge.PutTargetsInput
			if err := json.Unmarshal([]byte(fixture.row(t, 55).InputJSON), &invocation); err != nil {
				t.Fatal(err)
			}
			role := aws.ToString(invocation.Targets[0].RoleArn)
			fixture.call(t, clients, 22, func(v any) { v.(*iam.PutRolePolicyInput).RoleName = aws.String(role[strings.LastIndex(role, "/")+1:]) })
			fixture.call(t, clients, 57)
			eventBridgeECSReceipt(t, fixture, clients, queue, 69)
			trails := cloudtrail.New(cloudtrail.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), RetryMaxAttempts: 1})
			audit := auditLatestRecord(t, trails, "RunTask")
			if audit["errorCode"] != "AccessDenied" {
				t.Fatalf("delivery did not cross the audited ECS command: %#v", audit)
			}
			if audit["requestParameters"] != nil {
				t.Fatalf("denied execution exposed request parameters: %#v", audit["requestParameters"])
			}
			actor := audit["userIdentity"].(map[string]any)
			if actor["type"] != "AssumedRole" || !strings.Contains(actor["arn"].(string), ":assumed-role/"+role[strings.LastIndex(role, "/")+1:]+"/") {
				t.Fatalf("wrong ECS command authority: %#v", actor)
			}
			fixture.call(t, clients, 61)
			fixture.call(t, clients, 63)
			fixture.call(t, clients, 64, func(v any) {
				in := v.(*eventbridge.PutTargetsInput)
				for _, target := range in.Targets {
					if aws.ToString(target.Id) == "badtrust" {
						in.Targets = []eventtypes.Target{target}
						return
					}
				}
				t.Fatal("native wrong-trust target missing")
			})
			fixture.call(t, clients, 65)
			eventBridgeECSReceipt(t, fixture, clients, queue, 84)
			// Restore current authority; invalid override is accepted by EventBridge,
			// rejected by the real ECS command, and never becomes a task.
			fixture.call(t, clients, 21)
			fixture.call(t, clients, 78)
			fixture.call(t, clients, 79)
			fixture.call(t, clients, 80)
			eventBridgeECSReceipt(t, fixture, clients, queue, 96)
			audit = auditLatestRecord(t, trails, "RunTask")
			if audit["errorCode"] != "InvalidParameterException" {
				t.Fatalf("invalid container bypassed ECS command: %#v", audit)
			}
			var history struct {
				Events []struct{ CloudTrailEvent string }
			}
			if err := json.Unmarshal(fixture.row(t, 94).Output, &history); err != nil {
				t.Fatal(err)
			}
			for _, event := range history.Events {
				var native struct {
					ErrorCode         string
					RequestParameters map[string]any
				}
				if err := json.Unmarshal([]byte(event.CloudTrailEvent), &native); err != nil {
					t.Fatal(err)
				}
				if native.ErrorCode != "InvalidParameterException" {
					continue
				}
				got, ok := audit["requestParameters"].(map[string]any)
				if !ok {
					t.Fatalf("invalid override lost native request parameters: %#v", audit)
				}
				delete(got, "clientToken")
				delete(native.RequestParameters, "clientToken")
				if !reflect.DeepEqual(got, native.RequestParameters) {
					t.Fatalf("invalid override audit differs: got %#v want %#v", got, native.RequestParameters)
				}
				return
			}
			t.Fatal("native invalid-override audit observation missing")
		})
	}
}

func eventBridgeECSReceipt(t *testing.T, f eventBridgeECSFixture, c cloudClients, queue *string, nativeID int) {
	t.Helper()
	var native sqs.ReceiveMessageOutput
	if err := json.Unmarshal(f.row(t, nativeID).Output, &native); err != nil {
		t.Fatal(err)
	}
	if len(native.Messages) != 1 {
		t.Fatalf("expected one native DLQ observation, got %d", len(native.Messages))
	}
	queues := c.sqs(f.Account, "test", "")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue, MaxNumberOfMessages: 1, MessageAttributeNames: []string{"All"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		got, want := out.Messages[0], native.Messages[0]
		expected := map[string]string{}
		for key, v := range want.MessageAttributes {
			expected[key] = aws.ToString(v.StringValue)
		}
		// The current-role case deliberately uses the invoke role and broad rule;
		// error class, transformed body and absence of retry fields are native.
		if nativeID == 69 {
			expected["RULE_ARN"] = strings.TrimSuffix(expected["RULE_ARN"], "-failures")
		}
		assertEventDeliveryAttributes(t, got.MessageAttributes, expected)
		var gotBody, wantBody any
		if err := json.Unmarshal([]byte(aws.ToString(got.Body)), &gotBody); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(aws.ToString(want.Body)), &wantBody); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotBody, wantBody) {
			t.Fatalf("DLQ lost transformed override input: got %s want %s", aws.ToString(got.Body), aws.ToString(want.Body))
		}
		if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queue, ReceiptHandle: got.ReceiptHandle}); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("ECS delivery did not reach the real SQS dead-letter queue")
}

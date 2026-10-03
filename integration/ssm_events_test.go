package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"stackd"
)

func TestSSMNativeEventProjection(t *testing.T) {
	var fixture struct {
		Prefix string
		Calls  []struct {
			Label   string
			Request json.RawMessage
		}
		CloudTrail struct {
			Events []struct {
				Label string `json:"call_label"`
				Event map[string]any
			}
		}
		EventBridge struct{ Events []map[string]any }
	}
	raw, err := os.ReadFile("../testdata/aws/ssm/parameter_store.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	const account = "000000000000"
	cloud, server := startPublicCloud(t, stackd.Config{AccountID: account})
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = cloud.Close() })
	cl := cloudClients{server}
	ctx := t.Context()
	queues := cl.sqs(account, "test", "")
	queue, err := queues.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: new("ssm-native-events")})
	if err != nil {
		t.Fatal(err)
	}
	queueARN := "arn:aws:sqs:us-east-1:" + account + ":ssm-native-events"
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q}]}`, queueARN)
	_, err = queues.SetQueueAttributes(ctx, &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}})
	if err != nil {
		t.Fatal(err)
	}
	events := eventDeliveryClient(cl, account)
	_, err = events.PutRule(ctx, &eventbridge.PutRuleInput{Name: new("ssm-native-events"), EventPattern: new(`{"source":["aws.ssm"],"detail-type":["Parameter Store Change"]}`)})
	if err != nil {
		t.Fatal(err)
	}
	targets, err := events.PutTargets(ctx, &eventbridge.PutTargetsInput{Rule: new("ssm-native-events"), Targets: []eventtypes.Target{{Id: new("queue"), Arn: new(queueARN)}}})
	if err != nil || targets.FailedEntryCount != 0 {
		t.Fatalf("event target: %+v %v", targets, err)
	}
	client := cl.ssm("us-east-1", account, "test")
	for _, label := range []string{"create-string", "duplicate-string", "get-missing"} {
		var input json.RawMessage
		for _, call := range fixture.Calls {
			if call.Label == label {
				input = call.Request
				break
			}
		}
		if input == nil {
			t.Fatalf("native call %s absent", label)
		}
		switch label {
		case "create-string", "duplicate-string":
			var request ssm.PutParameterInput
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			_, err := client.PutParameter(ctx, &request)
			if label == "create-string" && err != nil {
				t.Fatal(err)
			}
			if label == "duplicate-string" {
				assertAPIError(t, err, "ParameterAlreadyExists")
			}
		case "get-missing":
			var request ssm.GetParameterInput
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			_, err := client.GetParameter(ctx, &request)
			assertAPIError(t, err, "ParameterNotFound")
		}
	}
	if _, err := cloud.RunDueJobs(ctx, 100); err != nil {
		t.Fatal(err)
	}
	messages, err := queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(messages.Messages) != 1 {
		t.Fatalf("one committed create event expected; duplicate and read must emit none: %+v", messages.Messages)
	}
	var actualEvent map[string]any
	if err := json.Unmarshal([]byte(aws.ToString(messages.Messages[0].Body)), &actualEvent); err != nil {
		t.Fatal(err)
	}
	var expectedEvent map[string]any
	for _, event := range fixture.EventBridge.Events {
		detail, _ := event["detail"].(map[string]any)
		if detail["name"] == fixture.Prefix+"/string" && detail["operation"] == "Create" {
			expectedEvent = event
			break
		}
	}
	if expectedEvent == nil {
		t.Fatal("native create event missing")
	}
	for _, field := range []string{"detail", "detail-type", "source", "resources", "account", "region"} {
		if !reflect.DeepEqual(actualEvent[field], expectedEvent[field]) {
			t.Fatalf("EventBridge %s: got %#v want %#v", field, actualEvent[field], expectedEvent[field])
		}
	}
	trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: new(server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	history, err := trails.LookupEvents(ctx, &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: new("ssm.amazonaws.com")}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Events) != 3 {
		t.Fatalf("parameter failures and reads should retain native audit: %d", len(history.Events))
	}
	matched := map[string]bool{}
	for _, event := range history.Events {
		var actual map[string]any
		if err := json.Unmarshal([]byte(aws.ToString(event.CloudTrailEvent)), &actual); err != nil {
			t.Fatal(err)
		}
		label := "get-missing"
		if actual["eventName"] == "PutParameter" {
			label = "create-string"
			if actual["responseElements"] == nil {
				label = "duplicate-string"
			}
		}
		var expected map[string]any
		for _, native := range fixture.CloudTrail.Events {
			if native.Label == label {
				expected = native.Event
				break
			}
		}
		if expected == nil {
			t.Fatalf("native audit missing: %s", label)
		}
		for _, field := range []string{"eventName", "eventSource", "eventCategory", "readOnly", "requestParameters", "responseElements", "resources", "errorCode", "errorMessage"} {
			if !reflect.DeepEqual(actual[field], expected[field]) {
				t.Fatalf("CloudTrail %s %s: got %#v want %#v", label, field, actual[field], expected[field])
			}
		}
		matched[label] = true
	}
	if len(matched) != 3 {
		t.Fatalf("audits not independently matched: %v", matched)
	}
}

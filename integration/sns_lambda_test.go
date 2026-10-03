package stackd_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"stackd"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/storage"
)

func TestSNSLambdaDockerNativeReplay(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	data, err := os.ReadFile("../testdata/aws/sns/lambda.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		snsAdmissionFixture
		Deliveries []struct {
			Record       json.RawMessage
			Correlations []struct {
				Label string `json:"publication_label"`
			}
		}
	}
	awsDecodeJSON(t, data, &fixture)
	for _, limitation := range fixture.Limitations {
		t.Log(limitation)
	}
	native := make(map[string]json.RawMessage)
	for _, delivery := range fixture.Deliveries {
		if len(delivery.Correlations) != 1 {
			t.Fatal("native handler receipt must correlate with exactly one publication")
		}
		native[delivery.Correlations[0].Label] = delivery.Record
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sns-lambda.sqlite"))
			}
			cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, Clock: nil}, nil)
			clients := cloudClients{server}
			endpoint := strings.Replace(server.URL, "127.0.0.1", "host.docker.internal", 1)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			queueOptions := clients.sqs(fixture.Account, "test", "").Options()
			queueOptions.Region = fixture.Region
			queues := sqs.New(queueOptions)
			functions := awslambda.New(awslambda.Options{Region: fixture.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			root := clients.iam(fixture.Account, "test", "")
			row := func(label string) awsNativeObservation {
				return snsControlRow(t, fixture.snsAdmissionFixture, label)
			}
			topic := snsControlReplay(t, topics, row("create-topic")).(*sns.CreateTopicOutput)
			var nativeTopic sns.CreateTopicOutput
			awsDecodeJSON(t, row("create-topic").Result.Output, &nativeTopic)
			if aws.ToString(topic.TopicArn) != aws.ToString(nativeTopic.TopicArn) {
				t.Fatal("topic account, region or name changed from native capture")
			}
			queue := snsControlReplay(t, queues, row("create-output-queue")).(*sqs.CreateQueueOutput)
			snsControlReplay(t, root, row("create-execution-role"))
			snsControlReplay(t, root, row("grant-owned-output-only"))
			function := snsControlReplay(t, functions, row("create-function"), func(value any) {
				input := value.(*awslambda.CreateFunctionInput)
				// Preserve the captured ZipFile, handler and customer environment.
				// The unchanged boto3.client("sqs") must only reach this instance.
				input.Environment.Variables["QUEUE_URL"] = strings.Replace(aws.ToString(queue.QueueUrl), "127.0.0.1", "host.docker.internal", 1)
				input.Environment.Variables["AWS_ENDPOINT_URL"] = endpoint
			}).(*awslambda.CreateFunctionOutput)
			if err := awslambda.NewFunctionActiveWaiter(functions, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: function.FunctionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			snsControlReplay(t, functions, row("grant-exact-topic-invocation"))
			subscription := snsControlReplay(t, topics, row("subscribe-lambda")).(*sns.SubscribeOutput)
			// Stack cleanup owns the Docker executor even if a replay assertion fails.
			// Successful replay additionally deletes the captured resources via SDK.
			consumer := &lambdaEventsCloud{cloud: cloud, server: server, lambda: functions, queues: queues, outputURL: queue.QueueUrl, functionName: function.FunctionName, functionARN: aws.ToString(function.FunctionArn)}
			requests := make(map[string]bool)
			publications := make(map[string]bool)
			for _, observation := range fixture.Observations {
				if observation.Operation != "publish" && observation.Operation != "set-subscription-attributes" {
					continue
				}
				label := observation.Label
				if !t.Run(label, func(t *testing.T) {
					if observation.Operation == "set-subscription-attributes" {
						snsControlReplay(t, topics, observation, func(value any) {
							value.(*sns.SetSubscriptionAttributesInput).SubscriptionArn = subscription.SubscriptionArn
						})
						return
					}
					before := time.Now().UTC().Add(-time.Second)
					published := snsControlReplay(t, topics, observation).(*sns.PublishOutput)
					id := aws.ToString(published.MessageId)
					if id == "" || publications[id] {
						t.Fatalf("missing/reused publication ID: %q", id)
					}
					publications[id] = true
					wanted, delivered := native[label]
					if !delivered {
						// Native observed no default-only match during its bounded
						// window. Drain real local work, then check a bounded quiet
						// period; neither observation promises permanent AWS absence.
						if messages := snsAdmissionReceive(t, cloud, queues, queue.QueueUrl); len(messages) != 0 {
							t.Fatalf("default body matched instead of selected Lambda body: %+v", messages)
						}
						lambdaEventsQuiet(t, consumer, queue.QueueUrl)
						return
					}
					receipts := lambdaEventsReceive(t, consumer, queue.QueueUrl, 1)
					var got, want map[string]any
					awsDecodeJSON(t, []byte(aws.ToString(receipts[0].Body)), &got)
					awsDecodeJSON(t, wanted, &want)
					request, _ := got["handler_request_id"].(string)
					if request == "" || requests[request] {
						t.Fatalf("missing/reused actual Lambda request ID: %q", request)
					}
					requests[request] = true
					received, ok := got["received_unix"].(float64)
					if !ok || received < float64(before.Unix()) || received > float64(time.Now().Unix()+1) {
						t.Fatalf("handler receipt has invalid wall timestamp: %v", got["received_unix"])
					}
					actualRecord, actualSNS := snsLambdaEnvelope(t, got)
					nativeRecord, nativeSNS := snsLambdaEnvelope(t, want)
					if actualRecord["EventSubscriptionArn"] != aws.ToString(subscription.SubscriptionArn) || actualSNS["MessageId"] != id {
						t.Fatalf("handler receipt lost accepted subscription/publication identity: %+v", got)
					}
					stamp, ok := actualSNS["Timestamp"].(string)
					publishedAt, err := time.Parse(time.RFC3339Nano, stamp)
					if !ok || err != nil || publishedAt.Before(before) || publishedAt.After(time.Now()) {
						t.Fatalf("invalid publication timestamp: %v", actualSNS["Timestamp"])
					}
					snsVerifySignature(t, actualSNS, endpoint, server.URL)
					unsubscribe, err := url.Parse(fmt.Sprint(actualSNS["UnsubscribeUrl"]))
					if err != nil || unsubscribe.Scheme+"://"+unsubscribe.Host != endpoint || unsubscribe.Path != "/" || !reflect.DeepEqual(unsubscribe.Query(), url.Values{"Action": {"Unsubscribe"}, "SubscriptionArn": {aws.ToString(subscription.SubscriptionArn)}}) {
						t.Fatalf("unsubscribe URL does not identify the advertised subscription: %v", actualSNS["UnsubscribeUrl"])
					}
					// Normalize only validated dynamic identities/times and local
					// signing material. Full map equality retains exact native key
					// spelling, null Subject, empty attributes, Number/Binary values,
					// selected/default message bytes and every Records/Sns field.
					got["handler_request_id"], got["received_unix"] = want["handler_request_id"], want["received_unix"]
					actualRecord["EventSubscriptionArn"] = nativeRecord["EventSubscriptionArn"]
					for _, field := range []string{"MessageId", "Timestamp", "Signature", "SigningCertUrl", "UnsubscribeUrl"} {
						actualSNS[field] = nativeSNS[field]
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("real Lambda receipt differs from native:\ngot: %#v\nnative: %#v", got, want)
					}
				}) {
					t.FailNow()
				}
			}
			for _, cleanup := range []struct {
				label  string
				client any
			}{
				{"delete-subscription", topics}, {"delete-topic", topics},
				{"delete-function-and-permission", functions}, {"delete-inline-policy", root},
				{"delete-execution-role", root}, {"delete-output-queue", queues},
			} {
				snsControlReplay(t, cleanup.client, row(cleanup.label), func(value any) {
					switch input := value.(type) {
					case *sns.UnsubscribeInput:
						input.SubscriptionArn = subscription.SubscriptionArn
					case *sqs.DeleteQueueInput:
						input.QueueUrl = queue.QueueUrl
					}
				})
			}
		})
	}
}

func TestSNSNativeCrossAccountLambdaDocker(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	var fixture struct {
		Region       string
		Observations []snsCrossObservation
		Receipts     []struct{ Payload map[string]any }
		ResourceSets []struct{ Function, Bucket string } `json:"resource_sets"`
	}
	awsReadFixture(t, "sns/cross_account_lambda.json", &fixture)
	// The middle attempt deleted its topic before confirming and left a native
	// pending orphan. Replay both complete workflows, not that cleanup accident.
	for _, scenario := range []int{0, len(fixture.ResourceSets) - 1} {
		resource := fixture.ResourceSets[scenario]
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(resource.Function+"/"+backend, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "cross-lambda.sqlite"))
				}
				cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends}, nil)
				clients := cloudClients{server}
				const owner, subscriber = "000000000000", "917546008205"
				topics := snsCrossTopics(t, clients, owner, subscriber, fixture.Region)
				objects := s3NativeClient(clients, subscriber, "test")
				functions := awslambda.New(awslambda.Options{Region: fixture.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(subscriber, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
				endpoint := strings.Replace(server.URL, "127.0.0.1", "host.docker.internal", 1)
				mapped := map[string]string{}
				var replacements []string
				bind := func(native, local string) {
					t.Helper()
					if old, exists := mapped[native]; exists {
						if old != local {
							t.Fatalf("native identity %s changed from %s to %s", native, old, local)
						}
						return
					}
					mapped[native] = local
					replacements = append(replacements, native, local)
				}
				normalize := func(data []byte) []byte { return []byte(strings.NewReplacer(replacements...).Replace(string(data))) }
				includesTopic := func(topic string) bool { return strings.Contains(topic, ":"+resource.Function+"-") }
				nativeReceipt := func(kind, identity string) map[string]any {
					for _, receipt := range fixture.Receipts {
						_, notification := snsLambdaEnvelope(t, receipt.Payload)
						if notification["Type"] == kind && (notification["MessageId"] == identity || kind == "SubscriptionConfirmation" && notification["TopicArn"] == identity) {
							return receipt.Payload
						}
					}
					return nil
				}
				collect := func(kind, identity string, expected bool) map[string]any {
					t.Helper()
					window := 300 * time.Millisecond
					if expected {
						window = time.Minute
					}
					deadline := time.Now().Add(window)
					for {
						trailNativeDrain(t, cloud)
						for _, body := range firehoseConsumerObjects(t, objects, resource.Bucket, "") {
							var receipt map[string]any
							awsDecodeJSON(t, body, &receipt)
							_, notification := snsLambdaEnvelope(t, receipt)
							if notification["Type"] == kind && (notification["MessageId"] == identity || kind == "SubscriptionConfirmation" && notification["TopicArn"] == identity) {
								if !expected {
									t.Fatalf("publication outside native authority/state reached Lambda: %v", receipt)
								}
								return receipt
							}
						}
						if !time.Now().Before(deadline) {
							if expected {
								t.Fatalf("no real Lambda %s receipt for %s", kind, identity)
							}
							return nil
						}
						time.Sleep(20 * time.Millisecond)
					}
				}
				requests := map[string]bool{}
				checkReceipt := func(got, want map[string]any, before time.Time) {
					t.Helper()
					actualRecord, actualSNS := snsLambdaEnvelope(t, got)
					nativeRecord, nativeSNS := snsLambdaEnvelope(t, want)
					if actualRecord["EventSubscriptionArn"] != nil {
						if actualRecord["EventSubscriptionArn"] != mapped[fmt.Sprint(nativeRecord["EventSubscriptionArn"])] {
							t.Fatalf("Lambda invocation changed subscription ownership: %v", actualRecord)
						}
					} else if nativeRecord["EventSubscriptionArn"] != nil {
						t.Fatal("ordinary Lambda notification lost subscription ARN")
					}
					stamp, err := time.Parse(time.RFC3339Nano, fmt.Sprint(actualSNS["Timestamp"]))
					if err != nil || stamp.Before(before) || stamp.After(time.Now()) {
						t.Fatalf("invalid real publication time: %v", actualSNS["Timestamp"])
					}
					snsVerifySignature(t, actualSNS, endpoint, server.URL)
					if actualSNS["Type"] == "SubscriptionConfirmation" {
						control, err := url.Parse(fmt.Sprint(actualSNS["SubscribeUrl"]))
						if err != nil || control.Scheme+"://"+control.Host != endpoint || control.Query().Get("Action") != "ConfirmSubscription" || control.Query().Get("TopicArn") != actualSNS["TopicArn"] || control.Query().Get("Token") != actualSNS["Token"] {
							t.Fatalf("Lambda control URL lost actual topic/token: %v", actualSNS)
						}
						bind(fmt.Sprint(nativeSNS["Token"]), fmt.Sprint(actualSNS["Token"]))
					} else {
						link, err := url.Parse(fmt.Sprint(actualSNS["UnsubscribeUrl"]))
						if err != nil || link.Scheme+"://"+link.Host != endpoint || link.Query().Get("SubscriptionArn") != actualRecord["EventSubscriptionArn"] {
							t.Fatal("Lambda notification lost its unsubscribe identity")
						}
					}
					id, _ := got["aws_request_id"].(string)
					if id == "" || requests[id] {
						t.Fatalf("missing/reused real Lambda invocation ID: %q", id)
					}
					requests[id] = true
					got["aws_request_id"] = want["aws_request_id"]
					actualRecord["EventSubscriptionArn"] = nativeRecord["EventSubscriptionArn"]
					for _, field := range []string{"MessageId", "Timestamp", "Signature", "SigningCertUrl", "Token", "SubscribeUrl", "UnsubscribeUrl"} {
						if value, exists := nativeSNS[field]; exists {
							actualSNS[field] = value
						}
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("actual Lambda payload differs:\ngot: %#v\nnative: %#v", got, want)
					}
				}
				current := ""
				for _, capture := range fixture.Observations {
					if capture.Label == "create-topic-A" {
						var input sns.CreateTopicInput
						awsDecodeJSON(t, capture.Input, &input)
						current = strings.TrimSuffix(aws.ToString(input.Name), "-A")
					}
					if current != resource.Function || strings.HasPrefix(capture.Label, "independent-") {
						continue
					}
					// Native IAM role visibility retries are timing observations, not
					// deterministic requests that should fail after local creation.
					if capture.Operation == "create-function" && capture.Result.Code != "Success" {
						continue
					}
					var client any
					switch capture.Service {
					case "sns":
						client = topics[capture.Caller]
					case "iam":
						if capture.Operation != "create-role" && capture.Operation != "put-role-policy" {
							continue
						}
						client = clients.iam(subscriber, "test", "")
					case "s3api":
						if capture.Operation != "create-bucket" {
							continue
						}
						client = objects
					case "lambda":
						switch capture.Operation {
						case "create-function", "add-permission", "remove-permission", "delete-function":
							client = functions
						default:
							continue
						}
					default:
						continue
					}
					if !t.Run(capture.Label, func(t *testing.T) {
						row := capture.awsNativeObservation
						row.Input = normalize(row.Input)
						before := time.Now().Add(-time.Second)
						result := snsControlReplay(t, client, row, func(value any) {
							if input, ok := value.(*awslambda.CreateFunctionInput); ok {
								input.Environment.Variables["AWS_ENDPOINT_URL"] = endpoint
							}
						})
						if row.Result.Code != "Success" {
							return
						}
						switch out := result.(type) {
						case *awslambda.CreateFunctionOutput:
							if err := awslambda.NewFunctionActiveWaiter(functions, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: out.FunctionName}, time.Minute); err != nil {
								t.Fatal(err)
							}
						case *sns.SubscribeOutput:
							var want sns.SubscribeOutput
							var input sns.SubscribeInput
							awsDecodeJSON(t, row.Result.Output, &want)
							awsDecodeJSON(t, row.Input, &input)
							bind(aws.ToString(want.SubscriptionArn), aws.ToString(out.SubscriptionArn))
							if capture.Caller == owner {
								native := nativeReceipt("SubscriptionConfirmation", aws.ToString(input.TopicArn))
								if native == nil {
									t.Fatal("native cross-account Subscribe lacks actual confirmation receipt")
								}
								checkReceipt(collect("SubscriptionConfirmation", aws.ToString(input.TopicArn), true), native, before)
							}
						case *sns.ConfirmSubscriptionOutput:
							var want sns.ConfirmSubscriptionOutput
							awsDecodeJSON(t, normalize(row.Result.Output), &want)
							if aws.ToString(out.SubscriptionArn) != aws.ToString(want.SubscriptionArn) {
								t.Fatal("token confirmation changed subscription identity")
							}
						case *sns.PublishOutput:
							var want sns.PublishOutput
							awsDecodeJSON(t, row.Result.Output, &want)
							bind(aws.ToString(want.MessageId), aws.ToString(out.MessageId))
							native := nativeReceipt("Notification", aws.ToString(want.MessageId))
							got := collect("Notification", aws.ToString(out.MessageId), native != nil)
							if native != nil {
								checkReceipt(got, native, before)
							}
						}
						snsCrossResult(t, result, normalize(row.Result.Output), includesTopic)
					}) {
						t.FailNow()
					}
				}
			})
		}
	}
}

func snsLambdaEnvelope(t *testing.T, receipt map[string]any) (map[string]any, map[string]any) {
	t.Helper()
	event, _ := receipt["event"].(map[string]any)
	records, _ := event["Records"].([]any)
	if len(records) != 1 {
		t.Fatalf("SNS Lambda event must have one native record: %+v", receipt)
	}
	record, _ := records[0].(map[string]any)
	notification, _ := record["Sns"].(map[string]any)
	if notification == nil {
		t.Fatalf("SNS Lambda event lacks native Sns envelope: %+v", receipt)
	}
	return record, notification
}

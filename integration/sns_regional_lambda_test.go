package stackd_test

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"

	"stackd"
	"stackd/clock"
	"stackd/internal/awscatalog"
	"stackd/storage"
)

func TestSNSRegionalLambdaDockerNativeReplay(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	data, err := os.ReadFile("../testdata/aws/sns/regional_lambda.json")
	if err != nil {
		t.Fatal(err)
	}
	type observation struct {
		awsNativeObservation
		Region string
	}
	type receipt struct {
		Region, Destination string
		Message             struct{ Body string }
	}
	var fixture struct {
		Account               string
		CapturedAt            time.Time `json:"capture_started"`
		Observations, Cleanup []observation
		Receipts              []receipt
		Limitations           []string
	}
	awsDecodeJSON(t, data, &fixture)
	for _, limitation := range fixture.Limitations {
		t.Log(limitation)
	}
	notification := func(body map[string]any) (map[string]any, map[string]any) {
		if _, executed := body["event"]; executed {
			return snsLambdaEnvelope(t, body)
		}
		return nil, body
	}
	nativeDeliveries := map[string][]receipt{}
	for _, captured := range fixture.Receipts {
		var body map[string]any
		awsDecodeJSON(t, []byte(captured.Message.Body), &body)
		_, event := notification(body)
		id := fmt.Sprint(event["MessageId"])
		nativeDeliveries[id] = append(nativeDeliveries[id], captured)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sns-regional-lambda.sqlite"))
			}
			source := clock.NewManual(fixture.CapturedAt.Truncate(time.Millisecond))
			cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, Clock: source}, nil)
			clients := cloudClients{server}
			endpoint := strings.Replace(server.URL, "127.0.0.1", "host.docker.internal", 1)
			clientFor := func(service, region string) any {
				switch service {
				case "sns":
					return admissionSNSClient(clients, fixture.Account, region)
				case "sqs":
					options := clients.sqs(fixture.Account, "test", "").Options()
					options.Region = region
					return sqs.New(options)
				case "lambda":
					return awslambda.New(awslambda.Options{Region: region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
				case "iam":
					return clients.iam(fixture.Account, "test", "")
				case "logs":
					options := logsClient(clients, fixture.Account).Options()
					options.Region = region
					return cloudwatchlogs.New(options)
				default:
					t.Fatalf("unsupported regional service: %s", service)
					return nil
				}
			}
			enabled := map[string]bool{}
			for _, row := range fixture.Observations {
				if !enabled[row.Region] && awscatalog.CommercialRegionRequiresOptIn(row.Region) {
					enableAccountRegion(t, clients, source, fixture.Account, row.Region)
					enabled[row.Region] = true
				}
			}
			queueURLs, subscriptions := map[string]string{}, map[string]string{}
			requests, publications, functionRegions := map[string]bool{}, map[string]bool{}, map[string]bool{}
			prepare := func(value any) {
				switch input := value.(type) {
				case *awslambda.CreateFunctionInput:
					// Preserve captured code and configuration; only local network addresses change.
					input.Environment.Variables["COLLECTOR_URL"] = strings.Replace(queueURLs[input.Environment.Variables["COLLECTOR_URL"]], "127.0.0.1", "host.docker.internal", 1)
					input.Environment.Variables["AWS_ENDPOINT_URL"] = endpoint
				case *sqs.GetQueueAttributesInput:
					input.QueueUrl = aws.String(queueURLs[aws.ToString(input.QueueUrl)])
				case *sqs.SetQueueAttributesInput:
					input.QueueUrl = aws.String(queueURLs[aws.ToString(input.QueueUrl)])
				case *sqs.DeleteQueueInput:
					input.QueueUrl = aws.String(queueURLs[aws.ToString(input.QueueUrl)])
				case *sns.GetSubscriptionAttributesInput:
					input.SubscriptionArn = aws.String(subscriptions[aws.ToString(input.SubscriptionArn)])
				case *sns.UnsubscribeInput:
					input.SubscriptionArn = aws.String(subscriptions[aws.ToString(input.SubscriptionArn)])
				}
			}
			for _, row := range fixture.Observations {
				// Account observations establish native prerequisites. IAM propagation
				// samples and receive polling do not define a local latency contract.
				if row.Service == "sts" || row.Service == "account" || row.Service == "probe" || row.Operation == "receive-message" || row.Operation == "delete-message" || row.Operation == "get-function-configuration" || row.Operation == "create-function" && row.Result.Code != "Success" {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					client := clientFor(row.Service, row.Region)
					out := snsControlReplay(t, client, row.awsNativeObservation, prepare)
					if row.Result.Code != "Success" {
						return
					}
					switch output := out.(type) {
					case *sns.CreateTopicOutput:
						var native sns.CreateTopicOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						if aws.ToString(output.TopicArn) != aws.ToString(native.TopicArn) {
							t.Fatal("source topic identity differs from native")
						}
					case *sqs.CreateQueueOutput:
						var native sqs.CreateQueueOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						queueURLs[aws.ToString(native.QueueUrl)] = aws.ToString(output.QueueUrl)
					case *sqs.GetQueueAttributesOutput:
						var native sqs.GetQueueAttributesOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						if output.Attributes["QueueArn"] != native.Attributes["QueueArn"] {
							t.Fatal("queue escaped its native account/Region")
						}
					case *awslambda.CreateFunctionOutput:
						var native awslambda.CreateFunctionOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						if aws.ToString(output.FunctionArn) != aws.ToString(native.FunctionArn) {
							t.Fatal("function escaped its destination account/Region")
						}
						functionRegions[row.Region] = true
						if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: output.FunctionName}, time.Minute); err != nil {
							t.Fatal(err)
						}
					case *awslambda.CreateAliasOutput:
						var native awslambda.CreateAliasOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						if aws.ToString(output.AliasArn) != aws.ToString(native.AliasArn) || aws.ToString(output.FunctionVersion) != aws.ToString(native.FunctionVersion) {
							t.Fatal("alias lost destination or version identity")
						}
					case *sns.SubscribeOutput:
						var native sns.SubscribeOutput
						var input sns.SubscribeInput
						awsDecodeJSON(t, row.Result.Output, &native)
						awsDecodeJSON(t, row.Input, &input)
						prefix := aws.ToString(input.TopicArn) + ":"
						if !strings.HasPrefix(aws.ToString(output.SubscriptionArn), prefix) {
							t.Fatal("subscription escaped source topic scope")
						}
						if _, err := uuid.Parse(strings.TrimPrefix(aws.ToString(output.SubscriptionArn), prefix)); err != nil {
							t.Fatal(err)
						}
						subscriptions[aws.ToString(native.SubscriptionArn)] = aws.ToString(output.SubscriptionArn)
					case *sns.GetSubscriptionAttributesOutput:
						var native sns.GetSubscriptionAttributesOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						for _, key := range []string{"TopicArn", "Endpoint", "Protocol", "Owner", "RedrivePolicy"} {
							if want, exists := native.Attributes[key]; exists {
								snsRegionalSQSAttribute(t, key, output.Attributes[key], want)
							}
						}
						if output.Attributes["SubscriptionArn"] != subscriptions[native.Attributes["SubscriptionArn"]] {
							t.Fatal("subscription readback lost source identity")
						}
					case *sns.PublishOutput:
						var native sns.PublishOutput
						var input sns.PublishInput
						awsDecodeJSON(t, row.Result.Output, &native)
						awsDecodeJSON(t, row.Input, &input)
						id := aws.ToString(output.MessageId)
						if _, err := uuid.Parse(id); err != nil || publications[id] {
							t.Fatalf("invalid/reused publication ID: %q", id)
						}
						publications[id] = true
						wanted := map[string][]receipt{}
						for _, delivery := range nativeDeliveries[aws.ToString(native.MessageId)] {
							wanted[delivery.Destination] = append(wanted[delivery.Destination], delivery)
						}
						if len(wanted) == 0 {
							t.Fatalf("missing native delivery for %s", row.Label)
						}
						for queue, deliveries := range wanted {
							consumer := &lambdaEventsCloud{cloud: cloud, server: server, queues: clientFor("sqs", deliveries[0].Region).(*sqs.Client)}
							messages := lambdaEventsReceive(t, consumer, aws.String(queueURLs[queue]), len(deliveries))
							matched := map[int]bool{}
							for _, message := range messages {
								var got map[string]any
								awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &got)
								actualRecord, actualSNS := notification(got)
								certKey, unsubscribeKey := "SigningCertURL", "UnsubscribeURL"
								if actualRecord != nil {
									certKey, unsubscribeKey = "SigningCertUrl", "UnsubscribeUrl"
								}
								unsubscribe, err := url.Parse(fmt.Sprint(actualSNS[unsubscribeKey]))
								if err != nil || unsubscribe.Scheme+"://"+unsubscribe.Host != endpoint || unsubscribe.Path != "/" || unsubscribe.Query().Get("Action") != "Unsubscribe" {
									t.Fatalf("invalid source unsubscribe URL: %v", actualSNS[unsubscribeKey])
								}
								found := -1
								for index, delivery := range deliveries {
									var want map[string]any
									awsDecodeJSON(t, []byte(delivery.Message.Body), &want)
									nativeRecord, nativeSNS := notification(want)
									nativeURL, err := url.Parse(fmt.Sprint(nativeSNS[unsubscribeKey]))
									if err != nil {
										t.Fatal(err)
									}
									if unsubscribe.Query().Get("SubscriptionArn") != subscriptions[nativeURL.Query().Get("SubscriptionArn")] {
										continue
									}
									if (actualRecord == nil) != (nativeRecord == nil) {
										t.Fatal("delivery changed between execution and source dead-lettering")
									}
									if actualRecord != nil {
										request := fmt.Sprint(got["request_id"])
										if _, err := uuid.Parse(request); err != nil || requests[request] {
											t.Fatalf("invalid/reused actual runtime request ID: %s", request)
										}
										requests[request] = true
										if got["runtime_aws_region"] != want["runtime_aws_region"] || got["invoked_function_arn"] != want["invoked_function_arn"] || actualRecord["EventSubscriptionArn"] != subscriptions[fmt.Sprint(nativeRecord["EventSubscriptionArn"])] {
											t.Fatalf("runtime lost regional identity: %+v", got)
										}
										got["request_id"] = want["request_id"]
										actualRecord["EventSubscriptionArn"] = nativeRecord["EventSubscriptionArn"]
									}
									if actualSNS["TopicArn"] != aws.ToString(input.TopicArn) || actualSNS["MessageId"] != id {
										t.Fatalf("delivery lost source publication identity: %+v", actualSNS)
									}
									stamp, err := time.Parse(time.RFC3339Nano, fmt.Sprint(actualSNS["Timestamp"]))
									if err != nil || !stamp.Equal(source.Now()) {
										t.Fatalf("publication timestamp changed: %v", actualSNS["Timestamp"])
									}
									snsVerifySignature(t, actualSNS, endpoint, server.URL)
									for _, key := range []string{certKey, unsubscribeKey} {
										nativeURL, err := url.Parse(fmt.Sprint(nativeSNS[key]))
										if err != nil || nativeURL.Host != "sns."+row.Region+".amazonaws.com" {
											t.Fatalf("native URL lost source Region: %v", nativeSNS[key])
										}
									}
									for _, key := range []string{"MessageId", "Timestamp", "Signature", certKey, unsubscribeKey} {
										actualSNS[key] = nativeSNS[key]
									}
									if !reflect.DeepEqual(got, want) {
										t.Fatalf("regional receipt differs from native:\ngot: %#v\nnative: %#v", got, want)
									}
									found = index
									break
								}
								if found < 0 {
									t.Fatalf("unexpected regional delivery: %+v", got)
								}
								matched[found] = true
							}
							if len(matched) != len(deliveries) {
								t.Fatalf("missing native regional outcomes: got %d, want %d", len(matched), len(deliveries))
							}
						}
					}
				}) {
					t.FailNow()
				}
			}
			for region := range functionRegions {
				if awscatalog.CommercialRegionRequiresOptIn(region) {
					enableAccountRegion(t, clients, source, "111122223333", region)
				}
				options := clientFor("lambda", region).(*awslambda.Client).Options()
				options.Credentials = credentials.NewStaticCredentialsProvider("111122223333", "test", "")
				listed, err := awslambda.New(options).ListFunctions(t.Context(), &awslambda.ListFunctionsInput{})
				if err != nil {
					t.Fatal(err)
				}
				if len(listed.Functions) != 0 {
					t.Fatalf("function leaked into another account: %+v", listed.Functions)
				}
			}
			for _, row := range fixture.Cleanup {
				if row.Service == "sts" {
					continue
				}
				snsControlReplay(t, clientFor(row.Service, row.Region), row.awsNativeObservation, prepare)
			}
		})
	}
}

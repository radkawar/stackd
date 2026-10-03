package stackd_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type snsTraceCase struct {
	Label, Kind, Phase string
	Header             *string
	Batch              bool
	Deliveries         map[string][]sqstypes.Message
}

type snsTraceCapture struct {
	snsAdmissionFixture
	Cases     []snsTraceCase
	Resources struct {
		Topics map[string]string
		Queues map[string]struct{ Name, URL, ARN string }
	}
}

type snsTraceFixture struct {
	snsTraceCapture
	PassThrough snsTraceCapture `json:"passthrough_supplement"`
}

func snsTracingNative(t *testing.T) snsTraceFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/sns/tracing.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture snsTraceFixture
	awsDecodeJSON(t, data, &fixture)
	return fixture
}

func snsTracingClient(client *sns.Client, header *string) *sns.Client {
	return sns.New(client.Options(), func(options *sns.Options) {
		if header != nil {
			options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
				return stack.Build.Add(middleware.BuildMiddlewareFunc("SNSTraceHeader", func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
					in.Request.(*smithyhttp.Request).Header.Set("X-Amzn-Trace-Id", *header)
					return next.HandleBuild(ctx, in)
				}), middleware.After)
			})
		}
	})
}

// Use the native setup and inputs, but not Active transitions: the original
// capture's misleading "passive" labels actually refer to Active topics. Only
// the finalized supplement supplies default/PassThrough delivery expectations.
func snsTracingSetup(t *testing.T, clients cloudClients, capture snsTraceCapture) {
	t.Helper()
	topics, queues := admissionSNSClient(clients, capture.Account, capture.Region), clients.sqs(capture.Account, "test", "")
	urls := map[string]string{}
	for _, row := range capture.Observations {
		switch row.Operation {
		case "create-topic", "subscribe":
			snsControlReplay(t, topics, row)
		case "create-queue":
			out := snsControlReplay(t, queues, row).(*sqs.CreateQueueOutput)
			var native sqs.CreateQueueOutput
			awsDecodeJSON(t, row.Result.Output, &native)
			urls[aws.ToString(native.QueueUrl)] = aws.ToString(out.QueueUrl)
		case "set-queue-attributes":
			snsControlReplay(t, queues, row, func(input any) {
				in := input.(*sqs.SetQueueAttributesInput)
				in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
			})
		}
	}
}

func snsTracingAttributes(t *testing.T, topics *sns.Client, arn string, row awsNativeObservation) {
	t.Helper()
	out, err := topics.GetTopicAttributes(t.Context(), &sns.GetTopicAttributesInput{TopicArn: &arn})
	if err != nil {
		t.Fatal(err)
	}
	var native sns.GetTopicAttributesOutput
	awsDecodeJSON(t, row.Result.Output, &native)
	got, present := out.Attributes["TracingConfig"]
	want, nativePresent := native.Attributes["TracingConfig"]
	if got != want || present != nativePresent {
		t.Fatalf("TracingConfig = %q (present %v), native %q (present %v)", got, present, want, nativePresent)
	}
}

func snsTracingPublish(t *testing.T, topics *sns.Client, capture snsTraceCapture, c snsTraceCase, arn string) map[string]string {
	t.Helper()
	row := snsControlRow(t, capture.snsAdmissionFixture, c.Label)
	out, err := awstest.CallSDK(t.Context(), snsTracingClient(topics, c.Header), row.Operation, row.Input, func(input any) {
		switch in := input.(type) {
		case *sns.PublishInput:
			in.TopicArn = &arn
		case *sns.PublishBatchInput:
			in.TopicArn = &arn
		}
	})
	awsNativeResult(t, row, err)
	ids := map[string]string{}
	switch actual := out.(type) {
	case *sns.PublishOutput:
		var native sns.PublishOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		ids[aws.ToString(actual.MessageId)] = aws.ToString(native.MessageId)
	case *sns.PublishBatchOutput:
		var native sns.PublishBatchOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		if len(actual.Successful) != len(native.Successful) || len(actual.Failed) != len(native.Failed) {
			t.Fatalf("batch admission = %+v, native %+v", actual, native)
		}
		for _, entry := range actual.Successful {
			for _, wanted := range native.Successful {
				if aws.ToString(entry.Id) == aws.ToString(wanted.Id) {
					ids[aws.ToString(entry.MessageId)] = aws.ToString(wanted.MessageId)
				}
			}
		}
	}
	return ids
}

func snsTracingReceive(t *testing.T, cloud *stackd.Stack, clients cloudClients, setup snsTraceCapture, c snsTraceCase, ids map[string]string, admissionOnly bool) {
	t.Helper()
	trailNativeDrain(t, cloud)
	queues := clients.sqs(setup.Account, "test", "")
	for _, mode := range []string{"raw", "wrapped"} {
		resource := setup.Resources.Queues[c.Kind+"-"+mode]
		url := snsRecoveryQueueURL(t, queues, resource.Name)
		var actual []sqstypes.Message
		for {
			out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: url, MaxNumberOfMessages: 10,
				MessageSystemAttributeNames: []sqstypes.MessageSystemAttributeName{sqstypes.MessageSystemAttributeNameAll}, MessageAttributeNames: []string{"All"}})
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Messages) == 0 {
				break
			}
			actual = append(actual, out.Messages...)
			for _, message := range out.Messages {
				if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: url, ReceiptHandle: message.ReceiptHandle}); err != nil {
					t.Fatal(err)
				}
			}
		}
		wanted := c.Deliveries[mode]
		if len(actual) != len(wanted) {
			t.Fatalf("%s %s: got %d deliveries, native %d", c.Label, mode, len(actual), len(wanted))
		}
		for _, native := range wanted {
			matched := false
			for _, message := range actual {
				if mode == "raw" {
					if aws.ToString(message.Body) != aws.ToString(native.Body) {
						continue
					}
				} else {
					var got, want snsAdmissionNotification
					awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &got)
					awsDecodeJSON(t, []byte(aws.ToString(native.Body)), &want)
					if ids[got.MessageId] != want.MessageId {
						continue
					}
					got.MessageId = want.MessageId
					want.TopicArn = setup.Resources.Topics[c.Kind]
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("notification = %+v, native %+v", got, want)
					}
				}
				if !reflect.DeepEqual(message.MessageAttributes, native.MessageAttributes) {
					t.Fatalf("user attributes = %+v, native %+v", message.MessageAttributes, native.MessageAttributes)
				}
				want, present := native.Attributes["AWSTraceHeader"]
				if admissionOnly && present {
					// Active evidence establishes admission, field normalization and
					// transport precedence, not PassThrough's parent. Keep the caller
					// parent rather than fabricating the native service-generated one.
					var parent string
					for _, field := range strings.Split(aws.ToString(c.Header), ";") {
						if value, ok := strings.CutPrefix(strings.TrimSpace(field), "Parent="); ok {
							parent = value
						}
					}
					fields := strings.Split(want, ";")
					for i, field := range fields {
						if strings.HasPrefix(field, "Parent=") {
							fields[i] = "Parent=" + parent
						}
					}
					want = strings.Join(fields, ";")
				}
				got, exists := message.Attributes["AWSTraceHeader"]
				if got != want || exists != present {
					t.Fatalf("%s %s: AWSTraceHeader = %q (present %v), native %q (present %v)", c.Label, mode, got, exists, want, present)
				}
				matched = true
				break
			}
			if !matched {
				t.Fatalf("missing %s native delivery: %s", mode, aws.ToString(native.Body))
			}
		}
	}
}

func TestSNSNativeTracePropagation(t *testing.T) {
	fixture := snsTracingNative(t)
	capture := fixture.PassThrough
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, _ := admissionFixtureCloud(t, backend, capture.snsAdmissionFixture)
			snsTracingSetup(t, clients, capture)
			topics := admissionSNSClient(clients, capture.Account, capture.Region)
			for _, c := range capture.Cases {
				if c.Phase != "default" && c.Phase != "passthrough" {
					continue
				}
				t.Run(c.Label, func(t *testing.T) {
					arn := capture.Resources.Topics[c.Kind]
					label := "default-" + c.Kind
					if c.Phase == "passthrough" {
						snsControlReplay(t, topics, snsControlRow(t, capture.snsAdmissionFixture, "transition-"+c.Kind+"-PassThrough"))
						label = "read-transition-" + c.Kind + "-PassThrough"
					}
					snsTracingAttributes(t, topics, arn, snsControlRow(t, capture.snsAdmissionFixture, label))
					ids := snsTracingPublish(t, topics, capture, c, arn)
					snsTracingReceive(t, cloud, clients, capture, c, ids, false)
				})
			}
			for kind, arn := range capture.Resources.Topics {
				for _, row := range fixture.Observations {
					if row.Operation != "set-topic-attributes" || row.Result.Code == "Success" || !strings.HasPrefix(row.Label, "tracing-"+kind+"-") {
						continue
					}
					snsControlSetCaptured(t, topics, arn, row)
					snsTracingAttributes(t, topics, arn, snsControlRow(t, capture.snsAdmissionFixture, "read-transition-"+kind+"-PassThrough"))
				}
				_, err := topics.SetTopicAttributes(t.Context(), &sns.SetTopicAttributesInput{TopicArn: &arn, AttributeName: aws.String("TracingConfig"), AttributeValue: aws.String("Active")})
				assertAPIError(t, err, "NotImplementedException")
				snsTracingAttributes(t, topics, arn, snsControlRow(t, capture.snsAdmissionFixture, "read-transition-"+kind+"-PassThrough"))
			}
			for _, c := range fixture.Cases {
				if !strings.Contains(c.Label, "invalid-parent") && !strings.Contains(c.Label, "invalid-sampled") && !strings.Contains(c.Label, "whitespace-extension") && !strings.Contains(c.Label, "duplicate-sampled") && !strings.Contains(c.Label, "attribute-precedence") {
					continue
				}
				t.Run(c.Label+"-admission-only", func(t *testing.T) {
					ids := snsTracingPublish(t, topics, fixture.snsTraceCapture, c, capture.Resources.Topics[c.Kind])
					snsTracingReceive(t, cloud, clients, capture, c, ids, true)
				})
			}
			c := capture.Cases[0]
			row := snsControlRow(t, capture.snsAdmissionFixture, c.Label)
			for _, scope := range []struct{ account, region, code string }{{"999999999999", capture.Region, "AuthorizationError"}, {capture.Account, "us-west-2", "InvalidParameter"}} {
				client := snsTracingClient(admissionSNSClient(clients, scope.account, scope.region), c.Header)
				_, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
				assertAPIError(t, err, scope.code)
			}
			trailNativeDrain(t, cloud)
			queues := clients.sqs(capture.Account, "test", "")
			for _, resource := range capture.Resources.Queues {
				out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: snsRecoveryQueueURL(t, queues, resource.Name)})
				if err != nil || len(out.Messages) != 0 {
					t.Fatalf("isolated publication reached queue: %+v, %v", out, err)
				}
			}
		})
	}
}

func TestSNSNativeTraceSQLiteRestart(t *testing.T) {
	capture := snsTracingNative(t).PassThrough
	path := filepath.Join(t.TempDir(), "sns-tracing.sqlite")
	backends, closeDatabase := openSQLiteBackends(t, path)
	hold := &snsRecoveryDiscovery{Repository: backends.SNS}
	hold.delivery.Store(true)
	backends.SNS = hold
	source := clock.NewManual(time.UnixMilli(capture.Observations[0].Started).UTC())
	_, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
	snsTracingSetup(t, clients, capture)
	topics := admissionSNSClient(clients, capture.Account, capture.Region)
	ids := map[string]map[string]string{}
	for _, c := range capture.Cases {
		if c.Phase != "passthrough" || !c.Batch {
			continue
		}
		snsControlReplay(t, topics, snsControlRow(t, capture.snsAdmissionFixture, "transition-"+c.Kind+"-PassThrough"))
		ids[c.Label] = snsTracingPublish(t, topics, capture, c, capture.Resources.Topics[c.Kind])
	}
	closeCloud()
	closeDatabase()
	backends, _ = openSQLiteBackends(t, path)
	cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
	topics = admissionSNSClient(clients, capture.Account, capture.Region)
	for _, c := range capture.Cases {
		if idMap, ok := ids[c.Label]; ok {
			snsTracingAttributes(t, topics, capture.Resources.Topics[c.Kind], snsControlRow(t, capture.snsAdmissionFixture, "read-transition-"+c.Kind+"-PassThrough"))
			snsTracingReceive(t, cloud, clients, capture, c, idMap, false)
		}
	}
}

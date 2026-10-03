package stackd_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"
	"stackd"
	"stackd/clock"
	"stackd/storage"
)

type snsHTTPReceipt struct {
	Header http.Header
	Body   string
	Path   string
}
type snsHTTPFixture struct {
	Account, Region string
	Observations    map[string]json.RawMessage
	Requests        []struct {
		Event struct {
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
			Path    string            `json:"rawPath"`
		} `json:"event"`
	} `json:"requests"`
}

func snsHTTPNative(t *testing.T) snsHTTPFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/sns/http_delivery.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture snsHTTPFixture
	awsDecodeJSON(t, data, &fixture)
	return fixture
}
func snsHTTPDrain(t *testing.T, cloud *stackd.Stack) {
	t.Helper()
	if out, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || out.More {
		t.Fatalf("HTTP jobs did not settle: %+v %v", out, err)
	}
}
func snsHTTPNext(t *testing.T, receipts chan snsHTTPReceipt) snsHTTPReceipt {
	t.Helper()
	select {
	case receipt := <-receipts:
		return receipt
	default:
		t.Fatal("HTTP consumer did not receive expected request")
		return snsHTTPReceipt{}
	}
}
func snsHTTPEnvelope(t *testing.T, receipt snsHTTPReceipt) map[string]any {
	t.Helper()
	var envelope map[string]any
	awsDecodeJSON(t, []byte(receipt.Body), &envelope)
	return envelope
}
func snsHTTPAnonymous(clients cloudClients, region string) *sns.Client {
	return sns.New(sns.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: aws.AnonymousCredentials{}, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
}

func TestSNSHTTPNativeLifecycleAndRetainedDelivery(t *testing.T) {
	fixture := snsHTTPNative(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			receipts := make(chan snsHTTPReceipt, 32)
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				receipts <- snsHTTPReceipt{Header: r.Header.Clone(), Body: string(body), Path: r.URL.Path}
				w.WriteHeader(200)
			}))
			defer receiver.Close()
			source := clock.NewManual(time.Date(2026, 9, 22, 19, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			closeDB := func() {}
			db := filepath.Join(t.TempDir(), "sns-http.sqlite")
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, db)
			}
			var active atomic.Pointer[stackd.Stack]
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { active.Load().ServeHTTP(w, r) }))
			defer server.Close()
			open := func() {
				cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: source, PublicEndpoint: server.URL})
				if err != nil {
					t.Fatal(err)
				}
				active.Store(cloud)
			}
			open()
			defer func() { _ = active.Load().Close(); closeDB() }()
			reopen := func() {
				t.Helper()
				if err := active.Load().Close(); err != nil {
					t.Fatal(err)
				}
				closeDB()
				if backend == "sqlite" {
					backends, closeDB = openSQLiteBackends(t, db)
				}
				open()
			}
			clients := cloudClients{server}
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			anonymous := snsHTTPAnonymous(clients, fixture.Region)
			topic, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("http-lifecycle")})
			if err != nil {
				t.Fatal(err)
			}
			input := &sns.SubscribeInput{TopicArn: topic.TopicArn, Protocol: aws.String("http"), Endpoint: aws.String(receiver.URL + "/wrapped")}
			pending, err := topics.Subscribe(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			var nativePending sns.SubscribeOutput
			awsDecodeJSON(t, fixture.Observations["subscribe"], &nativePending)
			if aws.ToString(pending.SubscriptionArn) != aws.ToString(nativePending.SubscriptionArn) {
				t.Fatalf("pending response: %+v", pending)
			}
			input.ReturnSubscriptionArn = true
			subscription, err := topics.Subscribe(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := topics.Unsubscribe(t.Context(), &sns.UnsubscribeInput{SubscriptionArn: subscription.SubscriptionArn}); snsHTTPErrorCode(err) != "InvalidParameter" {
				t.Fatalf("pending unsubscribe: %v", err)
			}
			listed, err := topics.ListSubscriptionsByTopic(t.Context(), &sns.ListSubscriptionsByTopicInput{TopicArn: topic.TopicArn})
			if err != nil || len(listed.Subscriptions) != 1 || aws.ToString(listed.Subscriptions[0].SubscriptionArn) != "PendingConfirmation" {
				t.Fatalf("pending list: %+v %v", listed, err)
			}
			if _, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: topic.TopicArn, Message: aws.String("excluded pending publication")}); err != nil {
				t.Fatal(err)
			}
			// Reopen before even the confirmation POST. This exercises retained endpoint,
			// independent tokens, signed control payloads and jobs, not an in-process send.
			reopen()
			snsHTTPDrain(t, active.Load())
			first := snsHTTPNext(t, receipts)
			second := snsHTTPNext(t, receipts)
			for _, receipt := range []snsHTTPReceipt{first, second} {
				if receipt.Header.Get("X-Amz-Sns-Message-Type") != "SubscriptionConfirmation" || receipt.Header.Get("X-Amz-Sns-Subscription-Arn") != "" {
					t.Fatalf("confirmation headers: %v", receipt.Header)
				}
			}
			select {
			case got := <-receipts:
				t.Fatalf("pending subscriber received publication: %s", got.Body)
			default:
			}
			firstEnvelope := snsHTTPEnvelope(t, first)
			secondEnvelope := snsHTTPEnvelope(t, second)
			if firstEnvelope["Token"] == secondEnvelope["Token"] {
				t.Fatal("repeated Subscribe did not issue independent confirmation tokens")
			}
			if _, err := anonymous.ConfirmSubscription(t.Context(), &sns.ConfirmSubscriptionInput{TopicArn: topic.TopicArn, Token: aws.String("invalid")}); snsHTTPErrorCode(err) != "InvalidParameter" {
				t.Fatalf("invalid token: %v", err)
			}
			confirmed, err := anonymous.ConfirmSubscription(t.Context(), &sns.ConfirmSubscriptionInput{TopicArn: topic.TopicArn, Token: aws.String(firstEnvelope["Token"].(string))})
			if err != nil || aws.ToString(confirmed.SubscriptionArn) != aws.ToString(subscription.SubscriptionArn) {
				t.Fatalf("confirm retained token: %+v %v", confirmed, err)
			}
			if _, err := anonymous.ConfirmSubscription(t.Context(), &sns.ConfirmSubscriptionInput{TopicArn: topic.TopicArn, Token: aws.String(secondEnvelope["Token"].(string))}); err != nil {
				t.Fatal("second token lost idempotency", err)
			}
			attrs, err := topics.GetSubscriptionAttributes(t.Context(), &sns.GetSubscriptionAttributesInput{SubscriptionArn: subscription.SubscriptionArn})
			if err != nil {
				t.Fatal(err)
			}
			var nativeAttrs sns.GetSubscriptionAttributesOutput
			awsDecodeJSON(t, fixture.Observations["confirmed_attributes"], &nativeAttrs)
			for _, name := range []string{"PendingConfirmation", "ConfirmationWasAuthenticated", "RawMessageDelivery"} {
				if attrs.Attributes[name] != nativeAttrs.Attributes[name] {
					t.Fatalf("%s: local %q native %q", name, attrs.Attributes[name], nativeAttrs.Attributes[name])
				}
			}
			body := "native HTTP wrapped payload"
			published, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: topic.TopicArn, Message: &body, Subject: aws.String("native subject"), MessageAttributes: map[string]snstypes.MessageAttributeValue{"kind": {DataType: aws.String("String"), StringValue: aws.String("wrapped")}}})
			if err != nil {
				t.Fatal(err)
			}
			reopen()
			snsHTTPDrain(t, active.Load())
			notification := snsHTTPNext(t, receipts)
			envelope := snsHTTPEnvelope(t, notification)
			snsVerifySignature(t, envelope, server.URL, server.URL)
			if envelope["Message"] != body || envelope["MessageId"] != aws.ToString(published.MessageId) || notification.Header.Get("X-Amz-Sns-Subscription-Arn") != aws.ToString(subscription.SubscriptionArn) || notification.Header.Get("X-Amz-Sns-Message-Id") != aws.ToString(published.MessageId) {
				t.Fatalf("retained notification: %s %v", notification.Body, notification.Header)
			}
			for _, native := range fixture.Requests {
				if native.Event.Path == "/wrapped" && native.Event.Headers["x-amz-sns-message-type"] == "Notification" && native.Event.Headers["x-amz-sns-rawdelivery"] == "" {
					var want map[string]any
					awsDecodeJSON(t, []byte(native.Event.Body), &want)
					for _, name := range []string{"Message", "Subject", "Type"} {
						if envelope[name] != want[name] {
							t.Fatalf("native %s mismatch", name)
						}
					}
					break
				}
			}
			if _, err := topics.SetSubscriptionAttributes(t.Context(), &sns.SetSubscriptionAttributesInput{SubscriptionArn: subscription.SubscriptionArn, AttributeName: aws.String("RawMessageDelivery"), AttributeValue: aws.String("true")}); err != nil {
				t.Fatal(err)
			}
			policy := `{"requestPolicy":{"headerContentType":"application/json"}}`
			if _, err := topics.SetSubscriptionAttributes(t.Context(), &sns.SetSubscriptionAttributesInput{SubscriptionArn: subscription.SubscriptionArn, AttributeName: aws.String("DeliveryPolicy"), AttributeValue: &policy}); err != nil {
				t.Fatal(err)
			}
			raw := `{"native":"raw payload"}`
			if _, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: topic.TopicArn, Message: &raw}); err != nil {
				t.Fatal(err)
			}
			snsHTTPDrain(t, active.Load())
			rawReceipt := snsHTTPNext(t, receipts)
			if rawReceipt.Body != raw || rawReceipt.Header.Get("X-Amz-Sns-Rawdelivery") != "true" || rawReceipt.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("raw request: %+v", rawReceipt)
			}
			if _, err := anonymous.Unsubscribe(t.Context(), &sns.UnsubscribeInput{SubscriptionArn: subscription.SubscriptionArn}); err != nil {
				t.Fatal(err)
			}
			snsHTTPDrain(t, active.Load())
			cancel := snsHTTPEnvelope(t, snsHTTPNext(t, receipts))
			if cancel["Type"] != "UnsubscribeConfirmation" {
				t.Fatalf("cancellation: %v", cancel)
			}
			if _, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: topic.TopicArn, Message: aws.String("excluded cancelled publication")}); err != nil {
				t.Fatal(err)
			}
			snsHTTPDrain(t, active.Load())
			select {
			case got := <-receipts:
				t.Fatalf("cancelled subscriber received publication: %s", got.Body)
			default:
			}
			if status := snsHTTPFollow(t, cancel["SubscribeURL"].(string)); status != 200 {
				t.Fatalf("cancellation public link returned %d", status)
			}
			// Expiry uses service time; no wall-clock sleep or delivery timing claim.
			expiring, err := topics.Subscribe(t.Context(), &sns.SubscribeInput{TopicArn: topic.TopicArn, Protocol: aws.String("http"), Endpoint: aws.String(receiver.URL + "/expires"), ReturnSubscriptionArn: true})
			if err != nil {
				t.Fatal(err)
			}
			snsHTTPDrain(t, active.Load())
			expiry := snsHTTPEnvelope(t, snsHTTPNext(t, receipts))
			source.Advance(48 * time.Hour)
			if _, err := anonymous.ConfirmSubscription(t.Context(), &sns.ConfirmSubscriptionInput{TopicArn: topic.TopicArn, Token: aws.String(expiry["Token"].(string))}); snsHTTPErrorCode(err) != "InvalidParameter" {
				t.Fatalf("expired token: %v", err)
			}
			snsHTTPDrain(t, active.Load())
			if _, err := topics.GetSubscriptionAttributes(t.Context(), &sns.GetSubscriptionAttributesInput{SubscriptionArn: expiring.SubscriptionArn}); snsHTTPErrorCode(err) != "NotFound" {
				t.Fatalf("expired pending subscription remained: %v", err)
			}
		})
	}
}

func TestSNSHTTPRetryAndDeadLetterBoundary(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/sns/http_metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Region, Prefix string
		Identity       struct{ Account string }
		Requests       []struct {
			Path     string
			Message  struct{ Type, Message string }
			Response struct{ StatusCode int }
		}
		Metrics map[string]map[string]struct {
			Datapoints []struct{ Sum float64 }
		}
		DLQ struct{ Messages []struct{ Body string } }
	}
	awsDecodeJSON(t, data, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for path, nativeMetrics := range fixture.Metrics {
			t.Run(backend+"/"+path, func(t *testing.T) {
				cloud, clients, source := admissionFixtureCloud(t, backend, snsAdmissionFixture{Account: fixture.Identity.Account, Region: fixture.Region, Observations: []awsNativeObservation{{Started: 1790103600000}}})
				topics := admissionSNSClient(clients, fixture.Identity.Account, fixture.Region)
				start := source.Now()
				statuses, counts := map[string]int{}, map[string]int{}
				message := ""
				for _, request := range fixture.Requests {
					if request.Path == path {
						statuses[request.Message.Type] = request.Response.StatusCode
						counts[request.Message.Type]++
						if request.Message.Type == "Notification" {
							message = request.Message.Message
						}
					}
				}
				receipts := make(chan snsHTTPReceipt, 32)
				receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					receipts <- snsHTTPReceipt{Header: r.Header.Clone(), Body: string(body), Path: r.URL.Path}
					w.WriteHeader(statuses[r.Header.Get("X-Amz-Sns-Message-Type")])
				}))
				defer receiver.Close()
				name := "http-" + path
				policy := `{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":1,"maxDelayTarget":1,"numRetries":1,"numNoDelayRetries":0,"numMinDelayRetries":1,"numMaxDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false}}`
				topic, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: &name, Attributes: map[string]string{"DeliveryPolicy": policy}})
				if err != nil {
					t.Fatal(err)
				}
				queues, queueURL, queueARN := snsControlQueue(t, clients, fixture.Identity.Account, "http-dlq", aws.ToString(topic.TopicArn))
				if _, err := topics.Subscribe(t.Context(), &sns.SubscribeInput{TopicArn: topic.TopicArn, Protocol: aws.String("http"), Endpoint: aws.String(receiver.URL), Attributes: map[string]string{"RedrivePolicy": `{"deadLetterTargetArn":"` + queueARN + `"}`}}); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					snsHTTPDrain(t, cloud)
					source.Advance(time.Second)
				}
				confirmation := snsHTTPNext(t, receipts)
				envelope := snsHTTPEnvelope(t, confirmation)
				for range counts["SubscriptionConfirmation"] - 1 {
					if repeated := snsHTTPNext(t, receipts); repeated.Body != confirmation.Body {
						t.Fatalf("confirmation retry changed body: %s", repeated.Body)
					}
				}
				if _, err := topics.ConfirmSubscription(t.Context(), &sns.ConfirmSubscriptionInput{TopicArn: topic.TopicArn, Token: aws.String(envelope["Token"].(string))}); err != nil {
					t.Fatal(err)
				}
				if counts["Notification"] > 0 {
					published, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: topic.TopicArn, Message: &message})
					if err != nil {
						t.Fatal(err)
					}
					for range 2 {
						snsHTTPDrain(t, cloud)
						source.Advance(time.Second)
					}
					first := snsHTTPNext(t, receipts)
					envelope = snsHTTPEnvelope(t, first)
					if envelope["MessageId"] != aws.ToString(published.MessageId) || envelope["Message"] != message {
						t.Fatalf("HTTP lost original publication: %s", first.Body)
					}
					for range counts["Notification"] - 1 {
						if repeated := snsHTTPNext(t, receipts); repeated.Body != first.Body {
							t.Fatalf("notification retry changed body: %s", repeated.Body)
						}
					}
				}
				wantDLQ := 0
				for _, receipt := range fixture.DLQ.Messages {
					var native struct{ TopicArn string }
					awsDecodeJSON(t, []byte(receipt.Body), &native)
					if strings.HasSuffix(native.TopicArn, ":"+fixture.Prefix+"-"+path) {
						wantDLQ++
					}
				}
				deadLetters, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10})
				if err != nil || len(deadLetters.Messages) != wantDLQ {
					t.Fatalf("HTTP %s DLQ: got %+v %v, want %d", path, deadLetters, err, wantDLQ)
				}
				for _, receipt := range deadLetters.Messages {
					var redriven map[string]any
					awsDecodeJSON(t, []byte(aws.ToString(receipt.Body)), &redriven)
					if redriven["MessageId"] != envelope["MessageId"] || redriven["Message"] != envelope["Message"] {
						t.Fatalf("DLQ lost original message: %s", aws.ToString(receipt.Body))
					}
					snsVerifySignature(t, redriven, clients.server.URL, clients.server.URL)
				}
				source.Advance(time.Minute)
				snsHTTPDrain(t, cloud)
				for metric, native := range nativeMetrics {
					statistics, err := metricsClient(clients, fixture.Identity.Account).GetMetricStatistics(t.Context(), &cloudwatch.GetMetricStatisticsInput{
						Namespace: aws.String("AWS/SNS"), MetricName: &metric,
						Dimensions: []cloudwatchtypes.Dimension{{Name: aws.String("TopicName"), Value: &name}},
						StartTime:  aws.Time(start), EndTime: aws.Time(source.Now()), Period: aws.Int32(60),
						Statistics: []cloudwatchtypes.Statistic{cloudwatchtypes.StatisticSum},
					})
					if err != nil {
						t.Fatal(err)
					}
					var got, want float64
					for _, point := range statistics.Datapoints {
						got += aws.ToFloat64(point.Sum)
					}
					for _, point := range native.Datapoints {
						want += point.Sum
					}
					if got != want {
						t.Errorf("%s: got %v, native %v", metric, got, want)
					}
				}
				select {
				case got := <-receipts:
					t.Fatalf("unexpected additional HTTP attempt: %s", got.Body)
				default:
				}
			})
		}
	}
}

// The consumer follows native public links, not an emulator token inspection API.
func snsHTTPFollow(t *testing.T, link string) int {
	t.Helper()
	parsed, err := url.Parse(link)
	if err != nil || !strings.HasPrefix(parsed.Host, "127.0.0.1:") {
		t.Fatalf("unexpected public link: %s", link)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, link, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func snsHTTPErrorCode(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}

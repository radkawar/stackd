package stackd_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

type snsFeedbackFixture struct {
	snsAdmissionFixture
	Limitations json.RawMessage
	Resources   struct{ Prefix string }
	Logs        []struct {
		Group  string
		Event  struct{ Message string }
		Events []struct{ Message string }
	}
}

type snsFeedbackLog struct {
	Group  string
	Record map[string]any
}

func snsFeedbackNative(t *testing.T, name string) snsFeedbackFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/sns/" + name + "_feedback.json")
	if err != nil {
		t.Fatal(err)
	}
	var f snsFeedbackFixture
	awsDecodeJSON(t, data, &f)
	return f
}

func (f snsFeedbackFixture) row(t *testing.T, label string) awsNativeObservation {
	t.Helper()
	return snsControlRow(t, f.snsAdmissionFixture, label)
}

func (f snsFeedbackFixture) records(t *testing.T, id, destination string) []snsFeedbackLog {
	t.Helper()
	var out []snsFeedbackLog
	seen := map[string]bool{}
	for _, group := range f.Logs {
		messages := []string{group.Event.Message}
		for _, event := range group.Events {
			messages = append(messages, event.Message)
		}
		for _, message := range messages {
			if message == "" {
				continue
			}
			var record map[string]any
			awsDecodeJSON(t, []byte(message), &record)
			n, d := record["notification"].(map[string]any), record["delivery"].(map[string]any)
			if (id != "" && n["messageId"] != id) || !strings.Contains(d["destination"].(string), destination) {
				continue
			}
			key := d["deliveryId"].(string)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, snsFeedbackLog{group.Group, record})
		}
	}
	return out
}

func snsFeedbackEvents(t *testing.T, logs *cloudwatchlogs.Client, group, id string) []snsFeedbackLog {
	t.Helper()
	var out []snsFeedbackLog
	for _, name := range []string{group, group + "/Failure"} {
		in := &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &name}
		for {
			page, err := logs.FilterLogEvents(t.Context(), in)
			if snsHTTPErrorCode(err) == "ResourceNotFoundException" {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range page.Events {
				var record map[string]any
				awsDecodeJSON(t, []byte(aws.ToString(event.Message)), &record)
				if id == "" || record["notification"].(map[string]any)["messageId"] == id {
					out = append(out, snsFeedbackLog{name, record})
				}
			}
			if page.NextToken == nil {
				break
			}
			in.NextToken = page.NextToken
		}
	}
	return out
}

// Compare native key presence as well as values, replacing only identities and
// elapsed time. The wire JSON remains independent of internal service structs.
func snsFeedbackAssert(t *testing.T, got, want snsFeedbackLog, id, destination string, provider map[string]string) {
	t.Helper()
	gn, gd := got.Record["notification"].(map[string]any), got.Record["delivery"].(map[string]any)
	wn, wd := want.Record["notification"].(map[string]any), want.Record["delivery"].(map[string]any)
	if got.Group != want.Group || gn["messageId"] != id || gd["destination"] != destination {
		t.Fatalf("feedback identity mismatch: %+v", got)
	}
	if _, err := uuid.Parse(gd["deliveryId"].(string)); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse("2006-01-02 15:04:05.000", gn["timestamp"].(string)); err != nil {
		t.Fatal(err)
	}
	if gd["dwellTimeMs"].(float64) < 0 {
		t.Fatal("negative dwell time")
	}
	gn["messageId"], gn["timestamp"] = wn["messageId"], wn["timestamp"]
	gd["deliveryId"], gd["dwellTimeMs"], gd["destination"] = wd["deliveryId"], wd["dwellTimeMs"], wd["destination"]
	if policy, present := wd["redrivePolicy"]; present {
		encoded, ok := gd["redrivePolicy"].(string)
		if !ok {
			t.Fatal("feedback omitted the JSON-string redrive policy")
		}
		var actual, native map[string]any
		awsDecodeJSON(t, []byte(encoded), &actual)
		awsDecodeJSON(t, []byte(policy.(string)), &native)
		if !reflect.DeepEqual(actual, native) {
			t.Fatalf("feedback redrive policy: got %#v, native %#v", actual, native)
		}
		gd["redrivePolicy"] = policy
	}
	if provider != nil {
		var actual, native map[string]any
		awsDecodeJSON(t, []byte(gd["providerResponse"].(string)), &actual)
		awsDecodeJSON(t, []byte(wd["providerResponse"].(string)), &native)
		// Error classes and JSON shape are public; IAM explanatory wording is not.
		if message, ok := native["ErrorMessage"]; ok {
			if _, present := actual["ErrorMessage"].(string); !present {
				t.Fatal("provider failure omitted its error message")
			}
			actual["ErrorMessage"] = message
		}
		for key, receipt := range provider {
			value, ok := actual[key].(string)
			if !ok || value == "" || (receipt != "" && value != receipt) {
				t.Fatalf("provider %s not correlated with accepted receipt: %v, receipt %q", key, actual, receipt)
			}
			if receipt == "" {
				if _, err := uuid.Parse(value); err != nil {
					t.Fatal(err)
				}
			}
			actual[key] = native[key]
		}
		if !reflect.DeepEqual(actual, native) {
			t.Fatalf("provider response: got %#v, native %#v", actual, native)
		}
		gd["providerResponse"] = wd["providerResponse"]
	}
	if !reflect.DeepEqual(got.Record, want.Record) {
		t.Fatalf("feedback projection: got %#v, native %#v", got.Record, want.Record)
	}
}

func snsFeedbackCloud(t *testing.T, backend string) (*stackd.Stack, cloudClients, *clock.Manual, func() *stackd.Stack) {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 22, 22, 0, 0, 0, time.UTC))
	backends := storage.NewMemory()
	path := filepath.Join(t.TempDir(), "sns-feedback.sqlite")
	closeDB := func() {}
	if backend == "sqlite" {
		backends, closeDB = openSQLiteBackends(t, path)
	}
	var active atomic.Pointer[stackd.Stack]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { active.Load().ServeHTTP(w, r) }))
	open := func() *stackd.Stack {
		cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: source, PublicEndpoint: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		active.Store(cloud)
		return cloud
	}
	cloud := open()
	t.Cleanup(func() { server.Close(); _ = active.Load().Close(); closeDB() })
	reopen := func() *stackd.Stack {
		t.Helper()
		if err := active.Load().Close(); err != nil {
			t.Fatal(err)
		}
		closeDB()
		if backend == "sqlite" {
			backends, closeDB = openSQLiteBackends(t, path)
		}
		return open()
	}
	return cloud, cloudClients{server}, source, reopen
}

func snsFeedbackAttributes(t *testing.T, topics *sns.Client, f snsFeedbackFixture, label string) {
	t.Helper()
	row := f.row(t, label)
	got := snsControlReplay(t, topics, row).(*sns.GetTopicAttributesOutput)
	var want sns.GetTopicAttributesOutput
	awsDecodeJSON(t, row.Result.Output, &want)
	for _, protocol := range []string{"HTTP", "SQS", "Lambda", "Firehose"} {
		for _, suffix := range []string{"SuccessFeedbackRoleArn", "FailureFeedbackRoleArn", "SuccessFeedbackSampleRate"} {
			key := protocol + suffix
			gv, gp := got.Attributes[key]
			wv, wp := want.Attributes[key]
			if gv != wv || gp != wp {
				t.Fatalf("%s %s: got %q/%t, native %q/%t", label, key, gv, gp, wv, wp)
			}
		}
	}
}

func snsFeedbackConfigurationReplay(t *testing.T, observer *sns.Client, client any, row awsNativeObservation) {
	t.Helper()
	if row.Operation != "set-topic-attributes" || row.Result.Code == "Success" {
		snsControlReplay(t, client, row)
		return
	}
	var input sns.SetTopicAttributesInput
	awsDecodeJSON(t, row.Input, &input)
	before, err := observer.GetTopicAttributes(t.Context(), &sns.GetTopicAttributesInput{TopicArn: input.TopicArn})
	if err != nil {
		t.Fatal(err)
	}
	snsControlReplay(t, client, row)
	after, err := observer.GetTopicAttributes(t.Context(), &sns.GetTopicAttributesInput{TopicArn: input.TopicArn})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Attributes, after.Attributes) {
		t.Fatalf("%s: rejected write changed topic state", row.Label)
	}
}

func TestSNSFeedbackNativeConfigurationSDK(t *testing.T) {
	f := snsFeedbackNative(t, "managed")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			_, clients, _, reopen := snsFeedbackCloud(t, backend)
			topics, roles := admissionSNSClient(clients, f.Account, f.Region), clients.iam(f.Account, "test", "")
			for _, label := range []string{"create-main-topic", "create-no-feedback-topic"} {
				snsControlReplay(t, topics, f.row(t, label))
			}
			for _, suffix := range []string{"feedback", "wrong-trust"} {
				snsControlReplay(t, roles, f.row(t, "create-role-"+f.Resources.Prefix+"-"+suffix))
			}
			snsFeedbackAttributes(t, topics, f, "default-topic-attributes")
			// No Logs policy exists yet: role admission does not preflight writes.
			for _, row := range f.Observations {
				if strings.HasPrefix(row.Label, "admission-") || strings.HasPrefix(row.Label, "configure-") {
					snsFeedbackConfigurationReplay(t, topics, topics, row)
				}
			}
			snsFeedbackAttributes(t, topics, f, "configured-zero-attributes")
			for _, label := range []string{"sample-full-SQS", "sample-full-Lambda"} {
				snsControlReplay(t, topics, f.row(t, label))
			}
			snsControlReplay(t, roles, f.row(t, "create-config-user"))
			snsControlReplay(t, roles, f.row(t, "config-user-policy"))
			key := snsControlReplay(t, roles, f.row(t, "create-config-key")).(*iam.CreateAccessKeyOutput).AccessKey
			user := clients.snsRegion(f.Region, aws.ToString(key.AccessKeyId), aws.ToString(key.SecretAccessKey), "")
			for _, step := range []struct {
				label  string
				client any
			}{
				{"user-without-passrole", user}, {"grant-user-scoped-passrole", roles}, {"user-passrole-positive-2", user},
				{"deny-user-passrole", roles}, {"user-passrole-current-deny-2", user}, {"clear-role-without-passrole", user},
			} {
				snsFeedbackConfigurationReplay(t, topics, step.client, f.row(t, step.label))
			}
			snsFeedbackAttributes(t, topics, f, "after-role-clear")
			for _, step := range []struct {
				label  string
				client any
			}{
				{"restore-role", topics}, {"clear-rate", topics}, {"restore-rate", topics},
				{"wrong-trust-after-propagation", topics}, {"change-wrong-trust-to-sns", roles}, {"fixed-trust-positive-3", topics},
				{"remove-sns-trust", roles}, {"removed-trust-current-2", topics}, {"restore-good-role-after-trust", topics},
				{"delegated-missing-role", topics}, {"user-denied-passrole-missing-role", user}, {"user-denied-passrole-wrong-trust", user},
			} {
				snsFeedbackConfigurationReplay(t, topics, step.client, f.row(t, step.label))
			}
			snsFeedbackAttributes(t, topics, f, "after-precedence-attributes")
			snsControlReplay(t, roles, f.row(t, "grant-existing-and-missing-passrole"))
			snsFeedbackConfigurationReplay(t, topics, user, f.row(t, "missing-role-passrole-positive-control-2"))
			snsFeedbackConfigurationReplay(t, topics, user, f.row(t, "missing-role-with-explicit-propagated-passrole"))
			snsControlReplay(t, topics, f.row(t, "default-rate-role-only"))
			snsFeedbackAttributes(t, topics, f, "role-without-rate-attributes")
			reopen()
			snsFeedbackAttributes(t, topics, f, "after-precedence-attributes")
			snsFeedbackAttributes(t, topics, f, "role-without-rate-attributes")
			groups, err := logsClient(clients, f.Account).DescribeLogGroups(t.Context(), &cloudwatchlogs.DescribeLogGroupsInput{LogGroupNamePrefix: aws.String("sns/")})
			if err != nil || len(groups.LogGroups) != 0 {
				t.Fatalf("configuration wrote log groups: %+v %v", groups, err)
			}
		})
	}
}

func TestSNSFeedbackNativeSQSAuthoritySDK(t *testing.T) {
	f := snsFeedbackNative(t, "managed")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, _, reopen := snsFeedbackCloud(t, backend)
			topics, roles := admissionSNSClient(clients, f.Account, f.Region), clients.iam(f.Account, "test", "")
			topic := snsControlReplay(t, topics, f.row(t, "create-main-topic")).(*sns.CreateTopicOutput)
			queues, queueURL, queueARN := snsControlQueue(t, clients, f.Account, f.Resources.Prefix+"-sqs", aws.ToString(topic.TopicArn))
			snsControlSubscribe(t, topics, aws.ToString(topic.TopicArn), queueARN)
			snsControlReplay(t, roles, f.row(t, "create-role-"+f.Resources.Prefix+"-feedback"))
			snsControlReplay(t, roles, f.row(t, "feedback-log-policy"))
			for _, label := range []string{"configure-SQS-success", "configure-SQS-failure", "configure-SQS-zero"} {
				snsControlReplay(t, topics, f.row(t, label))
			}
			group := "sns/" + f.Region + "/" + f.Account + "/" + f.Resources.Prefix
			logs := logsClient(clients, f.Account)
			publish := func(label string) string {
				t.Helper()
				row := f.row(t, label)
				out := snsControlReplay(t, topics, row).(*sns.PublishOutput)
				messages := snsAdmissionReceive(t, cloud, queues, queueURL)
				if len(messages) != 1 {
					t.Fatalf("%s: feedback authority suppressed target receipt: %+v", label, messages)
				}
				var envelope snsAdmissionNotification
				awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &envelope)
				if envelope.MessageId != aws.ToString(out.MessageId) {
					t.Fatal("queue receipt belongs to a different publication")
				}
				var native sns.PublishOutput
				awsDecodeJSON(t, row.Result.Output, &native)
				wanted := f.records(t, aws.ToString(native.MessageId), ":sqs:")
				got := snsFeedbackEvents(t, logs, group, aws.ToString(out.MessageId))
				if len(got) != len(wanted) {
					t.Fatalf("%s: got %d feedback records, native %d", label, len(got), len(wanted))
				}
				if len(got) == 1 {
					snsFeedbackAssert(t, got[0], wanted[0], aws.ToString(out.MessageId), queueARN, map[string]string{"sqsMessageId": aws.ToString(messages[0].MessageId), "sqsRequestId": ""})
				}
				return aws.ToString(out.MessageId)
			}
			publish("sample-zero")
			snsControlReplay(t, topics, f.row(t, "sample-full-SQS"))
			cloud = reopen()
			publish("sample-hundred")
			snsControlReplay(t, roles, f.row(t, "deny-feedback-write"))
			denied := publish("denied-feedback-authority")
			snsControlReplay(t, roles, f.row(t, "restore-feedback-write"))
			publish("restored-feedback-authority")
			// Existing resources need only append authority, not creation authority.
			roleName := f.Resources.Prefix + "-feedback"
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:PutLogEvents","Resource":%q}]}`, "arn:aws:logs:"+f.Region+":"+f.Account+":log-group:"+group+":*")
			if _, err := roles.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("owned-feedback"), PolicyDocument: &policy}); err != nil {
				t.Fatal(err)
			}
			publish("restored-feedback-authority")
			if got := snsFeedbackEvents(t, logs, group, denied); len(got) != 0 {
				t.Fatal("restoring Logs authority replayed historical denied feedback")
			}
			snsControlReplay(t, roles, f.row(t, "restore-feedback-write"))
			snsControlReplay(t, queues, f.row(t, "deny-queue-delivery"), func(value any) {
				value.(*sqs.SetQueueAttributesInput).QueueUrl = queueURL
			})
			row := f.row(t, "permanent-denied-targets")
			out := snsControlReplay(t, topics, row).(*sns.PublishOutput)
			if messages := snsAdmissionReceive(t, cloud, queues, queueURL); len(messages) != 0 {
				t.Fatal("denied SNS publication reached the queue")
			}
			var native sns.PublishOutput
			awsDecodeJSON(t, row.Result.Output, &native)
			want := f.records(t, aws.ToString(native.MessageId), ":sqs:")
			got := snsFeedbackEvents(t, logs, group, aws.ToString(out.MessageId))
			if len(got) != 1 || len(want) != 1 {
				t.Fatalf("permanent queue failure: got %d records, native %d", len(got), len(want))
			}
			snsFeedbackAssert(t, got[0], want[0], aws.ToString(out.MessageId), queueARN, map[string]string{})
		})
	}
}

func TestSNSFeedbackNativeHTTPAttemptsSDK(t *testing.T) {
	f := snsFeedbackNative(t, "external")
	var nativePublish sns.PublishOutput
	awsDecodeJSON(t, f.row(t, "publish-http-statuses").Result.Output, &nativePublish)
	wantedNotifications := f.records(t, aws.ToString(nativePublish.MessageId), "https://")
	statuses := map[string]int{}
	for _, record := range wantedNotifications {
		d := record.Record["delivery"].(map[string]any)
		u, err := url.Parse(d["destination"].(string))
		if err != nil {
			t.Fatal(err)
		}
		statuses[u.Path] = int(d["statusCode"].(float64))
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, source, reopen := snsFeedbackCloud(t, backend)
			receipts := make(chan snsHTTPReceipt, 64)
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				receipts <- snsHTTPReceipt{Header: r.Header.Clone(), Body: string(body), Path: r.URL.Path}
				if r.Header.Get("x-amz-sns-message-type") == "UnsubscribeConfirmation" {
					// Dwell ends at handoff, not when the endpoint responds.
					source.Advance(2 * time.Second)
				}
				status := statuses[r.URL.Path]
				if r.Header.Get("x-amz-sns-message-type") != "Notification" {
					status = 200
					if r.URL.Path == "/confirm503" {
						status = 503
					}
				}
				w.WriteHeader(status)
			}))
			defer receiver.Close()
			topics, roles := admissionSNSClient(clients, f.Account, f.Region), clients.iam(f.Account, "test", "")
			for _, label := range []string{"create-logs", "policy-logs"} {
				snsControlReplay(t, roles, f.row(t, label))
			}
			topic := snsControlReplay(t, topics, f.row(t, "create-topic-http"), func(value any) {
				// Keep the captured attempt count but leave one pending deadline to
				// exercise retention instead of racing an immediate worker retry.
				in := value.(*sns.CreateTopicInput)
				in.Attributes["DeliveryPolicy"] = `{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":1,"maxDelayTarget":1,"numRetries":1,"numNoDelayRetries":0,"numMinDelayRetries":1,"numMaxDelayRetries":0,"backoffFunction":"linear"}}}`
			}).(*sns.CreateTopicOutput)
			snsControlQueue(t, clients, f.Account, f.Resources.Prefix, aws.ToString(topic.TopicArn))
			logs := logsClient(clients, f.Account)
			group := "sns/" + f.Region + "/" + f.Account + "/" + f.Resources.Prefix + "-http"
			subscriptions := map[string]*string{}
			for _, row := range f.Observations {
				if !strings.HasPrefix(row.Label, "subscribe-http-") {
					continue
				}
				var in sns.SubscribeInput
				awsDecodeJSON(t, row.Input, &in)
				nativeEndpoint := aws.ToString(in.Endpoint)
				path, err := url.Parse(nativeEndpoint)
				if err != nil {
					t.Fatal(err)
				}
				subscription := snsControlReplay(t, topics, row, func(value any) {
					input := value.(*sns.SubscribeInput)
					input.Protocol, input.Endpoint = aws.String("http"), aws.String(receiver.URL+path.Path)
				}).(*sns.SubscribeOutput)
				subscriptions[path.Path] = subscription.SubscriptionArn
				snsHTTPDrain(t, cloud)
				receipt := snsHTTPNext(t, receipts)
				envelope := snsHTTPEnvelope(t, receipt)
				id := envelope["MessageId"].(string)
				var wanted []snsFeedbackLog
				for _, record := range f.records(t, "", nativeEndpoint) {
					n := record.Record["notification"].(map[string]any)
					if _, notification := n["messageMD5Sum"]; notification {
						continue
					}
					if len(wanted) == 0 || n["messageId"] == wanted[0].Record["notification"].(map[string]any)["messageId"] {
						wanted = append(wanted, record)
					}
				}
				if len(wanted) == 0 {
					t.Fatalf("no captured confirmation feedback for %s", path.Path)
				}
				if len(wanted) > 1 {
					cloud = reopen()
					advanceClock(t, source, time.Second)
					snsHTTPDrain(t, cloud)
					retry := snsHTTPEnvelope(t, snsHTTPNext(t, receipts))
					if retry["MessageId"] != id {
						t.Fatal("retained confirmation retry changed message identity")
					}
				}
				snsFeedbackMatchHTTP(t, snsFeedbackEvents(t, logs, group, id), wanted, id, receiver.URL)
				link, _ := envelope["SubscribeURL"].(string)
				if status := snsHTTPFollow(t, link); status != 200 {
					t.Fatalf("public confirmation returned %d", status)
				}
			}
			out := snsControlReplay(t, topics, f.row(t, "publish-http-statuses")).(*sns.PublishOutput)
			snsHTTPDrain(t, cloud)
			cloud = reopen()
			advanceClock(t, source, time.Second)
			snsHTTPDrain(t, cloud)
			seenRequests := map[string]int{}
			for len(receipts) != 0 {
				receipt := snsHTTPNext(t, receipts)
				if receipt.Header.Get("x-amz-sns-message-id") != aws.ToString(out.MessageId) {
					t.Fatal("HTTP attempt lost publication ID")
				}
				seenRequests[receipt.Path]++
			}
			wantRequests := map[string]int{}
			for _, wanted := range wantedNotifications {
				u, _ := url.Parse(wanted.Record["delivery"].(map[string]any)["destination"].(string))
				wantRequests[u.Path]++
			}
			if !reflect.DeepEqual(seenRequests, wantRequests) {
				t.Fatalf("actual endpoint attempts: got %v, native %v", seenRequests, wantRequests)
			}
			snsFeedbackMatchHTTP(t, snsFeedbackEvents(t, logs, group, aws.ToString(out.MessageId)), wantedNotifications, aws.ToString(out.MessageId), receiver.URL)
			if _, err := snsHTTPAnonymous(clients, f.Region).Unsubscribe(t.Context(), &sns.UnsubscribeInput{SubscriptionArn: subscriptions["/200"]}); err != nil {
				t.Fatal(err)
			}
			snsHTTPDrain(t, cloud)
			cancelled := snsHTTPEnvelope(t, snsHTTPNext(t, receipts))
			if cancelled["Type"] != "UnsubscribeConfirmation" {
				t.Fatal("endpoint did not receive cancellation")
			}
			var cancellation snsFeedbackLog
			for _, record := range f.records(t, "", "/200") {
				if _, notification := record.Record["notification"].(map[string]any)["messageMD5Sum"]; !notification {
					cancellation = record
				}
			}
			cancellationID := cancelled["MessageId"].(string)
			cancelledLogs := snsFeedbackEvents(t, logs, group, cancellationID)
			if len(cancelledLogs) == 1 && cancelledLogs[0].Record["delivery"].(map[string]any)["dwellTimeMs"].(float64) >= 2000 {
				t.Fatal("feedback dwell included the consumer's response time")
			}
			snsFeedbackMatchHTTP(t, cancelledLogs, []snsFeedbackLog{cancellation}, cancellationID, receiver.URL)
		})
	}
}

func snsFeedbackMatchHTTP(t *testing.T, got, wanted []snsFeedbackLog, id, endpoint string) {
	t.Helper()
	if len(got) != len(wanted) {
		t.Fatalf("HTTP feedback count: got %d, native %d", len(got), len(wanted))
	}
	key := func(record snsFeedbackLog) string {
		d := record.Record["delivery"].(map[string]any)
		u, _ := url.Parse(d["destination"].(string))
		return u.Path + "/" + fmt.Sprint(d["attempts"])
	}
	remaining := map[string]snsFeedbackLog{}
	for _, record := range wanted {
		remaining[key(record)] = record
	}
	ids := map[string]bool{}
	for _, record := range got {
		d := record.Record["delivery"].(map[string]any)
		deliveryID := d["deliveryId"].(string)
		if ids[deliveryID] {
			t.Fatal("HTTP attempts reused a delivery ID")
		}
		ids[deliveryID] = true
		k := key(record)
		native, ok := remaining[k]
		if !ok {
			t.Fatalf("unexpected HTTP feedback %s", k)
		}
		u, _ := url.Parse(d["destination"].(string))
		snsFeedbackAssert(t, record, native, id, endpoint+u.Path, nil)
		delete(remaining, k)
	}
}

func TestSNSFeedbackNativeLambdaReceiptsSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	f := snsFeedbackNative(t, "managed")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sns-feedback-lambda.sqlite"))
			}
			cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends}, nil)
			clients := cloudClients{server}
			topics, roles := admissionSNSClient(clients, f.Account, f.Region), clients.iam(f.Account, "test", "")
			queues := clients.sqs(f.Account, "test", "")
			functions := awslambda.New(awslambda.Options{Region: f.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(f.Account, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			snsControlReplay(t, topics, f.row(t, "create-main-topic"))
			queue := snsControlReplay(t, queues, f.row(t, "create-receipts")).(*sqs.CreateQueueOutput)
			for _, suffix := range []string{"feedback", "lambda"} {
				snsControlReplay(t, roles, f.row(t, "create-role-"+f.Resources.Prefix+"-"+suffix))
			}
			for _, label := range []string{"feedback-log-policy", "receiver-send-policy"} {
				snsControlReplay(t, roles, f.row(t, label))
			}
			function := snsControlReplay(t, functions, f.row(t, "create-lambda-2"), func(value any) {
				in := value.(*awslambda.CreateFunctionInput)
				in.Environment.Variables["QUEUE_URL"] = strings.Replace(aws.ToString(queue.QueueUrl), "127.0.0.1", "host.docker.internal", 1)
				in.Environment.Variables["AWS_ENDPOINT_URL"] = strings.Replace(server.URL, "127.0.0.1", "host.docker.internal", 1)
			}).(*awslambda.CreateFunctionOutput)
			if err := awslambda.NewFunctionActiveWaiter(functions, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: function.FunctionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			snsControlReplay(t, functions, f.row(t, "restore-lambda-delivery-permission"))
			snsControlReplay(t, topics, f.row(t, "subscribe-lambda-"+f.Resources.Prefix))
			for _, label := range []string{"configure-Lambda-success", "configure-Lambda-failure", "configure-Lambda-zero"} {
				snsControlReplay(t, topics, f.row(t, label))
			}
			consumer := &lambdaEventsCloud{cloud: cloud, server: server, lambda: functions, queues: queues, outputURL: queue.QueueUrl, functionName: function.FunctionName, functionARN: aws.ToString(function.FunctionArn)}
			logs := logsClient(clients, f.Account)
			group := "sns/" + f.Region + "/" + f.Account + "/" + f.Resources.Prefix
			for _, label := range []string{"sample-zero", "sample-hundred", "denied-feedback-authority", "restored-feedback-authority"} {
				switch label {
				case "sample-hundred":
					snsControlReplay(t, topics, f.row(t, "sample-full-Lambda"))
				case "denied-feedback-authority":
					snsControlReplay(t, roles, f.row(t, "deny-feedback-write"))
				case "restored-feedback-authority":
					snsControlReplay(t, roles, f.row(t, "restore-feedback-write"))
				}
				row := f.row(t, label)
				published := snsControlReplay(t, topics, row).(*sns.PublishOutput)
				messages := lambdaEventsReceive(t, consumer, queue.QueueUrl, 1)
				var receipt map[string]any
				awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &receipt)
				_, notification := snsLambdaEnvelope(t, receipt)
				if notification["MessageId"] != aws.ToString(published.MessageId) {
					t.Fatal("Lambda receipt belongs to a different publication")
				}
				request, _ := receipt["handler_request_id"].(string)
				if request == "" {
					t.Fatalf("runtime receipt has no context.aws_request_id: %#v", receipt)
				}
				snsHTTPDrain(t, cloud)
				var native sns.PublishOutput
				awsDecodeJSON(t, row.Result.Output, &native)
				want := f.records(t, aws.ToString(native.MessageId), ":lambda:")
				got := snsFeedbackEvents(t, logs, group, aws.ToString(published.MessageId))
				if len(got) != len(want) {
					t.Fatalf("%s: got %d Lambda feedback records, native %d", label, len(got), len(want))
				}
				if len(got) == 1 {
					snsFeedbackAssert(t, got[0], want[0], aws.ToString(published.MessageId), aws.ToString(function.FunctionArn), map[string]string{"lambdaRequestId": request})
				}
			}
			snsControlReplay(t, functions, f.row(t, "remove-lambda-delivery-permission"))
			row := f.row(t, "permanent-denied-targets")
			published := snsControlReplay(t, topics, row).(*sns.PublishOutput)
			if messages := snsAdmissionReceive(t, cloud, queues, queue.QueueUrl); len(messages) != 0 {
				t.Fatal("denied SNS publication executed customer code")
			}
			var native sns.PublishOutput
			awsDecodeJSON(t, row.Result.Output, &native)
			want := f.records(t, aws.ToString(native.MessageId), ":lambda:")
			got := snsFeedbackEvents(t, logs, group, aws.ToString(published.MessageId))
			if len(got) != 1 || len(want) != 1 {
				t.Fatalf("permanent Lambda failure: got %d records, native %d", len(got), len(want))
			}
			snsFeedbackAssert(t, got[0], want[0], aws.ToString(published.MessageId), aws.ToString(function.FunctionArn), map[string]string{})
		})
	}
}

func TestSNSFeedbackNativeFirehoseSDK(t *testing.T) {
	f := snsFeedbackNative(t, "external")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, source, _ := snsFeedbackCloud(t, backend)
			topics, roles := admissionSNSClient(clients, f.Account, f.Region), clients.iam(f.Account, "test", "")
			streams, objects := clients.firehose(f.Account, "test", ""), s3NativeClient(clients, f.Account, "test")
			var streamARN string
			for _, row := range f.Observations {
				var client any
				switch row.Service {
				case "s3api":
					if row.Label == "create-bucket" {
						client = objects
					}
				case "iam":
					switch row.Label {
					case "create-logs", "policy-logs", "create-stream", "policy-stream", "create-producer", "policy-producer":
						client = roles
					}
				case "firehose":
					if row.Operation == "create-delivery-stream" {
						client = streams
					}
				}
				if client == nil {
					continue
				}
				out := snsControlReplay(t, client, row)
				if created, ok := out.(*firehose.CreateDeliveryStreamOutput); ok {
					streamARN = aws.ToString(created.DeliveryStreamARN)
				}
			}
			awaitFirehoseActive(t, source, streams, f.Resources.Prefix)
			topic := snsControlReplay(t, topics, f.row(t, "create-topic-firehose")).(*sns.CreateTopicOutput)
			snsControlQueue(t, clients, f.Account, f.Resources.Prefix, aws.ToString(topic.TopicArn))
			subscription := snsControlReplay(t, topics, f.row(t, "subscribe-firehose")).(*sns.SubscribeOutput)
			logs := logsClient(clients, f.Account)
			group := "sns/" + f.Region + "/" + f.Account + "/" + f.Resources.Prefix + "-firehose"
			for _, label := range []string{"publish-firehose-success", "publish-firehose-denied", "publish-firehose-restored", "publish-firehose-raw"} {
				switch label {
				case "publish-firehose-denied":
					snsControlReplay(t, roles, f.row(t, "deny-current-firehose-authority"))
				case "publish-firehose-restored":
					snsControlReplay(t, roles, f.row(t, "restore-current-firehose-authority"))
				case "publish-firehose-raw":
					snsControlReplay(t, topics, f.row(t, "raw-firehose"), func(value any) {
						value.(*sns.SetSubscriptionAttributesInput).SubscriptionArn = subscription.SubscriptionArn
					})
				}
				row := f.row(t, label)
				var input sns.PublishInput
				awsDecodeJSON(t, row.Input, &input)
				out := snsControlReplay(t, topics, row).(*sns.PublishOutput)
				snsHTTPDrain(t, cloud)
				advanceClock(t, source, time.Second)
				snsHTTPDrain(t, cloud)
				var native sns.PublishOutput
				awsDecodeJSON(t, row.Result.Output, &native)
				wanted := f.records(t, aws.ToString(native.MessageId), ":firehose:")
				got := snsFeedbackEvents(t, logs, group, aws.ToString(out.MessageId))
				if len(got) != 1 || len(wanted) != 1 {
					t.Fatalf("%s: feedback count got %d, native %d", label, len(got), len(wanted))
				}
				success := wanted[0].Record["status"] == "SUCCESS"
				provider := map[string]string{}
				if success {
					provider["firehoseRequestId"] = ""
				}
				snsFeedbackAssert(t, got[0], wanted[0], aws.ToString(out.MessageId), streamARN, provider)
				found := false
				for _, body := range firehoseConsumerObjects(t, objects, f.Resources.Prefix, "records/") {
					if strings.Contains(string(body), aws.ToString(input.Message)) {
						if label != "publish-firehose-raw" && !strings.Contains(string(body), aws.ToString(out.MessageId)) {
							t.Fatal("Firehose effect lost SNS message identity")
						}
						found = true
					}
				}
				if found != success {
					t.Fatalf("%s: real S3 delivery=%t, native feedback success=%t", label, found, success)
				}
			}
		})
	}
}

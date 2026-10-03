package stackd_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	pipeapi "github.com/aws/aws-sdk-go-v2/service/pipes"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
	kinesisengine "stackd/engine/kinesis"
	"stackd/internal/awstest"
	pipestore "stackd/storage/pipes"
)

type pipeDestinationCloud struct {
	*apiDestinationCloud
	pipes pipestore.Repository
}

func newPipeDestinationCloud(t *testing.T, backend string, outbound *http.Client, runtime kinesisengine.Runtime) *pipeDestinationCloud {
	t.Helper()
	r := &pipeDestinationCloud{apiDestinationCloud: &apiDestinationCloud{source: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))}}
	r.clients, r.reopen = retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: r.source, OutboundHTTP: outbound, KinesisRuntime: runtime}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		r.repository, r.pipes = config.Storage.EventBridge, config.Storage.Pipes
		cloud, server := startPublicCloud(t, config)
		r.cloud = cloud
		return cloud, server
	})
	return r
}

func (r *pipeDestinationCloud) pipeCall(t *testing.T, operation string, input any) any {
	t.Helper()
	client := pipeapi.New(pipeapi.Options{Region: "us-east-1", BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	out, err := awstest.CallSDK(t.Context(), client, operation, body)
	if err != nil {
		t.Fatal(operation, err)
	}
	return out
}

func (r *pipeDestinationCloud) pipeState(t *testing.T, name string) (pipestore.PipeRecord, []pipestore.Work, []pipestore.Checkpoint) {
	t.Helper()
	var pipe pipestore.PipeRecord
	var work []pipestore.Work
	var checkpoints []pipestore.Checkpoint
	err := r.pipes.View(t.Context(), func(reader pipestore.Reader) error {
		var err error
		pipe, err = reader.Pipe(pipestore.Key{Scope: pipestore.Scope{Partition: "aws", AccountID: eventDeliveryAccount, Region: "us-east-1"}, Name: name})
		if err != nil {
			return err
		}
		work, err = reader.Work(pipe.ID)
		if err == nil {
			checkpoints, err = reader.Checkpoints(pipe.ID)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return pipe, work, checkpoints
}

func (r *pipeDestinationCloud) waitPipe(t *testing.T, name string, advance bool, ready func(pipestore.PipeRecord, []pipestore.Work, []pipestore.Checkpoint) bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r.drain(t)
		p, work, checkpoints := r.pipeState(t, name)
		if ready(p, work, checkpoints) {
			return
		}
		if advance {
			inFlight := false
			for _, w := range work {
				inFlight = inFlight || w.Phase == "executing"
			}
			if !inFlight {
				advanceClock(t, r.source, 100*time.Millisecond)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	p, work, _ := r.pipeState(t, name)
	for _, w := range work {
		t.Logf("record=%s phase=%s due=%v attempts=%d error=%s", w.RecordID, w.Phase, w.Due, w.Attempts, w.LastError)
	}
	t.Fatalf("pipe did not reach expected consumer state: state=%s reason=%s now=%v due=%v", p.State, p.Reason, r.source.Now(), p.Due)
}

func (r *pipeDestinationCloud) createStreamPipe(t *testing.T, name, stream, destination string, retries, age, parallel int, dlq string) {
	t.Helper()
	identity := r.clients.iam(eventDeliveryAccount, "test", "")
	role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"pipes.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, identity, name, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"events:InvokeApiDestination","Resource":%q},{"Effect":"Allow","Action":"kinesis:*","Resource":%q},{"Effect":"Allow","Action":"sqs:SendMessage","Resource":%q},{"Effect":"Deny","Action":["events:RetrieveConnectionCredentials","secretsmanager:*","kms:*"],"Resource":"*"}]}`, destination, stream, dlq))
	r.pipeCall(t, "CreatePipe", map[string]any{"Name": name, "RoleArn": aws.ToString(role.Role.Arn), "Source": stream, "Target": destination, "DesiredState": "RUNNING", "SourceParameters": map[string]any{"KinesisStreamParameters": map[string]any{"BatchSize": 1, "ParallelizationFactor": parallel, "StartingPosition": "LATEST", "MaximumRetryAttempts": retries, "MaximumRecordAgeInSeconds": age, "DeadLetterConfig": map[string]string{"Arn": dlq}}}, "TargetParameters": map[string]string{"InputTemplate": `<$.data>`}})
	r.waitPipe(t, name, true, func(p pipestore.PipeRecord, _ []pipestore.Work, checkpoints []pipestore.Checkpoint) bool {
		return p.State == "RUNNING" && len(checkpoints) == 1 && checkpoints[0].Initialized
	})
}

func TestPipesAPIDestinationRetryAfter(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var attempts atomic.Int64
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
				if attempts.Add(1) == 1 {
					w.Header().Set("Retry-After", "15")
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newPipeDestinationCloud(t, backend, tls.Client(), newKinesisReplayRuntime(t))
			streams := r.clients.kinesis(eventDeliveryAccount, "test", "")
			name := "pipe-http-retry"
			if _, err := streams.CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: aws.String(name), ShardCount: aws.Int32(1)}); err != nil {
				t.Fatal(err)
			}
			stream := aws.ToString(awaitKinesisActive(t, r.source, streams, name).StreamDescriptionSummary.StreamARN)
			connection := r.connection(t, name, "BASIC", apiDestinationBasic("owned-password"), "")
			destination := r.destination(t, name, aws.ToString(connection.ConnectionArn), tls.URL+"/retry", "POST", 100)
			queue, err := r.clients.sqs(eventDeliveryAccount, "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(name + "-dlq")})
			if err != nil {
				t.Fatal(err)
			}
			dlq := "arn:aws:sqs:us-east-1:" + eventDeliveryAccount + ":" + name + "-dlq"
			r.createStreamPipe(t, name, stream, destination, 2, 60, 1, dlq)
			put, err := streams.PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: aws.String(stream), PartitionKey: aws.String("owned"), Data: []byte(`{"retain":"original-stream-record"}`)})
			if err != nil {
				t.Fatal(err)
			}
			r.waitPipe(t, name, true, func(_ pipestore.PipeRecord, work []pipestore.Work, _ []pipestore.Checkpoint) bool {
				return len(work) == 1 && work[0].Phase == "ready" && work[0].Attempts == 1
			})
			_, work, _ := r.pipeState(t, name)
			pending := work[0]
			if pending.Due.Before(r.source.Now().Add(14 * time.Second)) {
				t.Fatalf("Pipes discarded HTTP Retry-After: now=%v due=%v", r.source.Now(), pending.Due)
			}
			r.clients = r.reopen()
			r.advance(t, pending.Due.Add(-time.Second))
			if attempts.Load() != 1 {
				t.Fatal("Pipes invoked HTTP before retained Retry-After deadline")
			}
			r.advance(t, pending.Due)
			r.waitPipe(t, name, false, func(_ pipestore.PipeRecord, work []pipestore.Work, checkpoints []pipestore.Checkpoint) bool {
				return len(work) == 0 && len(checkpoints) == 1 && checkpoints[0].Sequence == aws.ToString(put.SequenceNumber)
			})
			requests := provider.snapshot()
			if attempts.Load() != 2 || len(requests) != 2 || requests[1].Header.Get("Authorization") != "Basic b3duZWQtdXNlcjpvd25lZC1wYXNzd29yZA==" {
				t.Fatal("retained Pipes retry lost its actual authenticated HTTP effect", requests)
			}
			apiDestinationJSON(t, requests[1].Body, map[string]any{"retain": "original-stream-record"})
			messages, err := r.clients.sqs(eventDeliveryAccount, "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
			if err != nil || len(messages.Messages) != 0 {
				t.Fatal("successful retry incorrectly dead-lettered source record", messages, err)
			}
		})
	}
}

func (r *pipeDestinationCloud) stream(t *testing.T, name string) string {
	t.Helper()
	client := r.clients.kinesis(eventDeliveryAccount, "test", "")
	if _, err := client.CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: aws.String(name), ShardCount: aws.Int32(1)}); err != nil {
		t.Fatal(err)
	}
	return aws.ToString(awaitKinesisActive(t, r.source, client, name).StreamDescriptionSummary.StreamARN)
}

func (r *pipeDestinationCloud) queue(t *testing.T, name string, attributes map[string]string) (string, string) {
	t.Helper()
	out, err := r.clients.sqs(eventDeliveryAccount, "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(name), Attributes: attributes})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.QueueUrl), "arn:aws:sqs:us-east-1:" + eventDeliveryAccount + ":" + name
}

func TestPipesAPIDestinationStreamDispositions(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, _ apiDestinationRequest) {
				switch request.URL.Path {
				case "/negative":
					w.Header().Set("Retry-After", "-1")
					w.WriteHeader(http.StatusServiceUnavailable)
				case "/age":
					w.Header().Set("Retry-After", "120")
					w.WriteHeader(http.StatusServiceUnavailable)
				default:
					w.WriteHeader(http.StatusBadRequest)
				}
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newPipeDestinationCloud(t, backend, tls.Client(), newKinesisReplayRuntime(t))
			stream := r.stream(t, "pipe-http-dispositions")
			connection := r.connection(t, "pipe-http-dispositions", "BASIC", apiDestinationBasic("owned-password"), "")
			for _, disposition := range []string{"terminal", "negative", "age"} {
				t.Run(disposition, func(t *testing.T) {
					name := "pipe-http-" + disposition
					destination := r.destination(t, name, aws.ToString(connection.ConnectionArn), tls.URL+"/"+disposition, "POST", 100)
					queue, dlq := r.queue(t, name+"-dlq", nil)
					r.createStreamPipe(t, name, stream, destination, 5, 10, 1, dlq)
					body := `{"source":"` + disposition + `"}`
					put, err := r.clients.kinesis(eventDeliveryAccount, "test", "").PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: aws.String(stream), PartitionKey: aws.String("owned"), Data: []byte(body)})
					if err != nil {
						t.Fatal(err)
					}
					if disposition == "age" {
						r.waitPipe(t, name, true, func(_ pipestore.PipeRecord, work []pipestore.Work, _ []pipestore.Checkpoint) bool {
							return len(work) == 1 && work[0].Phase == "dlq"
						})
						_, work, _ := r.pipeState(t, name)
						if work[0].Attempts != 1 || !work[0].Due.Equal(work[0].Created.Add(10*time.Second)) {
							t.Fatal("Retry-After escaped source record age", work)
						}
						due := work[0].Due
						r.clients = r.reopen()
						r.advance(t, due)
					}
					r.waitPipe(t, name, true, func(_ pipestore.PipeRecord, work []pipestore.Work, checkpoints []pipestore.Checkpoint) bool {
						return len(work) == 0 && len(checkpoints) == 1 && checkpoints[0].Sequence == aws.ToString(put.SequenceNumber)
					})
					messages, err := r.clients.sqs(eventDeliveryAccount, "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(queue), MaxNumberOfMessages: 10})
					if err != nil || len(messages.Messages) != 1 {
						t.Fatal("terminal/expired stream record did not reach source DLQ", messages, err)
					}
					var event struct {
						RequestPayload struct {
							Data string `json:"data"`
						} `json:"requestPayload"`
						RequestContext struct {
							Attempts int `json:"approximateInvokeCount"`
						} `json:"requestContext"`
					}
					if err := json.Unmarshal([]byte(aws.ToString(messages.Messages[0].Body)), &event); err != nil || event.RequestContext.Attempts != 1 {
						t.Fatal("invalid stream DLQ envelope", messages, err)
					}
					decoded, err := base64.StdEncoding.DecodeString(event.RequestPayload.Data)
					if err != nil || string(decoded) != body {
						t.Fatal("stream DLQ lost original source record", string(decoded), err)
					}
					attempts := 0
					for _, request := range provider.snapshot() {
						if request.Path == "/"+disposition {
							attempts++
							if request.Body != body {
								t.Fatal("HTTP received a substituted source record", request)
							}
						}
					}
					if attempts != 1 {
						t.Fatal("terminal/expired HTTP effect was retried", disposition, attempts)
					}
					r.pipeCall(t, "StopPipe", map[string]string{"Name": name})
					r.waitPipe(t, name, true, func(p pipestore.PipeRecord, _ []pipestore.Work, _ []pipestore.Checkpoint) bool {
						return p.State == "STOPPED"
					})
				})
			}
		})
	}
}

func TestPipesAPIDestinationAdmissionDoesNotConsumeRetry(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			provider := &apiDestinationReceiver{}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newPipeDestinationCloud(t, backend, tls.Client(), newKinesisReplayRuntime(t))
			name := "pipe-http-admission"
			stream := r.stream(t, name)
			connection := r.connection(t, name, "BASIC", apiDestinationBasic("owned-password"), "")
			destination := r.destination(t, name, aws.ToString(connection.ConnectionArn), tls.URL+"/admission", "POST", 1)
			queue, dlq := r.queue(t, name+"-dlq", nil)
			r.createStreamPipe(t, name, stream, destination, 0, 60, 2, dlq)
			for _, body := range []string{`{"ordinal":1}`, `{"ordinal":2}`} {
				if _, err := r.clients.kinesis(eventDeliveryAccount, "test", "").PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: aws.String(stream), PartitionKey: aws.String("owned"), Data: []byte(body)}); err != nil {
					t.Fatal(err)
				}
			}
			r.waitPipe(t, name, true, func(_ pipestore.PipeRecord, work []pipestore.Work, _ []pipestore.Checkpoint) bool {
				return len(work) > 0
			})
			r.waitPipe(t, name, false, func(_ pipestore.PipeRecord, work []pipestore.Work, _ []pipestore.Checkpoint) bool {
				return len(work) == 1 && work[0].Phase == "ready" && work[0].LastError != ""
			})
			_, work, _ := r.pipeState(t, name)
			pending := work[0]
			if pending.Attempts != 0 || len(provider.snapshot()) != 1 || !pending.Due.After(r.source.Now()) {
				t.Fatal("rate admission consumed a source retry or invoked HTTP", work, provider.snapshot())
			}
			r.clients = r.reopen()
			r.drain(t)
			if len(provider.snapshot()) != 1 {
				t.Fatal("reopen bypassed admission deadline")
			}
			r.advance(t, pending.Due)
			r.waitPipe(t, name, true, func(_ pipestore.PipeRecord, work []pipestore.Work, checkpoints []pipestore.Checkpoint) bool {
				return len(work) == 0 && len(checkpoints) == 1 && checkpoints[0].Sequence == pending.Sequence
			})
			seen := map[string]int{}
			for _, request := range provider.snapshot() {
				seen[request.Body]++
			}
			if len(seen) != 2 || seen[`{"ordinal":1}`] != 1 || seen[`{"ordinal":2}`] != 1 {
				t.Fatal("admission lost or duplicated a source record", seen)
			}
			messages, err := r.clients.sqs(eventDeliveryAccount, "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(queue)})
			if err != nil || len(messages.Messages) != 0 {
				t.Fatal("zero-retry policy dead-lettered admission", messages, err)
			}
		})
	}
}

func TestPipesAPIDestinationSQSRedriveOwnsFailedEffect(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var attempts atomic.Int64
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, _ *http.Request, _ apiDestinationRequest) {
				if attempts.Add(1) == 1 {
					w.Header().Set("Retry-After", "15")
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newPipeDestinationCloud(t, backend, tls.Client(), nil)
			name := "pipe-http-sqs-redrive"
			dlqURL, dlqARN := r.queue(t, name+"-dlq", nil)
			sourceURL, sourceARN := r.queue(t, name, map[string]string{"VisibilityTimeout": "1", "RedrivePolicy": fmt.Sprintf(`{"deadLetterTargetArn":%q,"maxReceiveCount":4}`, dlqARN)})
			connection := r.connection(t, name, "BASIC", apiDestinationBasic("owned-password"), "")
			destination := r.destination(t, name, aws.ToString(connection.ConnectionArn), tls.URL+"/sqs", "POST", 100)
			identity := r.clients.iam(eventDeliveryAccount, "test", "")
			role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"pipes.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, identity, name, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes","sqs:ChangeMessageVisibility"],"Resource":%q},{"Effect":"Allow","Action":"events:InvokeApiDestination","Resource":%q},{"Effect":"Deny","Action":["events:RetrieveConnectionCredentials","secretsmanager:*","kms:*"],"Resource":"*"}]}`, sourceARN, destination))
			r.pipeCall(t, "CreatePipe", map[string]any{"Name": name, "RoleArn": aws.ToString(role.Role.Arn), "Source": sourceARN, "Target": destination, "DesiredState": "RUNNING", "SourceParameters": map[string]any{"SqsQueueParameters": map[string]int{"BatchSize": 1}}, "TargetParameters": map[string]string{"InputTemplate": `<$.body>`}})
			r.waitPipe(t, name, true, func(p pipestore.PipeRecord, _ []pipestore.Work, _ []pipestore.Checkpoint) bool {
				return p.State == "RUNNING"
			})
			body := `{"retain":"queue-owned-redrive"}`
			sent, err := r.clients.sqs(eventDeliveryAccount, "test", "").SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: aws.String(sourceURL), MessageBody: aws.String(body)})
			if err != nil {
				t.Fatal(err)
			}
			r.waitPipe(t, name, true, func(_ pipestore.PipeRecord, work []pipestore.Work, _ []pipestore.Checkpoint) bool {
				return len(work) == 1 && work[0].Phase == "waiting" && work[0].Attempts == 1
			})
			_, work, _ := r.pipeState(t, name)
			due := work[0].Due
			r.clients = r.reopen()
			r.advance(t, due.Add(-time.Second))
			if attempts.Load() != 1 {
				t.Fatal("renewed SQS receipt bypassed retained Retry-After")
			}
			r.advance(t, due)
			r.waitPipe(t, name, true, func(_ pipestore.PipeRecord, work []pipestore.Work, _ []pipestore.Checkpoint) bool {
				return len(work) == 1 && work[0].Phase == "waiting" && work[0].Attempts >= 2
			})
			var dead []sqstypes.Message
			r.waitPipe(t, name, true, func(_ pipestore.PipeRecord, work []pipestore.Work, _ []pipestore.Checkpoint) bool {
				out, err := r.clients.sqs(eventDeliveryAccount, "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(dlqURL)})
				if err != nil {
					t.Fatal(err)
				}
				dead = out.Messages
				return len(dead) == 1
			})
			if aws.ToString(dead[0].Body) != body || aws.ToString(dead[0].MessageId) != aws.ToString(sent.MessageId) {
				t.Fatal("queue-owned redrive lost source identity/payload", dead)
			}
			_, work, _ = r.pipeState(t, name)
			if len(work) != 1 || work[0].Phase != "waiting" || work[0].Attempts < 2 {
				t.Fatal("failed HTTP effect was falsely acknowledged", work)
			}
			if attempts.Load() < 2 {
				t.Fatal("source redrive did not follow actual failed HTTP retries", provider.snapshot())
			}
			for _, request := range provider.snapshot() {
				if request.Body != body {
					t.Fatal("SQS HTTP request lost original source body", request)
				}
			}
		})
	}
}

package awsapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskinesis "github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	smithytime "github.com/aws/smithy-go/time"

	"stackd/internal/awsapi"
	kinesisapi "stackd/internal/awsapi/kinesis"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
)

// Replay CRC-checked native frames through both the shared encoder and the real
// SDK decoder. In particular, a terminal event's required continuation sequence
// is absent on AWS and must stay absent; the model is not a response validator.
func TestKinesisEventStreamNativeFrames(t *testing.T) {
	data, err := os.ReadFile("../../testdata/aws/kinesis/records.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Calls []struct {
			Label  string
			Frames []struct{ WireBase64 string }
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var sawRecords, sawTerminal bool
	for _, call := range fixture.Calls {
		if len(call.Frames) == 0 {
			continue
		}
		t.Run(call.Label, func(t *testing.T) {
			var native bytes.Buffer
			var messages []eventstream.Message
			events := make(chan kinesisapi.SubscribeToShardEventStream, len(call.Frames))
			for i, frame := range call.Frames {
				wire, err := base64.StdEncoding.DecodeString(frame.WireBase64)
				if err != nil {
					t.Fatal(err)
				}
				native.Write(wire)
				message, err := eventstream.NewDecoder().Decode(bytes.NewReader(wire), nil)
				if err != nil {
					t.Fatal(err)
				}
				messages = append(messages, message)
				if i == 0 {
					if message.Headers.Get(":event-type").String() != "initial-response" {
						t.Fatal("native fixture lacks initial-response")
					}
					continue
				}
				var document map[string]any
				if err := json.Unmarshal(message.Payload, &document); err != nil {
					t.Fatal(err)
				}
				// Generated timestamps are time.Time; translate only fixture epoch
				// timestamps into Go's JSON time syntax before populating the DTO.
				if records, ok := document["Records"].([]any); ok {
					for _, record := range records {
						fields := record.(map[string]any)
						if stamp, ok := fields["ApproximateArrivalTimestamp"].(float64); ok {
							fields["ApproximateArrivalTimestamp"] = smithytime.ParseEpochSeconds(stamp)
						}
					}
				}
				converted, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				var event kinesisapi.SubscribeToShardEvent
				if err := json.Unmarshal(converted, &event); err != nil {
					t.Fatal(err)
				}
				sawRecords = sawRecords || len(event.Records) > 0
				sawTerminal = sawTerminal || len(event.ChildShards) > 0 && event.ContinuationSequenceNumber == nil
				events <- kinesisapi.SubscribeToShardEventStream{SubscribeToShardEvent: &event}
			}
			close(events)
			response := kinesisStreamResponse(t, events)
			recorder := httptest.NewRecorder()
			if err := response.Stream(t.Context(), recorder); err != nil {
				t.Fatal(err)
			}
			if !recorder.Flushed || response.Header.Get("Content-Type") != "application/vnd.amazon.eventstream" {
				t.Fatal("stream was not flushed with event-stream content type")
			}
			wire := bytes.Clone(recorder.Body.Bytes())
			decoder := eventstream.NewDecoder()
			for _, want := range messages {
				got, err := decoder.Decode(recorder.Body, nil)
				if err != nil {
					t.Fatal(err)
				}
				for _, header := range want.Headers {
					if value := got.Headers.Get(header.Name); value == nil || value.String() != header.Value.String() {
						t.Fatalf("header %s differs: %v", header.Name, value)
					}
				}
				var gotDocument, wantDocument any
				if err := json.Unmarshal(got.Payload, &gotDocument); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(want.Payload, &wantDocument); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(gotDocument, wantDocument) {
					t.Fatalf("event document differs from native:\ngot %s\nwant %s", got.Payload, want.Payload)
				}
			}
			if _, err := decoder.Decode(recorder.Body, nil); err != io.EOF {
				t.Fatalf("stream did not end after producer close: %v", err)
			}
			want, err := decodeKinesisSDKEvents(t, native.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeKinesisSDKEvents(t, wire)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("SDK events differ from native: got %+v, want %+v", got, want)
			}
		})
	}
	if !sawRecords || !sawTerminal {
		t.Fatal("native replay must cover binary records and terminal child shards without continuation")
	}
}

func TestKinesisEventStreamExceptionTerminates(t *testing.T) {
	message := kinesisapi.ErrorMessage("stream was deleted")
	events := make(chan kinesisapi.SubscribeToShardEventStream, 1)
	events <- kinesisapi.SubscribeToShardEventStream{ResourceNotFoundException: &kinesisapi.ResourceNotFoundException{Message: &message}}
	// Leave the producer open: an exception itself terminates the wire stream.
	response := kinesisStreamResponse(t, events)
	recorder := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := response.Stream(ctx, recorder); err != nil {
		t.Fatal(err)
	}
	got, err := decodeKinesisSDKEvents(t, recorder.Body.Bytes())
	var notFound *kinesistypes.ResourceNotFoundException
	if len(got) != 0 || !errors.As(err, &notFound) || aws.ToString(notFound.Message) != string(message) {
		t.Fatalf("expected modeled SDK exception, got events %v and error %v", got, err)
	}
}

func TestLambdaEventStreamHasNoInitialResponse(t *testing.T) {
	payload := []byte{0, 255, '\n', 128}
	events := make(chan lambdaapi.InvokeWithResponseStreamResponseEvent, 2)
	events <- lambdaapi.InvokeWithResponseStreamResponseEvent{PayloadChunk: &lambdaapi.InvokeResponseStreamUpdate{Payload: payload}}
	events <- lambdaapi.InvokeWithResponseStreamResponseEvent{InvokeComplete: &lambdaapi.InvokeWithResponseStreamCompleteEvent{}}
	close(events)
	service, _ := awscatalog.LookupService("lambda")
	operation, _ := service.Operation("InvokeWithResponseStream")
	response, err := awsapi.EncodeHTTPResponse(service, operation, &lambdaapi.InvokeWithResponseStreamOutput{EventStream: events})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if err := response.Stream(t.Context(), recorder); err != nil {
		t.Fatal(err)
	}
	decoder := eventstream.NewDecoder()
	first, err := decoder.Decode(recorder.Body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Headers.Get(":event-type").String() != "PayloadChunk" || first.Headers.Get(":content-type").String() != "application/octet-stream" || !bytes.Equal(first.Payload, payload) {
		t.Fatalf("Lambda raw first event changed: %+v", first)
	}
	last, err := decoder.Decode(recorder.Body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if last.Headers.Get(":event-type").String() != "InvokeComplete" || last.Headers.Get(":content-type").String() != "application/json" || string(last.Payload) != "{}" {
		t.Fatalf("Lambda completion changed: %+v", last)
	}
	if _, err := decoder.Decode(recorder.Body, nil); err != io.EOF {
		t.Fatalf("Lambda stream did not close: %v", err)
	}
}

func TestEventStreamCancellationInterruptsBlockedWrite(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	writer := &blockedEventWriter{Conn: server, entered: make(chan struct{}, 1)}
	response := kinesisStreamResponse(t, make(chan kinesisapi.SubscribeToShardEventStream))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- response.Stream(ctx, writer) }()
	select {
	case <-writer.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("initial frame never reached the blocked writer")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled blocked write returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt blocked write")
	}
}

type blockedEventWriter struct {
	net.Conn
	entered chan struct{}
}

func (w *blockedEventWriter) Header() http.Header { return make(http.Header) }
func (w *blockedEventWriter) WriteHeader(int)     {}
func (w *blockedEventWriter) Flush()              {}
func (w *blockedEventWriter) Write(p []byte) (int, error) {
	select {
	case w.entered <- struct{}{}:
	default:
	}
	return w.Conn.Write(p)
}

func kinesisStreamResponse(t *testing.T, events <-chan kinesisapi.SubscribeToShardEventStream) awsapi.HTTPResponse {
	t.Helper()
	service, _ := awscatalog.LookupService("kinesis")
	operation, _ := service.Operation("SubscribeToShard")
	response, err := awsapi.EncodeHTTPResponse(service, operation, &kinesisapi.SubscribeToShardOutput{EventStream: events})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

type eventStreamHTTPClient func(*http.Request) (*http.Response, error)

func (f eventStreamHTTPClient) Do(r *http.Request) (*http.Response, error) { return f(r) }

func decodeKinesisSDKEvents(t *testing.T, wire []byte) ([]kinesistypes.SubscribeToShardEvent, error) {
	t.Helper()
	client := awskinesis.New(awskinesis.Options{
		Region:           "us-east-1",
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", ""),
		RetryMaxAttempts: 1,
		HTTPClient: eventStreamHTTPClient(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/vnd.amazon.eventstream"}}, Body: io.NopCloser(bytes.NewReader(wire))}, nil
		}),
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	out, err := client.SubscribeToShard(ctx, &awskinesis.SubscribeToShardInput{
		ConsumerARN:      aws.String("arn:aws:kinesis:us-east-1:123456789012:stream/test/consumer/test:1"),
		ShardId:          aws.String("shardId-000000000000"),
		StartingPosition: &kinesistypes.StartingPosition{Type: kinesistypes.ShardIteratorTypeTrimHorizon},
	})
	if err != nil {
		return nil, err
	}
	stream := out.GetStream()
	defer stream.Close()
	var result []kinesistypes.SubscribeToShardEvent
	for event := range stream.Events() {
		value, ok := event.(*kinesistypes.SubscribeToShardEventStreamMemberSubscribeToShardEvent)
		if !ok {
			t.Fatalf("unexpected SDK event %T", event)
		}
		result = append(result, value.Value)
	}
	return result, stream.Err()
}

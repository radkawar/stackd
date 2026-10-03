package stackd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/internal/awstest"
)

// Keep both metadata envelopes and every service-modeled header. HTTP field names
// are case-insensitive; HttpHeaders contains the last value in AllHttpHeaders,
// as specified by the Java SDK metadata shape used by optimized integrations.
func stepFunctionsNormalizeMetadata(t *testing.T, path string, result map[string]any) {
	t.Helper()
	httpValue, hasHTTP := result["SdkHttpMetadata"]
	responseValue, hasResponse := result["SdkResponseMetadata"]
	if !hasHTTP && !hasResponse {
		return
	}
	metadata, httpOK := httpValue.(map[string]any)
	response, responseOK := responseValue.(map[string]any)
	if !httpOK || !responseOK {
		t.Fatalf("%s: optimized result lost a metadata envelope: %#v", path, result)
	}
	status, ok := metadata["HttpStatusCode"].(float64)
	if !ok || status < 100 || status > 599 || status != float64(int(status)) {
		t.Fatalf("%s: invalid HTTP status: %#v", path, metadata)
	}
	if modeledStatus, present := result["StatusCode"]; present && modeledStatus != status {
		t.Fatalf("%s: modeled status %v differs from HTTP status %v", path, modeledStatus, status)
	}
	headers := func(field string) map[string]any {
		raw, ok := metadata[field].(map[string]any)
		if !ok {
			t.Fatalf("%s: missing %s", path, field)
		}
		lower := make(map[string]any, len(raw))
		for name, value := range raw {
			name = strings.ToLower(name)
			if _, duplicate := lower[name]; duplicate {
				t.Fatalf("%s: duplicate case-insensitive header %s", path, name)
			}
			lower[name] = value
		}
		metadata[field] = lower
		return lower
	}
	single, all := headers("HttpHeaders"), headers("AllHttpHeaders")
	if len(single) != len(all) {
		t.Fatalf("%s: header maps disagree: %#v / %#v", path, single, all)
	}
	for name, raw := range all {
		values, ok := raw.([]any)
		if !ok || len(values) == 0 {
			t.Fatalf("%s: invalid header values %s: %#v", path, name, raw)
		}
		for _, value := range values {
			if _, ok := value.(string); !ok {
				t.Fatalf("%s: nonstring HTTP header %s: %#v", path, name, value)
			}
		}
		if single[name] != values[len(values)-1] {
			t.Fatalf("%s: last header value differs for %s: %#v / %#v", path, name, single[name], values)
		}
	}
	requestID, ok := response["RequestId"].(string)
	if !ok || requestID == "" {
		t.Fatalf("%s: missing command request ID: %#v", path, response)
	}
	foundID := false
	for _, name := range []string{"x-amzn-requestid", "x-amz-request-id"} {
		if id, present := single[name]; present {
			foundID = true
			if id != requestID {
				t.Fatalf("%s: HTTP request ID %#v differs from SDK request ID %s", path, id, requestID)
			}
			for _, value := range all[name].([]any) {
				if value != requestID {
					t.Fatalf("%s: AllHttpHeaders request ID %#v differs from SDK request ID %s", path, value, requestID)
				}
			}
		}
	}
	if !foundID {
		t.Fatalf("%s: HTTP headers have no command request ID", path)
	}
	length, ok := single["content-length"].(string)
	n, err := strconv.Atoi(length)
	if !ok || err != nil || n < 0 {
		t.Fatalf("%s: invalid encoded response byte length %#v", path, single["content-length"])
	}
	if status == http.StatusAccepted && result["Payload"] == "" && n != 0 {
		t.Fatalf("%s: asynchronous Lambda acknowledgement has a response body", path)
	}
	if n > 0 {
		// The native SDK and local service encoder need not spell the same JSON
		// bytes (whitespace, escaped Unicode, timestamp precision, generated IDs).
		// Never equate their lengths. Preserve presence and positive/empty body
		// distinction; the SDK workflow below checks local encoded byte length.
		single["content-length"] = "<positive encoded byte length>"
		all["content-length"] = []any{"<positive encoded byte length>"}
	}
	for _, name := range []string{"date", "connection", "x-amzn-remapped-content-length", "x-amzn-trace-id", "x-amz-crc32"} {
		// Date/Connection belong to the network hop, remapped length to AWS's
		// proxy, and Trace-ID to AWS's tracing transport. AWS's optional CRC32
		// protects that transport representation, not the decoded command result.
		// No equivalent AWS gateway fields are fabricated by the local command.
		delete(single, name)
		delete(all, name)
	}
}

// Description/queue observations already bind the generated service identities.
// Match history-only submissions by those identities, not by the event index:
// parallel nested executions can submit in either order. The shared causal
// history comparator still checks every event, including all metadata fields.
func (r *stepFunctionsTaskReplay) bindHistoryMetadata(t *testing.T, want, got any) {
	t.Helper()
	collect := func(value any) map[string][]string {
		out := map[string][]string{}
		var visit func(any)
		visit = func(value any) {
			switch value := value.(type) {
			case map[string]any:
				if metadata, ok := value["SdkResponseMetadata"].(map[string]any); ok {
					var identity string
					for _, field := range []string{"MessageId", "ExecutionArn"} {
						if id, ok := value[field].(string); ok {
							identity = field + ":" + r.boundString(id)
							break
						}
					}
					if identity == "" {
						t.Fatalf("history metadata has no captured service identity: %#v", value)
					}
					id, _ := metadata["RequestId"].(string)
					out[identity] = append(out[identity], id)
				}
				for _, child := range value {
					visit(child)
				}
			case []any:
				for _, child := range value {
					visit(child)
				}
			case string:
				if json.Valid([]byte(value)) {
					var decoded any
					awsDecodeJSON(t, []byte(value), &decoded)
					visit(decoded)
				}
			}
		}
		visit(value)
		return out
	}
	native, local := collect(want), collect(got)
	if len(native) != len(local) {
		t.Fatalf("history metadata identities differ: native %#v, local %#v", native, local)
	}
	for identity, ids := range native {
		actual := local[identity]
		if len(ids) != len(actual) {
			t.Fatalf("history metadata occurrences differ for %s: native %#v, local %#v", identity, ids, actual)
		}
		for index, id := range ids {
			r.bind(t, r.bindings, id, actual[index], true)
		}
	}
}

// Extend the recorded optimized SQS scenario through public SDK calls. Unlike a
// fixture-only assertion, ResultSelector is a real consumer: losing either SDK
// envelope fails the workflow before its Choice can accept the response status.
func TestStepFunctionsOptimizedMetadataResultSelector(t *testing.T) {
	var fixture struct {
		Account, Region string
		Observations    []stepFunctionsTaskObservation
	}
	awsReadFixture(t, "stepfunctions/task_integrations.json", &fixture)
	rows := map[string]stepFunctionsTaskObservation{}
	for _, row := range fixture.Observations {
		rows[row.Label] = row
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := stepFunctionsTaskCloud(t, backend, stepFunctionsNativeFixture{Account: fixture.Account, Region: fixture.Region}, fixture.Observations[0].StartedAt)
			for _, label := range []string{"create-queue", "create-primary-role", "put-primary-policy-no-eventbridge"} {
				r.call(t, rows[label])
			}
			var create sfn.CreateStateMachineInput
			if err := awstest.DecodeSDK(r.input(t, rows["create-primary"].Input), &create); err != nil {
				t.Fatal(err)
			}
			var definition map[string]any
			awsDecodeJSON(t, []byte(aws.ToString(create.Definition)), &definition)
			state := definition["States"].(map[string]any)["sqs-optimized-request-response"].(map[string]any)
			state["ResultSelector"] = map[string]any{
				"status.$": "$.SdkHttpMetadata.HttpStatusCode", "requestId.$": "$.SdkResponseMetadata.RequestId",
				"headers.$": "$.SdkHttpMetadata.HttpHeaders", "allHeaders.$": "$.SdkHttpMetadata.AllHttpHeaders",
				"messageId.$": "$.MessageId", "digest.$": "$.MD5OfMessageBody",
			}
			delete(state, "End")
			state["Next"] = "AcceptStatus"
			definition = map[string]any{"StartAt": "Send", "States": map[string]any{
				"Send":         state,
				"AcceptStatus": map[string]any{"Type": "Choice", "Choices": []any{map[string]any{"Variable": "$.status", "NumericEquals": 200, "Next": "Accepted"}}, "Default": "Rejected"},
				"Accepted":     map[string]any{"Type": "Succeed"}, "Rejected": map[string]any{"Type": "Fail", "Error": "UnexpectedHTTPStatus"},
			}}
			encoded, err := json.Marshal(definition)
			if err != nil {
				t.Fatal(err)
			}
			create.Definition = aws.String(string(encoded))
			create.Name = aws.String(aws.ToString(create.Name) + "-metadata")
			config := aws.Config{Region: fixture.Region, HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1,
				Credentials: credentials.NewStaticCredentialsProvider(r.identity.AccessKeyID, r.identity.SecretAccessKey, "")}
			workflows := sfn.NewFromConfig(config, func(o *sfn.Options) { o.BaseEndpoint = aws.String(r.clients.server.URL) })
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			machine, err := workflows.CreateStateMachine(ctx, &create)
			if err != nil {
				t.Fatal(err)
			}
			started, err := workflows.StartExecution(ctx, &sfn.StartExecutionInput{StateMachineArn: machine.StateMachineArn, Input: aws.String(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			var completed *sfn.DescribeExecutionOutput
			for {
				r.drain(t)
				completed, err = workflows.DescribeExecution(ctx, &sfn.DescribeExecutionInput{ExecutionArn: started.ExecutionArn})
				if err != nil {
					t.Fatal(err)
				}
				if completed.Status != "RUNNING" {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("metadata consumer did not finish", ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			if completed.Status != "SUCCEEDED" {
				t.Fatalf("metadata ResultSelector/Choice failed: %#v", completed)
			}
			var selected struct {
				Status                       int
				RequestID, MessageID, Digest string
				Headers                      map[string]string
				AllHeaders                   map[string][]string
			}
			awsDecodeJSON(t, []byte(aws.ToString(completed.Output)), &selected)
			lower := http.Header{}
			for name, values := range selected.AllHeaders {
				lower[http.CanonicalHeaderKey(name)] = values
			}
			if selected.Status != 200 || selected.RequestID == "" || lower.Get("x-amzn-RequestId") != selected.RequestID || lower.Get("Content-Type") != "application/x-amz-json-1.0" {
				t.Fatalf("selected SDK metadata lost its status, request identity or content type: %#v", selected)
			}
			for name, value := range selected.Headers {
				values := lower.Values(name)
				if len(values) == 0 || values[len(values)-1] != value {
					t.Fatalf("selected header maps disagree for %s: %#v", name, selected)
				}
			}
			if len(selected.Headers) != len(selected.AllHeaders) {
				t.Fatal("selected header maps have different fields", selected)
			}

			// Read the actual delivered body, then ask the same public SQS encoder
			// for a response to those bytes. Preserve its wire representation and
			// substitute only the independently generated message ID. This asserts
			// local Content-Length, not equality with AWS's differently encoded body.
			wire := &awstest.WireClient{Client: r.clients.server.Client()}
			queues := sqs.NewFromConfig(config, func(o *sqs.Options) { o.BaseEndpoint = aws.String(r.clients.server.URL); o.HTTPClient = wire })
			parameters := state["Parameters"].(map[string]any)
			queueURL := r.boundString(parameters["QueueUrl"].(string))
			received, err := queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: aws.String(queueURL)})
			if err != nil || len(received.Messages) != 1 {
				t.Fatalf("optimized task delivery: %#v, %v", received, err)
			}
			message := received.Messages[0]
			if aws.ToString(message.MessageId) != selected.MessageID || aws.ToString(message.MD5OfBody) != selected.Digest {
				t.Fatalf("selected result does not identify the delivered message: %#v / %#v", selected, message)
			}
			response, err := queues.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: aws.String(queueURL), MessageBody: message.Body})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(response.MD5OfMessageBody) != selected.Digest || !bytes.Contains(wire.Body, []byte(aws.ToString(response.MessageId))) {
				t.Fatalf("public encoder response does not represent the same message body: %s", wire.Body)
			}
			body := bytes.ReplaceAll(wire.Body, []byte(aws.ToString(response.MessageId)), []byte(selected.MessageID))
			if length := lower.Get("Content-Length"); length != strconv.Itoa(len(body)) {
				t.Fatalf("selected Content-Length = %q, actual public service encoding = %d bytes: %s", length, len(body), body)
			}
			if selected.RequestID == selected.MessageID {
				t.Fatal("command request ID was replaced by the message identity")
			}
			t.Logf("metadata selected by workflow; encoded SQS body %d bytes", len(body))
		})
	}
}

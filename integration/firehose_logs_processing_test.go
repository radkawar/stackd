package stackd_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

type firehoseLogsPlan struct {
	Source                                                                     string
	Setup, Cases, Admission, Origin, KinesisSetup, KinesisCreates, KinesisPuts []string
}

type firehoseLogsObject struct {
	Key   string
	Bytes struct{ Base64 string }
}

type firehoseLogsFixture struct {
	firehoseNativeFixture
	Resources        struct{ Bucket, Function string }
	Objects          []firehoseLogsObject
	AdmissionSummary []struct {
		Label                            string
		CanonicalProcessingConfiguration *firehosetypes.ProcessingConfiguration
	}
	KinesisSourceProbe struct {
		firehoseNativeFixture
		Objects []firehoseLogsObject
		Records []struct {
			Kind     string
			Original struct{ Base64 string }
		}
		Resources struct{ Bucket, Role string }
	}
}

func firehoseLogsLoad(t *testing.T) (firehoseLogsPlan, firehoseLogsFixture) {
	t.Helper()
	var plan firehoseLogsPlan
	awsReadFixture(t, "firehose/logs_processing_replay.json", &plan)
	var native firehoseLogsFixture
	awsReadFixture(t, "firehose/"+plan.Source, &native)
	native.Calls = firehoseCapturedCalls(t, native.Calls).Calls
	native.KinesisSourceProbe.Calls = firehoseCapturedCalls(t, native.KinesisSourceProbe.Calls).Calls
	return plan, native
}

func firehoseLogsReplay(t *testing.T, clients cloudClients, row firehoseNativeCall) any {
	t.Helper()
	var client any
	switch row.Service {
	case "s3":
		client = s3NativeClient(clients, "test", "test")
	case "iam":
		client = clients.iam("test", "test", "")
	case "logs":
		client = logsClient(clients, "test")
	case "lambda":
		client = lambdaDynamoDBClient(clients)
	case "firehose":
		client = clients.firehose("test", "test", "")
	case "kinesis":
		client = clients.kinesis("test", "test", "")
	case "sts":
		client = clients.sts("test", "test", "")
	default:
		t.Fatalf("unhandled Logs capture service %q", row.Service)
	}
	return firehoseReplayCall(t, client, row)
}

// Native object packing and generated Logs IDs are not contracts. The backup
// consumer supplies the actual gzip envelopes; native requests supply messages,
// and captured outputs supply the byte-level extraction/Lambda/append contract.
func TestFirehoseNativeLogsProcessing(t *testing.T) {
	lambdaURLDocker(t)
	plan, native := firehoseLogsLoad(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(native.StartedAt.Add(3 * time.Minute))
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: native.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return newLambdaDockerStack(t, config, nil)
			})
			row := func(label string) firehoseNativeCall {
				return firehoseCapturedRow(t, native.firehoseNativeFixture, label)
			}
			replay := func(label string) any { return firehoseLogsReplay(t, clients, row(label)) }
			for _, label := range plan.Setup {
				replay(label)
			}
			if err := awslambda.NewFunctionActiveWaiter(lambdaDynamoDBClient(clients), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &native.Resources.Function}, time.Minute); err != nil {
				t.Fatal(err)
			}
			for _, name := range append(append([]string{}, plan.Cases...), "admission") {
				replay("create-" + name)
				awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), native.Prefix+"-"+name)
			}
			// Replay real UpdateDestination transitions, including disable then
			// rejected re-enable without Lambda and accepted re-enable with it.
			for _, label := range plan.Admission {
				change := row(label)
				var input firehose.UpdateDestinationInput
				if err := json.Unmarshal(change.Input, &input); err != nil {
					t.Fatal(err)
				}
				before, err := clients.firehose("test", "test", "").DescribeDeliveryStream(t.Context(), &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: input.DeliveryStreamName})
				if err != nil {
					t.Fatal(err)
				}
				firehoseReplayCall(t, clients.firehose("test", "test", ""), change, func(v any) {
					in := v.(*firehose.UpdateDestinationInput)
					in.CurrentDeliveryStreamVersionId = before.DeliveryStreamDescription.VersionId
					in.DestinationId = before.DeliveryStreamDescription.Destinations[0].DestinationId
				})
				awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), aws.ToString(input.DeliveryStreamName))
				after, err := clients.firehose("test", "test", "").DescribeDeliveryStream(t.Context(), &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: input.DeliveryStreamName})
				if err != nil {
					t.Fatal(err)
				}
				got := after.DeliveryStreamDescription.Destinations[0].ExtendedS3DestinationDescription.ProcessingConfiguration
				want := before.DeliveryStreamDescription.Destinations[0].ExtendedS3DestinationDescription.ProcessingConfiguration
				for _, observed := range native.AdmissionSummary {
					if observed.Label == label && observed.CanonicalProcessingConfiguration != nil {
						want = observed.CanonicalProcessingConfiguration
					}
				}
				// Parameter order is immaterial; processor declaration order is not.
				firehoseLogsConfiguration(t, label, got, want)
			}
			for _, name := range plan.Cases {
				if name != "real-logs" && name != "disabled" {
					replay("put-" + name)
				}
				for _, prefix := range []string{"create-source-group-", "create-source-log-stream-", "configure-real-subscription-", "publish-real-logs-"} {
					replay(prefix + name)
				}
				if name == "real-logs" || name == "reversed-lambda" {
					replay("create-failed-log-stream-" + name)
					replay("publish-failed-logs-" + name)
				}
			}
			// An IAM role used by Logs is not itself a trusted service origin.
			trust := row(plan.Origin[0])
			trust.Input = bytes.ReplaceAll(trust.Input, []byte(":user/Delegated"), []byte(":root"))
			firehoseLogsReplay(t, clients, trust)
			session := replay(plan.Origin[1]).(*sts.AssumeRoleOutput)
			credentials := session.Credentials
			firehoseReplayCall(t, clients.firehose(aws.ToString(credentials.AccessKeyId), aws.ToString(credentials.SecretAccessKey), aws.ToString(credentials.SessionToken)), row(plan.Origin[2]))
			replay(plan.Origin[3])
			for _, label := range []string{"edge-native-empty-decomp", "edge-native-empty-extract", "edge-native-empty-extract-append", "edge-native-empty-real-logs"} {
				replay(label)
			}
			for _, name := range plan.Cases {
				firehoseProcessingPoll(t, clients, source, func() bool {
					return firehoseLogsConsumers(t, clients, native, name, row("publish-real-logs-"+name))
				})
			}
			// Disabled preprocessing admits ordinary producer bytes unchanged.
			before := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, "disabled/")
			var disabled firehose.PutRecordBatchInput
			if err := json.Unmarshal(row("put-disabled").Input, &disabled); err != nil {
				t.Fatal(err)
			}
			replay("put-disabled")
			var rawRecords [][]byte
			for _, record := range disabled.Records {
				rawRecords = append(rawRecords, record.Data)
			}
			firehoseProcessingPoll(t, clients, source, func() bool {
				for _, prefix := range []string{"disabled/processed/", "disabled/backup/"} {
					fresh := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, prefix)
					for key := range before {
						delete(fresh, key)
					}
					if !firehoseLogsPacked(fresh, rawRecords, false) {
						return false
					}
				}
				return true
			})
		})
	}
}

func firehoseLogsConfiguration(t *testing.T, label string, got, want *firehosetypes.ProcessingConfiguration) {
	t.Helper()
	if got == nil || want == nil || aws.ToBool(got.Enabled) != aws.ToBool(want.Enabled) || len(got.Processors) != len(want.Processors) {
		t.Fatalf("%s processing configuration got=%+v want=%+v", label, got, want)
	}
	for i, processor := range want.Processors {
		actual := got.Processors[i]
		if actual.Type != processor.Type {
			t.Fatalf("%s processor %d type=%s want=%s", label, i, actual.Type, processor.Type)
		}
		parameters := func(p firehosetypes.Processor) map[firehosetypes.ProcessorParameterName]string {
			m := map[firehosetypes.ProcessorParameterName]string{}
			for _, v := range p.Parameters {
				m[v.ParameterName] = aws.ToString(v.ParameterValue)
			}
			return m
		}
		if !reflect.DeepEqual(parameters(actual), parameters(processor)) {
			t.Fatalf("%s processor %d parameters=%v want=%v", label, i, parameters(actual), parameters(processor))
		}
	}
}

type firehoseLogsEnvelope struct {
	MessageType string
	LogEvents   []struct{ Message string }
}

type firehoseLogsMember struct {
	raw, plain []byte
	envelope   firehoseLogsEnvelope
}

func firehoseLogsMembers(t *testing.T, objects map[string][]byte) []firehoseLogsMember {
	t.Helper()
	var result []firehoseLogsMember
	for _, body := range objects {
		reader := bytes.NewReader(body)
		for reader.Len() > 0 {
			start := len(body) - reader.Len()
			compressed, err := gzip.NewReader(reader)
			if err != nil {
				t.Fatalf("backup lost original gzip: %v", err)
			}
			compressed.Multistream(false)
			plain, err := io.ReadAll(compressed)
			if err != nil {
				t.Fatal(err)
			}
			if err := compressed.Close(); err != nil {
				t.Fatal(err)
			}
			member := firehoseLogsMember{raw: body[start : len(body)-reader.Len()], plain: plain}
			if err := json.Unmarshal(plain, &member.envelope); err != nil {
				t.Fatal(err)
			}
			result = append(result, member)
		}
	}
	return result
}

// Match complete records across arbitrary S3 packing without UUID or object-order
// assertions. Every consumer byte must belong to exactly one expected record.
func firehoseLogsPacked(objects map[string][]byte, records [][]byte, delimiter bool) bool {
	remaining := append([][]byte(nil), records...)
	for _, body := range objects {
		first := true
		for len(body) > 0 {
			if !first && delimiter {
				if body[0] != '\n' {
					return false
				}
				body = body[1:]
			}
			match := -1
			for i, record := range remaining {
				if (len(record) > 0 || delimiter) && bytes.HasPrefix(body, record) && (match < 0 || len(record) > len(remaining[match])) {
					match = i
				}
			}
			if match < 0 {
				return false
			}
			body = body[len(remaining[match]):]
			remaining = append(remaining[:match], remaining[match+1:]...)
			first = false
		}
	}
	for _, record := range remaining {
		if len(record) > 0 {
			return false
		}
	}
	return true
}

func firehoseLogsConsumers(t *testing.T, clients cloudClients, native firehoseLogsFixture, name string, producer firehoseNativeCall) bool {
	t.Helper()
	objects := func(prefix string) map[string][]byte {
		return firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, prefix)
	}
	members := firehoseLogsMembers(t, objects(name+"/backup/"))
	var request cloudwatchlogs.PutLogEventsInput
	if err := json.Unmarshal(producer.Input, &request); err != nil {
		t.Fatal(err)
	}
	wantMessages := map[string]int{}
	for _, event := range request.LogEvents {
		wantMessages[aws.ToString(event.Message)]++
	}
	lambda := name == "real-logs" || name == "reversed-lambda"
	delimiter := lambda || name == "false-append" || name == "extract-append"
	gotMessages := map[string]int{}
	var expected, lambdaInputs [][]byte
	failedRaw := map[string]bool{}
	controls := 0
	for _, member := range members {
		var extracted []byte
		if member.envelope.MessageType == "CONTROL_MESSAGE" {
			controls++
		} else {
			for _, event := range member.envelope.LogEvents {
				if !strings.Contains(event.Message, "FAIL_STAGE") {
					gotMessages[event.Message]++
				}
				extracted = append(extracted, []byte(event.Message)...)
				extracted = append(extracted, '\n')
			}
		}
		if lambda {
			lambdaInputs = append(lambdaInputs, extracted)
			if bytes.Contains(extracted, []byte("FAIL_STAGE")) {
				failedRaw[string(member.raw)] = true
				continue
			}
			expected = append(expected, append(append([]byte("LAMBDA["), extracted...), ']'))
		} else {
			switch name {
			case "disabled":
				expected = append(expected, member.raw)
			case "decomp", "false-append":
				expected = append(expected, member.plain)
			case "extract", "extract-append":
				expected = append(expected, extracted)
			}
		}
	}
	if controls == 0 || !reflect.DeepEqual(gotMessages, wantMessages) {
		return false
	}
	if !firehoseLogsPacked(objects(name+"/processed/"), expected, delimiter) {
		return false
	}
	if name == "extract" || name == "extract-append" || lambda {
		captured := map[string][]byte{}
		for _, object := range native.Objects {
			if strings.HasPrefix(object.Key, name+"/processed/") {
				captured[object.Key] = firehoseProcessingDecode(t, object.Bytes.Base64)
			}
		}
		// Both native and local objects must contain the same records, while
		// inter-record separators depend on each object's independent packing.
		if !firehoseLogsPacked(captured, expected, delimiter) {
			t.Fatalf("%s expected records disagree with native consumer bytes", name)
		}
	}
	if !lambda {
		return true
	}
	if len(failedRaw) != 1 {
		return false
	}
	errors := firehoseLogsErrors(t, objects(name+"/errors/"), "processing-failed")
	if len(errors) != len(failedRaw) {
		return false
	}
	for _, failure := range errors {
		if !failedRaw[string(firehoseProcessingDecode(t, failure.RawData))] || failure.ErrorCode != "Lambda.ProcessingFailedStatus" {
			t.Fatalf("Lambda failure did not retain gzip input: %+v", failure)
		}
	}
	// The real captured handler writes the event it actually received to S3.
	// Require one record per envelope, including the empty CONTROL record.
	gotInputs := map[string]int{}
	for _, body := range objects("lambda-evidence/") {
		var evidence struct {
			Event struct {
				DeliveryStreamArn string
				Records           []struct{ Data string }
			}
		}
		if err := json.Unmarshal(body, &evidence); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(evidence.Event.DeliveryStreamArn, "/"+native.Prefix+"-"+name) {
			continue
		}
		for _, record := range evidence.Event.Records {
			gotInputs[string(firehoseProcessingDecode(t, record.Data))]++
		}
	}
	wantInputs := map[string]int{}
	for _, input := range lambdaInputs {
		wantInputs[string(input)]++
	}
	return reflect.DeepEqual(gotInputs, wantInputs)
}

func firehoseLogsErrors(t *testing.T, objects map[string][]byte, kind string) []firehoseProcessingError {
	t.Helper()
	var result []firehoseProcessingError
	for key, body := range objects {
		if !strings.Contains(key, "/errors/"+kind+"/") {
			t.Fatalf("wrong failure obligation prefix %q", key)
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		for {
			var failure firehoseProcessingError
			if err := decoder.Decode(&failure); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			result = append(result, failure)
		}
	}
	return result
}

// Kinesis is the real non-Logs producer used in the native capture. It reaches
// preprocessing without forging a trusted-service header or internal context.
func TestFirehoseNativeLogsKinesisFailures(t *testing.T) {
	plan, native := firehoseLogsLoad(t)
	probe := native.KinesisSourceProbe
	var originals, decompressed, extracted [][]byte
	for _, record := range probe.Records {
		raw := firehoseProcessingDecode(t, record.Original.Base64)
		originals = append(originals, raw)
		if record.Kind == "malformed-gzip" || record.Kind == "invalid-json" {
			continue
		}
		compressed, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := io.ReadAll(compressed)
		if err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
		decompressed = append(decompressed, plain)
	}
	// This is the measured extraction, including empty, Unicode, embedded and
	// terminal newline messages. Do not derive a competing normalization rule.
	for _, object := range probe.Objects {
		if strings.HasPrefix(object.Key, "extract/processed/") {
			extracted = append(extracted, firehoseProcessingDecode(t, object.Bytes.Base64))
		}
	}
	wantFailures := map[string]map[string]firehoseProcessingError{}
	for _, name := range []string{"decomp", "extract"} {
		nativeErrors := map[string][]byte{}
		for _, object := range probe.Objects {
			if strings.HasPrefix(object.Key, name+"/errors/") {
				nativeErrors[object.Key] = firehoseProcessingDecode(t, object.Bytes.Base64)
			}
		}
		wantFailures[name] = map[string]firehoseProcessingError{}
		for _, failure := range firehoseLogsErrors(t, nativeErrors, "decompression-failed") {
			wantFailures[name][failure.RawData] = failure
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			runtime := newKinesisReplayRuntime(t)
			source := clock.NewManual(probe.StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: native.Account, Clock: source, KinesisRuntime: runtime})
			row := func(label string) firehoseNativeCall {
				return firehoseCapturedRow(t, probe.firehoseNativeFixture, label)
			}
			replay := func(label string) any { return firehoseLogsReplay(t, clients, row(label)) }
			for _, label := range plan.KinesisSetup {
				replay(label)
			}
			awaitKinesisActive(t, source, clients.kinesis("test", "test", ""), probe.Prefix)
			for _, label := range plan.KinesisCreates {
				replay(label)
				var input firehose.CreateDeliveryStreamInput
				if err := json.Unmarshal(row(label).Input, &input); err != nil {
					t.Fatal(err)
				}
				awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), aws.ToString(input.DeliveryStreamName))
			}
			role := probe.Resources.Role[strings.LastIndex(probe.Resources.Role, "/")+1:]
			deny := func(prefixes ...string) {
				resources := make([]string, len(prefixes))
				for i, prefix := range prefixes {
					resources[i] = "arn:aws:s3:::" + probe.Resources.Bucket + "/" + prefix + "*"
				}
				policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Deny", "Action": "s3:PutObject", "Resource": resources}}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: &role, PolicyName: aws.String("retained-log-failures"), PolicyDocument: aws.String(string(policy))}); err != nil {
					t.Fatal(err)
				}
			}
			objects := func(prefix string) map[string][]byte {
				return firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), probe.Resources.Bucket, prefix)
			}
			errorsMatch := func(name string) bool {
				got := firehoseLogsErrors(t, objects(name+"/errors/"), "decompression-failed")
				if len(got) != len(wantFailures[name]) {
					return false
				}
				seen := map[string]bool{}
				for _, failure := range got {
					want, ok := wantFailures[name][failure.RawData]
					if !ok || seen[failure.RawData] || failure.ErrorCode != want.ErrorCode || failure.AttemptsMade != want.AttemptsMade {
						t.Fatalf("%s decompression failure changed original/code/attempts: %+v", name, failure)
					}
					seen[failure.RawData] = true
				}
				return true
			}
			// Local durability extension, not an assertion about AWS retry time:
			// decompression failures and raw backup remain separate obligations.
			deny("extract/errors/", "extract/backup/")
			for _, label := range plan.KinesisPuts {
				replay(label)
			}
			firehoseProcessingPoll(t, clients, source, func() bool {
				return firehoseLogsPacked(objects("decomp/processed/"), decompressed, false) &&
					firehoseLogsPacked(objects("decomp/backup/"), originals, false) && errorsMatch("decomp") &&
					firehoseLogsPacked(objects("extract/processed/"), extracted, false)
			})
			clients = reopen()
			advanceClock(t, source, 3*time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			if len(objects("extract/errors/")) != 0 || len(objects("extract/backup/")) != 0 {
				t.Fatal("denied decompression error or backup escaped")
			}
			deny("extract/errors/")
			firehoseProcessingPoll(t, clients, source, func() bool { return firehoseLogsPacked(objects("extract/backup/"), originals, false) })
			if len(objects("extract/errors/")) != 0 {
				t.Fatal("failure obligation escaped while independently restoring backup")
			}
			backupBefore := objects("extract/backup/")
			processedBefore := objects("extract/processed/")
			clients = reopen()
			if _, err := clients.iam("test", "test", "").DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: &role, PolicyName: aws.String("retained-log-failures")}); err != nil {
				t.Fatal(err)
			}
			firehoseProcessingPoll(t, clients, source, func() bool { return errorsMatch("extract") })
			if !reflect.DeepEqual(objects("extract/backup/"), backupBefore) || !reflect.DeepEqual(objects("extract/processed/"), processedBefore) {
				t.Fatal("restoring failure output duplicated an already completed output obligation")
			}
		})
	}
}

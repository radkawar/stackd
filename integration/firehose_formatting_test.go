package stackd_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/klauspost/compress/snappy"

	"stackd"
	"stackd/clock"
)

type firehoseFormattingView struct {
	VersionID    string
	Destinations []firehosetypes.DestinationDescription
}

type firehoseFormattingObject struct {
	Label, Key, ObservedCodec          string
	RawBytesBase64, DecodedBytesBase64 []byte
	Metadata                           struct {
		ContentType, ContentEncoding string
		ServerSideEncryption         string
		Metadata                     map[string]string
	}
}

// Replay every formatting control, including failed and canonical no-op updates.
// Select settled native deliveries: ACTIVE never promised immediate AWS cutover.
func TestFirehoseNativeFormatting(t *testing.T) {
	var plan struct {
		Source            string
		Setup, SkipCreate []string
		Deliveries        []struct{ Put, Object string }
	}
	awsReadFixture(t, "firehose/"+"formatting_replay.json", &plan)
	var native struct {
		Account   string
		StartedAt time.Time
		Resources struct{ Bucket string }
		Calls     []struct {
			Label, Service, Operation, Code string
			Parameters, Result              json.RawMessage
		}
		Cases []struct {
			Label                  string
			After                  firehoseFormattingView
			ConfigurationBeforePut firehoseFormattingView
		}
		Objects []firehoseFormattingObject
	}
	awsReadFixture(t, "firehose/"+plan.Source, &native)
	objects := make(map[string]firehoseFormattingObject)
	for _, object := range native.Objects {
		// An independent decoder must also consume the retained native bytes,
		// not merely agree with the local encoder about its own private framing.
		if got := firehoseDecodeFormatting(t, object.ObservedCodec, object.RawBytesBase64); !bytes.Equal(got, object.DecodedBytesBase64) {
			t.Fatalf("native object %s decoding differs from captured independent decoder", object.Label)
		}
		objects[object.Label] = object
	}
	expected := make(map[string]firehoseFormattingView)
	for _, observation := range native.Cases {
		if observation.After.VersionID != "" {
			expected[observation.Label] = observation.After
		}
		if observation.ConfigurationBeforePut.VersionID != "" {
			expected[observation.Label+".put"] = observation.ConfigurationBeforePut
		}
	}
	deliveries := make(map[string]firehoseFormattingObject)
	for _, selection := range plan.Deliveries {
		object, ok := objects[selection.Object]
		if !ok {
			t.Fatalf("missing native object %s", selection.Object)
		}
		deliveries[selection.Put] = object
	}
	operations := map[string]string{
		"create_bucket": "CreateBucket", "create_role": "CreateRole", "put_role_policy": "PutRolePolicy",
		"create_delivery_stream": "CreateDeliveryStream", "update_destination": "UpdateDestination", "put_record_batch": "PutRecordBatch",
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(native.StartedAt.UTC().Truncate(time.Second))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: native.Account, Clock: source})
			for _, call := range native.Calls {
				object, delivery := deliveries[call.Label]
				control := call.Operation == "create_delivery_stream" || call.Operation == "update_destination"
				if slices.Contains(plan.SkipCreate, call.Label) || !(slices.Contains(plan.Setup, call.Label) || control || delivery) {
					continue
				}
				row := firehoseNativeCall{Label: call.Label, Service: call.Service, Operation: operations[call.Operation], Input: call.Parameters}
				row.Result.Code, row.Result.Output = call.Code, call.Result
				var client any
				switch call.Service {
				case "s3":
					client = s3NativeClient(clients, "test", "test")
				case "iam":
					client = clients.iam("test", "test", "")
				case "firehose":
					client = clients.firehose("test", "test", "")
				default:
					t.Fatalf("unsupported formatting setup service %s", call.Service)
				}
				if delivery {
					var captured struct {
						DeliveryStreamName *string
						Records            []struct{ Data struct{ Base64 []byte } }
					}
					if err := json.Unmarshal(call.Parameters, &captured); err != nil {
						t.Fatal(err)
					}
					input := firehose.PutRecordBatchInput{DeliveryStreamName: captured.DeliveryStreamName}
					for _, record := range captured.Records {
						input.Records = append(input.Records, firehosetypes.Record{Data: record.Data.Base64})
					}
					var err error
					row.Input, err = json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					name := aws.ToString(input.DeliveryStreamName)
					clients = reopen() // canonical processors, codec and timezone survive reopening.
					client = clients.firehose("test", "test", "")
					description, err := clients.firehose("test", "test", "").DescribeDeliveryStream(t.Context(), &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: &name})
					if err != nil {
						t.Fatal(err)
					}
					firehoseCheckFormattingView(t, call.Label, description.DeliveryStreamDescription, expected[call.Label])
					config := description.DeliveryStreamDescription.Destinations[0].ExtendedS3DestinationDescription
					location := time.UTC
					if zone := aws.ToString(config.CustomTimeZone); zone != "" {
						location, err = time.LoadLocation(zone)
						if err != nil {
							t.Fatal(err)
						}
					}
					// Replay the native object's arrival second. The captured key itself
					// is the oracle for Java text, week, quoting, zone and padding syntax.
					marker := name + "-" + aws.ToString(description.DeliveryStreamDescription.VersionId) + "-"
					index := strings.LastIndex(object.Key, marker)
					if index < 0 {
						t.Fatalf("%s does not identify current native version", object.Key)
					}
					dateStart := index + len(marker)
					arrival, err := time.ParseInLocation("2006-01-02-15-04-05", object.Key[dateStart:dateStart+19], location)
					if err != nil {
						t.Fatal(err)
					}
					if arrival.Before(source.Now()) {
						t.Fatalf("native delivery time moved backwards at %s", call.Label)
					}
					advanceClock(t, source, arrival.Sub(source.Now()))
					before := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, "")
					firehoseReplayCall(t, client, row)
					clients = reopen() // queued or delivered bytes must not disappear.
					appendDelimiter := config.ProcessingConfiguration != nil && aws.ToBool(config.ProcessingConfiguration.Enabled)
					firehoseAwaitFormatting(t, clients, source, native.Resources.Bucket, before, input.Records, appendDelimiter, object, object.Key[:dateStart+19])
					continue
				}
				firehoseReplayCall(t, client, row)
				if !control {
					continue
				}
				var input struct{ DeliveryStreamName string }
				if err := json.Unmarshal(call.Parameters, &input); err != nil {
					t.Fatal(err)
				}
				if call.Code == "Success" {
					awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), input.DeliveryStreamName)
				}
				if want, ok := expected[call.Label]; ok {
					out, err := clients.firehose("test", "test", "").DescribeDeliveryStream(t.Context(), &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: &input.DeliveryStreamName})
					if err != nil {
						t.Fatal(err)
					}
					firehoseCheckFormattingView(t, call.Label, out.DeliveryStreamDescription, want)
				}
			}
		})
	}
}

// Large retained binary inputs exercise the real S3 codecs rather than locally
// generated approximations. The independent decoder accepts any legal packing.
func TestFirehoseNativeMultiblockFormatting(t *testing.T) {
	var plan struct {
		Source     string
		Setup      []string
		Deliveries []struct{ Create, Put, Object, Codec string }
	}
	awsReadFixture(t, "firehose/multiblock_replay.json", &plan)
	var native struct {
		Account   string
		StartedAt time.Time
		Resources struct{ Bucket string }
		Calls     []firehoseNativeCall
		Objects   []firehoseFormattingObject
	}
	awsReadFixture(t, "firehose/"+plan.Source, &native)
	fixture := firehoseCapturedCalls(t, native.Calls)
	objects := map[string]firehoseFormattingObject{}
	for _, object := range native.Objects {
		objects[object.Label] = object
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(native.StartedAt.UTC().Truncate(time.Second))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: native.Account, Clock: source})
			for _, label := range plan.Setup {
				row := firehoseCapturedRow(t, fixture, label)
				var client any
				switch row.Service {
				case "s3":
					client = s3NativeClient(clients, "test", "test")
				case "iam":
					client = clients.iam("test", "test", "")
				default:
					t.Fatalf("unsupported multiblock prerequisite %s", row.Service)
				}
				firehoseReplayCall(t, client, row)
			}
			for _, delivery := range plan.Deliveries {
				object, ok := objects[delivery.Object]
				if !ok {
					t.Fatalf("missing captured binary object %s", delivery.Object)
				}
				object.ObservedCodec = delivery.Codec
				put := firehoseCapturedRow(t, fixture, delivery.Put)
				var input firehose.PutRecordBatchInput
				if err := json.Unmarshal(put.Input, &input); err != nil {
					t.Fatal(err)
				}
				var raw []byte
				for _, record := range input.Records {
					raw = append(raw, record.Data...)
				}
				if len(raw) <= 1024*1024 {
					t.Fatal("multiblock capture no longer exercises more than 1 MiB")
				}
				if !bytes.Equal(raw, object.DecodedBytesBase64) || !bytes.Equal(raw, firehoseDecodeFormatting(t, delivery.Codec, object.RawBytesBase64)) {
					t.Fatalf("%s native object does not independently decode to exact captured producer bytes", delivery.Codec)
				}
				firehoseReplayCall(t, clients.firehose("test", "test", ""), firehoseCapturedRow(t, fixture, delivery.Create))
				awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), aws.ToString(input.DeliveryStreamName))
				clients = reopen()
				description, err := clients.firehose("test", "test", "").DescribeDeliveryStream(t.Context(), &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: input.DeliveryStreamName})
				if err != nil {
					t.Fatal(err)
				}
				if got := string(description.DeliveryStreamDescription.Destinations[0].ExtendedS3DestinationDescription.CompressionFormat); got != delivery.Codec {
					t.Fatalf("retained codec=%s, native=%s", got, delivery.Codec)
				}
				before := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, "")
				firehoseReplayCall(t, clients.firehose("test", "test", ""), put)
				clients = reopen()
				firehoseAwaitFormatting(t, clients, source, native.Resources.Bucket, before, input.Records, false, object, delivery.Codec+"/")
			}
		})
	}
}

func firehoseCheckFormattingView(t *testing.T, label string, got *firehosetypes.DeliveryStreamDescription, want firehoseFormattingView) {
	t.Helper()
	if aws.ToString(got.VersionId) != want.VersionID || !reflect.DeepEqual(got.Destinations, want.Destinations) {
		actual, _ := json.Marshal(got.Destinations)
		native, _ := json.Marshal(want.Destinations)
		t.Fatalf("%s retained version/configuration: %s %s; native %s %s", label, aws.ToString(got.VersionId), actual, want.VersionID, native)
	}
}

func firehoseAwaitFormatting(t *testing.T, clients cloudClients, source *clock.Manual, bucket string, before map[string][]byte, records []firehosetypes.Record, delimiter bool, native firehoseFormattingObject, keyPrefix string) {
	t.Helper()
	for range 60 {
		trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
		objects := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, "")
		used := make([]bool, len(records))
		// A zero-byte record has no observable S3 bytes without a delimiter.
		for i, record := range records {
			used[i] = !delimiter && len(record.Data) == 0
		}
		for key, compressed := range objects {
			if _, existed := before[key]; existed {
				continue
			}
			if !strings.HasPrefix(key, keyPrefix) || !strings.HasSuffix(key, native.Key[strings.LastIndexByte(native.Key, '.'):]) {
				t.Fatalf("unexpected formatted key %q, native timestamp prefix %q and suffix %q", key, keyPrefix, native.Key)
			}
			metadata, err := s3NativeClient(clients, "test", "test").HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(metadata.ContentType) != native.Metadata.ContentType || aws.ToString(metadata.ContentEncoding) != native.Metadata.ContentEncoding || string(metadata.ServerSideEncryption) != native.Metadata.ServerSideEncryption || !maps.Equal(metadata.Metadata, native.Metadata.Metadata) {
				t.Fatalf("%s metadata differs from native: %+v", key, metadata)
			}
			body := firehoseDecodeFormatting(t, native.ObservedCodec, compressed)
			for len(body) != 0 {
				match := -1
				for i, record := range records {
					if !used[i] && len(record.Data) != 0 && bytes.HasPrefix(body, record.Data) && (match < 0 || len(record.Data) > len(records[match].Data)) {
						match = i
					}
				}
				if match < 0 {
					t.Fatalf("%s has corrupt, duplicate or unexpected record bytes", key)
				}
				used[match] = true
				body = body[len(records[match].Data):]
				if delimiter && len(body) != 0 {
					if body[0] != '\n' || len(body) == 1 {
						t.Fatalf("%s must have one inter-record LF, no terminal delimiter", key)
					}
					body = body[1:]
				}
			}
		}
		if !slices.Contains(used, false) {
			return
		}
		advanceClock(t, source, time.Second)
	}
	t.Fatal("formatting delivery did not expose all accepted records")
}

// This consumer understands both containers independently of the production
// writer and accepts any legal chunk/block packing. Snappy Decode rejects S2-only
// opcodes, so an accidental S2 encoder cannot masquerade as a Snappy encoder.
func firehoseDecodeFormatting(t *testing.T, codec string, body []byte) []byte {
	t.Helper()
	switch codec {
	case "UNCOMPRESSED":
		return body
	case "ZIP":
		archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			t.Fatal(err)
		}
		var decoded []byte
		if len(archive.File) == 0 {
			t.Fatal("empty ZIP container")
		}
		for _, entry := range archive.File {
			if entry.Method != zip.Deflate {
				t.Fatal("ZIP entry is not DEFLATE")
			}
			reader, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			content, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			decoded = append(decoded, content...)
		}
		return decoded
	case "Snappy":
		if len(body) < 16 || !bytes.Equal(body[:8], []byte{0x82, 'S', 'N', 'A', 'P', 'P', 'Y', 0}) || binary.BigEndian.Uint32(body[8:12]) != 1 || binary.BigEndian.Uint32(body[12:16]) != 1 {
			t.Fatal("invalid snappy-java header")
		}
		body = body[16:]
	case "HADOOP_SNAPPY":
	default:
		t.Fatalf("unknown captured codec %s", codec)
	}
	readLength := func() int {
		if len(body) < 4 {
			t.Fatal("truncated Snappy length")
		}
		n := int(binary.BigEndian.Uint32(body[:4]))
		body = body[4:]
		return n
	}
	var decoded []byte
	for len(body) != 0 {
		remaining := -1
		if codec == "HADOOP_SNAPPY" {
			remaining = readLength()
		}
		for {
			length := readLength()
			if length > len(body) {
				t.Fatal("truncated Snappy block")
			}
			block, err := snappy.Decode(nil, body[:length])
			if err != nil {
				t.Fatal(err)
			}
			body = body[length:]
			decoded = append(decoded, block...)
			if remaining < 0 {
				break
			}
			remaining -= len(block)
			if remaining < 0 || len(block) == 0 && remaining != 0 {
				t.Fatal("invalid Hadoop uncompressed block length")
			}
			if remaining == 0 {
				break
			}
		}
	}
	return decoded
}

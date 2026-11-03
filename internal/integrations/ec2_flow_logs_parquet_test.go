package integrations

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/format"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/services/ec2"
)

func TestEC2FlowLogParquetSelectedColumnsTypesAndGaps(t *testing.T) {
	header := "srcport end account-id version packets tcp-flags protocol bytes start dstport log-status instance-id interface-id srcaddr traffic-path flow-direction"
	lines := []ec2.FlowLogLine{
		{Message: "49152 1798761660 001234567890 5 4294967297 18 6 9223372036854775807 1798761600 443 OK - eni-observed 10.0.0.4 1 egress"},
		{Message: "- 1798761720 001234567890 5 - - - - 1798761660 - SKIPDATA - eni-observed - - -"},
		{Message: "443 1798761660 001234567890 5 2 18 6 120 1798761600 49152 OK - eni-observed 10.0.0.8 - ingress"},
	}
	payload, err := encodeFlowLogParquet(header, lines)
	if err != nil {
		t.Fatal(err)
	}
	file, rows := readFlowLogParquet(t, payload)
	wantNames := []string{"srcport", "end", "account_id", "version", "packets", "tcp_flags", "protocol", "bytes", "start", "dstport", "log_status", "instance_id", "interface_id", "srcaddr", "traffic_path", "flow_direction"}
	wantTypes := []parquet.Kind{parquet.Int32, parquet.Int64, parquet.ByteArray, parquet.Int32, parquet.Int64, parquet.Int32, parquet.Int32, parquet.Int64, parquet.Int64, parquet.Int32, parquet.ByteArray, parquet.ByteArray, parquet.ByteArray, parquet.ByteArray, parquet.Int32, parquet.ByteArray}
	fields := file.Schema().Fields()
	if len(fields) != len(wantNames) || len(rows) != 3 {
		t.Fatalf("selected columns or rows changed: schema=%s rows=%v", file.Schema(), rows)
	}
	for i, field := range fields {
		if field.Name() != wantNames[i] || field.Type().Kind() != wantTypes[i] {
			t.Fatalf("column %d: name=%s kind=%s, want %s %s", i, field.Name(), field.Type().Kind(), wantNames[i], wantTypes[i])
		}
		if wantTypes[i] == parquet.ByteArray && field.Type().LogicalType().String() != "STRING" {
			t.Fatalf("column %s is binary rather than STRING: %s", field.Name(), field.Type())
		}
	}
	if rows[0][0].Int32() != 49152 || rows[0][3].Int32() != 5 || rows[0][5].Int32() != 18 || rows[0][6].Int32() != 6 || rows[0][9].Int32() != 443 || rows[0][14].Int32() != 1 || rows[0][14].DefinitionLevel() != 1 {
		t.Fatalf("INT32 values changed: %v", rows[0])
	}
	if rows[0][1].Int64() != 1798761660 || rows[0][4].Int64() != 4294967297 || rows[0][7].Int64() != 9223372036854775807 || rows[0][8].Int64() != 1798761600 {
		t.Fatalf("INT64 values were narrowed or changed: %v", rows[0])
	}
	for column, want := range map[int]string{2: "001234567890", 10: "OK", 11: "-", 12: "eni-observed", 13: "10.0.0.4"} {
		if got := string(rows[0][column].ByteArray()); got != want {
			t.Fatalf("column %s = %q, want %q", wantNames[column], got, want)
		}
	}
	for _, column := range []int{0, 4, 5, 6, 7, 9, 14} {
		if !fields[column].Optional() || !rows[1][column].IsNull() || rows[1][column].DefinitionLevel() != 0 {
			t.Fatalf("unavailable numeric column %s became a fabricated value: %v", wantNames[column], rows[1][column])
		}
	}
	if rows[1][1].Int64() != 1798761720 || rows[1][8].Int64() != 1798761660 || string(rows[1][10].ByteArray()) != "SKIPDATA" || string(rows[1][13].ByteArray()) != "-" {
		t.Fatalf("gap lost its retained times, status, or unavailable string: %v", rows[1])
	}
	if !fields[14].Optional() || !rows[2][14].IsNull() || rows[2][14].DefinitionLevel() != 0 || string(rows[2][10].ByteArray()) != "OK" || string(rows[2][15].ByteArray()) != "ingress" {
		t.Fatalf("valid ingress requires unavailable nullable INT32 traffic_path: %v", rows[2])
	}
}

func readFlowLogParquet(t *testing.T, payload []byte) (*parquet.File, []parquet.Row) {
	t.Helper()
	if len(payload) < 8 || string(payload[:4]) != "PAR1" || string(payload[len(payload)-4:]) != "PAR1" {
		t.Fatal("delivery is not a complete Parquet file")
	}
	file, err := parquet.OpenFile(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range file.Metadata().RowGroups {
		for _, column := range group.Columns {
			if column.MetaData.Codec != format.Gzip {
				t.Fatalf("column %v uses %v, not GZIP", column.MetaData.PathInSchema, column.MetaData.Codec)
			}
		}
	}
	reader := parquet.NewReader(bytes.NewReader(payload))
	defer reader.Close()
	rows := make([]parquet.Row, int(file.NumRows()))
	n, err := reader.ReadRows(rows)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n != len(rows) {
		t.Fatalf("read %d of %d Parquet rows", n, len(rows))
	}
	return file, rows
}

func flowLogParquetDestination(t *testing.T) (*cfnS3OwnerFixture, *EC2FlowLogs, ec2.FlowLogDeliveryRecord) {
	t.Helper()
	f := newCFNS3OwnerFixture(t, "memory")
	f.native(t, "s3", "CreateBucket", map[string]any{"Bucket": "parquet-flow-delivery"})
	f.native(t, "s3", "PutBucketEncryption", map[string]any{
		"Bucket":                            "parquet-flow-delivery",
		"ServerSideEncryptionConfiguration": map[string]any{"Rules": []any{map[string]any{"ApplyServerSideEncryptionByDefault": map[string]any{"SSEAlgorithm": "AES256"}}}},
	})
	scope := ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	batch := ec2.FlowLogDeliveryRecord{
		Key: ec2.ResourceKey{Scope: scope, ID: "immutable-sealed-window"}, FlowLogKey: ec2.ResourceKey{Scope: scope, ID: "fl-parquet"},
		DestinationType: "s3", Destination: "arn:aws:s3:::parquet-flow-delivery/selected", FileFormat: "parquet",
		HivePartitions: true, HourPartitions: true, WindowStart: time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC),
		Header: "interface-id packets log-status traffic-path",
	}
	adapter := &EC2FlowLogs{S3: f.owner}
	if wire := adapter.validateS3(f.ctx, ec2.FlowLogRecord{Key: batch.FlowLogKey, DestinationType: batch.DestinationType, Destination: batch.Destination, HivePartitions: true}); wire != nil {
		t.Fatal(wire)
	}
	return f, adapter, batch
}

func TestEC2FlowLogParquetS3DeliveryKeepsWindowRetryIdentityAndCurrentAuthority(t *testing.T) {
	f, adapter, batch := flowLogParquetDestination(t)
	lines := []ec2.FlowLogLine{{Message: "eni-real 9876543210 OK 1"}}
	if wire := adapter.Write(f.ctx, batch, lines); wire != nil {
		t.Fatal(wire)
	}
	key := flowLogObjectKey(batch, "selected")
	if !strings.HasPrefix(key, "selected/AWSLogs/aws-account-id=123456789012/aws-service=vpcflowlogs/aws-region=us-east-1/year=2026/month=12/day=31/hour=23/") || !strings.HasSuffix(key, ".log.parquet") {
		t.Fatalf("Parquet delivery lost original window partitions: %s", key)
	}
	get := func() []byte {
		t.Helper()
		object, wire := f.owner.GetObject(f.ctx, &s3api.GetObjectInput{Bucket: new(s3api.BucketName("parquet-flow-delivery")), Key: new(s3api.ObjectKey(key))})
		if wire != nil {
			t.Fatal(wire)
		}
		if object.Output.ContentType == nil || *object.Output.ContentType != "application/octet-stream" || object.Output.ContentEncoding != nil {
			t.Fatalf("Parquet was represented as an outer gzip stream: %+v", object.Output)
		}
		if object.Output.ServerSideEncryption == nil || *object.Output.ServerSideEncryption != "AES256" {
			t.Fatalf("delivery bypassed inherited bucket encryption: %+v", object.Output)
		}
		return object.Output.Body
	}
	payload := get()
	_, rows := readFlowLogParquet(t, payload)
	if len(rows) != 1 || string(rows[0][0].ByteArray()) != "eni-real" || rows[0][1].Int64() != 9876543210 || rows[0][3].Int32() != 1 {
		t.Fatalf("S3 payload lost observed records: %v", rows)
	}
	batch.Due = batch.WindowStart.Add(72 * time.Hour)
	if wire := adapter.Write(f.ctx, batch, lines); wire != nil {
		t.Fatal(wire)
	}
	if !bytes.Equal(payload, get()) {
		t.Fatal("retry changed the immutable window payload")
	}
	listed, err := cfnComputeCall[s3api.ListObjectsV2Output](f.ctx, f.commands, "s3", "ListObjectsV2", map[string]any{"Bucket": "parquet-flow-delivery"})
	if err != nil || len(listed.Contents) != 1 || listed.Contents[0].Key == nil || string(*listed.Contents[0].Key) != key {
		t.Fatalf("retry created another destination key: %+v %v", listed, err)
	}
	// Admission is not reusable delivery authority: retain the ACL grant but
	// revoke PutObject after a successful delivery through the real S3 owner.
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"delivery.logs.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::parquet-flow-delivery"},{"Effect":"Deny","Principal":{"Service":"delivery.logs.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::parquet-flow-delivery/*"}]}`
	f.native(t, "s3", "PutBucketPolicy", map[string]any{"Bucket": "parquet-flow-delivery", "Policy": policy})
	batch.Key.ID = "next-immutable-window"
	if wire := adapter.Write(f.ctx, batch, lines); wire == nil || wire.Code != "AccessDenied" {
		t.Fatalf("Parquet delivery reused old authority: %v", wire)
	}
	listed, err = cfnComputeCall[s3api.ListObjectsV2Output](f.ctx, f.commands, "s3", "ListObjectsV2", map[string]any{"Bucket": "parquet-flow-delivery"})
	if err != nil || len(listed.Contents) != 1 || listed.Contents[0].Key == nil || string(*listed.Contents[0].Key) != key {
		t.Fatalf("revoked delivery changed published objects: %+v %v", listed, err)
	}
}

func TestEC2FlowLogParquetMalformedBatchNeverCreatesS3Object(t *testing.T) {
	f, adapter, base := flowLogParquetDestination(t)
	for i, test := range []struct{ name, header, line string }{
		{"counter-overflow", "packets", "18446744073709551615"},
		{"counter-signed-overflow", "bytes", "9223372036854775808"},
		{"int32-overflow", "srcport", "2147483648"},
		{"int32-underflow", "protocol", "-2147483649"},
		{"malformed-number", "tcp-flags", "18x"},
		{"missing-cell", "interface-id packets", "eni-real"},
		{"extra-cell", "interface-id", "eni-real injected"},
		{"empty-cell", "interface-id packets", "eni-real  4"},
		{"newline", "interface-id", "eni-real\nforged"},
		{"invalid-string", "interface-id", "eni-\xff"},
		{"duplicate-column", "packets packets", "3 4"},
		{"unsupported-column", "invented-field", "value"},
	} {
		t.Run(test.name, func(t *testing.T) {
			batch := base
			batch.Key.ID, batch.Header = fmt.Sprintf("malformed-%d", i), test.header
			// The first row may be completely encoded before a later bad row;
			// neither a prefix nor a corrupt footer may escape to S3.
			lines := []ec2.FlowLogLine{{Message: test.line}}
			if test.header == "packets" {
				lines = append([]ec2.FlowLogLine{{Message: "2"}}, lines...)
			}
			if wire := adapter.Write(f.ctx, batch, lines); wire == nil || wire.Code != "InvalidParameter" {
				t.Fatalf("malformed Parquet batch was not an explicit delivery error: %v", wire)
			}
		})
	}
	listed, err := cfnComputeCall[s3api.ListObjectsV2Output](f.ctx, f.commands, "s3", "ListObjectsV2", map[string]any{"Bucket": "parquet-flow-delivery"})
	if err != nil || len(listed.Contents) != 0 {
		t.Fatalf("malformed batches published objects: %+v %v", listed, err)
	}
}

func TestEC2FlowLogTextDeliveryPreservesExistingContentAndSuffix(t *testing.T) {
	f, adapter, batch := flowLogParquetDestination(t)
	batch.Header = "interface-id packets log-status"
	lines := []ec2.FlowLogLine{{Message: "eni-real 5 OK"}, {Message: "eni-real - SKIPDATA"}}
	var legacy []byte
	for _, fileFormat := range []string{"", "plain-text"} {
		batch.FileFormat = fileFormat
		if wire := adapter.Write(f.ctx, batch, lines); wire != nil {
			t.Fatal(wire)
		}
		key := flowLogObjectKey(batch, "selected")
		if !strings.HasSuffix(key, ".log.gz") {
			t.Fatalf("text delivery suffix changed: %s", key)
		}
		object, wire := f.owner.GetObject(f.ctx, &s3api.GetObjectInput{Bucket: new(s3api.BucketName("parquet-flow-delivery")), Key: new(s3api.ObjectKey(key))})
		if wire != nil {
			t.Fatal(wire)
		}
		if object.Output.ContentType == nil || *object.Output.ContentType != "text/plain" || object.Output.ContentEncoding == nil || *object.Output.ContentEncoding != "gzip" {
			t.Fatalf("text delivery metadata changed: %+v", object.Output)
		}
		compressed, err := gzip.NewReader(bytes.NewReader(object.Output.Body))
		if err != nil {
			t.Fatal(err)
		}
		text, err := io.ReadAll(compressed)
		if err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
		if string(text) != "interface-id packets log-status\neni-real 5 OK\neni-real - SKIPDATA\n" {
			t.Fatalf("existing text bytes changed: %q", text)
		}
		if fileFormat == "" {
			legacy = object.Output.Body
		} else if !bytes.Equal(legacy, object.Output.Body) {
			t.Fatal("legacy and explicit plain-text output differ")
		}
	}
}

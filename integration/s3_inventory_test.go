package stackd_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestS3InventoryNativeControls(t *testing.T) {
	runS3ExecutionReplay(t, "s3/inventory_control_replay.json")
}

func TestS3InventoryNativeAudit(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/inventory_audit_replay.json")
}

func TestS3InventoryExecution(t *testing.T) {
	runS3ExecutionReplay(t, "s3/inventory_execution_replay.json")
}

type s3InventoryReportExpectation struct {
	Actor, Bucket, SourceBucket, Manifest string
	Columns                               []string
	Rows                                  []map[string]string
}

// Consume the published manifest and referenced CSV objects through the SDK.
// Row projections are unordered: inventory promises no report row ordering.
func assertS3InventoryReports(t *testing.T, replay *s3KMSReplay, expected []s3InventoryReportExpectation) {
	t.Helper()
	var reports []s3InventoryReportExpectation
	if err := json.Unmarshal(replay.rebind(t, expected), &reports); err != nil {
		t.Fatal(err)
	}
	for _, want := range reports {
		actor := want.Actor
		if actor == "" {
			actor = "caller"
		}
		client := replay.s3Client(actor)
		get := func(key string) []byte {
			t.Helper()
			object, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String(want.Bucket), Key: aws.String(key)})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(object.Body)
			_ = object.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
		data := get(want.Manifest)
		directory := strings.TrimSuffix(want.Manifest, "/manifest.json")
		digest := strings.TrimSpace(string(get(directory + "/manifest.checksum")))
		if digest != fmt.Sprintf("%x", md5.Sum(data)) {
			t.Fatalf("%s: manifest checksum mismatch", want.Manifest)
		}
		var manifest struct {
			SourceBucket, DestinationBucket, Version, CreationTimestamp, FileFormat, FileSchema string
			Files                                                                               []struct {
				Key, MD5Checksum string
				Size             int64
			}
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.SourceBucket != want.SourceBucket || manifest.DestinationBucket != "arn:aws:s3:::"+want.Bucket || manifest.Version != "2016-11-30" || manifest.FileFormat != "CSV" {
			t.Fatalf("%s: unexpected manifest: %s", want.Manifest, data)
		}
		prefix, stamp := directory[:strings.LastIndex(directory, "/")], directory[strings.LastIndex(directory, "/")+1:]
		at, err := time.Parse("2006-01-02T15-04Z", stamp)
		if err != nil || manifest.CreationTimestamp != strconv.FormatInt(at.UnixMilli(), 10) {
			t.Fatalf("%s: wrong report occurrence %q", want.Manifest, manifest.CreationTimestamp)
		}
		columns := strings.Split(manifest.FileSchema, ",")
		for i := range columns {
			columns[i] = strings.TrimSpace(columns[i])
		}
		if !slices.Equal(columns, want.Columns) {
			t.Fatalf("%s: columns %v; want %v", want.Manifest, columns, want.Columns)
		}
		var rows []map[string]string
		var targets strings.Builder
		for _, file := range manifest.Files {
			payload := get(file.Key)
			if int64(len(payload)) != file.Size || fmt.Sprintf("%x", md5.Sum(payload)) != file.MD5Checksum {
				t.Fatalf("%s: data-file size or checksum mismatch", file.Key)
			}
			fmt.Fprintf(&targets, "s3://%s/%s\n", want.Bucket, file.Key)
			compressed, err := gzip.NewReader(bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			reader := csv.NewReader(compressed)
			reader.FieldsPerRecord = len(columns)
			records, err := reader.ReadAll()
			_ = compressed.Close()
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range records {
				row := make(map[string]string, len(columns))
				for i, name := range columns {
					row[name] = record[i]
				}
				row["Key"], err = url.PathUnescape(row["Key"])
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, row)
			}
		}
		if got := string(get(prefix + "/hive/dt=" + at.Format("2006-01-02-15-04") + "/symlink.txt")); got != targets.String() {
			t.Fatalf("%s: symlink references %q; want %q", want.Manifest, got, targets.String())
		}
		if len(rows) != len(want.Rows) {
			t.Fatalf("%s: %d rows; want %d: %v", want.Manifest, len(rows), len(want.Rows), rows)
		}
		for _, expectedRow := range want.Rows {
			matched := -1
			for i, row := range rows {
				matches := true
				for name, value := range expectedRow {
					if got, present := row[name]; !present || got != value {
						matches = false
						break
					}
				}
				if matches {
					matched = i
					break
				}
			}
			if matched < 0 {
				t.Fatalf("%s: missing row %v; remaining %v", want.Manifest, expectedRow, rows)
			}
			rows = slices.Delete(rows, matched, matched+1)
		}
	}
}

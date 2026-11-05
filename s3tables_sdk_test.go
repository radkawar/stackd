package stackd_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3tables"
	tabletypes "github.com/aws/aws-sdk-go-v2/service/s3tables/types"
)

// Exercise the public generated protocol, private S3 data owner and durable CAS
// together. The same table must remain authoritative through a controller restart.
func TestS3TablesSDKPrivateWarehouseAndCommitRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture, reopen := newIcebergRESTFixture(t, backend)
			clientFor := func() *s3tables.Client {
				return s3tables.New(s3tables.Options{Region: icebergRESTRegion, BaseEndpoint: aws.String(fixture.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: fixture.server.Client(), RetryMaxAttempts: 1})
			}
			client := clientFor()
			bucket, err := client.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("sdk-tables")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = client.GetTableBucket(t.Context(), &s3tables.GetTableBucketInput{TableBucketARN: bucket.Arn}); err != nil {
				t.Fatal(err)
			}
			if _, err = client.CreateNamespace(t.Context(), &s3tables.CreateNamespaceInput{TableBucketARN: bucket.Arn, Namespace: []string{"analytics"}}); err != nil {
				t.Fatal(err)
			}
			if _, err = client.GetNamespace(t.Context(), &s3tables.GetNamespaceInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics")}); err != nil {
				t.Fatal(err)
			}
			created, err := client.CreateTable(t.Context(), &s3tables.CreateTableInput{
				TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("events"), Format: tabletypes.OpenTableFormatIceberg,
				Metadata: &tabletypes.TableMetadataMemberIceberg{Value: tabletypes.IcebergMetadata{Schema: &tabletypes.IcebergSchema{Fields: []tabletypes.SchemaField{{Name: aws.String("id"), Type: aws.String("long")}}}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			head, err := client.GetTableMetadataLocation(t.Context(), &s3tables.GetTableMetadataLocationInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("events")})
			if err != nil {
				t.Fatal(err)
			}
			warehouse, err := url.Parse(aws.ToString(head.WarehouseLocation))
			if err != nil || warehouse.Scheme != "s3" || !strings.HasSuffix(warehouse.Host, "--table-s3") {
				t.Fatalf("invalid managed warehouse: %v %v", warehouse, err)
			}
			readObject := func(location string) []byte {
				t.Helper()
				parsed, err := url.Parse(location)
				if err != nil {
					t.Fatal(err)
				}
				out, err := fixture.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(parsed.Host), Key: aws.String(strings.TrimPrefix(parsed.Path, "/"))})
				if err != nil {
					t.Fatal(err)
				}
				defer out.Body.Close()
				body, err := io.ReadAll(out.Body)
				if err != nil {
					t.Fatal(err)
				}
				return body
			}
			original := readObject(aws.ToString(head.MetadataLocation))
			var metadata map[string]any
			if err := json.Unmarshal(original, &metadata); err != nil {
				t.Fatal(err)
			}
			metadata["properties"] = map[string]string{"verification": "committed"}
			candidate, err := json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			location := aws.ToString(head.WarehouseLocation) + "/metadata/next.metadata.json"
			if _, err = fixture.s3.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(warehouse.Host), Key: aws.String("metadata/next.metadata.json"), Body: bytes.NewReader(candidate)}); err != nil {
				t.Fatal(err)
			}
			committed, err := client.UpdateTableMetadataLocation(t.Context(), &s3tables.UpdateTableMetadataLocationInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("events"), VersionToken: head.VersionToken, MetadataLocation: aws.String(location)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.UpdateTableMetadataLocation(t.Context(), &s3tables.UpdateTableMetadataLocationInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("events"), VersionToken: head.VersionToken, MetadataLocation: head.MetadataLocation})
			var conflict *tabletypes.ConflictException
			if !errors.As(err, &conflict) {
				t.Fatalf("stale writer must receive modeled conflict: %v", err)
			}
			if !bytes.Equal(readObject(aws.ToString(head.MetadataLocation)), original) {
				t.Fatal("commit changed the prior immutable metadata object")
			}
			if _, err = client.RenameTable(t.Context(), &s3tables.RenameTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("events"), NewName: aws.String("retained"), VersionToken: committed.VersionToken}); err != nil {
				t.Fatal(err)
			}
			_, err = client.DeleteNamespace(t.Context(), &s3tables.DeleteNamespaceInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics")})
			if !errors.As(err, &conflict) {
				t.Fatalf("nonempty namespace deletion must conflict: %v", err)
			}
			fixture = reopen()
			client = clientFor()
			retained, err := client.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: created.TableARN})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(retained.Name) != "retained" || aws.ToString(retained.MetadataLocation) != location || aws.ToString(retained.WarehouseLocation) != aws.ToString(head.WarehouseLocation) {
				t.Fatalf("rename/reopen lost table authority: %+v", retained)
			}
			if !bytes.Equal(readObject(location), candidate) {
				t.Fatal("private warehouse lost committed metadata on restart")
			}
			public, err := fixture.s3.ListBuckets(t.Context(), &s3.ListBucketsInput{})
			if err != nil {
				t.Fatal(err)
			}
			for _, ordinary := range public.Buckets {
				if aws.ToString(ordinary.Name) == warehouse.Host {
					t.Fatal("managed warehouse leaked into ordinary S3 bucket ownership")
				}
			}
			if _, err = client.DeleteTable(t.Context(), &s3tables.DeleteTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: retained.Name, VersionToken: retained.VersionToken}); err != nil {
				t.Fatal(err)
			}
			_, err = client.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: created.TableARN})
			var missing *tabletypes.NotFoundException
			if !errors.As(err, &missing) {
				t.Fatalf("deleted table remained visible: %v", err)
			}
			object, err := fixture.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(warehouse.Host), Key: aws.String("metadata/next.metadata.json")})
			if err == nil {
				object.Body.Close()
				t.Fatal("deleted warehouse remained readable through ordinary S3")
			}
			if _, err = client.DeleteNamespace(t.Context(), &s3tables.DeleteNamespaceInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics")}); err != nil {
				t.Fatal(err)
			}
			if _, err = client.DeleteTableBucket(t.Context(), &s3tables.DeleteTableBucketInput{TableBucketARN: bucket.Arn}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

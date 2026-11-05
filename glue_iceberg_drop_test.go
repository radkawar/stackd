package stackd_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// AWS Glue's S3 REST catalog explicitly rejects purge. This is distinct from
// S3 Tables, which requires purging deletion. The spelling comes from the
// AWS-referenced Iceberg 1.6.1 OpenAPI (AWS prose calls it "purgeRequest"):
// https://docs.aws.amazon.com/glue/latest/dg/iceberg-rest-apis.html#delete-table
// https://github.com/apache/iceberg/blob/apache-iceberg-1.6.1/open-api/rest-catalog-open-api.yaml#L793
func TestGlueIcebergRESTDropRetainsObjectsAndSharedMetadata(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, reopen := newIcebergRESTFixture(t, backend)
			if _, err := f.s3.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(icebergRESTBucket)}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s3.PutBucketVersioning(t.Context(), &s3.PutBucketVersioningInput{
				Bucket: aws.String(icebergRESTBucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled},
			}); err != nil {
				t.Fatal(err)
			}
			f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces", map[string]any{
				"namespace": []string{icebergRESTNamespace}, "properties": map[string]string{},
			}, http.StatusOK)
			_, initial := f.create(t, "events")
			const snapshotID int64 = 920000000000000101
			request := f.appendRequest(t, initial, snapshotID, 0, 1)
			head, metadata := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTTablePath("events"), request, http.StatusOK))
			headBytes := f.object(t, head.MetadataLocation)
			if _, err := f.glue.CreateTable(t.Context(), &glue.CreateTableInput{
				DatabaseName: aws.String(icebergRESTNamespace),
				TableInput: &gluetypes.TableInput{Name: aws.String("shared_events"), TableType: aws.String("EXTERNAL_TABLE"),
					Parameters: map[string]string{"table_type": "ICEBERG", "metadata_location": head.MetadataLocation}},
			}); err != nil {
				t.Fatal(err)
			}
			// Catalog-only drops must not inspect even corrupt manifests. Neither
			// a failed purge nor an ordinary drop owns unrelated same-prefix data.
			// The native PyIceberg fixture separately proves real Parquet/Avro.
			manifest := metadata.Snapshots[0].ManifestList
			manifestKey := strings.TrimPrefix(manifest, "s3://"+icebergRESTBucket+"/")
			for key, data := range map[string][]byte{
				manifestKey: []byte("malformed manifest list retained verbatim"),
				icebergRESTNamespace + "/events/data/unrelated.bin": []byte("unrelated same-prefix bytes"),
				"unrelated/outside.bin":                             []byte("unrelated outside-prefix bytes"),
			} {
				if _, err := f.s3.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(icebergRESTBucket), Key: aws.String(key), Body: bytes.NewReader(data)}); err != nil {
					t.Fatal(err)
				}
			}
			versions := func() *s3.ListObjectVersionsOutput {
				t.Helper()
				out, err := f.s3.ListObjectVersions(t.Context(), &s3.ListObjectVersionsInput{Bucket: aws.String(icebergRESTBucket)})
				if err != nil {
					t.Fatal(err)
				}
				if aws.ToBool(out.IsTruncated) {
					t.Fatal("unexpectedly truncated fixture object inventory")
				}
				return out
			}
			before := versions()
			assertUnchanged := func() {
				t.Helper()
				after := versions()
				if !reflect.DeepEqual(before.Versions, after.Versions) || !reflect.DeepEqual(before.DeleteMarkers, after.DeleteMarkers) {
					t.Fatal("catalog drop changed S3 object versions or created delete markers")
				}
				shared, _ := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath("shared_events"), nil, http.StatusOK))
				if shared.MetadataLocation != head.MetadataLocation || !bytes.Equal(headBytes, f.object(t, shared.MetadataLocation)) {
					t.Fatal("drop changed shared metadata")
				}
			}
			// PyIceberg 0.10.0 sends Python booleans through requests, producing
			// `True` and `False`. A literal-lowercase comparison rejected its
			// ordinary drop_table as if it had requested purge.
			for _, value := range []string{"true", "True", "TRUE"} {
				rejected := f.call(t, icebergRESTRoot, http.MethodDelete, icebergRESTTablePath("events")+"?purgeRequested="+value, nil, http.StatusBadRequest)
				assertIcebergRESTError(t, rejected, http.StatusBadRequest, "UnsupportedOperationException")
				current, _ := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusOK))
				if current.MetadataLocation != head.MetadataLocation {
					t.Fatal("rejected purge changed catalog head")
				}
				assertUnchanged()
			}
			f = reopen()
			assertUnchanged()
			f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath("events"), nil, http.StatusNoContent)
			for index, suffix := range []string{"?purgeRequested=False", "?purgeRequested=false", "?purgeRequested=FALSE", ""} {
				name := "events"
				if index != 0 {
					name = "another_events"
					if _, err := f.glue.CreateTable(t.Context(), &glue.CreateTableInput{DatabaseName: aws.String(icebergRESTNamespace), TableInput: &gluetypes.TableInput{
						Name: aws.String(name), Parameters: map[string]string{"table_type": "ICEBERG", "metadata_location": head.MetadataLocation},
					}}); err != nil {
						t.Fatal(err)
					}
				}
				response := f.call(t, icebergRESTRoot, http.MethodDelete, icebergRESTTablePath(name)+suffix, nil, http.StatusNoContent)
				if len(response.body) != 0 {
					t.Fatal("successful drop returned a response body")
				}
				f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath(name), nil, http.StatusNotFound)
				assertUnchanged()
			}
			f = reopen()
			f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath("events"), nil, http.StatusNotFound)
			assertUnchanged()
		})
	}
}

func TestGlueIcebergRESTDropUsesCurrentGlueAuthorityWithoutS3Effects(t *testing.T) {
	f, _ := newIcebergRESTFixture(t, "memory")
	if _, err := f.s3.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(icebergRESTBucket)}); err != nil {
		t.Fatal(err)
	}
	f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces", map[string]any{"namespace": []string{icebergRESTNamespace}, "properties": map[string]string{}}, http.StatusOK)
	head, _ := f.create(t, "events")
	before := f.object(t, head.MetadataLocation)
	const user = "iceberg-dropper"
	if _, err := f.iam.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)}); err != nil {
		t.Fatal(err)
	}
	access, err := f.iam.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: aws.String(user)})
	if err != nil {
		t.Fatal(err)
	}
	identity := aws.Credentials{AccessKeyID: aws.ToString(access.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(access.AccessKey.SecretAccessKey)}
	statements := []any{
		map[string]any{"Effect": "Allow", "Action": []string{"glue:GetCatalog", "glue:DeleteTable"}, "Resource": "*"},
		map[string]any{"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
	}
	putPolicy := func() {
		t.Helper()
		policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.iam.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String("catalog-drop"), PolicyDocument: aws.String(string(policy))}); err != nil {
			t.Fatal(err)
		}
	}
	putPolicy()
	// Revoking Glue authority affects this same access key immediately. A
	// rejected deletion must leave the catalog head and immutable bytes intact.
	statements = append(statements, map[string]any{"Effect": "Deny", "Action": "glue:DeleteTable", "Resource": "*"})
	putPolicy()
	f.call(t, identity, http.MethodDelete, icebergRESTTablePath("events")+"?purgeRequested=False", nil, http.StatusForbidden)
	f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath("events"), nil, http.StatusNoContent)
	statements = statements[:len(statements)-1]
	putPolicy()
	f.call(t, identity, http.MethodDelete, icebergRESTTablePath("events")+"?purgeRequested=False", nil, http.StatusNoContent)
	f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath("events"), nil, http.StatusNotFound)
	if !bytes.Equal(before, f.object(t, head.MetadataLocation)) {
		t.Fatal("catalog-only drop changed S3 bytes despite explicit S3 denial")
	}
}

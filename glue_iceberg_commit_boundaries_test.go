package stackd_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// AWS explicitly excludes stage-create and does not advertise the optional
// Apache Iceberg multi-table commit endpoint:
// https://docs.aws.amazon.com/glue/latest/dg/iceberg-rest-apis.html#create-table
// https://docs.aws.amazon.com/glue/latest/dg/connect-glu-iceberg-rest.html
// These are local protocol regressions, not a capture of AWS error wording.
func TestGlueIcebergRESTUnsupportedStagingAndTransactionsPreserveHeads(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, reopen := newIcebergRESTFixture(t, backend)
			if _, err := f.s3.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(icebergRESTBucket)}); err != nil {
				t.Fatal(err)
			}
			f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces", map[string]any{
				"namespace": []string{icebergRESTNamespace}, "properties": map[string]string{},
			}, http.StatusOK)
			created, metadata := f.create(t, "events")
			other, _ := f.create(t, "other_events")
			original := f.object(t, created.MetadataLocation)
			objectsBefore, err := f.s3.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: aws.String(icebergRESTBucket)})
			if err != nil {
				t.Fatal(err)
			}
			staged := map[string]any{
				"name": "staged_events", "stage-create": true,
				"location": "s3://" + icebergRESTBucket + "/staged_events",
				"schema": map[string]any{"type": "struct", "schema-id": 0, "fields": []any{
					map[string]any{"id": 1, "name": "id", "required": true, "type": "long"},
				}},
			}
			response := f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace+"/tables", staged, http.StatusBadRequest)
			assertIcebergRESTError(t, response, http.StatusBadRequest, "UnsupportedOperationException")
			f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath("staged_events"), nil, http.StatusNotFound)
			f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath("staged_events"), nil, http.StatusNotFound)
			_, err = f.glue.GetTable(t.Context(), &glue.GetTableInput{DatabaseName: aws.String(icebergRESTNamespace), Name: aws.String("staged_events")})
			var rejected smithy.APIError
			if !errors.As(err, &rejected) || rejected.ErrorCode() != "EntityNotFoundException" {
				t.Fatalf("rejected staging became visible to ordinary Glue: %v", err)
			}
			// The same rejection must not replace an existing table or emit S3 data.
			staged["name"] = "events"
			f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace+"/tables", staged, http.StatusBadRequest)
			objectsAfter, err := f.s3.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: aws.String(icebergRESTBucket)})
			if err != nil || !reflect.DeepEqual(objectsBefore.Contents, objectsAfter.Contents) {
				t.Fatalf("unsupported staging wrote S3 objects: %v", err)
			}
			config := f.call(t, icebergRESTRoot, http.MethodGet, "/iceberg/v1/config?warehouse="+icebergRESTAccount, nil, http.StatusOK)
			var capabilities struct {
				Endpoints []string `json:"endpoints"`
			}
			if err := json.Unmarshal(config.body, &capabilities); err != nil {
				t.Fatal(err)
			}
			for _, endpoint := range capabilities.Endpoints {
				if endpoint == "POST /v1/{prefix}/transactions/commit" {
					t.Fatal("config advertised unsupported multi-table transactions")
				}
			}
			change := func(name string) map[string]any {
				return map[string]any{
					"identifier":   map[string]any{"namespace": []string{icebergRESTNamespace}, "name": name},
					"requirements": []any{}, "updates": []any{map[string]any{"action": "set-properties", "updates": map[string]string{"owner": "must-not-publish"}}},
				}
			}
			transaction := map[string]any{"table-changes": []any{change("events"), change("other_events")}}
			response = f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/transactions/commit", transaction, http.StatusNotFound)
			assertIcebergRESTError(t, response, http.StatusNotFound, "NoSuchResourceException")
			// A single-table assert-create is not an overwrite or a back door to staging.
			createCommit := map[string]any{"requirements": []any{map[string]any{"type": "assert-create"}}, "updates": []any{map[string]any{"action": "set-properties", "updates": map[string]string{"owner": "must-not-publish"}}}}
			response = f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTTablePath("events"), createCommit, http.StatusConflict)
			assertIcebergRESTError(t, response, http.StatusConflict, "CommitFailedException")
			f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTTablePath("staged_events"), createCommit, http.StatusNotFound)
			f = reopen()
			for name, expected := range map[string]string{"events": created.MetadataLocation, "other_events": other.MetadataLocation} {
				retained, current := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath(name), nil, http.StatusOK))
				if retained.MetadataLocation != expected || current.Properties["owner"] != "boundary" {
					t.Fatalf("unsupported operation published %s: %s", name, retained.Metadata)
				}
			}
			f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath("staged_events"), nil, http.StatusNotFound)
			listed := f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace+"/tables", nil, http.StatusOK)
			var listing struct {
				Identifiers []struct {
					Name string `json:"name"`
				} `json:"identifiers"`
			}
			if err := json.Unmarshal(listed.body, &listing); err != nil || len(listing.Identifiers) != 2 || listing.Identifiers[0].Name != "events" || listing.Identifiers[1].Name != "other_events" {
				t.Fatalf("rejected staging entered listing: %s (%v)", listed.body, err)
			}
			if !bytes.Equal(original, f.object(t, created.MetadataLocation)) {
				t.Fatal("unsupported operation changed immutable metadata bytes")
			}
			f.assertSharedTable(t, "events", created, metadata)
		})
	}
}

// Java RESTSessionCatalog.replaceTransaction builds a replacement against the
// existing UUID; its create-or-replace missing-table branch instead stage-creates
// and is rejected by AWS. Exercise only the supported existing-table route.
// https://github.com/apache/iceberg/blob/apache-iceberg-1.6.1/core/src/main/java/org/apache/iceberg/rest/RESTSessionCatalog.java
func TestGlueIcebergRESTExistingTableReplacement(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, reopen := newIcebergRESTFixture(t, backend)
			if _, err := f.s3.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(icebergRESTBucket)}); err != nil {
				t.Fatal(err)
			}
			f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces", map[string]any{"namespace": []string{icebergRESTNamespace}, "properties": map[string]string{}}, http.StatusOK)
			_, initial := f.create(t, "events")
			first, appended := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTTablePath("events"), f.appendRequest(t, initial, 71, 0, 1), http.StatusOK))
			oldBytes := f.object(t, first.MetadataLocation)
			replacement := map[string]any{
				"requirements": []any{
					map[string]any{"type": "assert-table-uuid", "uuid": initial.UUID},
					map[string]any{"type": "assert-last-assigned-field-id", "last-assigned-field-id": 2},
					map[string]any{"type": "assert-last-assigned-partition-id", "last-assigned-partition-id": 999},
				},
				"updates": []any{
					map[string]any{"action": "remove-snapshot-ref", "ref-name": "main"},
					map[string]any{"action": "add-schema", "last-column-id": 3, "schema": map[string]any{"type": "struct", "schema-id": 1, "fields": []any{
						map[string]any{"id": 1, "name": "id", "required": true, "type": "long"},
						map[string]any{"id": 3, "name": "payload", "required": false, "type": "string"},
					}}},
					map[string]any{"action": "set-current-schema", "schema-id": -1},
					map[string]any{"action": "add-spec", "spec": map[string]any{"spec-id": 1, "fields": []any{map[string]any{"source-id": 3, "field-id": 1000, "name": "payload_bucket", "transform": "bucket[8]"}}}},
					map[string]any{"action": "set-default-spec", "spec-id": -1},
					map[string]any{"action": "add-sort-order", "sort-order": map[string]any{"order-id": 1, "fields": []any{map[string]any{"source-id": 3, "transform": "identity", "direction": "asc", "null-order": "nulls-first"}}}},
					map[string]any{"action": "set-default-sort-order", "sort-order-id": -1},
					map[string]any{"action": "set-properties", "updates": map[string]string{"owner": "replacement"}},
				},
			}
			replaced, current := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTTablePath("events"), replacement, http.StatusOK))
			if current.UUID != initial.UUID || current.CurrentSchemaID != 1 || current.LastSequenceNumber != appended.LastSequenceNumber || current.CurrentSnapshotID > 0 || len(current.Snapshots) != 1 || current.Snapshots[0].ID != 71 || current.Properties["owner"] != "replacement" {
				t.Fatalf("invalid replacement metadata: %s", replaced.Metadata)
			}
			if _, exists := current.Refs["main"]; exists || replaced.MetadataLocation == first.MetadataLocation {
				t.Fatal("replacement did not atomically reset the main branch")
			}
			ordinary, err := f.glue.GetTable(t.Context(), &glue.GetTableInput{DatabaseName: aws.String(icebergRESTNamespace), Name: aws.String("events")})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(ordinary.Table.VersionId) != "2" || ordinary.Table.Parameters["metadata_location"] != replaced.MetadataLocation || ordinary.Table.Parameters["previous_metadata_location"] != first.MetadataLocation {
				t.Fatalf("replacement diverged from native Glue head: %+v", ordinary.Table)
			}
			columns := ordinary.Table.StorageDescriptor.Columns
			if len(columns) != 2 || aws.ToString(columns[1].Name) != "payload" || aws.ToString(columns[1].Type) != "string" {
				t.Fatalf("replacement did not publish new Glue columns: %+v", columns)
			}
			stale := f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTTablePath("events"), replacement, http.StatusConflict)
			assertIcebergRESTError(t, stale, http.StatusConflict, "CommitFailedException")
			f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTTablePath("absent"), replacement, http.StatusNotFound)
			f = reopen()
			retained, retainedMetadata := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusOK))
			if retained.MetadataLocation != replaced.MetadataLocation || retainedMetadata.UUID != initial.UUID || retainedMetadata.CurrentSchemaID != 1 || retainedMetadata.Properties["owner"] != "replacement" {
				t.Fatalf("reopen lost replacement: %s", retained.Metadata)
			}
			if !bytes.Equal(oldBytes, f.object(t, first.MetadataLocation)) {
				t.Fatal("replacement changed previous metadata bytes")
			}
		})
	}
}

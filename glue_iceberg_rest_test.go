package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/hamba/avro/v2/ocf"

	"stackd"
	"stackd/storage"
	"stackd/storage/sqlite"
	sqlbackends "stackd/storage/sqlite/backends"
)

const (
	icebergRESTAccount   = "123456789012"
	icebergRESTRegion    = "us-east-1"
	icebergRESTPrefix    = "/iceberg/v1/catalogs/" + icebergRESTAccount
	icebergRESTNamespace = "boundary_analytics"
	icebergRESTBucket    = "iceberg-rest-boundary"
)

var icebergRESTRoot = aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}

type icebergRESTFixture struct {
	server *httptest.Server
	s3     *s3.Client
	glue   *glue.Client
	iam    *iam.Client
}

// Reopening reconstructs the gateway and all service owners; SQLite additionally
// closes and reopens the file. No service state or authentication is injected.
func newIcebergRESTFixture(t *testing.T, backend string) (*icebergRESTFixture, func() *icebergRESTFixture) {
	t.Helper()
	retained := storage.NewMemory()
	path := filepath.Join(t.TempDir(), "iceberg.sqlite")
	var closeCurrent func()
	t.Cleanup(func() {
		if closeCurrent != nil {
			closeCurrent()
		}
	})
	open := func() *icebergRESTFixture {
		t.Helper()
		if closeCurrent != nil {
			closeCurrent()
			closeCurrent = nil
		}
		backends := retained
		var closeDatabase func()
		if backend == "sqlite" {
			db, err := sqlite.Open(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			closeDatabase = func() {
				if err := db.Close(); err != nil {
					t.Error(err)
				}
			}
			backends, err = sqlbackends.New(t.Context(), db)
			if err != nil {
				closeDatabase()
				t.Fatal(err)
			}
		}
		cloud, err := stackd.New(stackd.Config{AccountID: icebergRESTAccount, Storage: backends})
		if err != nil {
			if closeDatabase != nil {
				closeDatabase()
			}
			t.Fatal(err)
		}
		server := httptest.NewServer(cloud)
		closeCurrent = func() {
			server.Close()
			if err := cloud.Close(); err != nil {
				t.Error(err)
			}
			if closeDatabase != nil {
				closeDatabase()
			}
		}
		cfg := aws.Config{Region: icebergRESTRegion, Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
		return &icebergRESTFixture{
			server: server,
			s3:     s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(server.URL); o.UsePathStyle = true }),
			glue:   glue.NewFromConfig(cfg, func(o *glue.Options) { o.BaseEndpoint = aws.String(server.URL) }),
			iam:    iam.NewFromConfig(cfg, func(o *iam.Options) { o.BaseEndpoint = aws.String(server.URL) }),
		}
	}
	return open(), open
}

type icebergRESTResponse struct {
	status int
	body   []byte
}

func (f *icebergRESTFixture) request(ctx context.Context, identity aws.Credentials, method, path string, payload any) (icebergRESTResponse, error) {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return icebergRESTResponse{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		return icebergRESTResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if identity.AccessKeyID != "" {
		digest := sha256.Sum256(body)
		if err := v4.NewSigner().SignHTTP(ctx, identity, req, hex.EncodeToString(digest[:]), "glue", icebergRESTRegion, time.Now()); err != nil {
			return icebergRESTResponse{}, err
		}
	}
	response, err := f.server.Client().Do(req)
	if err != nil {
		return icebergRESTResponse{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return icebergRESTResponse{status: response.StatusCode, body: data}, err
}

func (f *icebergRESTFixture) call(t *testing.T, identity aws.Credentials, method, path string, payload any, want int) icebergRESTResponse {
	t.Helper()
	response, err := f.request(t.Context(), identity, method, path, payload)
	if err != nil {
		t.Fatal(err)
	}
	if response.status != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, response.status, want, response.body)
	}
	return response
}

type icebergRESTMetadata struct {
	FormatVersion      int    `json:"format-version"`
	UUID               string `json:"table-uuid"`
	Location           string `json:"location"`
	LastSequenceNumber int64  `json:"last-sequence-number"`
	CurrentSchemaID    int    `json:"current-schema-id"`
	CurrentSnapshotID  int64  `json:"current-snapshot-id"`
	Snapshots          []struct {
		ID             int64  `json:"snapshot-id"`
		ParentID       *int64 `json:"parent-snapshot-id"`
		SequenceNumber int64  `json:"sequence-number"`
		SchemaID       int    `json:"schema-id"`
		ManifestList   string `json:"manifest-list"`
	} `json:"snapshots"`
	Refs map[string]struct {
		ID   int64  `json:"snapshot-id"`
		Type string `json:"type"`
	} `json:"refs"`
	Properties  map[string]string `json:"properties"`
	MetadataLog []struct {
		File string `json:"metadata-file"`
	} `json:"metadata-log"`
}

type icebergRESTTable struct {
	MetadataLocation string          `json:"metadata-location"`
	Metadata         json.RawMessage `json:"metadata"`
}

func decodeIcebergRESTTable(t *testing.T, response icebergRESTResponse) (icebergRESTTable, icebergRESTMetadata) {
	t.Helper()
	var table icebergRESTTable
	if err := json.Unmarshal(response.body, &table); err != nil {
		t.Fatalf("decode table response: %v: %s", err, response.body)
	}
	var metadata icebergRESTMetadata
	if err := json.Unmarshal(table.Metadata, &metadata); err != nil {
		t.Fatalf("decode metadata: %v: %s", err, table.Metadata)
	}
	if table.MetadataLocation == "" || metadata.UUID == "" || metadata.FormatVersion != 2 {
		t.Fatalf("incomplete v2 table response: %s", response.body)
	}
	return table, metadata
}

func icebergRESTTablePath(name string) string {
	return icebergRESTPrefix + "/namespaces/" + icebergRESTNamespace + "/tables/" + name
}

func (f *icebergRESTFixture) create(t *testing.T, name string) (icebergRESTTable, icebergRESTMetadata) {
	t.Helper()
	payload := map[string]any{
		"name":     name,
		"location": "s3://" + icebergRESTBucket + "/" + icebergRESTNamespace + "/" + name,
		"schema": map[string]any{
			"type": "struct", "schema-id": 0,
			"fields": []any{
				map[string]any{"id": 1, "name": "id", "required": true, "type": "long", "doc": "Durable event identifier"},
				map[string]any{"id": 2, "name": "label", "required": false, "type": "string"},
			},
		},
		"partition-spec": map[string]any{"spec-id": 0, "fields": []any{}},
		"write-order":    map[string]any{"order-id": 0, "fields": []any{}},
		"stage-create":   false,
		"properties":     map[string]string{"format-version": "2", "owner": "boundary"},
	}
	response := f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace+"/tables", payload, http.StatusOK)
	return decodeIcebergRESTTable(t, response)
}

func (f *icebergRESTFixture) object(t *testing.T, location string) []byte {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil || parsed.Scheme != "s3" || parsed.Host != icebergRESTBucket || parsed.Path == "" {
		t.Fatalf("invalid metadata location %q: %v", location, err)
	}
	object, err := f.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(parsed.Host), Key: aws.String(strings.TrimPrefix(parsed.Path, "/"))})
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	data, err := io.ReadAll(object.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *icebergRESTFixture) assertSharedTable(t *testing.T, name string, table icebergRESTTable, metadata icebergRESTMetadata) {
	t.Helper()
	ordinary, err := f.glue.GetTable(t.Context(), &glue.GetTableInput{CatalogId: aws.String(icebergRESTAccount), DatabaseName: aws.String(icebergRESTNamespace), Name: aws.String(name)})
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.Table == nil || ordinary.Table.Parameters["metadata_location"] != table.MetadataLocation || ordinary.Table.Parameters["table_type"] != "ICEBERG" {
		t.Fatalf("ordinary Glue did not observe REST metadata pointer: %+v", ordinary.Table)
	}
	if ordinary.Table.StorageDescriptor == nil || aws.ToString(ordinary.Table.StorageDescriptor.Location) != metadata.Location {
		t.Fatalf("ordinary Glue location does not match REST: %+v", ordinary.Table)
	}
	columns := ordinary.Table.StorageDescriptor.Columns
	if len(columns) != 2 || aws.ToString(columns[0].Name) != "id" || aws.ToString(columns[0].Type) != "bigint" || aws.ToString(columns[0].Comment) != "Durable event identifier" || aws.ToString(columns[1].Name) != "label" || aws.ToString(columns[1].Type) != "string" {
		t.Fatalf("ordinary Glue columns do not match Iceberg schema: %+v", columns)
	}
	stored := f.object(t, table.MetadataLocation)
	decode := func(data []byte) any {
		t.Helper()
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatalf("decode S3/REST metadata: %v: %s", err, data)
		}
		return value
	}
	if !reflect.DeepEqual(decode(stored), decode(table.Metadata)) {
		t.Fatalf("S3 bytes differ from REST metadata: S3=%s REST=%s", stored, table.Metadata)
	}
}

// These are actual empty manifest-list Avro containers, not dangling object
// paths. Empty append snapshots isolate the catalog's commit protocol from the
// native-engine row/file proof in TestGlueIcebergRESTPyIcebergAthenaRuntime.
// Schema field IDs are from Iceberg 1.6.1's v2 manifest-list specification:
// https://iceberg.apache.org/spec/#manifest-lists
const icebergRESTManifestListSchema = `{"type":"record","name":"manifest_file","fields":[
 {"name":"manifest_path","type":"string","field-id":500},
 {"name":"manifest_length","type":"long","field-id":501},
 {"name":"partition_spec_id","type":"int","field-id":502},
 {"name":"content","type":"int","field-id":517},
 {"name":"sequence_number","type":"long","field-id":515},
 {"name":"min_sequence_number","type":"long","field-id":516},
 {"name":"added_snapshot_id","type":"long","field-id":503},
 {"name":"added_files_count","type":"int","field-id":504},
 {"name":"existing_files_count","type":"int","field-id":505},
 {"name":"deleted_files_count","type":"int","field-id":506},
 {"name":"added_rows_count","type":"long","field-id":512},
 {"name":"existing_rows_count","type":"long","field-id":513},
 {"name":"deleted_rows_count","type":"long","field-id":514},
 {"name":"partitions","type":["null",{"type":"array","element-id":508,"items":{"type":"record","name":"field_summary","fields":[
  {"name":"contains_null","type":"boolean","field-id":509},
  {"name":"contains_nan","type":["null","boolean"],"default":null,"field-id":518},
  {"name":"lower_bound","type":["null","bytes"],"default":null,"field-id":510},
  {"name":"upper_bound","type":["null","bytes"],"default":null,"field-id":511}
 ]}}],"default":null,"field-id":507},
 {"name":"key_metadata","type":["null","bytes"],"default":null,"field-id":519}
]}`

func (f *icebergRESTFixture) appendRequest(t *testing.T, metadata icebergRESTMetadata, snapshotID, parentID, sequence int64) map[string]any {
	t.Helper()
	var container bytes.Buffer
	header := map[string][]byte{
		"format-version":  []byte("2"),
		"snapshot-id":     []byte(strconv.FormatInt(snapshotID, 10)),
		"sequence-number": []byte(strconv.FormatInt(sequence, 10)),
	}
	if parentID != 0 {
		header["parent-snapshot-id"] = []byte(strconv.FormatInt(parentID, 10))
	} else {
		header["parent-snapshot-id"] = []byte("null")
	}
	writer, err := ocf.NewEncoder(icebergRESTManifestListSchema, &container, ocf.WithMetadata(header))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	key := icebergRESTNamespace + "/events/metadata/snap-" + strconv.FormatInt(snapshotID, 10) + ".avro"
	if _, err := f.s3.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(icebergRESTBucket), Key: aws.String(key), Body: bytes.NewReader(container.Bytes()), ContentType: aws.String("application/avro")}); err != nil {
		t.Fatal(err)
	}
	snapshot := map[string]any{
		"snapshot-id": snapshotID, "sequence-number": sequence,
		"timestamp-ms": time.Now().UnixMilli(), "schema-id": metadata.CurrentSchemaID,
		"manifest-list": "s3://" + icebergRESTBucket + "/" + key,
		"summary":       map[string]string{"operation": "append", "added-data-files": "0", "added-records": "0", "total-data-files": "0", "total-delete-files": "0", "total-records": "0", "total-files-size": "0", "total-position-deletes": "0", "total-equality-deletes": "0"},
	}
	var expectedRef any
	if parentID != 0 {
		snapshot["parent-snapshot-id"] = parentID
		expectedRef = parentID
	}
	return map[string]any{
		"identifier": map[string]any{"namespace": []string{icebergRESTNamespace}, "name": "events"},
		"requirements": []any{
			map[string]any{"type": "assert-table-uuid", "uuid": metadata.UUID},
			map[string]any{"type": "assert-ref-snapshot-id", "ref": "main", "snapshot-id": expectedRef},
		},
		"updates": []any{
			map[string]any{"action": "add-snapshot", "snapshot": snapshot},
			map[string]any{"action": "set-snapshot-ref", "ref-name": "main", "type": "branch", "snapshot-id": snapshotID},
		},
	}
}

func assertIcebergRESTError(t *testing.T, response icebergRESTResponse, code int, errorType string) {
	t.Helper()
	var envelope struct {
		Error struct {
			Code    int    `json:"code"`
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.body, &envelope); err != nil || envelope.Error.Code != code || envelope.Error.Type != errorType || envelope.Error.Message == "" {
		t.Fatalf("expected REST %s (%d), got %s (%v)", errorType, code, response.body, err)
	}
}

func TestGlueIcebergRESTSignedProtocolAndConcurrentCommits(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, reopen := newIcebergRESTFixture(t, backend)
			if _, err := f.s3.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(icebergRESTBucket)}); err != nil {
				t.Fatal(err)
			}
			config := f.call(t, icebergRESTRoot, http.MethodGet, "/iceberg/v1/config?warehouse="+icebergRESTAccount, nil, http.StatusOK)
			var properties struct {
				Overrides map[string]string `json:"overrides"`
			}
			if err := json.Unmarshal(config.body, &properties); err != nil || properties.Overrides["prefix"] != "catalogs/"+icebergRESTAccount {
				t.Fatalf("config prefix: %s (%v)", config.body, err)
			}
			namespace := map[string]any{"namespace": []string{icebergRESTNamespace}, "properties": map[string]string{"location": "s3://" + icebergRESTBucket + "/" + icebergRESTNamespace}}
			f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces", namespace, http.StatusOK)
			f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace, nil, http.StatusOK)
			f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace, nil, http.StatusNoContent)
			if _, err := f.glue.GetDatabase(t.Context(), &glue.GetDatabaseInput{CatalogId: aws.String(icebergRESTAccount), Name: aws.String(icebergRESTNamespace)}); err != nil {
				t.Fatalf("ordinary Glue did not observe REST namespace: %v", err)
			}
			created, initial := f.create(t, "events")
			if initial.LastSequenceNumber != 0 || len(initial.Snapshots) != 0 || initial.CurrentSnapshotID > 0 {
				t.Fatalf("new table unexpectedly has snapshots: %s", created.Metadata)
			}
			f.assertSharedTable(t, "events", created, initial)
			originalBytes := f.object(t, created.MetadataLocation)
			loaded, loadedMetadata := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusOK))
			if loaded.MetadataLocation != created.MetadataLocation || loadedMetadata.UUID != initial.UUID {
				t.Fatalf("load changed table identity: %s", loaded.Metadata)
			}
			f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath("events"), nil, http.StatusNoContent)
			f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath("absent"), nil, http.StatusNotFound)
			listed := f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace+"/tables", nil, http.StatusOK)
			var listing struct {
				Identifiers []struct {
					Namespace []string `json:"namespace"`
					Name      string   `json:"name"`
				} `json:"identifiers"`
			}
			if err := json.Unmarshal(listed.body, &listing); err != nil || len(listing.Identifiers) != 1 || listing.Identifiers[0].Name != "events" || !reflect.DeepEqual(listing.Identifiers[0].Namespace, []string{icebergRESTNamespace}) {
				t.Fatalf("table listing: %s (%v)", listed.body, err)
			}
			// IDs deliberately exceed JavaScript's exact-number range. The wire,
			// persisted JSON, refs and Glue pointer must preserve every integer.
			const firstID int64 = 920000000000000001
			firstRequest := f.appendRequest(t, initial, firstID, 0, 1)
			firstTable, firstMetadata := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTTablePath("events"), firstRequest, http.StatusOK))
			if firstMetadata.CurrentSnapshotID != firstID || firstMetadata.LastSequenceNumber != 1 || firstMetadata.Refs["main"].ID != firstID || firstMetadata.Refs["main"].Type != "branch" || len(firstMetadata.Snapshots) != 1 || firstMetadata.Snapshots[0].SequenceNumber != 1 || firstMetadata.Snapshots[0].SchemaID != firstMetadata.CurrentSchemaID {
				t.Fatalf("append metadata: %s", firstTable.Metadata)
			}
			if firstTable.MetadataLocation == created.MetadataLocation {
				t.Fatal("append overwrote the original metadata location")
			}
			f.assertSharedTable(t, "events", firstTable, firstMetadata)
			stale := f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTTablePath("events"), firstRequest, http.StatusConflict)
			assertIcebergRESTError(t, stale, http.StatusConflict, "CommitFailedException")
			const contenderA int64 = firstID + 1
			const contenderB int64 = firstID + 2
			requests := []map[string]any{f.appendRequest(t, firstMetadata, contenderA, firstID, 2), f.appendRequest(t, firstMetadata, contenderB, firstID, 2)}
			type result struct {
				response   icebergRESTResponse
				err        error
				snapshotID int64
			}
			results := make(chan result, 2)
			start := make(chan struct{})
			for i, request := range requests {
				go func() {
					<-start
					response, err := f.request(t.Context(), icebergRESTRoot, http.MethodPost, icebergRESTTablePath("events"), request)
					results <- result{response: response, err: err, snapshotID: contenderA + int64(i)}
				}()
			}
			close(start)
			successes, conflicts := 0, 0
			var winner int64
			for range 2 {
				result := <-results
				if result.err != nil {
					t.Fatal(result.err)
				}
				switch result.response.status {
				case http.StatusOK:
					successes++
					winner = result.snapshotID
				case http.StatusConflict:
					conflicts++
					assertIcebergRESTError(t, result.response, http.StatusConflict, "CommitFailedException")
				default:
					t.Fatalf("concurrent commit status %d: %s", result.response.status, result.response.body)
				}
			}
			if successes != 1 || conflicts != 1 {
				t.Fatalf("concurrent commits: %d successes, %d conflicts; want exactly one each", successes, conflicts)
			}
			finalTable, finalMetadata := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusOK))
			if finalMetadata.CurrentSnapshotID != winner || finalMetadata.Refs["main"].ID != winner || finalMetadata.LastSequenceNumber != 2 || len(finalMetadata.Snapshots) != 2 {
				t.Fatalf("concurrent commit lost atomicity: %s", finalTable.Metadata)
			}
			foundWinner := false
			for _, snapshot := range finalMetadata.Snapshots {
				if snapshot.ID == firstID {
					continue
				}
				if snapshot.ID != winner || snapshot.ParentID == nil || *snapshot.ParentID != firstID || snapshot.SequenceNumber != 2 {
					t.Fatalf("invalid winning snapshot lineage: %+v", snapshot)
				}
				foundWinner = true
				if !bytes.HasPrefix(f.object(t, snapshot.ManifestList), []byte{'O', 'b', 'j', 1}) {
					t.Fatal("winning manifest-list object is not an Avro container")
				}
			}
			if !foundWinner {
				t.Fatal("winning snapshot is absent")
			}
			if !bytes.Equal(originalBytes, f.object(t, created.MetadataLocation)) {
				t.Fatal("immutable original metadata bytes changed")
			}
			foundPrevious := false
			for _, entry := range finalMetadata.MetadataLog {
				foundPrevious = foundPrevious || entry.File == firstTable.MetadataLocation
			}
			if !foundPrevious {
				t.Fatalf("metadata log does not retain previous pointer: %s", finalTable.Metadata)
			}
			f.assertSharedTable(t, "events", finalTable, finalMetadata)
			f = reopen()
			retainedTable, retainedMetadata := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusOK))
			if retainedTable.MetadataLocation != finalTable.MetadataLocation || retainedMetadata.CurrentSnapshotID != winner || retainedMetadata.UUID != initial.UUID {
				t.Fatalf("reopened catalog lost committed state: %s", retainedTable.Metadata)
			}
			f.assertSharedTable(t, "events", retainedTable, retainedMetadata)
			// Unsupported updates must fail explicitly and retain the pointer.
			unsupported := map[string]any{"requirements": []any{}, "updates": []any{map[string]any{"action": "unknown-iceberg-update"}}}
			rejected, err := f.request(t.Context(), icebergRESTRoot, http.MethodPost, icebergRESTTablePath("events"), unsupported)
			if err != nil {
				t.Fatal(err)
			}
			if rejected.status != http.StatusBadRequest && rejected.status != http.StatusUnprocessableEntity {
				t.Fatalf("unsupported update returned %d: %s", rejected.status, rejected.body)
			}
			afterRejected, _ := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusOK))
			if afterRejected.MetadataLocation != retainedTable.MetadataLocation {
				t.Fatal("unsupported update changed metadata pointer")
			}
		})
	}
}

func TestGlueIcebergRESTAuthenticationAndIAMResourceScopes(t *testing.T) {
	f, _ := newIcebergRESTFixture(t, "memory")
	if _, err := f.s3.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(icebergRESTBucket)}); err != nil {
		t.Fatal(err)
	}
	f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces", map[string]any{"namespace": []string{icebergRESTNamespace}, "properties": map[string]string{}}, http.StatusOK)
	created, _ := f.create(t, "events")
	f.create(t, "private_events")
	configPath := "/iceberg/v1/config?warehouse=" + icebergRESTAccount
	f.call(t, aws.Credentials{}, http.MethodGet, configPath, nil, http.StatusForbidden)
	f.call(t, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "invalid-secret"}, http.MethodGet, configPath, nil, http.StatusForbidden)
	// A correctly authenticated user with no policy is not a bootstrap root.
	const user = "iceberg-reader"
	if _, err := f.iam.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)}); err != nil {
		t.Fatal(err)
	}
	access, err := f.iam.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: aws.String(user)})
	if err != nil {
		t.Fatal(err)
	}
	reader := aws.Credentials{AccessKeyID: aws.ToString(access.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(access.AccessKey.SecretAccessKey)}
	f.call(t, reader, http.MethodGet, configPath, nil, http.StatusForbidden)
	f.call(t, reader, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusForbidden)
	catalogARN := "arn:aws:glue:" + icebergRESTRegion + ":" + icebergRESTAccount + ":catalog"
	databaseARN := "arn:aws:glue:" + icebergRESTRegion + ":" + icebergRESTAccount + ":database/" + icebergRESTNamespace
	tableARN := "arn:aws:glue:" + icebergRESTRegion + ":" + icebergRESTAccount + ":table/" + icebergRESTNamespace + "/events"
	putPolicy := func(statements []any) {
		t.Helper()
		policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.iam.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String("catalog-read"), PolicyDocument: aws.String(string(policy))}); err != nil {
			t.Fatal(err)
		}
	}
	catalogRead := map[string]any{"Effect": "Allow", "Action": "glue:GetCatalog", "Resource": catalogARN}
	tableRead := map[string]any{"Effect": "Allow", "Action": "glue:GetTable", "Resource": []string{catalogARN, databaseARN, tableARN}}
	objectRead := map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::" + icebergRESTBucket + "/*"}
	// Missing ancestor authorization cannot be bypassed by an exact table ARN.
	putPolicy([]any{catalogRead, objectRead, map[string]any{"Effect": "Allow", "Action": "glue:GetTable", "Resource": tableARN}})
	f.call(t, reader, http.MethodGet, configPath, nil, http.StatusOK)
	f.call(t, reader, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusForbidden)
	putPolicy([]any{catalogRead, tableRead, objectRead})
	readTable, _ := decodeIcebergRESTTable(t, f.call(t, reader, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusOK))
	if readTable.MetadataLocation != created.MetadataLocation {
		t.Fatal("authorized reader observed a different table")
	}
	f.call(t, reader, http.MethodHead, icebergRESTTablePath("events"), nil, http.StatusNoContent)
	f.call(t, reader, http.MethodGet, icebergRESTTablePath("private_events"), nil, http.StatusForbidden)
	f.call(t, reader, http.MethodGet, strings.Replace(icebergRESTTablePath("events"), icebergRESTAccount, "210987654321", 1), nil, http.StatusForbidden)
	mutation := map[string]any{"requirements": []any{}, "updates": []any{map[string]any{"action": "set-properties", "updates": map[string]string{"owner": "unauthorized"}}}}
	f.call(t, reader, http.MethodPost, icebergRESTTablePath("events"), mutation, http.StatusForbidden)
	f.call(t, reader, http.MethodDelete, icebergRESTTablePath("events"), nil, http.StatusForbidden)
	// The same valid access key immediately sees explicit policy denial.
	putPolicy([]any{catalogRead, tableRead, objectRead, map[string]any{"Effect": "Deny", "Action": "glue:GetTable", "Resource": tableARN}})
	f.call(t, reader, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusForbidden)
	rootTable, rootMetadata := decodeIcebergRESTTable(t, f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTTablePath("events"), nil, http.StatusOK))
	if rootTable.MetadataLocation != created.MetadataLocation || rootMetadata.Properties["owner"] != "boundary" {
		t.Fatalf("denied requests changed catalog state: %s", rootTable.Metadata)
	}
	f.assertSharedTable(t, "events", rootTable, rootMetadata)
	// Bad signatures also cannot create resources through a write route.
	invalidNamespace := map[string]any{"namespace": []string{"unsigned_namespace"}, "properties": map[string]string{}}
	f.call(t, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "invalid-secret"}, http.MethodPost, icebergRESTPrefix+"/namespaces", invalidNamespace, http.StatusForbidden)
	f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTPrefix+"/namespaces/unsigned_namespace", nil, http.StatusNotFound)
}

func TestGlueIcebergRESTNamespacePropertiesPaginationAndDrop(t *testing.T) {
	f, _ := newIcebergRESTFixture(t, "memory")
	if _, err := f.s3.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(icebergRESTBucket)}); err != nil {
		t.Fatal(err)
	}
	createNamespace := func(name string) {
		t.Helper()
		f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces", map[string]any{
			"namespace": []string{name}, "properties": map[string]string{
				"location": "s3://" + icebergRESTBucket + "/warehouse", "comment": "original", "owner": "fixture-team",
			},
		}, http.StatusOK)
	}
	createNamespace(icebergRESTNamespace)
	createNamespace("z_last")
	updated := f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace+"/properties", map[string]any{
		"updates": map[string]string{"comment": "updated", "team": "analytics"}, "removals": []string{"owner", "missing"},
	}, http.StatusOK)
	var changes struct {
		Updated []string `json:"updated"`
		Removed []string `json:"removed"`
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal(updated.body, &changes); err != nil || !reflect.DeepEqual(changes.Updated, []string{"comment", "team"}) || !reflect.DeepEqual(changes.Removed, []string{"owner"}) || !reflect.DeepEqual(changes.Missing, []string{"missing"}) {
		t.Fatalf("namespace property result: %s (%v)", updated.body, err)
	}
	database, err := f.glue.GetDatabase(t.Context(), &glue.GetDatabaseInput{Name: aws.String(icebergRESTNamespace)})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(database.Database.Description) != "updated" || database.Database.Parameters["team"] != "analytics" || database.Database.Parameters["owner"] != "" {
		t.Fatalf("ordinary Glue did not observe namespace properties: %+v", database.Database)
	}
	f.call(t, icebergRESTRoot, http.MethodPost, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace+"/properties", map[string]any{
		"updates": map[string]string{"team": "conflict"}, "removals": []string{"team"},
	}, http.StatusUnprocessableEntity)
	type namespacePage struct {
		Namespaces [][]string `json:"namespaces"`
		Next       string     `json:"next-page-token"`
	}
	unpaged := f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTPrefix+"/namespaces?pageSize=1", nil, http.StatusOK)
	var page namespacePage
	if err := json.Unmarshal(unpaged.body, &page); err != nil || len(page.Namespaces) != 2 || page.Next != "" {
		t.Fatalf("unpaginated namespace listing: %s (%v)", unpaged.body, err)
	}
	first := f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTPrefix+"/namespaces?pageToken=&pageSize=1", nil, http.StatusOK)
	if err := json.Unmarshal(first.body, &page); err != nil || len(page.Namespaces) != 1 || page.Namespaces[0][0] != icebergRESTNamespace || page.Next == "" {
		t.Fatalf("first namespace page: %s (%v)", first.body, err)
	}
	token := url.QueryEscape(page.Next)
	second := f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTPrefix+"/namespaces?pageToken="+token+"&pageSize=1", nil, http.StatusOK)
	page = namespacePage{}
	if err := json.Unmarshal(second.body, &page); err != nil || len(page.Namespaces) != 1 || page.Namespaces[0][0] != "z_last" || page.Next != "" {
		t.Fatalf("last namespace page: %s (%v)", second.body, err)
	}
	f.call(t, icebergRESTRoot, http.MethodGet, icebergRESTPrefix+"/namespaces?parent="+icebergRESTNamespace+"&pageToken="+token, nil, http.StatusBadRequest)
	created, _ := f.create(t, "events")
	f.call(t, icebergRESTRoot, http.MethodDelete, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace, nil, http.StatusConflict)
	f.call(t, icebergRESTRoot, http.MethodDelete, icebergRESTTablePath("events")+"?purgeRequested=true", nil, http.StatusBadRequest)
	f.call(t, icebergRESTRoot, http.MethodDelete, icebergRESTTablePath("events"), nil, http.StatusNoContent)
	f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTTablePath("events"), nil, http.StatusNotFound)
	// Nonpurging drop removes only shared catalog state, not immutable S3 bytes.
	if len(f.object(t, created.MetadataLocation)) == 0 {
		t.Fatal("nonpurging drop removed metadata bytes")
	}
	f.call(t, icebergRESTRoot, http.MethodDelete, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace, nil, http.StatusNoContent)
	f.call(t, icebergRESTRoot, http.MethodHead, icebergRESTPrefix+"/namespaces/"+icebergRESTNamespace, nil, http.StatusNotFound)
}

func TestGlueIcebergRESTNativeS3ChecksumModeCase(t *testing.T) {
	f, _ := newIcebergRESTFixture(t, "memory")
	if _, err := f.s3.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(icebergRESTBucket)}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("real Iceberg metadata and manifest bytes")
	if _, err := f.s3.PutObject(t.Context(), &s3.PutObjectInput{
		Bucket: aws.String(icebergRESTBucket), Key: aws.String("checksum"),
		Body: bytes.NewReader(payload), ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256,
	}); err != nil {
		t.Fatal(err)
	}
	// The SDK signs the original header value. A change before SigV4 validation
	// would invalidate these genuine signatures; normalization is binding-only.
	for _, mode := range []string{"ENABLED", "enabled", "EnAbLeD"} {
		t.Run(mode, func(t *testing.T) {
			out, err := f.s3.GetObject(t.Context(), &s3.GetObjectInput{
				Bucket: aws.String(icebergRESTBucket), Key: aws.String("checksum"), ChecksumMode: s3types.ChecksumMode(mode),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Body.Close()
			data, err := io.ReadAll(out.Body)
			if err != nil || !bytes.Equal(data, payload) || aws.ToString(out.ChecksumSHA256) == "" {
				t.Fatalf("checksum-mode %s: body=%q checksum=%q err=%v", mode, data, aws.ToString(out.ChecksumSHA256), err)
			}
		})
	}
	_, err := f.s3.GetObject(t.Context(), &s3.GetObjectInput{
		Bucket: aws.String(icebergRESTBucket), Key: aws.String("checksum"), ChecksumMode: s3types.ChecksumMode("unsupported-checksum-mode"),
	})
	var apiError smithy.APIError
	if !errors.As(err, &apiError) || apiError.ErrorCode() != "InvalidRequest" || apiError.ErrorMessage() != "Value for x-amz-checksum-mode header is invalid." {
		t.Fatalf("invalid checksum-mode: %v", err)
	}
}

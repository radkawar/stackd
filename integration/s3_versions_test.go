package stackd_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd/clock"
	"stackd/storage"
)

type s3VersionObservation struct {
	Label, Operation, Service string
	Input                     map[string]any
	Result                    struct {
		Code       string
		Output     map[string]any
		HTTPStatus int `json:"http_status"`
		Headers    map[string]string
		Error      struct {
			Detail map[string]string `json:"Error"`
		}
	}
}

type s3VersionCapture struct {
	Context struct {
		Account string
		Bucket  string `json:"owned_bucket"`
	}
	Observations []s3VersionObservation
}

// The JSON files are verbatim native runs, including negative observations,
// transport headers, provenance and the cleanup that proved bucket absence.
// Each backend replays the S3 observations in order, including state reads
// before and after rejected mutations and supported mixed-batch siblings.
func TestS3NativeVersionLifecycleReplay(t *testing.T) {
	for _, name := range []string{"versioning", "versioning_null", "version_policy_controls", "marker_policy", "conditional_versions"} {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(name+"/"+backend, func(t *testing.T) {
				body, err := os.ReadFile(filepath.Join("..", "testdata", "aws", "s3", name+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var capture s3VersionCapture
				if err := json.Unmarshal(body, &capture); err != nil {
					t.Fatal(err)
				}
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "versions.sqlite"))
				}
				source := clock.NewManual(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
				_, clients, _ := startEventDeliveryCloud(t, backends, source)
				wire := &s3VersionHTTPClient{HTTPClient: clients.server.Client()}
				client := s3NativeClient(clients, capture.Context.Account, "test")
				if name == "conditional_versions" {
					_, key, secret := clients.user(t, capture.Context.Account, "Delegated")
					putUserPolicy(t, clients.iam(capture.Context.Account, "test", ""), "Delegated", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
					client = s3NativeClient(clients, key, secret)
				}
				client = s3.New(client.Options(), func(options *s3.Options) {
					options.HTTPClient = wire
					options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
						return stack.Serialize.Add(middleware.SerializeMiddlewareFunc("NativeContentType", func(ctx context.Context, input middleware.SerializeInput, next middleware.SerializeHandler) (middleware.SerializeOutput, middleware.Metadata, error) {
							if put, ok := input.Parameters.(*s3.PutObjectInput); ok && put.ContentType == nil {
								// The native Python requests omit this header. Do not
								// substitute the Go SDK's application/octet-stream.
								input.Request.(*smithyhttp.Request).Header.Del("Content-Type")
							}
							return next.HandleSerialize(ctx, input)
						}), middleware.After)
					})
				})
				identities := &s3VersionIdentities{versions: map[string]string{}, issued: map[string]string{}}
				for _, row := range capture.Observations {
					if row.Service != "" && row.Service != "s3" {
						continue // Native caller identity evidence, not an S3 operation.
					}
					if row.Label == "iam-if-match/apply-policy" {
						// The initial probe used an invalid action/condition pairing.
						// Replay the corrected, independently captured Null controls below.
						continue
					}
					delete(row.Result.Output, "ResponseMetadata") // Provider request identity, not modeled output.
					if !t.Run(row.Label, func(t *testing.T) {
						s3VersionReplay(t, client, wire, identities, row)
					}) {
						// Later inputs depend on successful writes and their issued IDs.
						return
					}
					if row.Operation == "create-bucket" {
						acl, err := client.GetBucketAcl(t.Context(), &s3.GetBucketAclInput{Bucket: aws.String(capture.Context.Bucket)})
						if err != nil || acl.Owner == nil || aws.ToString(acl.Owner.ID) == "" {
							t.Fatalf("binding bucket owner identity: %v, %+v", err, acl)
						}
						identities.owner = aws.ToString(acl.Owner.ID)
					}
				}
			})
		}
	}
}

// Capture the actual HTTP response as well as the modeled SDK result. In
// particular a modeled nil VersionId must also mean an absent wire header.
type s3VersionHTTPClient struct {
	s3.HTTPClient
	header http.Header
	body   []byte
}

func (c *s3VersionHTTPClient) Do(request *http.Request) (*http.Response, error) {
	c.header = nil
	c.body = nil
	response, err := c.HTTPClient.Do(request)
	if response != nil {
		c.header = response.Header.Clone()
		if response.StatusCode >= 400 && request.Method != http.MethodHead {
			c.body, err = io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if err == nil {
				err = closeErr
			}
			response.Body = io.NopCloser(bytes.NewReader(c.body))
		}
	}
	return response, err
}

type s3VersionIdentities struct {
	versions map[string]string
	issued   map[string]string
	owner    string
}

func (ids *s3VersionIdentities) bind(t *testing.T, native string, local any) {
	t.Helper()
	value, ok := local.(string)
	if !ok || value == "" || value == "null" {
		t.Fatalf("expected an opaque non-null version identity, got %#v", local)
	}
	if previous, exists := ids.issued[value]; exists {
		t.Fatalf("new native version %q reused local version issued for %q", native, previous)
	}
	ids.versions[native], ids.issued[value] = value, native
}

// Only issued identity fields are substituted. In particular "null", deleted
// IDs and malformed native literals keep their distinct semantics. This does
// not claim to validate AWS's opaque token format: the local boundary is sv1_
// plus 24 raw-base64url bytes, and native invalid literals are sent unchanged.
func (ids *s3VersionIdentities) translate(value any, field string) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, child := range value {
			if key == "Owner" {
				owner := ids.translate(child, key).(map[string]any)
				owner["ID"] = ids.owner
				out[key] = owner
			} else {
				out[key] = ids.translate(child, key)
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = ids.translate(child, field)
		}
		return out
	case string:
		switch field {
		case "VersionId", "VersionIdMarker", "NextVersionIdMarker", "DeleteMarkerVersionId", "s3:VersionId", "x-amz-version-id":
			if local, exists := ids.versions[value]; exists {
				return local
			}
		}
	}
	return value
}

func s3VersionBody(t *testing.T, value any) []byte {
	t.Helper()
	if value == nil {
		return nil
	}
	if object, ok := value.(map[string]any); ok {
		value = object["base64"]
	}
	encoded, ok := value.(string)
	if !ok {
		t.Fatalf("capture body is not base64: %#v", value)
	}
	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func s3VersionReplay(t *testing.T, client *s3.Client, wire *s3VersionHTTPClient, ids *s3VersionIdentities, row s3VersionObservation) {
	t.Helper()
	parts := strings.Split(row.Operation, "-")
	for i, part := range parts {
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	operation := strings.Join(parts, "")
	input := ids.translate(row.Input, "").(map[string]any)
	if policy, ok := input["Policy"].(string); ok {
		var document any
		if err := json.Unmarshal([]byte(policy), &document); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(ids.translate(document, ""))
		if err != nil {
			t.Fatal(err)
		}
		input["Policy"] = string(encoded)
	}
	payload := s3VersionBody(t, input["Body"])
	// Reproduce botocore's transport defaults, not altered expected responses.
	// The first captures uploaded CRC32; policy captures used S3's CRC64NVME
	// default. The Go SDK computes CRC32 from the actual replayed body.
	if operation == "PutObject" && row.Result.Output["ChecksumCRC32"] != nil {
		input["ChecksumAlgorithm"] = "CRC32"
	}
	if operation == "GetObject" {
		input["ChecksumMode"] = "ENABLED"
	}
	autoEncoding := (operation == "ListObjectVersions" || operation == "ListObjectsV2") && input["EncodingType"] == nil && row.Result.Output["EncodingType"] == "url"
	if autoEncoding {
		input["EncodingType"] = "url"
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	native := s3NativeObservation{Label: row.Label, Operation: operation, Input: encoded}
	native.Result.Code, native.Result.HTTPStatus = row.Result.Code, row.Result.HTTPStatus
	got, _, err := s3NativeInvoke(t, client, native, payload)
	if row.Result.Code != "Success" {
		var response *smithyhttp.ResponseError
		if !errors.As(err, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus {
			t.Fatalf("HTTP error: %v; native %d", err, row.Result.HTTPStatus)
		}
		// HEAD's native numeric code records an empty error body, not an XML
		// error-code spelling. Its exact status is still mandatory.
		if _, numeric := strconv.Atoi(row.Result.Code); numeric != nil {
			var api smithy.APIError
			if !errors.As(err, &api) || api.ErrorCode() != row.Result.Code {
				t.Fatalf("error: %v; native code %s", err, row.Result.Code)
			}
		}
		if row.Result.Code == "NotImplemented" && row.Result.Error.Detail != nil {
			var detail struct {
				Code              string
				Message           string
				Header            string
				AdditionalMessage string `xml:"additionalMessage"`
			}
			if err := xml.Unmarshal(wire.body, &detail); err != nil {
				t.Fatal(err)
			}
			got := map[string]string{"Code": detail.Code, "Message": detail.Message, "Header": detail.Header, "additionalMessage": detail.AdditionalMessage}
			if !reflect.DeepEqual(got, row.Result.Error.Detail) {
				t.Fatalf("conditional XML error: got %#v; native %#v", got, row.Result.Error.Detail)
			}
		}
		s3VersionHeaders(t, row, wire.header, ids)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if issued, ok := row.Result.Output["VersionId"].(string); ok && issued != "null" && (operation == "PutObject" || operation == "DeleteObject" && input["VersionId"] == nil) {
		ids.bind(t, issued, got["VersionId"])
	}
	if operation == "DeleteObjects" {
		// Successful batch siblings issue markers even when other items fail.
		deleted, _ := row.Result.Output["Deleted"].([]any)
		localDeleted, _ := got["Deleted"].([]any)
		for _, item := range deleted {
			native := item.(map[string]any)
			version, ok := native["DeleteMarkerVersionId"].(string)
			if !ok || version == "null" {
				continue
			}
			if _, known := ids.versions[version]; known {
				continue // Explicit deletion of a previously issued marker.
			}
			for _, item := range localDeleted {
				local := item.(map[string]any)
				if local["Key"] == native["Key"] {
					ids.bind(t, version, local["DeleteMarkerVersionId"])
					break
				}
			}
		}
	}
	want := ids.translate(row.Result.Output, "").(map[string]any)
	if body, exists := want["Body"]; exists {
		decoded := s3VersionBody(t, body)
		captured, ok := got["captured_body"].(map[string]any)
		if !ok || captured["base64"] != base64.StdEncoding.EncodeToString(decoded) || captured["bytes"] != float64(len(decoded)) {
			t.Fatalf("body: got %#v; native %q", got["captured_body"], decoded)
		}
		delete(want, "Body")
	}
	if autoEncoding {
		// Botocore decodes only its implicitly requested URL encoding. The
		// explicit encoded-versions observation compares encoded bytes as-is.
		s3VersionDecodeListing(t, got)
	}
	if operation == "DeleteObjects" {
		// S3 batch deletion reports a set; these native runs themselves return
		// it in a different order than the request. History pages stay ordered.
		s3VersionSortDeleted(want)
		s3VersionSortDeleted(got)
		items, _ := want["Errors"].([]any)
		for _, item := range items {
			detail := item.(map[string]any)
			if detail["Code"] == "AccessDenied" {
				// Native denial prose embeds the provider's principal/policy description.
				delete(detail, "Message")
			}
		}
	}
	// Both SDKs represent no user metadata; Go may marshal the empty map as
	// null rather than botocore's {}. Nonempty metadata remains exact.
	if metadata, ok := want["Metadata"].(map[string]any); ok && len(metadata) == 0 && got["Metadata"] == nil {
		got["Metadata"] = map[string]any{}
	}
	if operation == "GetBucketPolicy" {
		// Policy JSON member ordering is not policy identity. Translate issued
		// version references just as on the corresponding PutBucketPolicy.
		for _, output := range []map[string]any{want, got} {
			var document any
			policy, ok := output["Policy"].(string)
			if !ok {
				t.Fatalf("missing policy document: %#v", output)
			}
			if err := json.Unmarshal([]byte(policy), &document); err != nil {
				t.Fatal(err)
			}
			output["Policy"] = ids.translate(document, "")
		}
	}
	s3NativeProjection(t, row.Label, want, got)
	// A projection alone misses extra fields. Pin omission contracts that
	// distinguish never-enabled, suspended null, markers and empty pages.
	for _, key := range []string{"VersionId", "DeleteMarker", "ChecksumCRC32", "ChecksumCRC64NVME", "ChecksumType", "Versions", "DeleteMarkers", "Contents", "CommonPrefixes", "NextKeyMarker", "NextVersionIdMarker", "Status"} {
		if _, exists := want[key]; !exists && !s3VersionEmpty(got[key]) {
			t.Fatalf("unexpected %s: %#v (absent natively)", key, got[key])
		}
	}
	if metadata, exists := want["Metadata"]; exists && !reflect.DeepEqual(metadata, got["Metadata"]) {
		t.Fatalf("metadata: got %#v; native %#v", got["Metadata"], metadata)
	}
	s3VersionHeaders(t, row, wire.header, ids)
}

func s3VersionEmpty(value any) bool {
	if value == nil || value == "" {
		return true
	}
	if array, ok := value.([]any); ok {
		return len(array) == 0
	}
	return false
}

func s3VersionSortDeleted(output map[string]any) {
	for _, field := range []string{"Deleted", "Errors"} {
		if items, ok := output[field].([]any); ok {
			sort.Slice(items, func(i, j int) bool {
				left, right := items[i].(map[string]any), items[j].(map[string]any)
				return fmt.Sprint(left["Key"], "\x00", left["VersionId"]) < fmt.Sprint(right["Key"], "\x00", right["VersionId"])
			})
		}
	}
}

func s3VersionDecodeListing(t *testing.T, value any) {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			switch key {
			case "Key", "KeyMarker", "NextKeyMarker", "Prefix", "Delimiter":
				if encoded, ok := child.(string); ok {
					decoded, err := url.QueryUnescape(encoded)
					if err != nil {
						t.Fatal(err)
					}
					value[key] = decoded
				}
			default:
				s3VersionDecodeListing(t, child)
			}
		}
	case []any:
		for _, child := range value {
			s3VersionDecodeListing(t, child)
		}
	}
}

func s3VersionHeaders(t *testing.T, row s3VersionObservation, got http.Header, ids *s3VersionIdentities) {
	t.Helper()
	if row.Result.Headers == nil {
		return // The policy captures did not record raw response headers.
	}
	for key, native := range row.Result.Headers {
		switch key {
		case "date":
			continue // Provider clock, not object state.
		case "last-modified":
			if _, err := http.ParseTime(got.Get(key)); err != nil {
				t.Fatalf("missing/invalid %s: %q", key, got.Get(key))
			}
			continue
		}
		want := ids.translate(native, key).(string)
		if got.Get(key) != want {
			t.Fatalf("header %s: got %q; native %q", key, got.Get(key), want)
		}
	}
	for _, key := range []string{"x-amz-version-id", "x-amz-delete-marker"} {
		if _, exists := row.Result.Headers[key]; !exists && len(got.Values(key)) != 0 {
			t.Fatalf("unexpected header %s: %q (absent natively)", key, got.Values(key))
		}
	}
}

// Historical reads evaluate the selected version; conditional explicit-version
// deletes are rejected as captured in conditional_versions.json. Rejected
// writes and deletes must preserve both current data and version history.
func TestS3VersionConditionalIsolation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "conditional-versions.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
			_, clients, _ := startEventDeliveryCloud(t, backends, source)
			client := s3NativeClient(clients, "123456789012", "test")
			bucket, key := "conditional-version-isolation", "object"
			if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.PutBucketVersioning(t.Context(), &s3.PutBucketVersioningInput{
				Bucket: &bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled},
			}); err != nil {
				t.Fatal(err)
			}
			put := func(body, tag string) *s3.PutObjectOutput {
				t.Helper()
				out, err := client.PutObject(t.Context(), &s3.PutObjectInput{
					Bucket: &bucket, Key: &key, Body: strings.NewReader(body), Metadata: map[string]string{"revision": tag},
				})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			first := put("historical-content", "first")
			second := put("current-content", "second")
			readBody := func(output *s3.GetObjectOutput, err error, want string) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(output.Body)
				closeErr := output.Body.Close()
				if readErr != nil || closeErr != nil || !bytes.Equal(body, []byte(want)) {
					t.Fatalf("body: got %q, errors %v/%v; want %q", body, readErr, closeErr, want)
				}
			}
			historical, err := client.GetObject(t.Context(), &s3.GetObjectInput{
				Bucket: &bucket, Key: &key, VersionId: first.VersionId, Range: aws.String("bytes=2-8"), IfMatch: first.ETag,
			})
			readBody(historical, err, "storica")
			if aws.ToString(historical.VersionId) != aws.ToString(first.VersionId) ||
				aws.ToString(historical.ETag) != aws.ToString(first.ETag) ||
				aws.ToString(historical.ContentRange) != "bytes 2-8/18" ||
				aws.ToInt64(historical.ContentLength) != 7 ||
				historical.ServerSideEncryption != types.ServerSideEncryptionAes256 ||
				historical.ChecksumCRC64NVME != nil || historical.ChecksumType != "" ||
				!reflect.DeepEqual(historical.Metadata, map[string]string{"revision": "first"}) {
				t.Fatalf("historical range selected wrong version or headers: %+v", historical)
			}
			precondition := func(err error) {
				t.Helper()
				assertAPIError(t, err, "PreconditionFailed")
				var response *smithyhttp.ResponseError
				if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusPreconditionFailed {
					t.Fatalf("conditional HTTP response: %v", err)
				}
			}
			_, err = client.GetObject(t.Context(), &s3.GetObjectInput{
				Bucket: &bucket, Key: &key, VersionId: first.VersionId, IfMatch: second.ETag,
			})
			precondition(err)
			inventory := func() *s3.ListObjectVersionsOutput {
				t.Helper()
				out, err := client.ListObjectVersions(t.Context(), &s3.ListObjectVersionsInput{Bucket: &bucket})
				if err != nil {
					t.Fatal(err)
				}
				if aws.ToBool(out.IsTruncated) {
					t.Fatal("unexpected truncated isolation inventory")
				}
				return out
			}
			unchanged := func(before *s3.ListObjectVersionsOutput) {
				t.Helper()
				after := inventory()
				if !reflect.DeepEqual(before.Versions, after.Versions) || !reflect.DeepEqual(before.DeleteMarkers, after.DeleteMarkers) {
					t.Fatalf("rejected conditional mutation changed history:\nbefore %+v / %+v\nafter %+v / %+v", before.Versions, before.DeleteMarkers, after.Versions, after.DeleteMarkers)
				}
			}
			before := inventory()
			_, err = client.PutObject(t.Context(), &s3.PutObjectInput{
				Bucket: &bucket, Key: &key, Body: strings.NewReader("rejected"), IfMatch: first.ETag,
			})
			precondition(err)
			unchanged(before)
			_, err = client.PutObject(t.Context(), &s3.PutObjectInput{
				Bucket: &bucket, Key: &key, Body: strings.NewReader("also-rejected"), IfNoneMatch: aws.String("*"),
			})
			precondition(err)
			unchanged(before)
			_, err = client.DeleteObject(t.Context(), &s3.DeleteObjectInput{Bucket: &bucket, Key: &key, IfMatch: first.ETag})
			precondition(err)
			unchanged(before)
			_, err = client.DeleteObject(t.Context(), &s3.DeleteObjectInput{
				Bucket: &bucket, Key: &key, VersionId: first.VersionId, IfMatch: second.ETag,
			})
			assertAPIError(t, err, "NotImplemented")
			var response *smithyhttp.ResponseError
			if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusNotImplemented {
				t.Fatalf("version-conditional HTTP response: %v", err)
			}
			unchanged(before)
			marker, err := client.DeleteObject(t.Context(), &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
			if err != nil || !aws.ToBool(marker.DeleteMarker) {
				t.Fatalf("creating current marker: %+v, %v", marker, err)
			}
			current, err := client.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: &bucket})
			if err != nil || len(current.Contents) != 0 || aws.ToInt32(current.KeyCount) != 0 {
				t.Fatalf("marker exposed historical object through current listing: %+v, %v", current, err)
			}
			third, err := client.PutObject(t.Context(), &s3.PutObjectInput{
				Bucket: &bucket, Key: &key, Body: strings.NewReader("replacement"), IfNoneMatch: aws.String("*"),
			})
			if err != nil {
				t.Fatalf("marker must count as absent for IfNoneMatch: %v", err)
			}
			after := inventory()
			wantIDs := []string{aws.ToString(third.VersionId), aws.ToString(second.VersionId), aws.ToString(first.VersionId)}
			gotIDs := make([]string, len(after.Versions))
			for i, version := range after.Versions {
				gotIDs[i] = aws.ToString(version.VersionId)
				if aws.ToBool(version.IsLatest) != (i == 0) {
					t.Fatalf("wrong latest version after conditional revival: %+v", after.Versions)
				}
			}
			if !reflect.DeepEqual(gotIDs, wantIDs) || len(after.DeleteMarkers) != 1 ||
				aws.ToString(after.DeleteMarkers[0].VersionId) != aws.ToString(marker.VersionId) || aws.ToBool(after.DeleteMarkers[0].IsLatest) {
				t.Fatalf("conditional revival lost or replaced history: %+v / %+v", after.Versions, after.DeleteMarkers)
			}
			latest, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
			readBody(latest, err, "replacement")
			if aws.ToString(latest.VersionId) != aws.ToString(third.VersionId) {
				t.Fatalf("current read returned historical version: %+v", latest)
			}
			old, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: first.VersionId})
			readBody(old, err, "historical-content")
		})
	}
}

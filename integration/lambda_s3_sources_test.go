package stackd_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd/internal/awstest"
)

type lambdaS3Fixture struct {
	Observations []lambdaQualifiedRow
	Context      struct {
		OperatorSession struct {
			Role        string
			SessionName string `json:"session_name"`
		} `json:"operator_session"`
	}
	LargePackageBoundary struct {
		Recipe lambdaS3Recipe
		Audit  struct{ Records []map[string]any }
	} `json:"large_package_boundary"`
}

type lambdaS3Recipe struct {
	Entries []lambdaS3Entry
	Size    int `json:"zip_size"`
}

type lambdaS3Entry struct {
	Name         string
	Timestamp    [6]int
	CreateSystem uint16 `json:"create_system"`
	ExternalAttr uint32 `json:"external_attr"`
	Source       string `json:"utf8_source"`
	Size         int64
	FillByte     byte `json:"fill_byte"`
}

type lambdaS3FillReader byte

func (r lambdaS3FillReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func (e lambdaS3Entry) reader() io.Reader {
	if e.Source != "" {
		return strings.NewReader(e.Source)
	}
	return io.LimitReader(lambdaS3FillReader(e.FillByte), e.Size)
}

// CreateRaw retains the native ZIP_STORED headers, CRCs and entry order without
// Go's streaming data descriptors. Padding is streamed, not allocated separately.
// The deployment's CodeSize/CodeSha256, download and runtime are the oracle; this
// is not a standalone digest attestation of fixture construction.
func lambdaS3Package(t *testing.T, recipe lambdaS3Recipe) []byte {
	t.Helper()
	var archive bytes.Buffer
	archive.Grow(recipe.Size)
	writer := zip.NewWriter(&archive)
	for _, entry := range recipe.Entries {
		hash := crc32.NewIEEE()
		size, err := io.Copy(hash, entry.reader())
		if err != nil {
			t.Fatal(err)
		}
		d := entry.Timestamp
		// FileInfoHeader fills the DOS timestamps required by CreateRaw,
		// without an extended timestamp field or deprecated-field access.
		info := (&zip.FileHeader{Modified: time.Date(d[0], time.Month(d[1]), d[2], d[3], d[4], d[5], 0, time.UTC)}).FileInfo()
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			t.Fatal(err)
		}
		header.Name, header.Method = entry.Name, zip.Store
		header.CreatorVersion, header.ReaderVersion = entry.CreateSystem<<8|20, 20
		header.ExternalAttrs, header.CRC32 = entry.ExternalAttr, hash.Sum32()
		header.CompressedSize64, header.UncompressedSize64 = uint64(size), uint64(size)
		member, err := writer.CreateRaw(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(member, entry.reader()); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

type lambdaS3Replay struct {
	*lambdaQualifiedReplay
	fixture        lambdaS3Fixture
	versions       lambdaPolicyRevisions
	operator       aws.CredentialsProvider
	location       string
	audit          bool
	createRequests map[string]string
}

func TestLambdaS3SourcesRuntimeNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := &lambdaS3Replay{lambdaQualifiedReplay: newLambdaQualifiedReplay(t, backend), fixture: lambdaFixture[lambdaS3Fixture](t, "s3_sources"), versions: lambdaPolicyRevisions{}}
			// These captures share previously issued source identities. Preserve
			// their mapping after deletion rather than replaying AWS's private
			// version-token format against a separately initialized backend.
			for _, scenario := range []string{"copy_authority_errors", "large_reference_dryrun", "reference_snapshots"} {
				r.audit = scenario == "large_reference_dryrun"
				r.run(t, scenario)
			}
		})
	}
}

// Replay applied policy transitions and each final stable pair of direct S3
// controls, not AWS's IAM propagation retry counts or wall-clock delays. Readiness
// uses the existing SDK waiter. Full capture, including cleanup, audit windows,
// interrupted attempts and absence records, remains verbatim in s3_sources.json.
func (r *lambdaS3Replay) run(t *testing.T, scenario string) {
	t.Helper()
	r.createRequests = map[string]string{}
	bounds := map[string][2]string{
		"copy_authority_errors":  {"create-stackd-s3code-a14f509c-src", "final-versions"},
		"large_reference_dryrun": {"large-create-bucket", "large-audit-copy-invoke"},
		"reference_snapshots":    {"coldref-create-bucket", "coldref-never-invoked-state-after-invoke"},
	}[scenario]
	controls := map[string]string{}
	for _, row := range r.fixture.Observations {
		if row.Service == "s3" && strings.Contains(row.Label, "-control-") {
			controls[row.Label[:strings.LastIndex(row.Label, "-")]] = row.Label
		}
	}
	inside := false
	for _, row := range r.fixture.Observations {
		if row.Label == bounds[0] {
			inside = true
		}
		if !inside {
			continue
		}
		last := row.Label == bounds[1]
		if r.selected(row, controls) {
			if row.Label == "deleted-source-latest-still-A" {
				// The resumed server belongs to the whole replay, not this row.
				r.reopen(t, row.Input["FunctionName"].(string))
			}
			if !t.Run(row.Label, func(t *testing.T) { r.step(t, row) }) {
				t.FailNow()
			}
		}
		if last {
			break
		}
	}
	if r.audit {
		r.auditRelationship(t)
	}
	r.auditFunctionSources(t)
}

func (r *lambdaS3Replay) selected(row lambdaQualifiedRow, controls map[string]string) bool {
	if lambdaQualifiedTransient(row) {
		return false
	}
	if row.Service == "s3" && strings.Contains(row.Label, "-control-") {
		return controls[row.Label[:strings.LastIndex(row.Label, "-")]] == row.Label
	}
	if row.Service == "lambda" && row.Operation == "get-function-configuration" {
		return row.Result.Output["State"] != "Pending" && row.Result.Output["LastUpdateStatus"] != "InProgress"
	}
	if strings.HasPrefix(row.Label, "large-audit-") {
		return r.audit || strings.HasPrefix(row.Label, "large-audit-copy-") || row.Label == "large-audit-final-direct-marker"
	}
	if row.Service == "cloudtrail" || row.Service == "logs" || strings.Contains(row.Label, "audit") {
		return false
	}
	return true
}

// This capture calls the digest member sha256 rather than sha256_hex. Adapt the
// envelope only, then use the shared native blob decoder. Source bytes stay exact.
func (r *lambdaS3Replay) value(value any) any {
	switch value := value.(type) {
	case map[string]any:
		if encoded, ok := value["base64"].(string); ok {
			return lambdaNativeBlobInput(map[string]any{"base64": encoded, "sha256_hex": value["sha256"]})
		}
		out := make(map[string]any, len(value))
		for key, child := range value {
			out[key] = r.value(child)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = r.value(child)
		}
		return out
	case string:
		if local, ok := r.versions[value]; ok {
			return local
		}
	}
	return value
}

func (r *lambdaS3Replay) lambdaClient(actor string) *awslambda.Client {
	options := r.c.lambda.Options()
	if actor == "operator-stable-session" {
		options.Credentials = r.operator
	}
	return awslambda.New(options)
}

func (r *lambdaS3Replay) objects(actor, bucket string) *s3.Client {
	options := s3NativeClient(cloudClients{r.c.server}, "test", "test").Options()
	options.HTTPClient = r.status
	if actor == "operator-stable-session" {
		options.Credentials = r.operator
	}
	if strings.HasSuffix(bucket, "-west") {
		options.Region = "us-west-2"
	}
	return s3.New(options)
}

func (r *lambdaS3Replay) step(t *testing.T, row lambdaQualifiedRow) {
	t.Helper()
	if r.setup(t, row) {
		if row.Label == "operator-allow-current-only" {
			// Native captured one reused STS session in context, not an observation.
			var assume lambdaQualifiedRow
			assume.Service, assume.Operation = "sts", "assume-role"
			assume.Input = map[string]any{"RoleArn": r.fixture.Context.OperatorSession.Role, "RoleSessionName": r.fixture.Context.OperatorSession.SessionName}
			assume.Result.Code = "Success"
			r.setup(t, assume)
			r.operator = r.actors[r.fixture.Context.OperatorSession.SessionName].Options().Credentials
		}
		return
	}
	input := r.value(r.input(t, row)).(map[string]any)
	if row.Service == "s3" {
		r.s3Step(t, row, input)
		return
	}
	if row.Service == "cloudtrail" {
		client := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(r.c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: r.status, RetryMaxAttempts: 1})
		operations := map[string]string{"create-trail": "CreateTrail", "put-event-selectors": "PutEventSelectors", "start-logging": "StartLogging"}
		_, err := awstest.CallSDK(t.Context(), client, operations[row.Operation], lambdaQualifiedJSON(t, input))
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if row.Service == "https" {
		r.download(t, row)
		return
	}
	if row.Service != "lambda" {
		t.Fatalf("unbound native source service %s", row.Service)
	}
	name, _ := input["FunctionName"].(string)
	if row.Operation == "get-function-configuration" && row.Result.Output["State"] == "Active" {
		r.ready(t, name)
	}
	atomic := row.Operation == "update-function-code" && (row.Result.Code != "Success" || input["DryRun"] == true)
	var before map[string]any
	if atomic {
		before = r.snapshot(t, name)
	}
	operation := lambdaQualifiedOperations(r.lambdaClient(row.Actor))[row.Operation]
	if operation == nil {
		t.Fatalf("unbound native source operation %s", row.Operation)
	}
	r.status.status = 0
	var actual map[string]any
	var err error
	if row.Operation == "create-function" {
		encoded, encodeErr := json.Marshal(input)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		var output any
		output, err = awstest.CallSDK(t.Context(), r.lambdaClient(row.Actor), "CreateFunction", encoded)
		r.createRequests[row.Label] = nativeAuditRequestID(t, output, err)
		if err == nil {
			encoded, encodeErr = json.Marshal(output)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			if encodeErr := json.Unmarshal(encoded, &actual); encodeErr != nil {
				t.Fatal(encodeErr)
			}
		}
	} else {
		actual, err = operation(t.Context(), input)
	}
	if r.status.status != row.Result.HTTPStatus {
		t.Fatalf("HTTP %d, native %d: %v", r.status.status, row.Result.HTTPStatus, err)
	}
	if atomic {
		after := r.snapshot(t, name)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("rejected/DryRun update changed deployment or publication: before=%#v after=%#v", before, after)
		}
	}
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
		lambdaS3ErrorCause(t, row, err)
		if row.Operation == "create-function" {
			_, err := r.c.lambda.GetFunction(t.Context(), &awslambda.GetFunctionInput{FunctionName: aws.String(name)})
			assertAPIError(t, err, "ResourceNotFoundException")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	want := r.value(row.Result.Output).(map[string]any)
	if row.Operation == "invoke" {
		r.invocation(t, actual, want)
		return
	}
	if row.Operation == "list-versions-by-function" {
		r.compare(t, actual, want, "")
		return
	}
	lambdaLayerFunction(t, actual, want)
	if row.Operation == "get-function" {
		r.code(t, actual, want)
	}
	if row.Operation == "create-function" || row.Operation == "update-function-code" && input["DryRun"] != true {
		r.ready(t, name)
	}
	// DryRun describes the candidate (small A), not the preserved large package.
	// Its temporary response revision/state is not persisted and is not bound.
	if input["DryRun"] != true && (row.Operation == "get-function" || row.Operation == "get-function-configuration") {
		if configuration, ok := want["Configuration"].(map[string]any); ok {
			want, actual = configuration, actual["Configuration"].(map[string]any)
		}
		for _, field := range []string{"State", "LastUpdateStatus"} {
			if expected, ok := want[field]; ok && actual[field] != expected {
				t.Fatalf("%s=%v, native %v", field, actual[field], expected)
			}
		}
		if native, ok := want["RevisionId"].(string); ok {
			r.revisions.observe(t, native, actual["RevisionId"].(string))
		}
	}
}

// Lambda reports several precedence branches with the same outer exception.
// Compare the embedded S3 error code, or the conflicting parameter/principal
// identity, rather than pinning native diagnostic prose.
func lambdaS3ErrorCause(t *testing.T, row lambdaQualifiedRow, err error) {
	t.Helper()
	var native struct{ Error struct{ Message string } }
	if decodeErr := json.Unmarshal(row.Result.Error, &native); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	message := err.Error()
	if _, source, ok := strings.Cut(native.Error.Message, "S3 Error Code: "); ok {
		code, _, _ := strings.Cut(source, ".")
		if !strings.Contains(message, "S3 Error Code: "+code+".") {
			t.Fatalf("source error lost native S3 cause %s: %v", code, err)
		}
	}
	if strings.Contains(native.Error.Message, "Publish and DryRun") {
		if !strings.Contains(message, "Publish") || !strings.Contains(message, "DryRun") {
			t.Fatalf("native rejects the Publish/DryRun conflict, got: %v", err)
		}
	}
	if strings.Contains(native.Error.Message, "Could not unzip") {
		if !strings.Contains(strings.ToLower(message), "zip") || strings.Contains(message, "DryRun") || strings.Contains(message, "Revision") {
			t.Fatalf("native rejects ZIP content before DryRun/revision checks, got: %v", err)
		}
	}
	if strings.Contains(native.Error.Message, "Lambda service principal") && !strings.Contains(message, "lambda.amazonaws.com") {
		t.Fatalf("native rejects missing Lambda service-principal source authority, got: %v", err)
	}
}

func (r *lambdaS3Replay) snapshot(t *testing.T, name string) map[string]any {
	t.Helper()
	operations := lambdaQualifiedOperations(r.c.lambda)
	function, err := operations["get-function"](t.Context(), map[string]any{"FunctionName": name})
	if err != nil {
		t.Fatal(err)
	}
	baseName := function["Configuration"].(map[string]any)["FunctionName"]
	versions, err := operations["list-versions-by-function"](t.Context(), map[string]any{"FunctionName": baseName})
	if err != nil {
		t.Fatal(err)
	}
	projection := func(configuration map[string]any) map[string]any {
		out := map[string]any{}
		for _, field := range strings.Fields("Version CodeSha256 CodeSize RevisionId LastModified State LastUpdateStatus") {
			out[field] = configuration[field]
		}
		return out
	}
	inventory := map[string]any{}
	for _, version := range versions["Versions"].([]any) {
		configuration := version.(map[string]any)
		inventory[configuration["Version"].(string)] = projection(configuration)
	}
	code := function["Code"].(map[string]any)
	return map[string]any{"configuration": projection(function["Configuration"].(map[string]any)), "versions": inventory, "reference": code["ResolvedS3Object"], "repository": code["RepositoryType"], "downloadable": code["Location"] != nil}
}

func (r *lambdaS3Replay) code(t *testing.T, actual, want map[string]any) {
	t.Helper()
	got, expected := actual["Code"].(map[string]any), want["Code"].(map[string]any)
	if got["RepositoryType"] != expected["RepositoryType"] {
		t.Fatalf("repository=%#v, native=%#v", got, expected)
	}
	if reference, ok := expected["ResolvedS3Object"].(map[string]any); ok {
		if !reflect.DeepEqual(got["ResolvedS3Object"], reference) || got["Location"] != nil && got["Location"] != "" {
			t.Fatalf("REFERENCE must preserve resolved source identity without a download Location: got=%#v native=%#v", got, expected)
		}
		r.location = ""
		return
	}
	if got["ResolvedS3Object"] != nil {
		t.Fatalf("COPY retained a reference: %#v", got)
	}
	r.location, _ = got["Location"].(string)
	if r.location == "" {
		t.Fatal("COPY lost its download Location")
	}
}

func (r *lambdaS3Replay) invocation(t *testing.T, actual, want map[string]any) {
	t.Helper()
	for _, field := range []string{"StatusCode", "ExecutedVersion", "FunctionError"} {
		if actual[field] != want[field] {
			t.Fatalf("invoke %s=%v, native=%v", field, actual[field], want[field])
		}
	}
	decode := func(value any) map[string]any {
		body, err := base64.StdEncoding.DecodeString(value.(string))
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("runtime payload %s: %v", body, err)
		}
		return payload
	}
	got, expected := decode(actual["Payload"]), r.value(decode(want["Payload"])).(map[string]any)
	// IAM diagnostic wording/session IDs are not a portable runtime contract.
	// Preserve the actual S3 error code, body size and exact successful version.
	for _, payload := range []map[string]any{got, expected} {
		if source, ok := payload["s3"].(map[string]any); ok {
			delete(source, "message")
		}
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("runtime payload=%#v, native=%#v", got, expected)
	}
}

func (r *lambdaS3Replay) download(t *testing.T, row lambdaQualifiedRow) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, r.location, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = request.URL.Host
	local, err := url.Parse(r.c.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	request.URL.Host = local.Host
	response, err := r.c.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != row.Result.HTTPStatus {
		t.Fatalf("download HTTP %d, native %d", response.StatusCode, row.Result.HTTPStatus)
	}
	if row.Label == "large-download" {
		digest := sha256.New()
		size, err := io.Copy(digest, response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if float64(size) != row.Result.Output["size"] || base64.StdEncoding.EncodeToString(digest.Sum(nil)) != row.Result.Output["CodeSha256"] {
			t.Fatalf("large deployed download differs from native: size=%d digest=%s", size, base64.StdEncoding.EncodeToString(digest.Sum(nil)))
		}
		return
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	expected := lambdaAdmissionInput[[]byte](t, lambdaQualifiedJSON(t, r.value(row.Result.Output["bytes"])))
	if !bytes.Equal(body, *expected) {
		t.Fatalf("COPY download changed: received %d bytes, native %d", len(body), len(*expected))
	}
}

func (r *lambdaS3Replay) s3Step(t *testing.T, row lambdaQualifiedRow, input map[string]any) {
	t.Helper()
	bucket, _ := input["Bucket"].(string)
	client := r.objects(row.Actor, bucket)
	var actual any
	var err error
	r.status.status = 0
	switch row.Operation {
	case "put-object":
		var body []byte
		if row.Label == "large-upload" {
			body = lambdaS3Package(t, r.fixture.LargePackageBoundary.Recipe)
		} else {
			body = *lambdaAdmissionInput[[]byte](t, lambdaQualifiedJSON(t, input["Body"]))
		}
		delete(input, "Body")
		in := lambdaAdmissionInput[s3.PutObjectInput](t, lambdaQualifiedJSON(t, input))
		in.Body = bytes.NewReader(body)
		actual, err = client.PutObject(t.Context(), in)
	case "get-object":
		var out *s3.GetObjectOutput
		out, err = client.GetObject(t.Context(), lambdaAdmissionInput[s3.GetObjectInput](t, lambdaQualifiedJSON(t, input)))
		if err == nil {
			body, readErr := io.ReadAll(out.Body)
			out.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if native, ok := row.Result.Output["Body"]; ok {
				expected := lambdaAdmissionInput[[]byte](t, lambdaQualifiedJSON(t, r.value(native)))
				if !bytes.Equal(body, *expected) {
					t.Fatalf("S3 source bytes changed: received %d, native %d", len(body), len(*expected))
				}
			}
			out.Body = nil
			actual = out
		}
	case "delete-object":
		actual, err = client.DeleteObject(t.Context(), lambdaAdmissionInput[s3.DeleteObjectInput](t, lambdaQualifiedJSON(t, input)))
	default:
		operations := map[string]string{"create-bucket": "CreateBucket", "put-bucket-versioning": "PutBucketVersioning", "put-bucket-policy": "PutBucketPolicy", "delete-bucket-policy": "DeleteBucketPolicy"}
		operation := operations[row.Operation]
		if operation == "" {
			t.Fatalf("unbound S3 source operation %s", row.Operation)
		}
		actual, err = awstest.CallSDK(t.Context(), client, operation, lambdaQualifiedJSON(t, input))
	}
	if r.status.status != row.Result.HTTPStatus {
		t.Fatalf("S3 HTTP %d, native %d: %v", r.status.status, row.Result.HTTPStatus, err)
	}
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	output := *lambdaAdmissionInput[map[string]any](t, lambdaQualifiedJSON(t, actual))
	if native, ok := row.Result.Output["VersionId"].(string); ok {
		local, _ := output["VersionId"].(string)
		r.versions.observe(t, native, local)
	}
	if marker, ok := row.Result.Output["DeleteMarker"]; ok && output["DeleteMarker"] != marker {
		t.Fatalf("delete-marker identity lost: got=%#v native=%#v", output, row.Result.Output)
	}
}

// Only positive delivered relationships are replayed. Native's bounded window
// proves neither an exact fetch count nor absence of other preparation fetches.
// Direct marker and Lambda COPY reads share a principal; REFERENCE additionally
// records a Lambda service-principal read of the resolved immutable version.
func (r *lambdaS3Replay) auditRelationship(t *testing.T) {
	t.Helper()
	advanceClock(t, r.clock, 6*time.Minute)
	trailNativeDrain(t, r.c.cloud)
	var bucket string
	for _, row := range r.fixture.Observations {
		if row.Label == "large-audit-create-bucket" {
			bucket = row.Input["Bucket"].(string)
		}
	}
	client := r.objects("administrator", bucket)
	objects := map[string][]byte{}
	pages := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, object := range page.Contents {
			if !strings.HasSuffix(aws.ToString(object.Key), ".json.gz") {
				continue
			}
			out, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: object.Key})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(out.Body)
			out.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			objects[aws.ToString(object.Key)] = body
		}
	}
	actual := trailNativeRecords(t, objects)
	var nativeMarker map[string]any
	for _, event := range r.fixture.LargePackageBoundary.Audit.Records {
		parameters := event["requestParameters"].(map[string]any)
		identity := event["userIdentity"].(map[string]any)
		if parameters["key"] == "audit-copy.zip" && identity["invokedBy"] == nil {
			nativeMarker = event
			break
		}
	}
	if nativeMarker == nil {
		t.Fatal("native capture lacks the independent COPY audit marker")
	}
	find := func(native map[string]any) map[string]any {
		wanted := r.value(native["requestParameters"]).(map[string]any)
		identity := native["userIdentity"].(map[string]any)
		for _, event := range actual {
			parameters, _ := event["requestParameters"].(map[string]any)
			principal, _ := event["userIdentity"].(map[string]any)
			if event["eventName"] == native["eventName"] && event["errorCode"] == native["errorCode"] && parameters["bucketName"] == wanted["bucketName"] && parameters["key"] == wanted["key"] && parameters["versionId"] == wanted["versionId"] && principal["invokedBy"] == identity["invokedBy"] && (identity["type"] != "AWSService" || principal["type"] == "AWSService") {
				return principal
			}
		}
		t.Fatalf("missing delivered native source-audit relationship: event=%v source=%#v invokedBy=%v type=%v", native["eventName"], wanted, identity["invokedBy"], identity["type"])
		return nil
	}
	marker := find(nativeMarker)
	for _, native := range r.fixture.LargePackageBoundary.Audit.Records {
		parameters := native["requestParameters"].(map[string]any)
		identity := native["userIdentity"].(map[string]any)
		if identity["invokedBy"] != "lambda.amazonaws.com" {
			continue
		}
		if parameters["key"] == "audit-copy.zip" {
			copy := find(native)
			if copy["principalId"] == nil || copy["principalId"] != marker["principalId"] {
				t.Fatalf("COPY source read lost the deploying principal: marker=%#v copy=%#v", marker, copy)
			}
		}
		if identity["type"] == "AWSService" {
			find(native)
		}
	}
}

// This supplement correlates the original CreateFunction request IDs. It proves
// request Code field presence, not a uniform error projection: one native S3
// denial lacks errorCode, and the modeled invalid-mode request was unobserved.
func (r *lambdaS3Replay) auditFunctionSources(t *testing.T) {
	t.Helper()
	fixture := lambdaFixture[struct {
		Observations []struct {
			Label     string
			RequestID string `json:"request_id"`
		}
		Events     []map[string]any
		Unobserved []struct{ Label string }
	}](t, "function_s3_audit")
	nativeByID := map[string]map[string]any{}
	for _, event := range fixture.Events {
		nativeByID[event["requestID"].(string)] = event
	}
	unobserved := map[string]bool{}
	for _, row := range fixture.Unobserved {
		unobserved[row.Label] = true
	}
	expected := map[string]map[string]any{}
	for _, row := range fixture.Observations {
		localID := r.createRequests[row.Label]
		if localID == "" || unobserved[row.Label] {
			continue
		}
		event := nativeByID[row.RequestID]
		if event == nil {
			t.Fatalf("missing native function audit correlation for %s", row.Label)
		}
		expected[localID] = r.value(event["requestParameters"]).(map[string]any)
	}
	if len(expected) == 0 {
		t.Fatal("source replay has no correlated native function audit requests")
	}
	trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(r.c.server.URL), Credentials: r.c.lambda.Options().Credentials, HTTPClient: r.c.server.Client(), RetryMaxAttempts: 1})
	lookup := &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("CreateFunction20150331")}}, MaxResults: aws.Int32(50)}
	found := map[string]bool{}
	for {
		out, err := trails.LookupEvents(t.Context(), lookup)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range out.Events {
			var document map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(event.CloudTrailEvent)), &document); err != nil {
				t.Fatal(err)
			}
			id, _ := document["requestID"].(string)
			want := expected[id]
			if want == nil {
				continue
			}
			if found[id] || !reflect.DeepEqual(document["requestParameters"], want) {
				t.Fatalf("function source audit parameters=%#v; native=%#v; duplicate=%v", document["requestParameters"], want, found[id])
			}
			found[id] = true
		}
		if out.NextToken == nil {
			break
		}
		lookup.NextToken = out.NextToken
	}
	if len(found) != len(expected) {
		t.Fatalf("LookupEvents exposed %d of %d correlated function source requests", len(found), len(expected))
	}
}

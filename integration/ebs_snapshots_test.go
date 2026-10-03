package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	ebsdomain "stackd/internal/services/ebs"
)

var ebsSnapshotIDPattern = regexp.MustCompile(`^snap-[0-9a-f]{17}$`)

type ebsNativeCall struct {
	Label, Service, Operation, Code, Caller, Reason string
	Region                                          string
	TargetRegion                                    string `json:"target_region"`
	Input, Output                                   json.RawMessage
	Error                                           struct{ Reason string }
	StartedAt                                       time.Time `json:"started_at"`
	FinishedAt                                      time.Time `json:"finished_at"`
	RequestID                                       string    `json:"request_id"`
	RequestPaginationTokenSHA256                    string    `json:"request_pagination_token_sha256"`
	ResponsePaginationTokenSHA256                   string    `json:"response_pagination_token_sha256"`
	HTTPStatus                                      int       `json:"http_status"`
	Bytes                                           struct {
		Length   int
		Checksum string `json:"sha256_base64"`
		Payload  string `json:"expected_payload"`
		Matches  bool   `json:"expected_bytes_match"`
	} `json:"bytes_verification"`
}

type ebsNativeFixture struct {
	Account, Region string
	Calls           []ebsNativeCall
	Payloads        map[string]struct {
		Recipe, Seed string
		Length       int
		Checksum     string `json:"sha256_base64"`
	}
	Payload struct {
		Length int
		SHA256 string
	}
	Sessions map[string]json.RawMessage
}

type ebsReplaySnapshot struct {
	created, sealed time.Time
	readable        bool
	copied          bool
}

type ebsSnapshotReplay struct {
	fixture      ebsNativeFixture
	clients      cloudClients
	reopen       func() cloudClients
	clock        *clock.Manual
	bindings     map[string]string
	payloads     map[string][]byte
	snapshots    map[string]*ebsReplaySnapshot
	polls        map[string]string
	tokens       map[string]string
	sessions     map[string]aws.CredentialsProvider
	roleARN      string
	sessionRoles map[string]string
	volumes      *ebsVolumeReplay
}

// These replays compare native SDK documents, not service structs. Binary bodies
// are reconstructed from capture recipes and checked byte-for-byte after restart.
// Native polling repetitions are collapsed: service time moves at phase boundaries,
// never by the incidental latency or polling interval of an AWS capture.
func TestEBSNativeSnapshots(t *testing.T) {
	for _, name := range []string{"blocks", "blocks_supplement", "blocks_lineage", "encryption_authorization"} {
		t.Run(name, func(t *testing.T) {
			var fixture ebsNativeFixture
			awsReadFixture(t, "ebs/"+name+".json", &fixture)
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					r := newEBSSnapshotReplay(t, fixture, backend)
					for _, row := range fixture.Calls {
						if !r.include(name, row) {
							continue
						}
						if !t.Run(row.Label, func(t *testing.T) { r.call(t, row) }) {
							return
						}
					}
				})
			}
		})
	}
}

// The capture establishes pending -> error and the terminal API behavior, not an
// AWS polling SLA. Probe the deterministic local boundary with the same native
// documents, including across repository reopen; do not sleep for captured polls.
func TestEBSSnapshotTerminalBoundaries(t *testing.T) {
	var fixture ebsNativeFixture
	awsReadFixture(t, "ebs/blocks_lineage.json", &fixture)
	rows := make(map[string]ebsNativeCall, len(fixture.Calls))
	for _, row := range fixture.Calls {
		rows[row.Label] = row
	}
	for _, test := range []struct {
		name              string
		setup             []string
		pending, terminal string
	}{
		{"timeout", []string{"lineage-timeout-no-writes"}, "lineage-timeout-state-909", "lineage-timeout-state-929"},
		{"bad-count", []string{"lineage-bad-count", "lineage-bad-count-put-one", "lineage-bad-count-complete-two"}, "lineage-bad-count-initial", "lineage-bad-count-state-677"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					r := newEBSSnapshotReplay(t, fixture, backend)
					call := func(label string) {
						t.Helper()
						row, ok := rows[label]
						if !ok {
							t.Fatalf("missing native terminal observation %q", label)
						}
						r.call(t, row)
					}
					var base time.Time
					for _, label := range test.setup {
						call(label)
						if ebsSDKOperation(rows[label].Operation) != "CompleteSnapshot" {
							base = r.clock.Now()
						}
					}
					var start struct{ Timeout int }
					awsDecodeJSON(t, rows[test.setup[0]].Input, &start)
					boundary := base.Add(time.Duration(start.Timeout) * time.Minute)
					if test.name == "bad-count" {
						boundary = r.clock.Now().Add(ebsdomain.CountValidationDelay)
					}
					r.clock.Advance(boundary.Add(-time.Millisecond).Sub(r.clock.Now()))
					call(test.pending)
					r.clock.Advance(time.Millisecond)
					call(test.terminal)
					for _, suffix := range []string{"list", "put", "complete", "parent"} {
						call("lineage-" + test.name + "-post-terminal-" + suffix)
					}
					call("lineage-" + test.name + "-after-admission")
				})
			}
		})
	}
}

func newEBSSnapshotReplay(t *testing.T, fixture ebsNativeFixture, backend string, start ...func(stackd.Config) (*stackd.Stack, *httptest.Server)) *ebsSnapshotReplay {
	t.Helper()
	source := clock.NewManual(fixture.Calls[0].StartedAt)
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, start...)
	r := &ebsSnapshotReplay{fixture: fixture, clients: clients, reopen: reopen, clock: source,
		bindings: map[string]string{}, payloads: map[string][]byte{}, snapshots: map[string]*ebsReplaySnapshot{},
		tokens: map[string]string{}, polls: map[string]string{}, sessions: map[string]aws.CredentialsProvider{}}
	for name, recipe := range fixture.Payloads {
		var data []byte
		switch recipe.Recipe {
		case "zero":
			data = make([]byte, recipe.Length)
		case "repeat_utf8_truncate":
			data = bytes.Repeat([]byte(recipe.Seed), (recipe.Length+len(recipe.Seed)-1)/len(recipe.Seed))[:recipe.Length]
		default:
			t.Fatalf("unknown native payload recipe %q", recipe.Recipe)
		}
		digest := sha256.Sum256(data)
		if base64.StdEncoding.EncodeToString(digest[:]) != recipe.Checksum {
			t.Fatalf("native recipe %s does not reproduce its recorded checksum", name)
		}
		r.payloads[name] = data
	}
	if fixture.Payload.Length != 0 {
		// This literal is the preserved recipe in encryption_authorization.json.
		data := bytes.Repeat([]byte("stackd synthetic EBS encryption evidence\n"), 14000)[:fixture.Payload.Length]
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != fixture.Payload.SHA256 {
			t.Fatal("native encryption recipe does not reproduce its recorded checksum")
		}
		r.payloads["encryption"] = data
	}
	return r
}

func ebsSDKOperation(operation string) string {
	if !strings.Contains(operation, "_") {
		return operation
	}
	return ec2NetworkAction(strings.ReplaceAll(operation, "_", "-"))
}

func (r *ebsSnapshotReplay) include(name string, row ebsNativeCall) bool {
	action := ebsSDKOperation(row.Operation)
	if name == "encryption_authorization" {
		if row.Label == "create-owned-key" || row.Label == "create-owned-role" || row.Label == "bound-owned-role" {
			return true
		}
		// Native disabled-key successes include previously cached data keys. They
		// do not establish a deterministic disabled-key contract for a fresh owner.
		if strings.Contains(row.Label, "disabled") || strings.HasPrefix(row.Label, "disable-") || strings.HasPrefix(row.Label, "enable-") {
			return false
		}
	}
	if row.Service != "ebs" && action != "DescribeSnapshots" && action != "DeleteSnapshot" {
		return false
	}
	// The native client disabled required-field validation; the Go SDK cannot
	// issue this particular malformed call without bypassing its public client.
	if row.Label == "start-missing-volume" {
		return false
	}
	if name == "blocks" && (strings.HasPrefix(row.Label, "bad-count") || strings.HasPrefix(row.Label, "complete-bad-count") || strings.HasPrefix(row.Label, "bad-aggregate") || row.Label == "complete-wrong-aggregate" || row.Label == "timeout-no-writes") {
		return false
	}
	if name == "blocks_lineage" && (strings.Contains(row.Label, "timeout") || strings.Contains(row.Label, "bad-count")) {
		return false // Replayed separately at their deterministic timeout boundary.
	}
	if strings.Contains(row.Label, "readiness") || strings.Contains(row.Label, "-ready-list") || strings.Contains(row.Label, "-terminal-") || strings.Contains(row.Label, "-state-") {
		key := action + "/" + string(row.Input)
		observation := row.Code + "/" + row.Reason + "/" + row.Error.Reason + "/" + string(row.Output)
		if r.polls[key] == observation {
			return false
		}
		r.polls[key] = observation
	}
	if strings.HasPrefix(row.Label, "cleanup-") {
		var input struct {
			SnapshotID  string   `json:"SnapshotId"`
			SnapshotIDs []string `json:"SnapshotIds"`
		}
		_ = json.Unmarshal(row.Input, &input)
		if input.SnapshotID != "" && r.bindings[input.SnapshotID] == "" {
			return false
		}
		for _, id := range input.SnapshotIDs {
			if r.bindings[id] == "" {
				return false
			}
		}
	}
	return true
}

func (r *ebsSnapshotReplay) provider(t *testing.T, caller string) aws.CredentialsProvider {
	t.Helper()
	if caller == "" || caller == "owner" {
		return credentials.NewStaticCredentialsProvider("test", "test", "")
	}
	if provider := r.sessions[caller]; provider != nil {
		return provider
	}
	policy, ok := r.fixture.Sessions[caller]
	if !ok {
		t.Fatalf("native session %q has no retained policy", caller)
	}
	policy = ec2AuditReplace(t, policy, r.bindings)
	role := r.roleARN
	if r.sessionRoles[caller] != "" {
		role = r.sessionRoles[caller]
	}
	session, err := r.clients.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: aws.String(role), RoleSessionName: aws.String(caller), Policy: aws.String(string(policy)),
	})
	if err != nil {
		t.Fatal(err)
	}
	value := session.Credentials
	provider := credentials.NewStaticCredentialsProvider(aws.ToString(value.AccessKeyId), aws.ToString(value.SecretAccessKey), aws.ToString(value.SessionToken))
	r.sessions[caller] = provider
	return provider
}

func (r *ebsSnapshotReplay) call(t *testing.T, row ebsNativeCall) {
	t.Helper()
	action := ebsSDKOperation(row.Operation)
	if r.volumes != nil {
		row = r.volumes.prepare(t, row)
	}
	input := ec2AuditReplace(t, row.Input, r.bindings)
	if row.Service == "iam" || row.Service == "kms" {
		r.setup(t, row, input)
		return
	}
	if row.Code == "Success" && (action == "StartSnapshot" || action == "CopySnapshot" || action == "CreateVolume" || action == "CreateSnapshot" || action == "ModifyVolume" || action == "DeleteVolume" || action == "PutSnapshotBlock" || action == "CompleteSnapshot" || action == "DeleteSnapshot") {
		// Independent snapshots must not share every deadline. A small logical
		// tick preserves write ordering without reproducing network latency.
		r.clock.Advance(time.Millisecond)
	}
	r.advancePhase(t, row)
	if r.volumes != nil {
		r.volumes.advancePhase(t, row)
	}
	trailNativeDrain(t, r.clients.server.Config.Handler.(*stackd.Stack))
	var parameters map[string]json.RawMessage
	awsDecodeJSON(t, input, &parameters)
	var nativeParameters map[string]json.RawMessage
	awsDecodeJSON(t, row.Input, &nativeParameters)
	var body []byte
	if action == "PutSnapshotBlock" {
		var recipe struct {
			Payload  string
			Length   int
			Checksum string `json:"sha256_base64"`
			SHA256   string
		}
		awsDecodeJSON(t, parameters["BlockData"], &recipe)
		name := recipe.Payload
		if name == "" && recipe.SHA256 != "" {
			name = "encryption"
		}
		body = r.payloads[name]
		if name == "" && recipe.Length == 5 {
			// The retained digest independently verifies these five bytes.
			body = []byte("short")
		}
		if len(body) != recipe.Length {
			t.Fatalf("missing retained payload %q of length %d", name, recipe.Length)
		}
		digest := sha256.Sum256(body)
		if recipe.Checksum != "" && base64.StdEncoding.EncodeToString(digest[:]) != recipe.Checksum {
			t.Fatal("upload body does not reproduce the captured digest")
		}
		delete(parameters, "BlockData")
	}
	var nativeID string
	_ = json.Unmarshal(nativeParameters["SnapshotId"], &nativeID)
	var nativeBlockToken string
	_ = json.Unmarshal(parameters["BlockToken"], &nativeBlockToken)
	if action == "GetSnapshotBlock" && nativeBlockToken == "<redacted>" {
		var index int
		awsDecodeJSON(t, parameters["BlockIndex"], &index)
		token := r.tokens[nativeID+"/"+strconv.Itoa(index)]
		if token == "" {
			t.Fatal("redacted native block token has no preceding successful list")
		}
		parameters["BlockToken"], _ = json.Marshal(token)
	}
	input, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}
	region := r.region(row)
	if row.Label == "region-isolation-list" {
		region = "us-west-2"
	}
	wire := &awstest.WireClient{Client: r.clients.server.Client()}
	provider := r.provider(t, row.Caller)
	var client any = ebs.New(ebs.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: provider, HTTPClient: wire, RetryMaxAttempts: 1})
	if row.Service == "ec2" {
		client = ec2.New(ec2.Options{
			Region: region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: provider, HTTPClient: wire, RetryMaxAttempts: 1,
			APIOptions: []func(*middleware.Stack) error{func(stack *middleware.Stack) error {
				// Native malformed-request captures disable required-field
				// validation. Keep the SDK serializer and signer, not a raw API.
				if r.volumes != nil {
					if _, ok := stack.Initialize.Get("OperationInputValidation"); ok {
						if _, err := stack.Initialize.Remove("OperationInputValidation"); err != nil {
							return err
						}
					}
				}
				if action == "CopySnapshot" {
					if _, ok := stack.Initialize.Get("OperationInputValidation"); ok {
						if _, err := stack.Initialize.Remove("OperationInputValidation"); err != nil {
							return err
						}
					}
					// The SDK replaces DestinationRegion during copy presigning.
					// Restore an explicit captured value after serialization while
					// retaining the SDK's real request signing and response decoding.
					if raw, present := parameters["DestinationRegion"]; present {
						var destination string
						awsDecodeJSON(t, raw, &destination)
						return awstest.QueryValues(url.Values{"DestinationRegion": {destination}})(stack)
					}
				}
				return nil
			}},
		})
	}
	actual, callErr := awstest.CallSDK(t.Context(), client, action, input, func(target any) {
		if upload, ok := target.(*ebs.PutSnapshotBlockInput); ok {
			upload.BlockData = bytes.NewReader(body)
		}
	})
	if row.Code != "Success" {
		r.checkError(t, row, wire, callErr)
		return
	}
	if callErr != nil {
		t.Fatal(callErr)
	}
	if wire.Status != row.HTTPStatus {
		t.Fatalf("HTTP %d, native %d", wire.Status, row.HTTPStatus)
	}
	if download, ok := actual.(*ebs.GetSnapshotBlockOutput); ok {
		r.checkBytes(t, row, download)
	}
	// Decode the independent native document into the same public SDK output
	// type, retaining absent fields and all modeled metadata rather than checking
	// only selected fields. Body bytes are checked independently above.
	var output map[string]json.RawMessage
	awsDecodeJSON(t, row.Output, &output)
	delete(output, "BlockData")
	expectedJSON, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	expected := reflect.New(reflect.TypeOf(actual).Elem()).Interface()
	if err := awstest.DecodeSDK(expectedJSON, expected); err != nil {
		t.Fatal(err)
	}
	want, got := ec2NetworkDocument(t, expected), ec2NetworkDocument(t, actual)
	delete(want, "BlockData")
	delete(got, "BlockData")
	if action == "StartSnapshot" || action == "CopySnapshot" || action == "CreateSnapshot" {
		before, after := want["SnapshotId"].(string), got["SnapshotId"].(string)
		if !ebsSnapshotIDPattern.MatchString(after) {
			t.Fatalf("invalid snapshot ID %q", after)
		}
		r.bind(t, before, after)
		if r.snapshots[before] == nil {
			r.snapshots[before] = &ebsReplaySnapshot{created: r.clock.Now()}
		}
		if action == "CopySnapshot" || action == "CreateSnapshot" {
			r.snapshots[before].sealed = r.clock.Now()
			r.snapshots[before].copied = action == "CopySnapshot"
		}
	}
	if r.volumes != nil {
		r.volumes.observe(t, row, want, got)
	}
	r.normalize(t, "response", want, got, nativeID)
	ec2NetworkCompare(t, "response", want, got, r.bindings)
	if row.Label == "root-list" {
		r.checkAccountIsolation(t, nativeID)
	}
	if action == "CompleteSnapshot" && r.snapshots[nativeID].sealed.IsZero() {
		r.snapshots[nativeID].sealed = r.clock.Now()
	}
	if action == "CopySnapshot" || action == "CreateSnapshot" {
		// Fixture replay has no interrupted transfer: commit payload work at
		// this service instant, before advancing completion/readiness clocks.
		trailNativeDrain(t, r.clients.server.Config.Handler.(*stackd.Stack))
	}
	// Reopen before the next operation, including between token issuance and use.
	// Sparse uploads, overwrite results, parent layers, sealing, IAM sessions and
	// token signing authority must all survive reconstruction of the owner.
	r.clients = r.reopen()
}

func (r *ebsSnapshotReplay) region(row ebsNativeCall) string {
	if row.Region != "" {
		return row.Region
	}
	if row.TargetRegion != "" && row.TargetRegion != "aws-global" {
		return row.TargetRegion
	}
	return r.fixture.Region
}

func (r *ebsSnapshotReplay) checkAccountIsolation(t *testing.T, nativeID string) {
	t.Helper()
	other := credentials.NewStaticCredentialsProvider("111111111111", "test", "")
	wire := &awstest.WireClient{Client: r.clients.server.Client()}
	direct := ebs.New(ebs.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: other, HTTPClient: wire, RetryMaxAttempts: 1})
	id := r.bindings[nativeID]
	_, err := direct.ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{SnapshotId: aws.String(id)})
	assertAPIError(t, err, "ResourceNotFoundException")
	var failure struct{ Reason string }
	awsDecodeJSON(t, wire.Body, &failure)
	if wire.Status != 404 || failure.Reason != "SNAPSHOT_NOT_FOUND" {
		t.Fatalf("another account can discover the snapshot: HTTP %d %s", wire.Status, wire.Body)
	}
	_, err = direct.GetSnapshotBlock(t.Context(), &ebs.GetSnapshotBlockInput{SnapshotId: aws.String(id), BlockIndex: aws.Int32(0), BlockToken: aws.String(r.tokens[nativeID+"/0"])})
	assertAPIError(t, err, "ResourceNotFoundException")
	controls := ec2.New(ec2.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: other, HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	_, err = controls.DescribeSnapshots(t.Context(), &ec2.DescribeSnapshotsInput{SnapshotIds: []string{id}})
	assertAPIError(t, err, "InvalidSnapshot.NotFound")
	_, err = controls.DeleteSnapshot(t.Context(), &ec2.DeleteSnapshotInput{SnapshotId: aws.String(id)})
	assertAPIError(t, err, "InvalidSnapshot.NotFound")
	// The following native Get rows still read the owner's exact bytes after
	// this unauthorized deletion attempt and another repository reopen.
}

func (r *ebsSnapshotReplay) setup(t *testing.T, row ebsNativeCall, input json.RawMessage) {
	t.Helper()
	switch ebsSDKOperation(row.Operation) {
	case "CreateKey":
		var request kms.CreateKeyInput
		awsDecodeJSON(t, input, &request)
		client := kms.New(kms.Options{Region: r.region(row), BaseEndpoint: aws.String(r.clients.server.URL), Credentials: r.provider(t, row.Caller), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
		output, err := client.CreateKey(t.Context(), &request)
		if err != nil {
			t.Fatal(err)
		}
		var native kms.CreateKeyOutput
		if err := awstest.DecodeSDK(row.Output, &native); err != nil {
			t.Fatal(err)
		}
		r.bind(t, aws.ToString(native.KeyMetadata.Arn), aws.ToString(output.KeyMetadata.Arn))
		r.bind(t, aws.ToString(native.KeyMetadata.KeyId), aws.ToString(output.KeyMetadata.KeyId))
	case "CreateRole":
		var request iam.CreateRoleInput
		awsDecodeJSON(t, input, &request)
		// The replay's owner is the local root credential, not the capture user's
		// unavailable secret. Session policies and the bounded role policy remain
		// exactly the observed native policies.
		request.AssumeRolePolicyDocument = aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}]}`, r.fixture.Account))
		output, err := r.clients.iam("test", "test", "").CreateRole(t.Context(), &request)
		if err != nil {
			t.Fatal(err)
		}
		r.roleARN = aws.ToString(output.Role.Arn)
	case "PutRolePolicy":
		if _, err := awstest.CallSDK(t.Context(), r.clients.iam("test", "test", ""), "PutRolePolicy", input); err != nil {
			t.Fatal(err)
		}
	case "PutKeyPolicy", "DisableKey", "EnableKey":
		wire := &awstest.WireClient{Client: r.clients.server.Client()}
		client := kms.New(kms.Options{Region: r.region(row), BaseEndpoint: aws.String(r.clients.server.URL), Credentials: r.provider(t, row.Caller), HTTPClient: wire, RetryMaxAttempts: 1})
		_, err := awstest.CallSDK(t.Context(), client, ebsSDKOperation(row.Operation), input)
		if row.Code != "Success" {
			r.checkError(t, row, wire, err)
		} else if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported native setup operation %s", row.Operation)
	}
	r.clients = r.reopen()
}

func (r *ebsSnapshotReplay) checkError(t *testing.T, row ebsNativeCall, wire *awstest.WireClient, err error) {
	t.Helper()
	assertAPIError(t, err, row.Code)
	if wire.Status != row.HTTPStatus {
		t.Fatalf("HTTP %d, native %d: %v", wire.Status, row.HTTPStatus, err)
	}
	if row.Service != "ebs" {
		return
	}
	var envelope struct{ Reason string }
	awsDecodeJSON(t, wire.Body, &envelope)
	reason := row.Reason
	if reason == "" {
		reason = row.Error.Reason
	}
	if envelope.Reason != reason {
		t.Fatalf("native error Reason %q, got %q: %s", reason, envelope.Reason, wire.Body)
	}
}

func (r *ebsSnapshotReplay) checkBytes(t *testing.T, row ebsNativeCall, output *ebs.GetSnapshotBlockOutput) {
	t.Helper()
	data, err := io.ReadAll(output.BlockData)
	output.BlockData.Close()
	output.BlockData = nil
	if err != nil {
		t.Fatal(err)
	}
	name := row.Bytes.Payload
	if name == "" && row.Bytes.Checksum != "" {
		// The exploratory deleted-parent read retained its digest rather than a
		// recipe name. Match that native digest, then still compare exact bytes.
		for candidate, payload := range r.payloads {
			digest := sha256.Sum256(payload)
			if base64.StdEncoding.EncodeToString(digest[:]) == row.Bytes.Checksum {
				name = candidate
				break
			}
		}
	} else if name == "" {
		name = "encryption"
	} else if !row.Bytes.Matches {
		t.Fatal("capture did not establish exact byte equality")
	}
	want, ok := r.payloads[name]
	if !ok || !bytes.Equal(data, want) {
		t.Fatalf("download does not reproduce native payload %q (%d bytes)", name, len(want))
	}
	digest := sha256.Sum256(data)
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	if aws.ToInt32(output.DataLength) != int32(len(data)) || aws.ToString(output.Checksum) != checksum || string(output.ChecksumAlgorithm) != "SHA256" {
		t.Fatalf("download checksum/length headers disagree with returned bytes: %#v", output)
	}
	if row.Bytes.Checksum != "" && checksum != row.Bytes.Checksum {
		t.Fatal("download digest differs from the native byte verification")
	}
}

func (r *ebsSnapshotReplay) bind(t *testing.T, native, actual string) {
	t.Helper()
	if prior := r.bindings[native]; prior != "" && prior != actual {
		t.Fatalf("native identity %q changed from %q to %q", native, prior, actual)
	}
	if strings.HasPrefix(native, "snap-") || strings.HasPrefix(native, "vol-") {
		for other, value := range r.bindings {
			if other != native && value == actual && strings.HasPrefix(other, strings.SplitN(native, "-", 2)[0]+"-") {
				t.Fatalf("distinct resources %s and %s collapsed to %s", native, other, actual)
			}
		}
	}
	r.bindings[native] = actual
}

func (r *ebsSnapshotReplay) normalize(t *testing.T, path string, want, got any, snapshot string) {
	t.Helper()
	switch before := want.(type) {
	case map[string]any:
		after, ok := got.(map[string]any)
		if !ok {
			return
		}
		if id, ok := before["SnapshotId"].(string); ok {
			snapshot = id
		}
		if tags, ok := before["Tags"].([]any); ok {
			ec2NetworkSort(t, tags, r.bindings, true)
			ec2NetworkSort(t, after["Tags"], r.bindings, false)
		}
		if before["State"] == "pending" {
			if nativeProgress, present := before["Progress"].(string); present {
				progress, ok := after["Progress"].(string)
				if nativeProgress == "" {
					// CreateSnapshot admits a volume-derived snapshot before any
					// progress percentage is published. Preserve that empty field.
					if !ok || progress != "" {
						t.Fatalf("%s pending creation progress = %v, native empty", path, after["Progress"])
					}
				} else {
					// DescribeSnapshots publishes a percentage. Worker timing can
					// change its value, but cannot turn it into an empty field.
					percent, err := strconv.Atoi(strings.TrimSuffix(progress, "%"))
					if !ok || !strings.HasSuffix(progress, "%") || err != nil || percent < 0 || percent >= 100 {
						t.Fatalf("%s invalid pending progress: %v", path, after["Progress"])
					}
					delete(before, "Progress")
					delete(after, "Progress")
				}
			}
			if state := r.snapshots[snapshot]; state != nil && state.copied {
				// Metadata publication is independent of the pending lifecycle.
				// Normalize only the captured worker-publication fields; tags,
				// encryption, ownership and terminal metadata remain contracts.
				message := before["StateMessage"]
				if message == "Metadata not updated" || message == "Metadata updated" {
					delete(before, "StateMessage")
					if actual := after["StateMessage"]; actual == nil || actual == "Metadata not updated" || actual == "Metadata updated" {
						delete(after, "StateMessage")
					}
				}
				if message == "Metadata not updated" && before["VolumeSize"] == float64(0) {
					delete(before, "VolumeSize")
					delete(after, "VolumeSize")
				}
				if before["KmsKeyId"] == "alias/aws/ebs" {
					delete(before, "KmsKeyId")
					delete(after, "KmsKeyId")
				}
			}
		}
		for key, value := range before {
			actual := after[key]
			if value == nil || actual == nil {
				continue
			}
			switch key {
			case "StartTime", "CompletionTime", "ExpiryTime":
				_, nativeOK := value.(string)
				actualTime, actualOK := actual.(string)
				when, err := time.Parse(time.RFC3339Nano, actualTime)
				if !nativeOK || !actualOK || err != nil || when.Before(r.fixture.Calls[0].StartedAt.Truncate(time.Second)) {
					t.Fatalf("%s.%s invalid timestamp: %v", path, key, actual)
				}
				if key == "ExpiryTime" {
					if blocks, ok := before["Blocks"].([]any); ok && len(blocks) == 0 {
						if when.Sub(r.clock.Now()).Abs() > time.Millisecond {
							t.Fatalf("empty page expiry = %v, want current time %v", when, r.clock.Now())
						}
					} else if !when.After(r.clock.Now()) {
						t.Fatal("newly issued native-style tokens are already expired")
					}
				} else if when.After(r.clock.Now().Add(time.Millisecond)) {
					t.Fatalf("%s is in the future", key)
				}
				if state := r.snapshots[snapshot]; state != nil && key != "ExpiryTime" {
					expected := state.created
					if key == "CompletionTime" {
						expected = state.sealed.Add(ebsdomain.CompletionDelay)
					}
					if when.Sub(expected).Abs() > time.Millisecond {
						t.Fatalf("%s.%s no longer identifies its original lifecycle transition: %v, want %v", path, key, when, expected)
					}
				}
				// Captures can assign the same millisecond to distinct transitions;
				// timestamps are normalized locally, not as identity substitutions.
				before[key] = actualTime
			case "BlockToken", "FirstBlockToken", "SecondBlockToken", "NextToken":
				nativeToken, nativeOK := value.(string)
				actualToken, actualOK := actual.(string)
				if !nativeOK || !actualOK || actualToken == "" {
					t.Fatalf("%s.%s lost native token", path, key)
				}
				if nativeToken == "<redacted>" {
					before[key] = actualToken
				} else {
					r.bind(t, nativeToken, actualToken)
				}
				if key == "BlockToken" {
					index, _ := before["BlockIndex"].(float64)
					r.tokens[snapshot+"/"+strconv.Itoa(int(index))] = actualToken
				}
			default:
				r.normalize(t, path+"."+key, value, actual, snapshot)
			}
		}
	case []any:
		after, ok := got.([]any)
		if !ok || len(before) != len(after) {
			return
		}
		for index, value := range before {
			r.normalize(t, fmt.Sprintf("%s[%d]", path, index), value, after[index], snapshot)
		}
	}
}

func (r *ebsSnapshotReplay) advancePhase(t *testing.T, row ebsNativeCall) {
	t.Helper()
	var input struct {
		SnapshotID string `json:"SnapshotId"`
	}
	var output struct {
		Status    string
		Snapshots []struct{ SnapshotID, State string }
	}
	awsDecodeJSON(t, row.Input, &input)
	if row.Code == "Success" {
		awsDecodeJSON(t, row.Output, &output)
	}
	advance := func(id string, readable bool) {
		state := r.snapshots[id]
		if state == nil || state.sealed.IsZero() {
			return
		}
		at := state.sealed.Add(ebsdomain.CompletionDelay)
		if readable {
			at = at.Add(ebsdomain.ReadinessDelay)
			if state.readable {
				// Reissue at a new instant so an old-token replay really uses
				// a previously issued token, not the latest identical token.
				at = r.clock.Now().Add(time.Second)
			}
			state.readable = true
		}
		if at.After(r.clock.Now()) {
			r.clock.Advance(at.Sub(r.clock.Now()))
		}
	}
	for _, snapshot := range output.Snapshots {
		if snapshot.State == "completed" || snapshot.State == "error" {
			advance(snapshot.SnapshotID, false)
		}
	}
	if output.Status == "completed" || output.Status == "error" {
		advance(input.SnapshotID, false)
	}
	if ebsSDKOperation(row.Operation) == "ListSnapshotBlocks" && row.Code == "Success" {
		advance(input.SnapshotID, true)
	}
}

func TestEBSEncryptionDefaults(t *testing.T) {
	var fixture struct {
		Cases []struct {
			Name, Key, ExpectedKey             string
			Enabled, Encrypted                 *bool
			ExpectedDefault, ExpectedEncrypted bool
		}
	}
	body, err := os.ReadFile("../testdata/integration/ebs/encryption_defaults.json")
	if err != nil {
		t.Fatal(err)
	}
	awsDecodeJSON(t, body, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC))
			cloud, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source})
			root := credentials.NewStaticCredentialsProvider("test", "test", "")
			control := func() *ec2.Client {
				return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(cloud.server.URL), Credentials: root, HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1})
			}
			direct := func() *ebs.Client {
				return ebs.New(ebs.Options{Region: "us-east-1", BaseEndpoint: aws.String(cloud.server.URL), Credentials: root, HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1})
			}
			initial, err := control().GetEbsDefaultKmsKeyId(t.Context(), &ec2.GetEbsDefaultKmsKeyIdInput{})
			if err != nil {
				t.Fatal(err)
			}
			managed, err := direct().StartSnapshot(t.Context(), &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1), Encrypted: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			selectedDefault := aws.ToString(initial.KmsKeyId)
			customer, err := cloud.kms("test", "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			keys := map[string]string{"managed": aws.ToString(managed.KmsKeyArn), "customer": aws.ToString(customer.KeyMetadata.Arn)}
			for _, row := range fixture.Cases {
				t.Run(row.Name, func(t *testing.T) {
					if row.Enabled != nil {
						if *row.Enabled {
							_, err = control().EnableEbsEncryptionByDefault(t.Context(), &ec2.EnableEbsEncryptionByDefaultInput{})
						} else {
							_, err = control().DisableEbsEncryptionByDefault(t.Context(), &ec2.DisableEbsEncryptionByDefaultInput{})
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					switch row.Key {
					case "customer":
						changed, err := control().ModifyEbsDefaultKmsKeyId(t.Context(), &ec2.ModifyEbsDefaultKmsKeyIdInput{KmsKeyId: customer.KeyMetadata.KeyId})
						if err != nil || aws.ToString(changed.KmsKeyId) != keys[row.Key] {
							t.Fatalf("select default key: %+v, %v", changed, err)
						}
					case "managed":
						reset, err := control().ResetEbsDefaultKmsKeyId(t.Context(), &ec2.ResetEbsDefaultKmsKeyIdInput{})
						if err != nil || aws.ToString(reset.KmsKeyId) != keys[row.Key] {
							t.Fatalf("reset default key: %+v, %v", reset, err)
						}
					}
					if row.Key != "" {
						selectedDefault = keys[row.Key]
					}
					cloud = reopen()
					enabled, err := control().GetEbsEncryptionByDefault(t.Context(), &ec2.GetEbsEncryptionByDefaultInput{})
					if err != nil || aws.ToBool(enabled.EbsEncryptionByDefault) != row.ExpectedDefault {
						t.Fatalf("retained encryption setting: %+v, %v", enabled, err)
					}
					selected, err := control().GetEbsDefaultKmsKeyId(t.Context(), &ec2.GetEbsDefaultKmsKeyIdInput{})
					if err != nil || aws.ToString(selected.KmsKeyId) != selectedDefault {
						t.Fatalf("retained key selection: %+v, %v", selected, err)
					}
					snapshot, err := direct().StartSnapshot(t.Context(), &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1), Encrypted: row.Encrypted})
					if err != nil {
						t.Fatal(err)
					}
					actualKey := aws.ToString(snapshot.KmsKeyArn)
					if row.ExpectedEncrypted && actualKey != keys[row.ExpectedKey] || !row.ExpectedEncrypted && actualKey != "" {
						t.Fatalf("snapshot used key %q, encrypted=%v, selected=%q", actualKey, row.ExpectedEncrypted, keys[row.ExpectedKey])
					}
					source.Advance(time.Second)
				})
			}
		})
	}
}

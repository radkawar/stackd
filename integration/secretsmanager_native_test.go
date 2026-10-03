package stackd_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type secretsNativeObservation struct {
	awsNativeObservation
	Actor    string
	Finished int64 `json:"request_finished_ms"`
}

type secretsNativeFixture struct {
	Account, Region, Prefix string
	Observations            []secretsNativeObservation
	Cleanup                 json.RawMessage
	CallerARN               string                     `json:"caller_arn"`
	ReplaySessions          map[string]json.RawMessage `json:"replay_sessions"`
	Actors                  map[string]struct {
		ARN        string `json:"arn"`
		SessionARN string `json:"session_arn"`
	}
	AuditEvents map[string]map[string]any `json:"audit_events"`
	Callbacks   []secretsNativeCallback   `json:"callback_events_deduplicated"`
}

type secretsNativeCallback struct {
	Kind, Probe, Secret, Step string
	RotationTokenPresent      bool `json:"rotation_token_present"`
}

type secretsNativeReplay struct {
	fixture  secretsNativeFixture
	clients  cloudClients
	reopen   func() cloudClients
	clock    *clock.Manual
	identity aws.Credentials
	sessions map[string]aws.Credentials
	bindings map[string]string
	audits   map[string]map[string]any
}

func TestSecretsManagerNativeLifecycle(t *testing.T) {
	secretsNativeRun(t, "lifecycle", false)
}

func TestSecretsManagerNativeAuthority(t *testing.T) {
	secretsNativeRun(t, "authority", false)
}

func TestSecretsManagerNativeEncryptionAudit(t *testing.T) {
	secretsNativeRun(t, "encryption_audit", false)
}

func TestSecretsManagerNativeReplication(t *testing.T) {
	secretsNativeRun(t, "rotation_replication", false)
}

func TestSecretsManagerNativeMetadataAuthority(t *testing.T) {
	secretsNativeRun(t, "metadata_authority", false)
}

func TestSecretsManagerNativeReplicationAuthority(t *testing.T) {
	secretsNativeRun(t, "replication_authority", false)
}

// This uses the captured ZIP, Python runtime and boto3 callbacks, not an in-process
// rotation substitute. The cancellation probe's deliberate 25-second callback
// pause is not replayed as a serial CLI transcript.
func TestSecretsManagerNativeRotationDocker(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda rotation runtime")
	}
	secretsNativeRun(t, "rotation_replication", true)
}

func secretsNativeRun(t *testing.T, name string, docker bool) {
	t.Helper()
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var fixture secretsNativeFixture
			awsReadFixture(t, "secretsmanager/"+name+".json", &fixture)
			if len(fixture.Observations) == 0 {
				t.Fatal("native fixture has no observations")
			}
			rows := fixture.Observations
			if name == "authority" {
				// The key deletion is captured in cleanup, before the final three
				// data-plane observations. It is a real dependency, not a key mock.
				var cleanup []secretsNativeObservation
				awsDecodeJSON(t, fixture.Cleanup, &cleanup)
				for _, row := range cleanup {
					if row.Service == "kms" {
						rows = append(rows, row)
					}
				}
				slices.SortStableFunc(rows, func(a, b secretsNativeObservation) int {
					if a.Started < b.Started {
						return -1
					}
					if a.Started > b.Started {
						return 1
					}
					return 0
				})
			}
			source := clock.NewManual(time.UnixMilli(rows[0].Started))
			start := func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				if docker {
					return newLambdaDockerStack(t, config, nil)
				}
				return startPublicCloud(t, config)
			}
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, start)
			r := &secretsNativeReplay{fixture: fixture, clients: clients, reopen: reopen, clock: source,
				identity: aws.Credentials{AccessKeyID: fixture.Account, SecretAccessKey: "test"},
				sessions: map[string]aws.Credentials{}, bindings: map[string]string{}, audits: map[string]map[string]any{}}
			callerARN := fixture.CallerARN
			for _, row := range rows {
				if row.Operation != "get-caller-identity" {
					continue
				}
				var caller struct{ Arn string }
				awsDecodeJSON(t, row.Result.Output, &caller)
				callerARN = caller.Arn
				break
			}
			if _, user, ok := strings.Cut(callerARN, ":user/"); ok {
				_, key, secret := clients.user(t, fixture.Account, user)
				putUserPolicy(t, clients.iam(fixture.Account, "test", ""), user, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
				r.identity = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
			}
			for index, row := range rows {
				if !secretsNativeInclude(name, docker, index, row) {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) { r.replay(t, row, docker) }) {
					return
				}
			}
			if len(r.audits) != 0 {
				r.checkAudits(t)
			}
			if docker {
				r.checkRotationCallbacks(t)
			}
		})
	}
}

func secretsNativeInclude(name string, docker bool, index int, row secretsNativeObservation) bool {
	if row.Operation == "get-caller-identity" {
		return false
	}
	// IAM propagation retries do not specify a local authorization outcome.
	if row.Operation == "assume-role" && row.Result.Code != "Success" {
		return false
	}
	if strings.HasPrefix(row.Label, "cleanup") || strings.HasPrefix(row.Label, "independent-final") {
		return false
	}
	if name == "metadata_authority" && strings.HasPrefix(row.Label, "wait-replica-") && strings.Contains(string(row.Result.Output), `"InProgress"`) {
		return false
	}
	if name == "replication_authority" && row.Operation == "describe-secret" && strings.Contains(string(row.Result.Output), `"InProgress"`) {
		return false // Native propagation samples do not define a local completion deadline.
	}
	if name != "rotation_replication" {
		return true
	}
	if !docker {
		if index >= 30 {
			return false
		}
		// Keep terminal replica observations, not samples of AWS propagation latency.
		return !slices.Contains([]string{"replication-in-sync-1", "replica-current-updated-1", "replica-absent-after-removal-1", "second-replication-in-sync-1"}, row.Label)
	}
	if index < 30 || index > 62 || row.Service == "logs" && row.Operation != "create-log-group" {
		return false
	}
	return !slices.Contains([]string{"create-rotation-lambda-1", "wait-lambda-active-1", "wait-real-rotation-current-1"}, row.Label)
}

func (r *secretsNativeReplay) drain(t *testing.T) {
	t.Helper()
	for {
		result, err := r.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 10000)
		if err != nil {
			t.Fatal(err)
		}
		if !result.More {
			return
		}
	}
}

// Bind entire identities (including JSON-encoded policy strings), not ARN
// suffixes or account-wide wildcard replacements. Redacted fixture tokens are
// stable UUID-sized hashes, never live credentials or native random bytes.
func (r *secretsNativeReplay) replace(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	var value any
	awsDecodeJSON(t, raw, &value)
	var visit func(any) any
	visit = func(value any) any {
		switch v := value.(type) {
		case string:
			if strings.HasPrefix(v, "<redacted-version-token-") {
				if r.bindings[v] == "" {
					sum := sha256.Sum256([]byte(v))
					r.bindings[v] = fmt.Sprintf("%x", sum[:16])
				}
			}
			if bound, ok := r.bindings[v]; ok {
				return bound
			}
			if strings.Contains(v, `"Statement"`) && json.Valid([]byte(v)) {
				var embedded any
				awsDecodeJSON(t, []byte(v), &embedded)
				if _, scalar := embedded.(string); !scalar {
					encoded, err := json.Marshal(visit(embedded))
					if err != nil {
						t.Fatal(err)
					}
					return string(encoded)
				}
			}
		case map[string]any:
			out := make(map[string]any, len(v))
			for key, child := range v {
				out[visit(key).(string)] = visit(child)
			}
			return out
		case []any:
			for i, child := range v {
				v[i] = visit(child)
			}
		}
		return value
	}
	encoded, err := json.Marshal(visit(value))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (r *secretsNativeReplay) secretClient(region string, identity aws.Credentials) *secretsmanager.Client {
	return secretsmanager.New(secretsmanager.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken),
		HTTPClient:  r.clients.server.Client(), RetryMaxAttempts: 1})
}

func (r *secretsNativeReplay) replay(t *testing.T, row secretsNativeObservation, docker bool) {
	t.Helper()
	if next := time.UnixMilli(row.Started); next.After(r.clock.Now()) {
		advanceClock(t, r.clock, next.Sub(r.clock.Now()))
	}
	r.drain(t)
	identity := r.identity
	if row.Actor != "" && row.Actor != "account-caller" {
		var ok bool
		identity, ok = r.sessions[row.Actor]
		if !ok {
			setup := r.fixture.ReplaySessions[row.Actor]
			if setup == nil {
				t.Fatalf("unreplayed native actor %q", row.Actor)
			}
			output, err := awstest.CallSDK(t.Context(), r.clients.sts(r.identity.AccessKeyID, r.identity.SecretAccessKey, r.identity.SessionToken), "assume-role", r.replace(t, setup))
			if err != nil {
				t.Fatal(err)
			}
			credential := output.(*sts.AssumeRoleOutput).Credentials
			identity = aws.Credentials{AccessKeyID: aws.ToString(credential.AccessKeyId), SecretAccessKey: aws.ToString(credential.SecretAccessKey), SessionToken: aws.ToString(credential.SessionToken)}
			r.sessions[row.Actor] = identity
		}
	}
	region := row.Region
	if region == "" {
		region = r.fixture.Region
	}
	input := r.replace(t, row.Input)
	var client any
	switch row.Service {
	case "secretsmanager":
		client = r.secretClient(region, identity)
	case "iam":
		client = r.clients.iam(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
	case "sts":
		client = r.clients.sts(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
	case "kms":
		client = r.clients.kmsRegion(region, identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
	case "events":
		client = eventbridge.New(eventbridge.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
			Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken),
			HTTPClient:  r.clients.server.Client(), RetryMaxAttempts: 1})
	case "logs":
		client = cloudwatchlogs.New(cloudwatchlogs.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
			Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken),
			HTTPClient:  r.clients.server.Client(), RetryMaxAttempts: 1})
	case "lambda":
		client = lambda.New(lambda.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
			Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken),
			HTTPClient:  r.clients.server.Client(), RetryMaxAttempts: 1})
	default:
		t.Fatalf("unmapped fixture service %q", row.Service)
	}
	output, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
	awsNativeResult(t, row.awsNativeObservation, err)
	if err != nil {
		if secretsNativeAudited(row.Label) {
			r.rememberAudit(t, row, output, err)
		}
		return
	}
	if session, ok := output.(*sts.AssumeRoleOutput); ok {
		var native sts.AssumeRoleOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		for actor, value := range r.fixture.Actors {
			if value.SessionARN == aws.ToString(native.AssumedRoleUser.Arn) {
				r.sessions[actor] = aws.Credentials{AccessKeyID: aws.ToString(session.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(session.Credentials.SecretAccessKey), SessionToken: aws.ToString(session.Credentials.SessionToken)}
			}
		}
		return
	}
	if row.Service == "iam" {
		return
	}
	if row.Service == "lambda" {
		if created, ok := output.(*lambda.CreateFunctionOutput); ok {
			waiter := lambda.NewFunctionActiveWaiter(client.(*lambda.Client), fastLambdaActiveWaiter)
			if err := waiter.Wait(t.Context(), &lambda.GetFunctionConfigurationInput{FunctionName: created.FunctionName}, time.Minute); err != nil {
				config, readErr := client.(*lambda.Client).GetFunctionConfiguration(t.Context(), &lambda.GetFunctionConfigurationInput{FunctionName: created.FunctionName})
				if readErr != nil {
					t.Fatalf("Lambda activation: %v; configuration read: %v", err, readErr)
				}
				t.Fatalf("Lambda activation: %v; %s: %s", err, config.StateReasonCode, aws.ToString(config.StateReason))
			}
		}
		return
	}
	r.bindOutput(t, row, output)
	if row.Service == "events" {
		return // Connection lifecycle projection is covered by TestEventBridgeNativeConnections.
	}
	if secretsNativeAudited(row.Label) {
		r.rememberAudit(t, row, output, nil)
	}
	if docker && (row.Label == "wait-real-rotation-current-2" || row.Label == "state-after-deferred-test") {
		output = r.awaitRotation(t, row, input, client.(*secretsmanager.Client))
	}
	r.compareOutput(t, row, output)
	// Reconstruct both services and storage before dependent reads: versions,
	// historical ciphertext keys and deletion metadata must survive restart.
	if !docker && (row.Operation == "update-secret" && strings.Contains(string(input), `"KmsKeyId"`) || row.Label == "schedule-deletion") {
		r.clients = r.reopen()
	}
}

func (r *secretsNativeReplay) bindOutput(t *testing.T, row secretsNativeObservation, output any) {
	t.Helper()
	bind := func(want, got *string) {
		if want == nil {
			return
		}
		if got == nil || *got == "" {
			t.Fatalf("missing identity for %q", *want)
		}
		if previous, ok := r.bindings[*want]; ok && previous != *got {
			t.Fatalf("identity %q changed from %q to %q", *want, previous, *got)
		}
		r.bindings[*want] = *got
	}
	bindGeneratedVersion := func(got *string) {
		var input struct{ ClientRequestToken *string }
		awsDecodeJSON(t, row.Input, &input)
		if input.ClientRequestToken == nil {
			var native struct{ VersionId *string }
			awsDecodeJSON(t, row.Result.Output, &native)
			bind(native.VersionId, got)
		}
	}
	switch out := output.(type) {
	case *eventbridge.CreateConnectionOutput:
		var native eventbridge.CreateConnectionOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		bind(native.ConnectionArn, out.ConnectionArn)
	case *eventbridge.DescribeConnectionOutput:
		var native eventbridge.DescribeConnectionOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		bind(native.ConnectionArn, out.ConnectionArn)
		bind(native.SecretArn, out.SecretArn)
		_, from, _ := strings.Cut(aws.ToString(native.SecretArn), ":secret:")
		_, to, _ := strings.Cut(aws.ToString(out.SecretArn), ":secret:")
		r.bindings[from[:len(from)-7]] = to[:len(to)-7]
	case *secretsmanager.CreateSecretOutput:
		var native secretsmanager.CreateSecretOutput
		if err := awstest.DecodeSDK(row.Result.Output, &native); err != nil {
			t.Fatal(err)
		}
		bind(native.ARN, out.ARN)
		bindGeneratedVersion(out.VersionId)
		// Replica ARNs preserve the primary secret's incarnation suffix.
		for _, observation := range r.fixture.Observations {
			if observation.Region == "" || observation.Region == r.fixture.Region {
				continue
			}
			want := strings.Replace(aws.ToString(native.ARN), ":"+r.fixture.Region+":", ":"+observation.Region+":", 1)
			got := strings.Replace(aws.ToString(out.ARN), ":"+r.fixture.Region+":", ":"+observation.Region+":", 1)
			r.bindings[want] = got
		}
	case *secretsmanager.UpdateSecretOutput:
		bindGeneratedVersion(out.VersionId)
	case *secretsmanager.PutSecretValueOutput:
		bindGeneratedVersion(out.VersionId)
	case *kms.CreateKeyOutput:
		var native kms.CreateKeyOutput
		if err := awstest.DecodeSDK(row.Result.Output, &native); err != nil {
			t.Fatal(err)
		}
		bind(native.KeyMetadata.KeyId, out.KeyMetadata.KeyId)
		bind(native.KeyMetadata.Arn, out.KeyMetadata.Arn)
	case *kms.DescribeKeyOutput:
		if row.Label == "default-key-identity" {
			var native kms.DescribeKeyOutput
			if err := awstest.DecodeSDK(row.Result.Output, &native); err != nil {
				t.Fatal(err)
			}
			bind(native.KeyMetadata.KeyId, out.KeyMetadata.KeyId)
			bind(native.KeyMetadata.Arn, out.KeyMetadata.Arn)
		}
	}
}

func (r *secretsNativeReplay) compareOutput(t *testing.T, row secretsNativeObservation, output any) {
	t.Helper()
	if password, ok := output.(*secretsmanager.GetRandomPasswordOutput); ok {
		var input secretsmanager.GetRandomPasswordInput
		awsDecodeJSON(t, row.Input, &input)
		value := aws.ToString(password.RandomPassword)
		lower, upper, digit := false, false, false
		for _, char := range value {
			lower = lower || unicode.IsLower(char)
			upper = upper || unicode.IsUpper(char)
			digit = digit || unicode.IsDigit(char)
			if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
				t.Fatal("password contains excluded punctuation or whitespace")
			}
		}
		if int64(len(value)) != aws.ToInt64(input.PasswordLength) || !lower || !upper || !digit {
			t.Fatal("password violates captured length or required character classes")
		}
		return
	}
	if deleted, ok := output.(*secretsmanager.DeleteSecretOutput); ok {
		var input secretsmanager.DeleteSecretInput
		awsDecodeJSON(t, row.Input, &input)
		if !aws.ToBool(input.ForceDeleteWithoutRecovery) {
			days := aws.ToInt64(input.RecoveryWindowInDays)
			if days == 0 {
				days = 30
			}
			deadline := r.clock.Now().Add(time.Duration(days) * 24 * time.Hour)
			if deleted.DeletionDate == nil || !deleted.DeletionDate.Equal(deadline) {
				t.Fatalf("recovery deadline = %v, want %s", deleted.DeletionDate, deadline)
			}
		}
	}
	if metadata, ok := output.(*secretsmanager.DescribeSecretOutput); ok && metadata.DeletedDate != nil && metadata.DeletedDate.After(r.clock.Now()) {
		t.Fatalf("DeletedDate is the deletion request time, not its recovery deadline: %s", metadata.DeletedDate)
	}
	if listed, ok := output.(*secretsmanager.ListSecretsOutput); ok {
		for _, metadata := range listed.SecretList {
			if metadata.DeletedDate != nil && metadata.DeletedDate.After(r.clock.Now()) {
				t.Fatalf("listed DeletedDate is a future recovery deadline: %s", metadata.DeletedDate)
			}
		}
	}
	want := reflect.New(reflect.TypeOf(output).Elem()).Interface()
	if err := awstest.DecodeSDK(r.replace(t, row.Result.Output), want); err != nil {
		t.Fatal(err)
	}
	if expected, ok := want.(*secretsmanager.DescribeSecretOutput); ok && len(expected.ReplicationStatus) != 0 {
		terminal := true
		for _, replica := range expected.ReplicationStatus {
			terminal = terminal && replica.Status != "InProgress"
		}
		current := output.(*secretsmanager.DescribeSecretOutput)
		for attempt := 0; terminal && attempt < 30; attempt++ {
			pending := false
			for _, replica := range current.ReplicationStatus {
				pending = pending || replica.Status == "InProgress"
			}
			if !pending {
				break
			}
			advanceClock(t, r.clock, time.Second)
			r.drain(t)
			region := row.Region
			if region == "" {
				region = r.fixture.Region
			}
			var err error
			current, err = r.secretClient(region, r.identity).DescribeSecret(t.Context(), &secretsmanager.DescribeSecretInput{SecretId: current.ARN})
			if err != nil {
				t.Fatal(err)
			}
		}
		output = current
	}
	expected, actual := secretsNativeProjection(t, want), secretsNativeProjection(t, output)
	if !reflect.DeepEqual(expected, actual) {
		wantJSON, _ := json.MarshalIndent(expected, "", "  ")
		gotJSON, _ := json.MarshalIndent(actual, "", "  ")
		t.Fatalf("%s response differs from native\ngot: %s\nwant: %s", row.Label, gotJSON, wantJSON)
	}
}

// Compare SDK-decoded domain fields, not transport metadata, ordering, diagnostic
// wording, asynchronous last-access telemetry or AWS wall-clock instants.
func secretsNativeProjection(t *testing.T, value any) any {
	t.Helper()
	data, err := awstest.MarshalSDK(value)
	if err != nil {
		t.Fatal(err)
	}
	var object any
	awsDecodeJSON(t, data, &object)
	var project func(any) any
	project = func(value any) any {
		switch v := value.(type) {
		case map[string]any:
			out := map[string]any{}
			for key, child := range v {
				if slices.Contains([]string{"ResultMetadata", "LastAccessedDate", "Message", "ErrorMessage", "StatusMessage", "CurrentKeyMaterialId", "KeyMaterialId"}, key) || child == nil {
					continue
				}
				if key == "Description" && v["KeyManager"] == "AWS" {
					continue // AWS-owned descriptive prose is not a customer contract.
				}
				if key == "NextToken" {
					out[key] = true // Pagination tokens are opaque to consumers.
					continue
				}
				if strings.HasSuffix(key, "Date") {
					out[key] = true
					continue
				}
				if key == "ResourcePolicy" {
					var policy any
					awsDecodeJSON(t, []byte(child.(string)), &policy)
					child = policy
				}
				child = project(child)
				if list, ok := child.([]any); ok && len(list) == 0 {
					continue
				}
				if mapping, ok := child.(map[string]any); ok && len(mapping) == 0 {
					continue
				}
				out[key] = child
			}
			return out
		case []any:
			for i, child := range v {
				v[i] = project(child)
			}
			sort.Slice(v, func(i, j int) bool {
				a, _ := json.Marshal(v[i])
				b, _ := json.Marshal(v[j])
				return string(a) < string(b)
			})
			return v
		}
		return value
	}
	return project(object)
}

func (r *secretsNativeReplay) awaitRotation(t *testing.T, row secretsNativeObservation, input json.RawMessage, client *secretsmanager.Client) any {
	t.Helper()
	var request secretsmanager.DescribeSecretInput
	awsDecodeJSON(t, input, &request)
	var native secretsmanager.DescribeSecretOutput
	if err := awstest.DecodeSDK(r.replace(t, row.Result.Output), &native); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		r.drain(t)
		out, err := client.DescribeSecret(t.Context(), &request)
		if err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(secretsNativeProjection(t, out.VersionIdsToStages), secretsNativeProjection(t, native.VersionIdsToStages)) {
			return out
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("real rotation did not reach captured version stages: %#v", out.VersionIdsToStages)
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
}

func secretsNativeAudited(label string) bool {
	return slices.Contains([]string{"default-create-value", "default-get", "permission-control-new-only-old", "audit-batch-mixed", "audit-update-metadata", "audit-update-sensitive-value"}, label)
}

func (r *secretsNativeReplay) rememberAudit(t *testing.T, row secretsNativeObservation, output any, callErr error) {
	t.Helper()
	var native map[string]any
	var request struct{ ClientRequestToken string }
	awsDecodeJSON(t, row.Input, &request)
	for _, event := range r.fixture.AuditEvents {
		if event["eventSource"] != "secretsmanager.amazonaws.com" || !strings.EqualFold(strings.ReplaceAll(row.Operation, "-", ""), fmt.Sprint(event["eventName"])) {
			continue
		}
		when, err := time.Parse(time.RFC3339, fmt.Sprint(event["eventTime"]))
		if err != nil {
			t.Fatal(err)
		}
		if when.Unix() < row.Started/1000 || when.Unix() > row.Finished/1000 {
			continue
		}
		identity := event["userIdentity"].(map[string]any)
		if row.Actor != "account-caller" && identity["arn"] != r.fixture.Actors[row.Actor].SessionARN {
			continue
		}
		parameters, _ := event["requestParameters"].(map[string]any)
		if request.ClientRequestToken != "" && parameters["clientRequestToken"] != request.ClientRequestToken {
			continue
		}
		if native != nil {
			t.Fatalf("ambiguous native audit for %s", row.Label)
		}
		native = event
	}
	if native == nil {
		t.Fatalf("missing native audit evidence for %s", row.Label)
	}
	id := nativeAuditRequestID(t, output, callErr)
	nativeID := native["requestID"].(string)
	add := func(actualID string, event map[string]any) {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var want map[string]any
		awsDecodeJSON(t, r.replace(t, encoded), &want)
		want["eventTime"] = r.clock.Now().UTC().Format(time.RFC3339)
		want["requestID"] = actualID
		// CLI and Go SDK independently generate omitted idempotency tokens.
		var input map[string]any
		awsDecodeJSON(t, row.Input, &input)
		if input["ClientRequestToken"] == nil {
			if params, ok := want["requestParameters"].(map[string]any); ok {
				delete(params, "clientRequestToken")
			}
		}
		r.audits[actualID] = want
	}
	add(id, native)
	if row.Operation == "batch-get-secret-value" {
		items := 0
		for _, event := range r.fixture.AuditEvents {
			childID, _ := event["requestID"].(string)
			if !strings.HasPrefix(childID, nativeID+":") {
				continue
			}
			secret := strings.TrimPrefix(childID, nativeID+":")
			if bound, ok := r.bindings[secret]; ok {
				secret = bound
			}
			add(id+":"+secret, event)
			items++
		}
		var input secretsmanager.BatchGetSecretValueInput
		awsDecodeJSON(t, row.Input, &input)
		if items != len(input.SecretIdList) {
			t.Fatalf("native batch has %d child audits for %d requests", items, len(input.SecretIdList))
		}
	}
}

func (r *secretsNativeReplay) checkAudits(t *testing.T) {
	t.Helper()
	r.drain(t)
	client := cloudtrail.New(cloudtrail.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(r.fixture.Account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	input := &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("secretsmanager.amazonaws.com")}}, MaxResults: aws.Int32(50)}
	found := map[string]bool{}
	for {
		out, err := client.LookupEvents(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range out.Events {
			var actual map[string]any
			awsDecodeJSON(t, []byte(aws.ToString(event.CloudTrailEvent)), &actual)
			id, _ := actual["requestID"].(string)
			want := r.audits[id]
			if want == nil {
				continue
			}
			if found[id] {
				t.Fatalf("duplicate secret audit %q", id)
			}
			found[id] = true
			if params, ok := want["requestParameters"].(map[string]any); ok && params["clientRequestToken"] == nil {
				if params, ok := actual["requestParameters"].(map[string]any); ok {
					delete(params, "clientRequestToken")
				}
			}
			assertNativeAuditEvent(t, actual, want, "")
			for _, field := range []string{"type", "arn", "accountId", "invokedBy"} {
				if !reflect.DeepEqual(awsFixtureField(actual, "userIdentity."+field), awsFixtureField(want, "userIdentity."+field)) {
					t.Fatalf("audit caller %s differs: %#v", field, actual["userIdentity"])
				}
			}
		}
		if out.NextToken == nil {
			break
		}
		input.NextToken = out.NextToken
	}
	for id, event := range r.audits {
		if !found[id] {
			t.Errorf("missing native %s audit outcome %s", event["eventName"], id)
		}
	}
}

func (r *secretsNativeReplay) checkRotationCallbacks(t *testing.T) {
	t.Helper()
	// The retained handler emits actual successful callbacks. Comparing the
	// captured multiset proves set/test ran too, and the deferred request ran
	// only testSecret; final AWSCURRENT alone cannot establish either fact.
	expected := map[string]int{}
	key := func(event secretsNativeCallback) string {
		value := event.Kind + ":" + event.Secret + ":" + event.Step
		if event.Kind == "callback_started" {
			value += fmt.Sprint(event.RotationTokenPresent)
		}
		return value
	}
	for _, event := range r.fixture.Callbacks {
		if !strings.Contains(event.Secret, "-normal-") || event.Kind != "callback_started" && event.Kind != "callback_succeeded" {
			continue
		}
		event.Secret = r.bindings[event.Secret]
		if event.Secret == "" {
			t.Fatal("unbound captured rotation secret")
		}
		expected[key(event)]++
	}
	if len(expected) == 0 {
		t.Fatal("fixture contains no normal rotation callback evidence")
	}
	client := cloudwatchlogs.New(cloudwatchlogs.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(r.fixture.Account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	deadline := time.NewTimer(time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		r.drain(t)
		actual, seen := map[string]int{}, map[string]bool{}
		input := &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String("/aws/lambda/" + r.fixture.Prefix), Limit: aws.Int32(1000)}
		for {
			out, err := client.FilterLogEvents(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			for _, log := range out.Events {
				id := aws.ToString(log.EventId)
				if seen[id] {
					continue
				}
				seen[id] = true
				for _, line := range strings.Split(aws.ToString(log.Message), "\n") {
					var event secretsNativeCallback
					if json.Unmarshal([]byte(line), &event) != nil || event.Probe != "stackd-sm-rotation" {
						continue
					}
					if event.Kind == "callback_failed" {
						t.Fatalf("real rotation callback failed: %s", line)
					}
					if event.Kind == "callback_started" || event.Kind == "callback_succeeded" {
						actual[key(event)]++
					}
				}
			}
			if out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(input.NextToken) {
				break
			}
			input.NextToken = out.NextToken
		}
		if reflect.DeepEqual(actual, expected) {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("real rotation callbacks = %#v, native = %#v", actual, expected)
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
}

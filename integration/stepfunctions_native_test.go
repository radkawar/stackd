package stackd_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/xray"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/internal/awsapi"
	"stackd/internal/awstest"
	sfnstore "stackd/storage/stepfunctions"
)

type stepFunctionsNativeObservation struct {
	awsNativeObservation
	Actor       string
	Finished    int64             `json:"request_finished_ms"`
	HTTPHeaders map[string]string `json:"http_headers"`
}

type stepFunctionsNativeFixture struct {
	Account       string
	CallerAccount string `json:"caller_account"`
	CallerARN     string `json:"caller_arn"`
	Actors        map[string]stepFunctionsNativeActor
	Region        string
	Observations  []stepFunctionsNativeObservation
}

// Record timer registration, rather than sleeping for native Wait states or
// racing clock advancement against an HTTP handler that has not started yet.
type stepFunctionsReplayClock struct {
	*clock.Manual
	timers chan time.Time
}

func (c *stepFunctionsReplayClock) NewTimerAt(at time.Time) clock.Timer {
	timer := c.Manual.NewTimerAt(at)
	select {
	case c.timers <- at:
	default:
	}
	return timer
}

func (c *stepFunctionsReplayClock) NewTimer(d time.Duration) clock.Timer {
	return c.NewTimerAt(c.Now().Add(d))
}

// The sync API commits admission before waiting for its execution. Observe that
// storage boundary, not an unrelated job or scheduler timer that can be ready
// while the HTTP request is still acquiring its transaction.
type stepFunctionsReplayRepository struct {
	sfnstore.Repository
	admitted chan struct{}
}

func (r stepFunctionsReplayRepository) Attempt(ctx context.Context, fn func(sfnstore.Transaction) error) error {
	err := r.Repository.Attempt(ctx, fn)
	if request, ok := awsapi.FromContext(ctx); err == nil && ok && request.Operation.Name == "StartSyncExecution" {
		select {
		case r.admitted <- struct{}{}:
		default:
		}
	}
	return err
}

type stepFunctionsNativeReplay struct {
	fixture    stepFunctionsNativeFixture
	clients    cloudClients
	reopen     func() cloudClients
	clock      *stepFunctionsReplayClock
	admitted   chan struct{}
	identity   aws.Credentials
	session    aws.Credentials
	sessions   map[string]aws.Credentials
	encryption *stepFunctionsEncryptionReplay
	bindings   map[string]string
	timestamps map[string]string
}

func TestStepFunctionsNativeControlLifecycle(t *testing.T) {
	stepFunctionsNativeRun(t, "control_lifecycle", false, func(row stepFunctionsNativeObservation) bool {
		// These pages include unrelated machines in the native account; no
		// owned-resource projection can preserve their opaque page boundaries.
		return stepFunctionsOperation(row.Operation) != "liststatemachines"
	})
}

func TestStepFunctionsNativeCreateIdentity(t *testing.T) {
	stepFunctionsNativeRun(t, "create_identity", false, nil)
}

func TestStepFunctionsNativeDataflow(t *testing.T) {
	stepFunctionsNativeRun(t, "dataflow_execution", false, nil)
}

func TestStepFunctionsNativeVariableLimits(t *testing.T) {
	stepFunctionsNativeRun(t, "variable_limits", false, nil)
}

func TestStepFunctionsNativeExpressionLimits(t *testing.T) {
	stepFunctionsNativeRun(t, "expression_limits", false, nil)
}

func TestStepFunctionsNativeTestState(t *testing.T) {
	stepFunctionsNativeRun(t, "test_state_mock", false, func(row stepFunctionsNativeObservation) bool {
		// Regional account throttling establishes no state-evaluation result.
		return row.Result.Code != "ThrottlingException"
	})
}

func TestStepFunctionsNativeSDKAdmission(t *testing.T) {
	stepFunctionsNativeRun(t, "sdk_admission", false, nil)
}

func TestStepFunctionsNativeMissingActivity(t *testing.T) {
	stepFunctionsNativeRun(t, "activity_missing", false, func(row stepFunctionsNativeObservation) bool {
		return !strings.HasPrefix(row.Label, "cleanup-") && !strings.HasPrefix(row.Label, "verify-")
	})
}

func stepFunctionsOperation(operation string) string {
	return strings.ToLower(strings.ReplaceAll(operation, "-", ""))
}

func stepFunctionsNativeRun(t *testing.T, name string, recoverLeases bool, include func(stepFunctionsNativeObservation) bool) {
	t.Helper()
	var fixture stepFunctionsNativeFixture
	awsReadFixture(t, "stepfunctions/"+name+".json", &fixture)
	if len(fixture.Observations) == 0 {
		t.Fatal("native fixture has no observations")
	}
	if fixture.Account == "" {
		fixture.Account = fixture.CallerAccount
	}
	if fixture.Account == "" {
		// TestState has no account header; its captured context carries the
		// account used for the synthetic execution and state-machine ARNs.
		for _, row := range fixture.Observations {
			match := regexp.MustCompile(`arn:aws:states:[^:]+:([0-9]{12}):`).FindSubmatch(row.Result.Output)
			if len(match) == 2 {
				fixture.Account = string(match[1])
				break
			}
		}
	}
	if fixture.Account == "" {
		t.Fatal("fixture does not identify its caller account")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newStepFunctionsNativeReplay(t, fixture, backend)
			for index, row := range fixture.Observations {
				if stepFunctionsOperation(row.Operation) == "getcalleridentity" && len(fixture.Actors) == 0 || include != nil && !include(row) {
					continue
				}
				// Poll samples establish convergence, not a fixed provider latency.
				// Keep terminal samples and the explicit immediate-delete probe.
				var native map[string]any
				if len(row.Result.Output) != 0 {
					awsDecodeJSON(t, row.Result.Output, &native)
				}
				if native["status"] == "DELETING" && strings.Contains(row.Label, "absence") {
					continue
				}
				if native["status"] == "RUNNING" && index+1 < len(fixture.Observations) {
					next := fixture.Observations[index+1]
					if row.Operation == next.Operation && string(row.Input) == string(next.Input) {
						continue
					}
				}
				if !t.Run(row.Label, func(t *testing.T) {
					r.replay(t, row)
					if r.encryption != nil {
						r.recoverEncryption(t, row)
					}
					if recoverLeases && stepFunctionsOperation(row.Operation) == "getactivitytask" && row.Result.Code == "Success" {
						r.clients = r.reopen()
						r.drain(t)
					}
				}) {
					return
				}
			}
		})
	}
}

func (r *stepFunctionsNativeReplay) drain(t *testing.T) *time.Time {
	t.Helper()
	for {
		result, err := r.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 10000)
		if err != nil {
			t.Fatalf("workflow jobs did not settle: %+v, %v", result, err)
		}
		if !result.More {
			return result.Next
		}
	}
}

// Drains dispatch real task effects without awaiting their I/O. Keep service
// time fixed until those effects commit; submitted callbacks/nested waits and
// activity leases remain pending until their own external input or deadline.
func (r *stepFunctionsNativeReplay) drainEffects(t *testing.T, repository sfnstore.Repository) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		r.drain(t)
		pending := false
		err := repository.View(t.Context(), func(reader sfnstore.Reader) error {
			tasks, err := reader.RecoverableTasks()
			if err != nil {
				return err
			}
			for _, task := range tasks {
				pending = pending || task.Status == sfnstore.TaskRunning
			}
			work, err := reader.NextWork()
			if errors.Is(err, sfnstore.ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			pending = pending || !work.Due.After(r.clock.Now())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !pending {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("workflow external effects did not settle")
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
}

func (r *stepFunctionsNativeReplay) advance(t *testing.T, at time.Time) {
	t.Helper()
	if at.After(r.clock.Now()) {
		advanceClock(t, r.clock.Manual, at.Sub(r.clock.Now()))
	}
	r.drain(t)
}

func (r *stepFunctionsNativeReplay) input(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	var value any
	awsDecodeJSON(t, raw, &value)
	var replace func(any) any
	replace = func(value any) any {
		switch value := value.(type) {
		case string:
			return r.boundString(value)
		case map[string]any:
			for key, child := range value {
				value[key] = replace(child)
			}
		case []any:
			for i, child := range value {
				value[i] = replace(child)
			}
		}
		return value
	}
	encoded, err := json.Marshal(replace(value))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (r *stepFunctionsNativeReplay) call(t *testing.T, row stepFunctionsNativeObservation) any {
	t.Helper()
	if row.Started != 0 {
		r.advance(t, time.UnixMilli(row.Started))
	} else {
		r.drain(t)
	}
	if r.encryption != nil {
		row = r.encryptionExpectation(t, row)
	}
	if row.Finished != 0 && stepFunctionsOperation(row.Operation) == "describeexecution" && row.Result.Code == "Success" {
		var observed struct{ Status string }
		awsDecodeJSON(t, row.Result.Output, &observed)
		if observed.Status != "RUNNING" {
			// Native CLI observations span request start through response. A
			// Wait may become due within that interval, not before it starts.
			r.advance(t, time.UnixMilli(row.Finished))
		}
	}
	input := r.input(t, row.Input)
	identity := r.identity
	if row.Actor == "owned-authority-role" {
		if r.session.AccessKeyID == "" {
			t.Fatal("captured authority session has not been replayed")
		}
		identity = r.session
	} else if row.Actor != "" && row.Actor != "default" {
		var ok bool
		identity, ok = r.sessions[row.Actor]
		if !ok {
			t.Fatalf("actor %q has no replayed STS session", row.Actor)
		}
	}
	var client any
	wire := &awstest.WireClient{Client: r.clients.server.Client()}
	region := row.Region
	if region == "" {
		region = r.fixture.Region
	}
	switch row.Service {
	case "iam":
		client = r.clients.iam(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
	case "sts":
		client = r.clients.sts(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
	case "kms":
		client = r.clients.kmsRegion(region, identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
	case "logs":
		client = cloudwatchlogs.New(cloudwatchlogs.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
			Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken),
			HTTPClient:  r.clients.server.Client(), RetryMaxAttempts: 1})
	case "xray":
		client = xray.New(xray.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL),
			Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken),
			HTTPClient:  r.clients.server.Client(), RetryMaxAttempts: 1})
	case "stepfunctions", "":
		options := []func(*middleware.Stack) error{awstest.JSONBody(input), stepFunctionsLocalEndpoint}
		for name, value := range row.HTTPHeaders {
			options = append(options, smithyhttp.SetHeaderValue(name, value))
		}
		client = sfn.New(sfn.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
			Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken),
			HTTPClient:  wire, RetryMaxAttempts: 1,
			APIOptions: options})
		// The signed body above remains exact, even for requests that omit SDK
		// required members. Reflection fills only the SDK validation envelope.
		input = json.RawMessage(`{"activityArn":"fixture","definition":"{}","executionArn":"fixture","mapRunArn":"fixture","name":"fixture","output":"{}","roleArn":"fixture","stateMachineArn":"fixture","stateMachineAliasArn":"fixture","stateMachineVersionArn":"fixture","resourceArn":"fixture","taskToken":"fixture","routingConfiguration":[],"tags":[],"tagKeys":[]}`)
	default:
		t.Fatalf("unmapped fixture service %q", row.Service)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	type reply struct {
		output any
		err    error
	}
	done := make(chan reply, 1)
	for len(r.clock.timers) != 0 {
		<-r.clock.timers
	}
	for len(r.admitted) != 0 {
		<-r.admitted
	}
	go func() { output, err := awstest.CallSDK(ctx, client, row.Operation, input); done <- reply{output, err} }()
	var result reply
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	syncAdmitted := false
wait:
	for {
		select {
		case result = <-done:
			break wait
		case <-r.admitted:
			syncAdmitted = true
		case at := <-r.clock.timers:
			switch stepFunctionsOperation(row.Operation) {
			case "teststate":
				// Scheduler recovery timers share this clock. They are not
				// evidence that the request owns a Wait, and must never move
				// service time past the captured response into later calls.
				if row.Finished != 0 && !at.After(time.UnixMilli(row.Finished)) {
					r.advance(t, at)
				}
			case "getactivitytask":
				// Wait for the request's documented 60-second poll timer,
				// not an unrelated scheduler timer before API admission.
				// Advance only through the capture, never to a lease expiry.
				if row.Finished != 0 && at.Equal(r.clock.Now().Add(time.Minute)) {
					r.advance(t, time.UnixMilli(row.Finished))
				}
			}
		case <-ticker.C:
			// Standard admission does not await execution. Draining a
			// 25,000-event workflow here can expire the request context
			// after its successful response is already queued.
			if stepFunctionsOperation(row.Operation) == "startsyncexecution" && syncAdmitted {
				if next := r.drain(t); next != nil && row.Finished != 0 && !next.After(time.UnixMilli(row.Finished)) {
					r.advance(t, *next)
				}
			}
		case <-ctx.Done():
			t.Fatalf("SDK replay did not complete: %v", ctx.Err())
		}
	}
	if r.deletionConverged(t, row, result.err) {
		return nil
	}
	if r.encryption != nil && r.encryptionEnvelope(t, row, result.err) {
		return nil
	}
	awsNativeResult(t, row.awsNativeObservation, result.err)
	if r.encryption != nil && (row.Service == "stepfunctions" || row.Service == "") {
		r.compareEncryptionWire(t, row, wire)
	}
	if result.err != nil {
		return nil
	}
	r.drain(t)
	if session, ok := result.output.(*sts.AssumeRoleOutput); ok {
		r.session = aws.Credentials{AccessKeyID: aws.ToString(session.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(session.Credentials.SecretAccessKey), SessionToken: aws.ToString(session.Credentials.SessionToken)}
		if len(r.fixture.Actors) != 0 {
			r.rememberActor(t, row, session)
		}
	}
	return result.output
}

func (r *stepFunctionsNativeReplay) replay(t *testing.T, row stepFunctionsNativeObservation) {
	t.Helper()
	output := r.call(t, row)
	if output == nil {
		return
	}
	if r.encryption != nil && row.Service != "stepfunctions" && row.Service != "" {
		r.compareEncryptionSetup(t, row, output)
		return
	}
	if row.Service != "stepfunctions" && row.Service != "" {
		return
	}
	want := reflect.New(reflect.TypeOf(output).Elem()).Interface()
	if err := awstest.DecodeSDK(row.Result.Output, want); err != nil {
		t.Fatal(err)
	}
	if alias, ok := want.(*sfn.DescribeStateMachineAliasOutput); ok {
		want = r.aliasReadAfterUpdate(t, row, alias, output.(*sfn.DescribeStateMachineAliasOutput))
	}
	if lease, ok := want.(*sfn.GetActivityTaskOutput); ok {
		want = r.activityLease(t, row, lease, output.(*sfn.GetActivityTaskOutput))
	}
	expected, actual := stepFunctionsSDKObject(t, want), stepFunctionsSDKObject(t, output)
	if r.encryption != nil {
		r.encryptionBilling(t, expected, actual)
	}
	if stepFunctionsOperation(row.Operation) == "getexecutionhistory" {
		r.compareHistory(t, expected, actual)
		return
	}
	r.compare(t, "", expected, actual)
}

// Asynchronous deletion may finish before a native DELETING/retained-execution
// sample. Accept only the deleted resource's modeled absence, after an
// acknowledged deletion and before any recreation; never relax pre-delete reads.
func (r *stepFunctionsNativeReplay) deletionConverged(t *testing.T, row stepFunctionsNativeObservation, err error) bool {
	var failure interface{ ErrorCode() string }
	if !errors.As(err, &failure) || failure.ErrorCode() != "StateMachineDoesNotExist" && failure.ErrorCode() != "ExecutionDoesNotExist" {
		return false
	}
	var input struct{ StateMachineArn, StateMachineAliasArn, ExecutionArn string }
	awsDecodeJSON(t, row.Input, &input)
	arn := input.StateMachineArn
	if arn == "" {
		arn = input.StateMachineAliasArn
	}
	if arn == "" {
		arn = input.ExecutionArn
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 7 || parts[5] != "execution" && parts[5] != "stateMachine" {
		return false
	}
	machine := strings.Join(parts[:5], ":") + ":stateMachine:" + parts[6]
	deleted := false
	for _, prior := range r.fixture.Observations {
		if prior.Label == row.Label && prior.Started == row.Started {
			break
		}
		if prior.Result.Code != "Success" {
			continue
		}
		switch stepFunctionsOperation(prior.Operation) {
		case "deletestatemachine":
			var request struct{ StateMachineArn string }
			awsDecodeJSON(t, prior.Input, &request)
			if request.StateMachineArn == machine {
				deleted = true
			}
		case "createstatemachine":
			var response struct{ StateMachineArn string }
			awsDecodeJSON(t, prior.Result.Output, &response)
			if response.StateMachineArn == machine {
				deleted = false
			}
		}
	}
	return deleted
}

// An immediate alias read may observe the captured old configuration or the
// latest acknowledged update. Require one complete configuration, never mixed
// fields or a particular propagation delay. Later settled reads remain exact.
// https://docs.aws.amazon.com/step-functions/latest/apireference/API_UpdateStateMachineAlias.html
func (r *stepFunctionsNativeReplay) aliasReadAfterUpdate(t *testing.T, row stepFunctionsNativeObservation, native, actual *sfn.DescribeStateMachineAliasOutput) *sfn.DescribeStateMachineAliasOutput {
	t.Helper()
	updated := *native
	for _, prior := range r.fixture.Observations {
		if prior.Label == row.Label {
			break
		}
		if stepFunctionsOperation(prior.Operation) != "updatestatemachinealias" || prior.Result.Code != "Success" {
			continue
		}
		var input sfn.UpdateStateMachineAliasInput
		if err := awstest.DecodeSDK(prior.Input, &input); err != nil {
			t.Fatal(err)
		}
		if aws.ToString(input.StateMachineAliasArn) != aws.ToString(native.StateMachineAliasArn) {
			continue
		}
		if input.Description != nil {
			updated.Description = input.Description
			if *input.Description == "" {
				updated.Description = nil
			}
		}
		if input.RoutingConfiguration != nil {
			updated.RoutingConfiguration = input.RoutingConfiguration
		}
		var output sfn.UpdateStateMachineAliasOutput
		if err := awstest.DecodeSDK(prior.Result.Output, &output); err != nil {
			t.Fatal(err)
		}
		updated.UpdateDate = output.UpdateDate
	}
	if reflect.DeepEqual(updated.Description, actual.Description) && reflect.DeepEqual(updated.RoutingConfiguration, actual.RoutingConfiguration) {
		return &updated
	}
	return native
}

func stepFunctionsSDKObject(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := awstest.MarshalSDK(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	awsDecodeJSON(t, encoded, &object)
	delete(object, "ResultMetadata")
	return object
}

// SDK normalization removes wire-only __type markers and retains modeled
// presence. JSON-valued data is compared structurally, but Definition remains
// byte-exact: native CreateStateMachine identity is sensitive to its spelling.
func (r *stepFunctionsNativeReplay) compare(t *testing.T, path string, want, got any) {
	t.Helper()
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("%s: native object, local %T", path, got)
		}
		if strings.Contains(path, "(JSON)") && len(expected) != len(actual) {
			t.Fatalf("%s: native JSON keys %v, local %v", path, expected, actual)
		}
		r.bindContext(t, expected, actual)
		keys := make([]string, 0, len(expected))
		for key := range expected {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if key == "RedriveStatusReason" || key == "Message" && strings.Contains(path, ".Diagnostics") {
				continue
			}
			// AWS exposes its JSON parser's Java exception text here, not an
			// ASL location. Preserve the invalid-JSON code and severity only.
			if key == "Location" && expected["Code"] == "INVALID_JSON_DESCRIPTION" {
				continue
			}
			if key == "Definition" && expected["Label"] != nil {
				// A labelled Map exposes a generated processor definition, not
				// the caller's source spelling used by Create idempotency.
				r.compare(t, path+".GeneratedDefinition", expected[key], actual[key])
				continue
			}
			if key == "Cause" {
				if r.encryption != nil && r.compareKMSCause(t, expected[key], actual[key]) {
					continue
				}
				if name, _ := expected["Error"].(string); strings.HasPrefix(name, "States.") {
					continue
				}
			}
			// Describe observations can omit a newly-visible optional revision
			// or update time. Returned values, when captured, remain bound.
			if expected[key] == nil && (key == "RevisionId" || key == "UpdateDate" || key == "VariableReferences") {
				continue
			}
			r.compare(t, path+"."+key, expected[key], actual[key])
		}
	case []any:
		actual, ok := got.([]any)
		if !ok && len(expected) == 0 && got == nil {
			return
		}
		if !ok || len(expected) != len(actual) {
			t.Fatalf("%s: native %d entries, local %d entries (%T)", path, len(expected), len(actual), got)
		}
		if strings.HasSuffix(path, ".Tags") || strings.HasSuffix(path, ".Diagnostics") {
			key := func(value any) string { data, _ := json.Marshal(value); return string(data) }
			if strings.HasSuffix(path, ".Diagnostics") {
				for _, values := range [][]any{expected, actual} {
					for _, value := range values {
						if object, ok := value.(map[string]any); ok {
							delete(object, "Message")
						}
					}
				}
			}
			slices.SortFunc(expected, func(a, b any) int { return strings.Compare(key(a), key(b)) })
			slices.SortFunc(actual, func(a, b any) int { return strings.Compare(key(a), key(b)) })
		}
		for i := range expected {
			r.compare(t, fmt.Sprintf("%s[%d]", path, i), expected[i], actual[i])
		}
	case string:
		actual, ok := got.(string)
		if !ok {
			t.Fatalf("%s: native %q, local %v", path, expected, got)
		}
		if expected == "" {
			if actual != "" {
				t.Fatalf("%s: native empty, local %q", path, actual)
			}
			return
		}
		if stepFunctionsTimestampPath(path) {
			wantTime, wantErr := time.Parse(time.RFC3339Nano, expected)
			gotTime, gotErr := time.Parse(time.RFC3339Nano, actual)
			if wantErr != nil || gotErr != nil || gotTime.After(r.clock.Now()) {
				t.Fatalf("%s: invalid timestamp binding: native %q, local %q", path, expected, actual)
			}
			nativeStamp := wantTime.UTC().Round(time.Millisecond).Format(time.RFC3339Nano)
			localStamp := gotTime.UTC().Round(time.Millisecond)
			if prior, found := r.timestamps[nativeStamp]; found {
				priorTime, _ := time.Parse(time.RFC3339Nano, prior)
				// Smithy's epoch decoder multiplies float64 seconds then floors
				// milliseconds. JSON context strings retain the exact instant;
				// comparing the two can therefore lose one millisecond.
				if delta := localStamp.Sub(priorTime); delta >= -time.Millisecond && delta <= time.Millisecond {
					return
				}
			}
			r.bind(t, r.timestamps, nativeStamp, localStamp.Format(time.RFC3339Nano), false)
			return
		}
		if strings.HasSuffix(path, ".RevisionId") || strings.HasSuffix(path, ".NextToken") || strings.HasSuffix(path, ".TaskToken") {
			if expected != actual {
				r.bind(t, r.bindings, expected, actual, true)
			}
			return
		}
		if strings.Contains(expected, ":express:") && strings.HasSuffix(path, ".ExecutionArn") && r.bindings[expected] == "" {
			nativeParts, localParts := strings.Split(expected, ":"), strings.Split(actual, ":")
			if len(nativeParts) != len(localParts) || strings.Join(nativeParts[:len(nativeParts)-1], ":") != strings.Join(localParts[:len(localParts)-1], ":") || !stepFunctionsContextUUID.MatchString(localParts[len(localParts)-1]) {
				t.Fatalf("%s: invalid generated execution ARN: native %q, local %q", path, expected, actual)
			}
			r.bind(t, r.bindings, expected, actual, true)
			return
		}
		expected = r.boundString(expected)
		if expected == actual {
			return
		}
		if !strings.HasSuffix(path, ".Definition") && json.Valid([]byte(expected)) {
			var a, b any
			awsDecodeJSON(t, json.RawMessage(expected), &a)
			awsDecodeJSON(t, json.RawMessage(actual), &b)
			r.compare(t, path+"(JSON)", a, b)
			return
		}
		if expected != actual {
			t.Fatalf("%s differs\nnative: %s\nlocal:  %s", path, expected, actual)
		}
	default:
		if want == nil {
			if values, ok := got.([]any); ok && len(values) == 0 {
				return
			}
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: native %v, local %v", path, want, got)
		}
	}
}

func stepFunctionsTimestampPath(path string) bool {
	for _, field := range []string{"CreationDate", "UpdateDate", "StartDate", "StopDate", "Timestamp", "StartTime", "EnteredTime", "RedriveDate", "RedriveTime"} {
		if strings.HasSuffix(path, "."+field) {
			return true
		}
	}
	return false
}

func (r *stepFunctionsNativeReplay) bind(t *testing.T, bindings map[string]string, native, local string, unique bool) {
	t.Helper()
	if local == "" {
		t.Fatalf("generated binding for %q is empty", native)
	}
	if prior, ok := bindings[native]; ok {
		if prior != local {
			t.Fatalf("binding changed for %q: %q -> %q", native, prior, local)
		}
		return
	}
	if unique {
		for other, bound := range bindings {
			if other != native && bound == local {
				t.Fatalf("distinct native values %q and %q collapsed to %q", other, native, local)
			}
		}
	}
	bindings[native] = local
}

var stepFunctionsContextUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (r *stepFunctionsNativeReplay) bindContext(t *testing.T, want, got map[string]any) {
	t.Helper()
	native, _ := want["Id"].(string)
	parts := strings.Split(native, ":")
	if len(parts) < 7 || !stepFunctionsContextUUID.MatchString(parts[6]) {
		return
	}
	if parts[5] != "stateMachine" && parts[5] != "express" {
		return
	}
	local, _ := got["Id"].(string)
	actual := strings.Split(local, ":")
	if len(actual) != len(parts) || strings.Join(parts[:6], ":") != strings.Join(actual[:6], ":") {
		t.Fatalf("synthetic context ARN differs: native %q, local %q", native, local)
	}
	for index := 6; index < len(parts); index++ {
		if !stepFunctionsContextUUID.MatchString(actual[index]) {
			t.Fatalf("invalid synthetic context UUID in %q", local)
		}
		r.bind(t, r.bindings, parts[index], actual[index], true)
	}
	r.bind(t, r.bindings, native, local, true)
}

// History IDs are presentation order across concurrent branches. Compare each
// event's data and its complete predecessor chain, sorting independent chains;
// this preserves causality without requiring one native goroutine interleaving.
func (r *stepFunctionsNativeReplay) compareHistory(t *testing.T, want, got map[string]any) {
	t.Helper()
	for label, object := range map[string]map[string]any{"native": want, "local": got} {
		var trace []string
		events, _ := object["Events"].([]any)
		for _, raw := range events {
			event := raw.(map[string]any)
			trace = append(trace, fmt.Sprintf("%v:%v<-%v", event["Id"], event["Type"], event["PreviousEventId"]))
		}
		t.Logf("%s history: %s", label, strings.Join(trace, " "))
	}
	canonical := func(object map[string]any) []any {
		events, _ := object["Events"].([]any)
		byID := map[float64]map[string]any{}
		var redrives []float64
		for _, raw := range events {
			event := raw.(map[string]any)
			id, _ := event["Id"].(float64)
			previous, _ := event["PreviousEventId"].(float64)
			if id <= 0 || previous < 0 || previous >= id || byID[id] != nil {
				t.Fatalf("invalid history causality: %+v", event)
			}
			byID[id] = event
			if event["Type"] == "ExecutionRedriven" {
				redrives = append(redrives, id)
			}
		}
		slices.Sort(redrives)
		var signature func(float64) string
		cache := map[float64]string{0: "root"}
		compoundScopes := map[float64][]float64{}
		signature = func(id float64) string {
			if value, ok := cache[id]; ok {
				return value
			}
			event := byID[id]
			if event == nil {
				// A paginated history can begin after its predecessor. Retain
				// that external event ID instead of inventing a missing event.
				return fmt.Sprintf("external:%v", id)
			}
			previous, _ := event["PreviousEventId"].(float64)
			parent := signature(previous)
			scope := compoundScopes[previous]
			compoundScopes[id] = scope
			switch event["Type"] {
			case "ParallelStateStarted", "MapStateStarted":
				compoundScopes[id] = append(slices.Clone(scope), id)
			case "ParallelStateSucceeded", "ParallelStateExited", "MapStateSucceeded", "MapStateExited":
				if len(scope) != 0 {
					// Native joins name whichever child finished last.
					// Keep each branch's complete chain, but bind the join
					// to its owning barrier rather than a scheduling winner.
					started := scope[len(scope)-1]
					if event["Type"] == "ParallelStateExited" || event["Type"] == "MapStateExited" {
						entry := byID[byID[started]["PreviousEventId"].(float64)]
						if entry != nil && event["StateExitedEventDetails"].(map[string]any)["Name"] != entry["StateEnteredEventDetails"].(map[string]any)["Name"] {
							t.Fatal("compound exit does not belong to its causal scope")
						}
					}
					parent = signature(started)
					compoundScopes[id] = scope[:len(scope)-1]
				}
			case "ParallelStateFailed", "ParallelStateAborted", "MapStateFailed", "MapStateAborted":
				if len(scope) != 0 {
					compoundScopes[id] = scope[:len(scope)-1]
				}
			}
			data := map[string]any{"Type": event["Type"], "Parent": parent}
			if len(redrives) != 0 {
				// Redrive schedules a new attempt from the original state entry,
				// not from ExecutionRedriven. Its predecessor chain can therefore
				// equal an earlier attempt's chain. Preserve the chronological
				// generation so sorting never pairs their distinct worker leases.
				generation, marker := slices.BinarySearch(redrives, id)
				if marker {
					generation++
				}
				data["RedriveGeneration"] = generation
			}
			for _, field := range []string{"StateEnteredEventDetails", "StateExitedEventDetails", "MapIterationStartedEventDetails", "MapIterationSucceededEventDetails", "MapIterationFailedEventDetails"} {
				if details, ok := event[field].(map[string]any); ok {
					data[field] = map[string]any{"Name": details["Name"], "Index": details["Index"]}
				}
			}
			encoded, _ := json.Marshal(data)
			cache[id] = fmt.Sprintf("%x", sha256.Sum256(encoded))
			return cache[id]
		}
		out := make([]any, 0, len(events))
		for _, raw := range events {
			event := raw.(map[string]any)
			id := event["Id"].(float64)
			event["CausalIdentity"] = signature(id)
			// Timestamp latency is not replayed. Causal predecessors above
			// and the stable execution timestamps are checked independently.
			delete(event, "Timestamp")
			out = append(out, event)
		}
		slices.SortFunc(out, func(a, b any) int {
			return strings.Compare(a.(map[string]any)["CausalIdentity"].(string), b.(map[string]any)["CausalIdentity"].(string))
		})
		for _, raw := range out {
			event := raw.(map[string]any)
			delete(event, "Id")
			delete(event, "PreviousEventId")
		}
		return out
	}
	r.compare(t, ".Events", canonical(want), canonical(got))
	r.compare(t, ".NextToken", want["NextToken"], got["NextToken"])
}

func stepFunctionsLocalEndpoint(stack *middleware.Stack) error {
	return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("LocalSFNEndpoint", func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
		return next.HandleInitialize(smithyhttp.DisableEndpointHostPrefix(ctx, true), in)
	}), middleware.Before)
}

func newStepFunctionsNativeReplay(t *testing.T, fixture stepFunctionsNativeFixture, backend string) *stepFunctionsNativeReplay {
	t.Helper()
	start := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	for _, row := range fixture.Observations {
		if row.Started != 0 {
			start = time.UnixMilli(row.Started)
			break
		}
	}
	source := &stepFunctionsReplayClock{Manual: clock.NewManual(start), timers: make(chan time.Time, 256)}
	admitted := make(chan struct{}, 1)
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		config.Storage.StepFunctions = stepFunctionsReplayRepository{Repository: config.Storage.StepFunctions, admitted: admitted}
		return startPublicCloud(t, config)
	})
	r := &stepFunctionsNativeReplay{fixture: fixture, clients: clients, reopen: reopen, clock: source, admitted: admitted,
		identity: aws.Credentials{AccessKeyID: fixture.Account, SecretAccessKey: "test"},
		bindings: map[string]string{}, timestamps: map[string]string{}}
	callerARN := fixture.CallerARN
	if callerARN == "" {
		for _, row := range fixture.Observations {
			if stepFunctionsOperation(row.Operation) == "getcalleridentity" {
				var actor struct{ Arn string }
				awsDecodeJSON(t, row.Result.Output, &actor)
				callerARN = actor.Arn
				break
			}
		}
	}
	// Preserve the captured principal in trust documents; credentials
	// always come from the local IAM/STS APIs, never native fixtures.
	if _, user, ok := strings.Cut(callerARN, ":user/"); ok {
		_, key, secret := clients.user(t, fixture.Account, user)
		putUserPolicy(t, clients.iam(fixture.Account, "test", ""), user, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
		r.identity = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
	}
	if len(fixture.Actors) != 0 {
		r.prepareEncryption(t)
	}
	return r
}

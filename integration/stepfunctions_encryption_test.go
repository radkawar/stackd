package stackd_test

import (
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/internal/awstest"
)

type stepFunctionsNativeActor struct {
	RoleName         string          `json:"role_name"`
	RoleARN          string          `json:"role_arn"`
	TrustPolicy      json.RawMessage `json:"trust_policy"`
	InlinePolicy     json.RawMessage `json:"inline_policy"`
	InlinePolicyName string          `json:"inline_policy_name"`
	SessionPolicy    json.RawMessage `json:"session_policy"`
	AssumeRoleInput  json.RawMessage `json:"assume_role_input"`
	SessionName      string          `json:"session_name"`
	SessionARN       string          `json:"session_arn"`
	Identity         struct{ Arn string }
}

type stepFunctionsEncryptionReplay struct {
	rejectedExecutions map[string]bool
	recovered          map[string]bool
}

func TestStepFunctionsNativeEncryptionAdmission(t *testing.T) {
	stepFunctionsNativeRun(t, "encryption_admission", false, stepFunctionsEncryptionInclude(t))
}

func TestStepFunctionsNativeEncryptionExecution(t *testing.T) {
	stepFunctionsNativeRun(t, "encryption_execution", false, stepFunctionsEncryptionInclude(t))
}

func stepFunctionsEncryptionInclude(t *testing.T) func(stepFunctionsNativeObservation) bool {
	return func(row stepFunctionsNativeObservation) bool {
		// CLI validation is not a service observation. The separate signed-wire
		// rows retain the same invalid shapes, including explicit JSON nulls.
		if row.Result.Code == "CLIError" {
			t.Logf("%s: client-side validation; no native HTTP request to replay", row.Label)
			return false
		}
		// Scoped CloudTrail records corroborate authority/context in the capture,
		// but its delayed account audit index is not a Step Functions response.
		if row.Service == "cloudtrail" {
			t.Logf("%s: retained native audit provenance, not a workflow API assertion", row.Label)
			return false
		}
		return true
	}
}

// Bind inside JSON-valued policy strings as well as ordinary fields. Replacing
// only complete field values leaves IAM and STS policies pointing at native keys.
// Longest-first replacement keeps a key ARN and its contained ID consistent.
func (r *stepFunctionsNativeReplay) boundString(value string) string {
	if bound, ok := r.bindings[value]; ok {
		return bound
	}
	var keys []string
	for native := range r.bindings {
		if strings.Contains(value, native) {
			keys = append(keys, native)
		}
	}
	slices.SortFunc(keys, func(a, b string) int { return len(b) - len(a) })
	pairs := make([]string, 0, 2*len(keys))
	for _, native := range keys {
		pairs = append(pairs, native, r.bindings[native])
	}
	if len(pairs) == 0 {
		return value
	}
	return strings.NewReplacer(pairs...).Replace(value)
}

func (r *stepFunctionsNativeReplay) prepareEncryption(t *testing.T) {
	t.Helper()
	r.sessions = map[string]aws.Credentials{}
	r.encryption = &stepFunctionsEncryptionReplay{rejectedExecutions: map[string]bool{}, recovered: map[string]bool{}}
	created, installed := map[string]bool{}, map[string]bool{}
	for _, row := range r.fixture.Observations {
		var input struct{ RoleName string }
		awsDecodeJSON(t, row.Input, &input)
		switch stepFunctionsOperation(row.Operation) {
		case "createrole":
			created[input.RoleName] = true
		case "putrolepolicy":
			installed[input.RoleName] = true
		}
	}
	// Admission resumed after an interrupted CreateRole. Reconstruct only that
	// missing setup from the captured trust policy, leaving its policy absent
	// until the recorded PutRolePolicy (the preceding NoSuchEntity is asserted).
	for name, actor := range r.fixture.Actors {
		if name == "default" || actor.RoleName == "" || created[actor.RoleName] {
			continue
		}
		out, err := r.clients.iam(r.identity.AccessKeyID, r.identity.SecretAccessKey, "").CreateRole(t.Context(), &iam.CreateRoleInput{
			RoleName: aws.String(actor.RoleName), AssumeRolePolicyDocument: aws.String(string(actor.TrustPolicy)),
		})
		if err != nil {
			t.Fatalf("bootstrap captured role %s: %v", name, err)
		}
		if aws.ToString(out.Role.Arn) != actor.RoleARN || !installed[actor.RoleName] {
			t.Fatalf("incomplete setup provenance for actor %s", name)
		}
	}
}

func (r *stepFunctionsNativeReplay) actorForRole(role string) (string, stepFunctionsNativeActor, bool) {
	for name, actor := range r.fixture.Actors {
		if role != "" && (actor.RoleARN == role || actor.RoleName == role) {
			return name, actor, true
		}
	}
	return "", stepFunctionsNativeActor{}, false
}

func (r *stepFunctionsNativeReplay) rememberActor(t *testing.T, row stepFunctionsNativeObservation, output *sts.AssumeRoleOutput) {
	t.Helper()
	var input struct{ RoleArn string }
	awsDecodeJSON(t, row.Input, &input)
	name, actor, ok := r.actorForRole(input.RoleArn)
	if !ok || output.Credentials == nil || output.AssumedRoleUser == nil {
		t.Fatalf("cannot bind captured session for %s", input.RoleArn)
	}
	arn := actor.SessionARN
	if arn == "" {
		arn = actor.Identity.Arn
	}
	if arn == "" || arn != aws.ToString(output.AssumedRoleUser.Arn) {
		t.Fatalf("%s: local session ARN does not match actor provenance", name)
	}
	r.sessions[name] = r.session
}

func (r *stepFunctionsNativeReplay) compareEncryptionSetup(t *testing.T, row stepFunctionsNativeObservation, output any) {
	t.Helper()
	actual := stepFunctionsSDKObject(t, output)
	var expected map[string]any
	if row.Service == "iam" {
		// AWS CLI decodes URL-encoded policy documents to JSON objects,
		// whereas the Go SDK exposes their original string representation.
		awsDecodeJSON(t, row.Result.Output, &expected)
	} else {
		want := reflect.New(reflect.TypeOf(output).Elem()).Interface()
		if err := awstest.DecodeSDK(row.Result.Output, want); err != nil {
			t.Fatal(err)
		}
		expected = stepFunctionsSDKObject(t, want)
	}
	switch row.Service {
	case "kms":
		if native, ok := expected["KeyMetadata"].(map[string]any); ok {
			local, ok := actual["KeyMetadata"].(map[string]any)
			if !ok {
				t.Fatal("KMS response omitted key metadata")
			}
			if stepFunctionsOperation(row.Operation) == "createkey" {
				for _, field := range []string{"KeyId", "Arn"} {
					r.bind(t, r.bindings, native[field].(string), local[field].(string), true)
				}
			}
			// Material identity is opaque KMS provenance, not workflow behavior.
			delete(native, "CurrentKeyMaterialId")
			delete(local, "CurrentKeyMaterialId")
			r.compareKeyDeletionDate(t, native, local)
		}
		r.compareKeyDeletionDate(t, expected, actual)
		r.compare(t, "", expected, actual)
		if stepFunctionsOperation(row.Operation) == "createalias" {
			r.bindKeyAlias(t, row)
		}
	case "sts":
		if stepFunctionsOperation(row.Operation) == "assumerole" {
			// Credentials and policy-compression size are provider-generated;
			// the exact captured boundary was supplied to the real STS call.
			expected = expected["AssumedRoleUser"].(map[string]any)
			actual = actual["AssumedRoleUser"].(map[string]any)
			r.bind(t, r.bindings, expected["AssumedRoleId"].(string), actual["AssumedRoleId"].(string), true)
		} else if stepFunctionsOperation(row.Operation) == "getcalleridentity" {
			r.bind(t, r.bindings, expected["UserId"].(string), actual["UserId"].(string), true)
		}
		r.compare(t, "", expected, actual)
	case "iam":
		if native, ok := expected["Role"].(map[string]any); ok {
			local := actual["Role"].(map[string]any)
			r.bind(t, r.bindings, native["RoleId"].(string), local["RoleId"].(string), true)
			for _, field := range []string{"Arn", "RoleName", "RoleId", "Path"} {
				r.compare(t, "."+field, native[field], local[field])
			}
			r.compareRolePolicy(t, native["AssumeRolePolicyDocument"], local["AssumeRolePolicyDocument"])
		} else if stepFunctionsOperation(row.Operation) == "getrolepolicy" {
			r.compare(t, ".RoleName", expected["RoleName"], actual["RoleName"])
			r.compare(t, ".PolicyName", expected["PolicyName"], actual["PolicyName"])
			r.compareRolePolicy(t, expected["PolicyDocument"], actual["PolicyDocument"])
		}
	}
}

func (r *stepFunctionsNativeReplay) compareRolePolicy(t *testing.T, expected, actual any) {
	t.Helper()
	decode := func(value any) any {
		if object, ok := value.(map[string]any); ok {
			return object
		}
		text, ok := value.(string)
		if !ok {
			t.Fatalf("missing policy document: %v", value)
		}
		if !json.Valid([]byte(text)) {
			var err error
			text, err = url.QueryUnescape(text)
			if err != nil {
				t.Fatal(err)
			}
		}
		var object any
		awsDecodeJSON(t, json.RawMessage(text), &object)
		return object
	}
	r.compare(t, ".Policy(JSON)", decode(expected), decode(actual))
}

func (r *stepFunctionsNativeReplay) compareKeyDeletionDate(t *testing.T, expected, actual map[string]any) {
	t.Helper()
	if expected["DeletionDate"] == nil {
		return
	}
	stamp, ok := actual["DeletionDate"].(string)
	at, err := time.Parse(time.RFC3339Nano, stamp)
	// DescribeKey may follow scheduling later in the capture. Preserve a
	// pending seven-day window without pinning provider day-rounding.
	if !ok || err != nil || at.Before(r.clock.Now().Add(6*24*time.Hour)) || at.After(r.clock.Now().Add(8*24*time.Hour)) {
		t.Fatalf("invalid seven-day KMS deletion window: %v", actual["DeletionDate"])
	}
	delete(expected, "DeletionDate")
	delete(actual, "DeletionDate")
}

func (r *stepFunctionsNativeReplay) bindKeyAlias(t *testing.T, row stepFunctionsNativeObservation) {
	t.Helper()
	var input struct{ AliasName, TargetKeyId string }
	awsDecodeJSON(t, row.Input, &input)
	out, err := r.clients.kmsRegion(row.Region, r.identity.AccessKeyID, r.identity.SecretAccessKey, "").ListAliases(t.Context(), &kms.ListAliasesInput{KeyId: aws.String(r.boundString(input.TargetKeyId))})
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range out.Aliases {
		if aws.ToString(alias.AliasName) == input.AliasName {
			if aws.ToString(alias.TargetKeyId) != r.boundString(input.TargetKeyId) {
				t.Fatal("alias does not resolve to the SDK-created key")
			}
			r.bind(t, r.bindings, input.AliasName, aws.ToString(alias.AliasName), true)
			r.bind(t, r.bindings, "arn:aws:kms:"+row.Region+":"+r.fixture.Account+":"+input.AliasName, aws.ToString(alias.AliasArn), true)
			return
		}
	}
	t.Fatal("SDK-created KMS alias is missing")
}

func (r *stepFunctionsNativeReplay) recoverEncryption(t *testing.T, row stepFunctionsNativeObservation) {
	t.Helper()
	switch row.Label {
	case "standard-allow-cold-history", "start-retained-old-execution", "delivery-caller-activity-only":
		if !r.encryption.recovered[row.Label] {
			r.encryption.recovered[row.Label] = true
			r.clients = r.reopen()
			r.drain(t)
			t.Log("reopened retained encrypted resources; subsequent SDK reads/callbacks must recover wrapped keys")
		}
	}
}

// https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
// Reuse is a maximum bound, not a promise that a particular worker or caller
// shares AWS's data-key cache. Keep cold/expired probes exact. For these two
// warm observations, either real admission or the precise KMS denial is valid.
func (r *stepFunctionsNativeReplay) encryptionEnvelope(t *testing.T, row stepFunctionsNativeObservation, err error) bool {
	t.Helper()
	code := ""
	switch row.Label {
	case "express-allow-caller-no-kms-start":
		code = "KmsAccessDeniedException"
	case "standard-disabled-warm-start":
		code = "KmsInvalidStateException"
	default:
		return false
	}
	t.Logf("documented cache guarantee envelope: captured %s; local must admit or return %s", row.Result.Code, code)
	if err == nil {
		return false
	}
	assertAPIError(t, err, code)
	var response interface{ HTTPStatusCode() int }
	if !errors.As(err, &response) || response.HTTPStatusCode() != 400 {
		t.Fatalf("cache-envelope rejection is not modeled HTTP 400: %v", err)
	}
	if code == "KmsInvalidStateException" {
		var invalid *sfntypes.KmsInvalidStateException
		if !errors.As(err, &invalid) || string(invalid.KmsKeyState) != "DISABLED" {
			t.Fatalf("missing modeled disabled-key rejection: %v", err)
		}
	}
	if stepFunctionsOperation(row.Operation) == "startexecution" {
		var native struct{ ExecutionArn string }
		awsDecodeJSON(t, row.Result.Output, &native)
		r.encryption.rejectedExecutions[native.ExecutionArn] = true
		// Prove rejection did not admit an execution, even if later native
		// observations happen only after the resource has been deleted.
		probe := row
		probe.Operation, probe.Actor = "describe-execution", "default"
		probe.Input, _ = json.Marshal(map[string]string{"executionArn": native.ExecutionArn, "includedData": "METADATA_ONLY"})
		probe.Result.Code, probe.Result.HTTPStatus = "ExecutionDoesNotExist", 400
		probe.Result.Output = nil
		probe.Label += "-rejected-without-effects"
		r.call(t, probe)
	}
	return true
}

func (r *stepFunctionsNativeReplay) encryptionExpectation(t *testing.T, row stepFunctionsNativeObservation) stepFunctionsNativeObservation {
	var input struct{ ExecutionArn string }
	awsDecodeJSON(t, row.Input, &input)
	if r.encryption.rejectedExecutions[input.ExecutionArn] {
		t.Log("cache guarantee envelope: rejected admission must remain absent, not synthesize the captured execution")
		row.Result.Code, row.Result.HTTPStatus = "ExecutionDoesNotExist", 400
		row.Result.Output = nil
	}
	return row
}

func (r *stepFunctionsNativeReplay) compareEncryptionWire(t *testing.T, row stepFunctionsNativeObservation, wire *awstest.WireClient) {
	t.Helper()
	if row.Result.HTTPStatus != 0 && wire.Status != row.Result.HTTPStatus {
		t.Fatalf("native HTTP %d, local HTTP %d", row.Result.HTTPStatus, wire.Status)
	}
	if row.Result.Code == "Success" || len(row.Result.Output) == 0 {
		return
	}
	var expected, actual map[string]any
	awsDecodeJSON(t, row.Result.Output, &expected)
	awsDecodeJSON(t, wire.Body, &actual)
	// boto3's signed-wire probes retain its synthetic Error wrapper alongside
	// native modeled members. Code and HTTP status are checked separately.
	for key, value := range expected {
		if key != "__type" && key != "Error" && !strings.EqualFold(key, "message") {
			r.compare(t, "."+key, value, actual[key])
		}
	}
}

func (r *stepFunctionsNativeReplay) encryptionBilling(t *testing.T, expected, actual map[string]any) {
	native, ok := expected["BillingDetails"].(map[string]any)
	if !ok {
		return
	}
	local, ok := actual["BillingDetails"].(map[string]any)
	if !ok {
		t.Fatal("sync response omitted billing details")
	}
	start, startErr := time.Parse(time.RFC3339Nano, actual["StartDate"].(string))
	stop, stopErr := time.Parse(time.RFC3339Nano, actual["StopDate"].(string))
	duration, ok := local["BilledDurationInMilliseconds"].(float64)
	minimum := math.Ceil(float64(stop.Sub(start).Milliseconds())/100) * 100
	if minimum < 100 {
		minimum = 100
	}
	if !ok || startErr != nil || stopErr != nil || stop.Before(start) || math.Mod(duration, 100) != 0 || duration < minimum || duration > minimum+100 {
		t.Fatalf("sync billing is outside the documented 100ms rounding envelope: %v", local)
	}
	// Native processing may cross a billing quantum; memory and all other
	// response fields still compare, but provider latency is not an oracle.
	native["BilledDurationInMilliseconds"] = duration
}

var stepFunctionsKMSCauseARN = regexp.MustCompile(`arn:aws:(?:kms|sts|iam):[A-Za-z0-9:/_-]+`)

func (r *stepFunctionsNativeReplay) compareKMSCause(t *testing.T, expected, actual any) bool {
	native, ok := expected.(string)
	if !ok || !strings.Contains(native, "Service: Kms") {
		return false
	}
	local, ok := actual.(string)
	if !ok || local == "" {
		t.Fatal("KMS runtime failure omitted cause")
	}
	// Do not pin SDK prose, UUID request IDs, retry counts or assumed-role
	// session names. Require the failure class; immutable actor policies and
	// the surrounding resource-specific success/denial controls prove authority.
	// If a cause names a key, it must not identify a different resource.
	lower := strings.ToLower(local)
	if strings.Contains(native, "is disabled") {
		if !strings.Contains(lower, "disabled") && !strings.Contains(lower, "invalidstate") {
			t.Fatalf("KMS runtime cause lost disabled-key failure class: %s", local)
		}
	} else {
		if !strings.Contains(lower, "denied") && !strings.Contains(lower, "not authorized") {
			t.Fatalf("KMS runtime cause lost authorization failure class: %s", local)
		}
	}
	for _, localARN := range stepFunctionsKMSCauseARN.FindAllString(local, -1) {
		if !strings.Contains(localARN, ":kms:") {
			continue
		}
		found := false
		for _, nativeARN := range stepFunctionsKMSCauseARN.FindAllString(native, -1) {
			found = found || localARN == r.boundString(nativeARN)
		}
		if !found {
			t.Fatalf("KMS runtime cause identifies the wrong key: %s", local)
		}
	}
	return true
}

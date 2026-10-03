package stackd_test

import (
	"cmp"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/xray"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type xrayNativeObservation struct {
	awsNativeObservation
	RawResponse string `json:"raw_response_body"`
}

type xrayNativeStream struct {
	Region, Prefix        string
	Observations, Cleanup []xrayNativeObservation
}

type xrayNativeFixture struct {
	xrayNativeStream
	AlternateRegionCapture struct{ Region string } `json:"alternate_region_capture"`
	PolicyBoundaries       xrayNativeStream        `json:"policy_boundaries"`
	PrincipalBinding       xrayNativeStream        `json:"principal_binding"`
	SegmentBoundaries      struct {
		Observation, Retrieval xrayNativeObservation
	} `json:"segment_boundaries"`
	AssemblyCaptures []xrayNativeStream `json:"assembly_captures"`
}

func (c cloudClients) xrayRegion(region, key, secret, token string) *xray.Client {
	return xray.New(xray.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestXRayNativeSegmentsAndPolicies(t *testing.T) {
	var fixture xrayNativeFixture
	awsReadFixture(t, "xray/segments_and_policies.json", &fixture)
	policies := xrayNativeStream{Region: fixture.Region, Prefix: fixture.Prefix, Cleanup: fixture.Cleanup}
	traces := xrayNativeStream{Region: fixture.AlternateRegionCapture.Region}
	for _, row := range fixture.Observations {
		switch row.Operation {
		case "put-resource-policy", "list-resource-policies", "delete-resource-policy":
			policies.Observations = append(policies.Observations, row)
		case "put-trace-segments", "batch-get-traces":
			// Transaction Search is a different destination, not an empty-trace
			// oracle for the classic X-Ray data plane exercised here.
			if row.Region == traces.Region {
				traces.Observations = append(traces.Observations, row)
			}
		}
	}
	traces.Observations = append(traces.Observations, fixture.SegmentBoundaries.Observation, fixture.SegmentBoundaries.Retrieval)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range []struct {
			name   string
			stream xrayNativeStream
		}{
			{"segments", traces},
			{"policy-revisions", policies},
			{"policy-principals-and-lockout", fixture.PolicyBoundaries},
			{"resource-grant-without-identity-permission", fixture.PrincipalBinding},
		} {
			t.Run(backend+"/"+scenario.name, func(t *testing.T) {
				replayXRayNative(t, backend, scenario.stream)
			})
		}
		for _, stream := range fixture.AssemblyCaptures {
			t.Run(backend+"/"+stream.Prefix, func(t *testing.T) {
				replayXRayNative(t, backend, stream)
			})
		}
	}
}

func replayXRayNative(t *testing.T, backend string, stream xrayNativeStream) {
	t.Helper()
	rows := append(slices.Clone(stream.Observations), stream.Cleanup...)
	first := rows[0]
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "xray.sqlite"))
	}
	source := clock.NewManual(time.UnixMilli(first.Started).UTC())
	_, clients, _ := startEventDeliveryCloud(t, backends, source)
	_, user, _ := strings.Cut(first.ActorARN, ":user/")
	arn, key, secret := clients.user(t, first.Account, user)
	putUserPolicy(t, clients.iam(first.Account, "test", ""), user, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	identities := map[string]aws.Credentials{arn: {AccessKeyID: key, SecretAccessKey: secret}}
	wire := &awstest.WireClient{Client: clients.server.Client()}
	for index, row := range rows {
		// Compare the last sample of a read-only phase for this exact caller,
		// region and input. Captured visibility delay is not a fixed latency.
		laterSample := false
		if row.Operation == "batch-get-traces" {
			for _, later := range rows[index+1:] {
				if later.Operation != row.Operation {
					break
				}
				if later.ActorARN == row.ActorARN && later.Region == row.Region && string(later.Input) == string(row.Input) {
					laterSample = true
					break
				}
			}
		}
		if laterSample {
			continue
		}
		t.Run(row.Label, func(t *testing.T) {
			when := time.UnixMilli(row.Started).UTC()
			if when.After(source.Now()) {
				advanceClock(t, source, when.Sub(source.Now()))
			}
			identity, ok := identities[row.ActorARN]
			if !ok {
				t.Fatalf("native actor has no replayed IAM/STS identity: %s", row.ActorARN)
			}
			region := row.Region
			if region == "" {
				region = stream.Region
			}
			var client any
			input := row.Input
			switch row.Service {
			case "iam":
				client = clients.iam(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
			case "sts":
				client = clients.sts(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
			case "xray":
				options := clients.xrayRegion(region, identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken).Options()
				options.HTTPClient = wire
				options.APIOptions = append(options.APIOptions, awstest.JSONBody(row.Input))
				client = xray.New(options)
				// Satisfy SDK-only required-field checks while the signed request
				// sends the exact native payload, including null/wrong-type input.
				input = json.RawMessage(`{"TraceSegmentDocuments":[],"TraceIds":[],"PolicyName":"request","PolicyDocument":"{}"}`)
			default:
				t.Fatalf("unexpected native setup service %q", row.Service)
			}
			output, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
			awsNativeResult(t, row.awsNativeObservation, err)
			if err != nil {
				return
			}
			if session, ok := output.(*sts.AssumeRoleOutput); ok {
				identities[aws.ToString(session.AssumedRoleUser.Arn)] = aws.Credentials{AccessKeyID: aws.ToString(session.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(session.Credentials.SecretAccessKey), SessionToken: aws.ToString(session.Credentials.SessionToken)}
			}
			if row.Service != "xray" {
				return
			}
			if wire.Status != row.Result.HTTPStatus {
				t.Fatalf("HTTP status: native %d, local %d", row.Result.HTTPStatus, wire.Status)
			}
			want := row.Result.Output
			response := wire.Body
			if row.RawResponse != "" {
				want = json.RawMessage(row.RawResponse)
			} else {
				// CLI captures have already passed through an SDK, which can
				// omit null members. Compare that evidence at the same layer.
				expectedOutput := reflect.New(reflect.TypeOf(output).Elem()).Interface()
				awsDecodeJSON(t, want, expectedOutput)
				want, err = json.Marshal(expectedOutput)
				if err != nil {
					t.Fatal(err)
				}
				response, err = json.Marshal(output)
				if err != nil {
					t.Fatal(err)
				}
			}
			actual := xrayNativeReply(t, response, stream.Prefix)
			expected := xrayNativeReply(t, want, stream.Prefix)
			if !reflect.DeepEqual(actual, expected) {
				actualJSON, _ := json.Marshal(actual)
				expectedJSON, _ := json.Marshal(expected)
				t.Fatalf("native response differs\nnative: %.2048s\nlocal:  %.2048s", expectedJSON, actualJSON)
			}
		})
	}
}

func xrayNativeReply(t *testing.T, raw []byte, prefix string) map[string]any {
	t.Helper()
	var result map[string]any
	awsDecodeJSON(t, raw, &result)
	if traces, ok := result["Traces"].([]any); ok {
		for _, rawTrace := range traces {
			trace := rawTrace.(map[string]any)
			segments := trace["Segments"].([]any)
			for _, rawSegment := range segments {
				segment := rawSegment.(map[string]any)
				var document map[string]any
				awsDecodeJSON(t, []byte(segment["Document"].(string)), &document)
				xrayNativeSegment(t, document)
				segment["Document"] = document
			}
			xraySortReply(segments, "Id")
		}
		xraySortReply(traces, "Id")
	}
	if unprocessed, ok := result["UnprocessedTraceSegments"].([]any); ok {
		for _, entry := range unprocessed {
			// Assert native rejection class and ID presence, not parser prose.
			delete(entry.(map[string]any), "Message")
		}
	}
	normalizePolicy := func(raw any) {
		value := raw.(map[string]any)
		delete(value, "LastUpdatedTime")
		var document any
		awsDecodeJSON(t, []byte(value["PolicyDocument"].(string)), &document)
		value["PolicyDocument"] = document
	}
	if value, ok := result["ResourcePolicy"]; ok {
		normalizePolicy(value)
	}
	if policies, ok := result["ResourcePolicies"].([]any); ok {
		// A concurrent, separately owned native SNS probe had its own policy.
		// Compare only this capture's policy namespace, never import that state.
		policies = slices.DeleteFunc(policies, func(raw any) bool {
			return !strings.HasPrefix(raw.(map[string]any)["PolicyName"].(string), prefix)
		})
		for _, value := range policies {
			normalizePolicy(value)
		}
		xraySortReply(policies, "PolicyName")
		result["ResourcePolicies"] = policies
	}
	return result
}

func xraySortReply(values []any, field string) {
	slices.SortFunc(values, func(a, b any) int {
		return cmp.Compare(a.(map[string]any)[field].(string), b.(map[string]any)[field].(string))
	})
}

func xrayNativeSegment(t *testing.T, document map[string]any) {
	t.Helper()
	// X-Ray renders binary64 timestamps as full decimal expansions in segment
	// JSON. Compare their numeric value, not two spellings of the same double.
	for _, field := range []string{"start_time", "end_time"} {
		if number, ok := document[field].(json.Number); ok {
			value, err := number.Float64()
			if err != nil {
				t.Fatal(err)
			}
			document[field] = value
		}
	}
	children, _ := document["subsegments"].([]any)
	for _, child := range children {
		xrayNativeSegment(t, child.(map[string]any))
	}
}

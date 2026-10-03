package iam_test

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	iampolicy "stackd/iam/policy"
	"stackd/internal/services/iam"
)

type simulationFixtureCall struct {
	Operation string          `json:"operation"`
	Input     json.RawMessage `json:"input"`
}

type simulationFixtureObservation struct {
	Case string `json:"case"`
	simulationFixtureCall
	Code               string                  `json:"code"`
	HTTPStatus         int                     `json:"http_status"`
	Output             json.RawMessage         `json:"output"`
	StateChangesBefore []simulationFixtureCall `json:"state_changes_before"`
	MarkerSourceCase   string                  `json:"marker_source_case"`
}

func loadSimulationFixture(t *testing.T) []simulationFixtureObservation {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/iam/simulation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations    []simulationFixtureObservation `json:"observations"`
		CaptureComplete bool                           `json:"capture_complete"`
		CleanupVerified bool                           `json:"cleanup_verified"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.CaptureComplete || !fixture.CleanupVerified {
		t.Fatal("simulation fixture is not a completed, cleaned AWS capture")
	}
	seen := make(map[string]bool)
	for _, observation := range fixture.Observations {
		if observation.Case == "" || seen[observation.Case] {
			t.Fatalf("missing or duplicate simulation fixture case %q", observation.Case)
		}
		seen[observation.Case] = true
	}
	return fixture.Observations
}

// Each request runs through the actual SDK Query serializer and generated
// frontend, including modeled failures. Statement sets are order independent;
// action/resource result order, decisions, diagnostics and positions remain
// exact. Empty collections are normalized because SDK XML decoding can erase
// the difference between an omitted container and an empty one.
func TestSimulateCustomPolicyAWSReplay(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	transport := &credentialReportWireTransport{base: http.DefaultTransport}
	options := client.Options()
	options.HTTPClient = &http.Client{Transport: transport}
	client = sdkiam.New(options)
	markers := make(map[string]string)
	count := 0
	for _, observation := range loadSimulationFixture(t) {
		for _, mutation := range observation.StateChangesBefore {
			applySimulationFixtureMutation(t, client, mutation)
		}
		if observation.Operation != "SimulateCustomPolicy" {
			continue
		}
		count++
		t.Run(observation.Case, func(t *testing.T) {
			if observation.Code == "CLIValidationError" {
				t.Skip("capture contains client validation only, not an AWS service response")
			}
			var input sdkiam.SimulateCustomPolicyInput
			if err := json.Unmarshal(observation.Input, &input); err != nil {
				t.Fatal(err)
			}
			input.Marker = simulationFixtureMarker(t, observation, input.Marker, markers)
			output, err := client.SimulateCustomPolicy(t.Context(), &input)
			if observation.Code != "Success" {
				requireCode(t, err, observation.Code)
				var response interface{ HTTPStatusCode() int }
				if !errors.As(err, &response) || response.HTTPStatusCode() != observation.HTTPStatus || output != nil {
					t.Fatalf("failure status/output differs from AWS: output=%+v error=%v", output, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, status := transport.last()
			if status != observation.HTTPStatus {
				t.Fatalf("HTTP status=%d; AWS=%d", status, observation.HTTPStatus)
			}
			assertSimulationFixtureOutput(t, observation.Output, output)
			if output.Marker != nil {
				markers[observation.Case] = *output.Marker
			}
		})
	}
	if count == 0 {
		t.Fatal("fixture contains no custom simulation observations")
	}
}

type simulationXMLNode struct {
	XMLName  xml.Name
	Text     string              `xml:",chardata"`
	Children []simulationXMLNode `xml:",any"`
}

func TestSimulateCustomPolicyAWSWireShape(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	transport := &credentialReportWireTransport{base: http.DefaultTransport}
	options := client.Options()
	options.HTTPClient = &http.Client{Transport: transport}
	client = sdkiam.New(options)
	selected := map[string]bool{"custom_default_resource": true, "custom_single_resource": true, "custom_two_resources_allowed": true, "missing_relevant": true}
	for _, observation := range loadSimulationFixture(t) {
		if !selected[observation.Case] {
			continue
		}
		delete(selected, observation.Case)
		t.Run(observation.Case, func(t *testing.T) {
			var input sdkiam.SimulateCustomPolicyInput
			if err := json.Unmarshal(observation.Input, &input); err != nil {
				t.Fatal(err)
			}
			if _, err := client.SimulateCustomPolicy(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			wire, _ := transport.last()
			var response simulationXMLNode
			if err := xml.Unmarshal(wire, &response); err != nil {
				t.Fatal(err)
			}
			var expected any
			if err := json.Unmarshal(observation.Output, &expected); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, node := range response.Children {
				if node.XMLName.Local == "SimulateCustomPolicyResult" {
					found = true
					assertSimulationXMLShape(t, node, expected, "result")
				}
			}
			if !found {
				t.Fatal("response omitted generated simulation result wrapper")
			}
		})
	}
	if len(selected) != 0 {
		t.Fatalf("wire fixtures are missing: %v", selected)
	}
}

func TestSimulateCustomPolicyExplicitCallerIDOverridesDefault(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	provided := &sdkiam.SimulateCustomPolicyInput{ActionNames: []string{"s3:GetObject"}, PolicyInputList: []string{`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:userid":"caller-provided-id"}}}}`}, ContextEntries: []types.ContextEntry{{ContextKeyName: aws.String("aws:userid"), ContextKeyType: types.ContextKeyTypeEnumString, ContextKeyValues: []string{"caller-provided-id"}}}}
	output, err := client.SimulateCustomPolicy(t.Context(), provided)
	if err != nil || len(output.EvaluationResults) != 1 || output.EvaluationResults[0].EvalDecision != types.PolicyEvaluationDecisionTypeAllowed {
		t.Fatalf("explicit caller ID did not replace the default: %+v %v", output, err)
	}
}

func TestSimulatePrincipalPolicyAWSReplay(t *testing.T) {
	// The captured account belongs to an organization with no restrictive
	// applicable SCPs. Configure that source explicitly instead of inventing
	// Organizations decision details for a standalone account.
	controls := &simulationMutableControls{levels: []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: simulationPolicy("Allow", "*")}}}}}
	service := iam.NewWithConfig(iam.Config{SimulationControls: controls})
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	markers := make(map[string]string)
	count := 0
	for _, observation := range loadSimulationFixture(t) {
		for _, mutation := range observation.StateChangesBefore {
			applySimulationFixtureMutation(t, client, mutation)
		}
		if observation.Operation != "SimulatePrincipalPolicy" {
			continue
		}
		count++
		t.Run(observation.Case, func(t *testing.T) {
			if observation.Code == "CLIValidationError" {
				t.Skip("capture contains client validation only, not an AWS service response")
			}
			input, err := decodePrincipalSimulationFixture(observation.Input)
			if err != nil {
				t.Fatal(err)
			}
			input.Marker = simulationFixtureMarker(t, observation, input.Marker, markers)
			output, err := client.SimulatePrincipalPolicy(t.Context(), &input)
			if observation.Code != "Success" {
				requireCode(t, err, observation.Code)
				var response interface{ HTTPStatusCode() int }
				if !errors.As(err, &response) || response.HTTPStatusCode() != observation.HTTPStatus || output != nil {
					t.Fatalf("failure status/output differs from AWS: output=%+v error=%v", output, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertSimulationFixtureOutput(t, observation.Output, output)
			if output.Marker != nil {
				markers[observation.Case] = *output.Marker
			}
		})
	}
	if count == 0 {
		t.Fatal("fixture contains no principal simulation observations")
	}
}

func applySimulationFixtureMutation(t *testing.T, client *sdkiam.Client, mutation simulationFixtureCall) {
	t.Helper()
	switch mutation.Operation {
	case "CreateUser":
		callSimulationFixtureMutation(t, mutation.Input, client.CreateUser)
	case "CreateGroup":
		callSimulationFixtureMutation(t, mutation.Input, client.CreateGroup)
	case "CreateRole":
		callSimulationFixtureMutation(t, mutation.Input, client.CreateRole)
	case "CreatePolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.CreatePolicy)
	case "PutUserPolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.PutUserPolicy)
	case "PutGroupPolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.PutGroupPolicy)
	case "PutRolePolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.PutRolePolicy)
	case "AttachUserPolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.AttachUserPolicy)
	case "AttachGroupPolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.AttachGroupPolicy)
	case "AttachRolePolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.AttachRolePolicy)
	case "DetachUserPolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.DetachUserPolicy)
	case "DetachGroupPolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.DetachGroupPolicy)
	case "DetachRolePolicy":
		callSimulationFixtureMutation(t, mutation.Input, client.DetachRolePolicy)
	case "AddUserToGroup":
		callSimulationFixtureMutation(t, mutation.Input, client.AddUserToGroup)
	case "RemoveUserFromGroup":
		callSimulationFixtureMutation(t, mutation.Input, client.RemoveUserFromGroup)
	case "PutUserPermissionsBoundary":
		callSimulationFixtureMutation(t, mutation.Input, client.PutUserPermissionsBoundary)
	case "DeleteUserPermissionsBoundary":
		callSimulationFixtureMutation(t, mutation.Input, client.DeleteUserPermissionsBoundary)
	case "CreatePolicyVersion":
		callSimulationFixtureMutation(t, mutation.Input, client.CreatePolicyVersion)
	case "SetDefaultPolicyVersion":
		callSimulationFixtureMutation(t, mutation.Input, client.SetDefaultPolicyVersion)
	default:
		t.Fatalf("unhandled recorded simulation mutation %q", mutation.Operation)
	}
}

func callSimulationFixtureMutation[Input, Output any](t *testing.T, raw json.RawMessage, call func(context.Context, *Input, ...func(*sdkiam.Options)) (*Output, error)) {
	t.Helper()
	var input Input
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t.Context(), &input); err != nil {
		t.Fatalf("recorded fixture mutation failed: %v", err)
	}
}

func assertSimulationXMLShape(t *testing.T, node simulationXMLNode, expected any, location string) {
	t.Helper()
	switch expected := expected.(type) {
	case map[string]any:
		fields := make(map[string]simulationXMLNode)
		for _, child := range node.Children {
			if _, duplicate := fields[child.XMLName.Local]; duplicate {
				t.Fatalf("%s: duplicated XML result field %s", location, child.XMLName.Local)
			}
			fields[child.XMLName.Local] = child
		}
		if len(fields) != len(expected) {
			t.Fatalf("%s: XML fields=%v; AWS fields=%v", location, fields, expected)
		}
		for key, value := range expected {
			child, exists := fields[key]
			if !exists {
				t.Fatalf("%s: XML omitted AWS field %s", location, key)
			}
			assertSimulationXMLShape(t, child, value, location+"."+key)
		}
	case []any:
		if len(node.Children) != len(expected) {
			t.Fatalf("%s: XML list has %d members; AWS has %d", location, len(node.Children), len(expected))
		}
		for index, item := range expected {
			if node.Children[index].XMLName.Local != "member" {
				t.Fatalf("%s: non-member XML list element %s", location, node.Children[index].XMLName.Local)
			}
			assertSimulationXMLShape(t, node.Children[index], item, fmt.Sprintf("%s[%d]", location, index))
		}
	default:
		if strings.TrimSpace(node.Text) != fmt.Sprint(expected) || len(node.Children) != 0 {
			t.Fatalf("%s: XML value=%q; AWS=%v", location, node.Text, expected)
		}
	}
}

func simulationFixtureMarker(t *testing.T, observation simulationFixtureObservation, marker *string, markers map[string]string) *string {
	t.Helper()
	if observation.MarkerSourceCase == "" {
		// Malformed-token cases deliberately retain their literal input.
		return marker
	}
	local, known := markers[observation.MarkerSourceCase]
	if marker == nil || !known || local == "" {
		t.Fatalf("continuation refers to uncaptured marker source %q", observation.MarkerSourceCase)
	}
	return aws.String(local)
}

func assertSimulationFixtureOutput(t *testing.T, expectedJSON []byte, output any) {
	t.Helper()
	actualJSON, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var expected, actual map[string]any
	if err := json.Unmarshal(expectedJSON, &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(actualJSON, &actual); err != nil {
		t.Fatal(err)
	}
	if _, exists := expected["Marker"]; exists {
		local, ok := actual["Marker"].(string)
		if !ok || local == "" {
			t.Fatal("truncated result omitted its continuation marker")
		}
	} else if token, exists := actual["Marker"]; exists && token != nil {
		t.Fatal("untruncated result added a continuation marker")
	}
	delete(actual, "Marker")
	delete(expected, "Marker")
	actualNormalized := normalizeSimulationFixture(actual, "")
	expectedNormalized := normalizeSimulationFixture(expected, "")
	if !reflect.DeepEqual(actualNormalized, expectedNormalized) {
		got, _ := json.MarshalIndent(actualNormalized, "", "  ")
		want, _ := json.MarshalIndent(expectedNormalized, "", "  ")
		t.Fatalf("simulation differs from captured AWS response\nactual: %s\nAWS: %s", got, want)
	}
}

func normalizeSimulationFixture(value any, field string) any {
	switch value := value.(type) {
	case map[string]any:
		result := make(map[string]any)
		for key, item := range value {
			if key == "ResultMetadata" {
				continue
			}
			if normalized := normalizeSimulationFixture(item, key); normalized != nil {
				result[key] = normalized
			}
		}
		if len(result) != 0 {
			return result
		}
		return nil
	case []any:
		if len(value) == 0 {
			return nil
		}
		result := make([]any, len(value))
		for index, item := range value {
			result[index] = normalizeSimulationFixture(item, "")
		}
		if field == "MatchedStatements" || field == "MissingContextValues" {
			slices.SortFunc(result, func(left, right any) int {
				a, _ := json.Marshal(left)
				b, _ := json.Marshal(right)
				return strings.Compare(string(a), string(b))
			})
		}
		return result
	default:
		return value
	}
}

func decodePrincipalSimulationFixture(data []byte) (sdkiam.SimulatePrincipalPolicyInput, error) {
	// encoding/json cannot populate an SDK union interface directly. Decode
	// the generated union alternatives explicitly while retaining SDK inputs
	// and its real Query serialization for the actual request.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return sdkiam.SimulatePrincipalPolicyInput{}, err
	}
	exclusions := fields["PolicyExclusionList"]
	delete(fields, "PolicyExclusionList")
	plain, err := json.Marshal(fields)
	if err != nil {
		return sdkiam.SimulatePrincipalPolicyInput{}, err
	}
	var input sdkiam.SimulatePrincipalPolicyInput
	if err := json.Unmarshal(plain, &input); err != nil {
		return input, err
	}
	if len(exclusions) == 0 {
		return input, nil
	}
	var list []map[string]json.RawMessage
	if err := json.Unmarshal(exclusions, &list); err != nil {
		return input, err
	}
	for _, entry := range list {
		if len(entry) != 1 {
			return input, fmt.Errorf("fixture exclusion must select one SDK union alternative")
		}
		for kind, encoded := range entry {
			switch kind {
			case "PolicyArn":
				var value string
				if err := json.Unmarshal(encoded, &value); err != nil {
					return input, err
				}
				input.PolicyExclusionList = append(input.PolicyExclusionList, &types.PolicyIdentifierMemberPolicyArn{Value: value})
			case "PolicyType":
				var value types.PolicyIdentifierPolicyType
				if err := json.Unmarshal(encoded, &value); err != nil {
					return input, err
				}
				input.PolicyExclusionList = append(input.PolicyExclusionList, &types.PolicyIdentifierMemberPolicyType{Value: value})
			case "InlinePolicyIdentifier":
				var value types.InlinePolicyIdentifierType
				if err := json.Unmarshal(encoded, &value); err != nil {
					return input, err
				}
				input.PolicyExclusionList = append(input.PolicyExclusionList, &types.PolicyIdentifierMemberInlinePolicyIdentifier{Value: value})
			default:
				return input, fmt.Errorf("unknown fixture policy exclusion %q", kind)
			}
		}
	}
	return input, nil
}

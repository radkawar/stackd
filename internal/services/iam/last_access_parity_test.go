package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	"stackd/internal/awstest"
	"stackd/internal/identity"
)

type lastAccessFixtureStep struct {
	Case               string                  `json:"case"`
	Operation          string                  `json:"operation"`
	Input              json.RawMessage         `json:"input"`
	Output             json.RawMessage         `json:"output"`
	Code               string                  `json:"code"`
	HTTPStatus         int                     `json:"http_status"`
	Credential         string                  `json:"credential"`
	JobSourceCase      string                  `json:"job_source_case"`
	MarkerSourceCase   string                  `json:"marker_source_case"`
	PropagationPending bool                    `json:"propagation_pending"`
	Changes            []lastAccessFixtureStep `json:"state_changes_before"`
}

type lastAccessFixture struct {
	Complete     bool                    `json:"capture_complete"`
	Cleaned      bool                    `json:"cleanup_verified"`
	Setup        []lastAccessFixtureStep `json:"setup"`
	Observations []lastAccessFixtureStep `json:"observations"`
}

func loadLastAccessFixture(t *testing.T, name string) lastAccessFixture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/iam/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var fixture lastAccessFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.Complete || !fixture.Cleaned {
		t.Fatal("last-access capture or owned-resource cleanup incomplete")
	}
	return fixture
}

// This replay exercises policies through the SDK. It compares the deliberately
// different report and per-policy service selection against recorded AWS results.
// It does not give the policy engine fabricated permission summaries.
func TestLastAccessAWSFixtureReplay(t *testing.T) {
	fixture := loadLastAccessFixture(t, "last_access.json")
	// The historical wildcard policy report predates a newly published service.
	// Its snapshot transition is replayed from the current native capture below;
	// retain the original evidence without pinning the old service inventory.
	fixture.Observations = slices.DeleteFunc(fixture.Observations, func(step lastAccessFixtureStep) bool {
		return strings.HasPrefix(step.Case, "pending_policy_")
	})
	replayLastAccessFixture(t, fixture)
}

func replayLastAccessFixture(t *testing.T, fixture lastAccessFixture) {
	t.Helper()
	r := newLastAccessReplay(t)
	for _, step := range fixture.Setup {
		r.mutate(t, step)
	}
	for _, step := range fixture.Observations {
		for _, change := range step.Changes {
			r.mutate(t, change)
		}
		if step.PropagationPending {
			continue // AWS propagation latency is separately identified in the fixture.
		}
		if r.isMutation(step.Operation) {
			if step.Code == "Success" {
				r.mutate(t, step)
			}
			continue
		}
		client := r.clients[step.Credential]
		if client == nil {
			// Role-session ownership is covered by the STS integration tests;
			// this IAM-only gateway has no AssumeRole issuer registered.
			continue
		}
		if strings.HasPrefix(step.Case, "page_entities_") {
			// Unused entities have equal last-access times. AWS does not promise
			// the tie order; explicit pagination behavior has separate SDK tests.
			continue
		}
		switch step.Operation {
		case "GenerateServiceLastAccessedDetails", "GetServiceLastAccessedDetails", "GetServiceLastAccessedDetailsWithEntities", "ListPoliciesGrantingServiceAccess":
			t.Run(step.Case, func(t *testing.T) { r.check(t, client, step) })
		}
	}
}

func TestLastAccessAWSCurrentCatalogReplay(t *testing.T) {
	for _, name := range []string{"last_access_service_names_20260927.json", "last_access_pending_policy_20260927.json"} {
		t.Run(name, func(t *testing.T) {
			replayLastAccessFixture(t, loadLastAccessFixture(t, name))
		})
	}
}

type lastAccessReplay struct {
	fixture *activityFixture
	clients map[string]*sdkiam.Client
	jobs    map[string]string
	markers map[string]string
	ids     map[string]string
}

func newLastAccessReplay(t *testing.T) *lastAccessReplay {
	t.Helper()
	f := newActivityFixture(t, nil, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	return &lastAccessReplay{fixture: f, clients: map[string]*sdkiam.Client{"": f.root, "original": f.root, "original_caller": f.root}, jobs: make(map[string]string), markers: make(map[string]string), ids: make(map[string]string)}
}

func (r *lastAccessReplay) isMutation(operation string) bool {
	switch operation {
	case "CreateUser", "CreateGroup", "CreateRole", "CreatePolicy", "CreateAccessKey", "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy", "AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy", "AddUserToGroup", "PutUserPermissionsBoundary", "DeleteUserPermissionsBoundary", "CreatePolicyVersion", "DeleteUserPolicy", "DeleteUser", "UpdateUser", "RemoveUserFromGroup", "DetachUserPolicy":
		return true
	}
	return false
}

func (r *lastAccessReplay) mutate(t *testing.T, step lastAccessFixtureStep) {
	t.Helper()
	client := r.fixture.root
	switch step.Operation {
	case "CreateUser":
		output := lastAccessMutation(t, step.Input, client.CreateUser)
		var expected struct {
			User struct {
				UserID string `json:"UserId"`
			}
		}
		if err := json.Unmarshal(step.Output, &expected); err != nil {
			t.Fatal(err)
		}
		r.ids[aws.ToString(output.User.UserId)] = expected.User.UserID
	case "CreateRole":
		output := lastAccessMutation(t, step.Input, client.CreateRole)
		var expected struct {
			Role struct {
				RoleID string `json:"RoleId"`
			}
		}
		if err := json.Unmarshal(step.Output, &expected); err != nil {
			t.Fatal(err)
		}
		r.ids[aws.ToString(output.Role.RoleId)] = expected.Role.RoleID
	case "CreateAccessKey":
		output := lastAccessMutation(t, step.Input, client.CreateAccessKey)
		var expected struct {
			AccessKey struct {
				ID string `json:"AccessKeyId"`
			}
		}
		if err := json.Unmarshal(step.Output, &expected); err != nil {
			t.Fatal(err)
		}
		key := identity.Credential{AccessKeyID: aws.ToString(output.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(output.AccessKey.SecretAccessKey)}
		keyClient := r.fixture.client("us-east-1", key)
		aliases := map[string][]string{
			"<access-key:observer-one>":      {"observer_key_one"},
			"<access-key:observer-two>":      {"observer_key_two", "same_user_other_key"},
			"<access-key:member>":            {"different_user"},
			"<access-key:target>":            {"target_key"},
			"<access-key:followup-reporter>": {"followup_reporter"},
		}
		for _, alias := range aliases[expected.AccessKey.ID] {
			r.clients[alias] = keyClient
		}
	case "UpdateUser":
		lastAccessMutation(t, step.Input, client.UpdateUser)
	case "DeleteUserPolicy":
		lastAccessMutation(t, step.Input, client.DeleteUserPolicy)
	case "DeleteUser":
		lastAccessMutation(t, step.Input, client.DeleteUser)
	default:
		if !r.isMutation(step.Operation) {
			t.Fatalf("unhandled last-access fixture mutation %q", step.Operation)
		}
		applySimulationFixtureMutation(t, client, simulationFixtureCall{Operation: step.Operation, Input: step.Input})
	}
}

func lastAccessMutation[Input, Output any](t *testing.T, raw json.RawMessage, call func(context.Context, *Input, ...func(*sdkiam.Options)) (*Output, error)) *Output {
	t.Helper()
	output, err := call(t.Context(), lastAccessInput[Input](t, raw))
	if err != nil {
		t.Fatalf("recorded last-access setup failed: %v", err)
	}
	return output
}

func lastAccessInput[T any](t *testing.T, raw json.RawMessage) *T {
	t.Helper()
	var input T
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	return &input
}

func (r *lastAccessReplay) check(t *testing.T, client *sdkiam.Client, step lastAccessFixtureStep) {
	t.Helper()
	var expected map[string]any
	if len(step.Output) != 0 {
		if err := json.Unmarshal(step.Output, &expected); err != nil {
			t.Fatal(err)
		}
	}
	if expected["JobStatus"] == "COMPLETED" {
		if err := r.fixture.clock.Advance(time.Second); err != nil {
			t.Fatal(err)
		}
		if _, err := r.fixture.service.RunDueJobs(t.Context(), 100); err != nil {
			t.Fatal(err)
		}
	}
	var output any
	var err error
	switch step.Operation {
	case "GenerateServiceLastAccessedDetails":
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(step.Input, &fields); err != nil {
			t.Fatal(err)
		}
		var options []func(*sdkiam.Options)
		if string(fields["Granularity"]) == `""` {
			options = append(options, lastAccessEmptyGranularity)
		}
		result, callErr := client.GenerateServiceLastAccessedDetails(t.Context(), lastAccessInput[sdkiam.GenerateServiceLastAccessedDetailsInput](t, step.Input), options...)
		output, err = result, callErr
		if callErr == nil {
			if aws.ToString(result.JobId) == "" {
				t.Fatal("empty report job ID")
			}
			r.jobs[step.Case] = aws.ToString(result.JobId)
		}
	case "GetServiceLastAccessedDetails":
		input := lastAccessInput[sdkiam.GetServiceLastAccessedDetailsInput](t, step.Input)
		r.references(t, step, &input.JobId, &input.Marker)
		result, callErr := client.GetServiceLastAccessedDetails(t.Context(), input)
		output, err = result, callErr
		if callErr == nil && result.Marker != nil {
			r.markers[step.Case] = *result.Marker
		}
	case "GetServiceLastAccessedDetailsWithEntities":
		input := lastAccessInput[sdkiam.GetServiceLastAccessedDetailsWithEntitiesInput](t, step.Input)
		r.references(t, step, &input.JobId, &input.Marker)
		result, callErr := client.GetServiceLastAccessedDetailsWithEntities(t.Context(), input)
		output, err = result, callErr
		if callErr == nil && result.Marker != nil {
			r.markers[step.Case] = *result.Marker
		}
	case "ListPoliciesGrantingServiceAccess":
		input := lastAccessInput[sdkiam.ListPoliciesGrantingServiceAccessInput](t, step.Input)
		r.references(t, step, nil, &input.Marker)
		result, callErr := client.ListPoliciesGrantingServiceAccess(t.Context(), input)
		output, err = result, callErr
		if callErr == nil && result.Marker != nil {
			r.markers[step.Case] = *result.Marker
		}
	default:
		t.Fatalf("unsupported last-access replay operation %s", step.Operation)
	}
	if step.Code != "Success" {
		var apiError smithy.APIError
		if !errors.As(err, &apiError) || apiError.ErrorCode() != step.Code {
			t.Fatalf("AWS %s; local error=%v", step.Code, err)
		}
		if step.HTTPStatus != 0 {
			requireCredentialReportHTTPStatus(t, err, step.HTTPStatus)
		}
		return
	}
	if err != nil {
		t.Fatalf("AWS succeeded; local error=%v", err)
	}
	data, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]any
	if err := json.Unmarshal(data, &actual); err != nil {
		t.Fatal(err)
	}
	want, got := r.normalize(expected, ""), r.normalize(actual, "")
	if !reflect.DeepEqual(want, got) {
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got)
		t.Errorf("AWS output=%s\nlocal output=%s", wantJSON, gotJSON)
	}
}

// The SDK's zero enum omits Granularity. Preserve the fixture's explicit empty
// Query value after serialization and before the SDK signs the request.
func lastAccessEmptyGranularity(options *sdkiam.Options) {
	options.APIOptions = append(options.APIOptions, awstest.QueryValues(url.Values{"Granularity": {""}}))
}

func (r *lastAccessReplay) references(t *testing.T, step lastAccessFixtureStep, job, marker **string) {
	t.Helper()
	if job != nil && step.JobSourceCase != "" {
		value, ok := r.jobs[step.JobSourceCase]
		if !ok {
			t.Fatalf("report source case %q has no locally generated job", step.JobSourceCase)
		}
		*job = aws.String(value)
	}
	if marker != nil && step.MarkerSourceCase != "" {
		value, ok := r.markers[step.MarkerSourceCase]
		if !ok {
			t.Fatalf("marker source case %q has no local continuation", step.MarkerSourceCase)
		}
		*marker = aws.String(value)
	}
}

func (r *lastAccessReplay) normalize(value any, field string) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any)
		for key, item := range value {
			if key == "ResultMetadata" || item == nil || ((key == "JobType" || key == "EntityType") && item == "") {
				continue
			}
			out[key] = r.normalize(item, key)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for index, item := range value {
			out[index] = r.normalize(item, "")
		}
		if field == "Policies" || field == "EntityDetailsList" {
			// AWS policy-source order and equal-last-access entity order vary
			// across identical requests. Preserve membership, not those ties.
			sort.Slice(out, func(i, j int) bool {
				a, _ := json.Marshal(out[i])
				b, _ := json.Marshal(out[j])
				return string(a) < string(b)
			})
		}
		return out
	case string:
		switch field {
		case "JobId":
			return "<job-id>"
		case "Marker":
			return "<marker>"
		case "JobCreationDate", "JobCompletionDate":
			if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
				return value
			}
			return "<timestamp>"
		case "Id":
			if replacement, ok := r.ids[value]; ok {
				return replacement
			}
		}
	}
	return value
}

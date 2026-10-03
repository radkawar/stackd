package iam_test

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	"stackd/internal/services/iam"
)

func TestListPoliciesGrantingServiceAccessAWSSelectors(t *testing.T) {
	type operation struct {
		Operation string
		Input     json.RawMessage
		Code      string
	}
	var fixture struct {
		Setup        []operation
		Observations []struct {
			operation
			Case               string
			Output             json.RawMessage
			StateChangesBefore []operation `json:"state_changes_before"`
		}
	}
	data, err := os.ReadFile("../../../testdata/aws/iam/last_access.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	owned := func(input json.RawMessage) bool {
		var name struct {
			UserName string
			Arn      string
		}
		if err := json.Unmarshal(input, &name); err != nil {
			t.Fatal(err)
		}
		for _, suffix := range []string{"fixture-selection", "fixture-followup", "fixture-deny-edges"} {
			if strings.HasSuffix(name.UserName, suffix) || strings.HasSuffix(name.Arn, suffix) {
				return true
			}
		}
		return false
	}
	mutate := func(t *testing.T, op operation) {
		t.Helper()
		var err error
		switch op.Operation {
		case "CreateUser":
			var in sdkiam.CreateUserInput
			if err = json.Unmarshal(op.Input, &in); err == nil {
				_, err = client.CreateUser(t.Context(), &in)
			}
		case "PutUserPolicy":
			var in sdkiam.PutUserPolicyInput
			if err = json.Unmarshal(op.Input, &in); err == nil {
				_, err = client.PutUserPolicy(t.Context(), &in)
			}
		case "DeleteUserPolicy":
			var in sdkiam.DeleteUserPolicyInput
			if err = json.Unmarshal(op.Input, &in); err == nil {
				_, err = client.DeleteUserPolicy(t.Context(), &in)
			}
		default:
			return
		}
		if op.Code != "" && op.Code != "Success" {
			requireCode(t, err, op.Code)
		} else if err != nil {
			t.Fatal(err)
		}
	}
	for _, setup := range fixture.Setup {
		if owned(setup.Input) {
			mutate(t, setup)
		}
	}
	for _, row := range fixture.Observations {
		if !owned(row.Input) {
			continue
		}
		for _, change := range row.StateChangesBefore {
			mutate(t, change)
		}
		if row.Operation != "ListPoliciesGrantingServiceAccess" {
			mutate(t, row.operation)
			continue
		}
		t.Run(row.Case, func(t *testing.T) {
			var input sdkiam.ListPoliciesGrantingServiceAccessInput
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			// SDK validation owns missing required fields. Raw Query cases are exercised
			// separately at the actual server boundary.
			if len(input.ServiceNamespaces) == 0 {
				return
			}
			got, err := client.ListPoliciesGrantingServiceAccess(t.Context(), &input)
			if row.Code != "Success" {
				requireCode(t, err, row.Code)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want sdkiam.ListPoliciesGrantingServiceAccessOutput
			if err = json.Unmarshal(row.Output, &want); err != nil {
				t.Fatal(err)
			}
			canonical := func(entries []types.ListPoliciesGrantingServiceAccessEntry) []types.ListPoliciesGrantingServiceAccessEntry {
				for i := range entries {
					slices.SortFunc(entries[i].Policies, func(a, b types.PolicyGrantingServiceAccess) int {
						return strings.Compare(aws.ToString(a.PolicyName)+"/"+aws.ToString(a.EntityName), aws.ToString(b.PolicyName)+"/"+aws.ToString(b.EntityName))
					})
				}
				return entries
			}
			if !reflect.DeepEqual(canonical(got.PoliciesGrantingServiceAccess), canonical(want.PoliciesGrantingServiceAccess)) || got.IsTruncated != want.IsTruncated || !reflect.DeepEqual(got.Marker, want.Marker) {
				t.Fatalf("got %#v; want %#v", got.PoliciesGrantingServiceAccess, want.PoliciesGrantingServiceAccess)
			}
		})
	}
}

func TestAccessReportAWSResourceSelection(t *testing.T) {
	type call struct {
		Operation string
		Input     json.RawMessage
	}
	var fixture struct {
		Setup        []call
		Observations []struct {
			call
			Case               string
			Output             json.RawMessage
			StateChangesBefore []call `json:"state_changes_before"`
		}
	}
	data, err := os.ReadFile("../../../testdata/aws/iam/last_access.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	source := clock.NewManual(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
	service := iam.NewWithConfig(iam.Config{Clock: source})
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	mutate := func(change call) {
		t.Helper()
		if !strings.Contains(string(change.Input), "fixture-report-controls") {
			return
		}
		switch change.Operation {
		case "CreateUser":
			var in sdkiam.CreateUserInput
			if err := json.Unmarshal(change.Input, &in); err != nil {
				t.Fatal(err)
			}
			if _, err := client.CreateUser(t.Context(), &in); err != nil {
				t.Fatal(err)
			}
		case "PutUserPolicy":
			var in sdkiam.PutUserPolicyInput
			if err := json.Unmarshal(change.Input, &in); err != nil {
				t.Fatal(err)
			}
			if _, err := client.PutUserPolicy(t.Context(), &in); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, setup := range fixture.Setup {
		mutate(setup)
	}
	jobs := make(map[string]*string)
	for _, row := range fixture.Observations {
		if !strings.HasPrefix(row.Case, "report_controls_") {
			continue
		}
		for _, change := range row.StateChangesBefore {
			mutate(change)
		}
		switch row.Operation {
		case "GenerateServiceLastAccessedDetails":
			var input sdkiam.GenerateServiceLastAccessedDetailsInput
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			output, err := client.GenerateServiceLastAccessedDetails(t.Context(), &input)
			if err != nil {
				t.Fatal(err)
			}
			var captured sdkiam.GenerateServiceLastAccessedDetailsOutput
			if err = json.Unmarshal(row.Output, &captured); err != nil {
				t.Fatal(err)
			}
			jobs[aws.ToString(captured.JobId)] = output.JobId
		case "GetServiceLastAccessedDetails":
			var want sdkiam.GetServiceLastAccessedDetailsOutput
			if err := json.Unmarshal(row.Output, &want); err != nil {
				t.Fatal(err)
			}
			if want.JobStatus != types.JobStatusTypeCompleted {
				continue
			}
			var input sdkiam.GetServiceLastAccessedDetailsInput
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			t.Run(row.Case, func(t *testing.T) {
				output := finishAccessReport(t, service, source, client, jobs[aws.ToString(input.JobId)])
				namespaces := func(services []types.ServiceLastAccessed) []string {
					result := make([]string, 0, len(services))
					for _, service := range services {
						result = append(result, aws.ToString(service.ServiceNamespace))
					}
					slices.Sort(result)
					return result
				}
				if !slices.Equal(namespaces(output.ServicesLastAccessed), namespaces(want.ServicesLastAccessed)) {
					t.Fatalf("actual grants=%v want %v", namespaces(output.ServicesLastAccessed), namespaces(want.ServicesLastAccessed))
				}
			})
		}
	}
}

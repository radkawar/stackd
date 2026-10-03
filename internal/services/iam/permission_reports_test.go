package iam

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"stackd/internal/iam/catalog"
)

func TestReportPermissionActionsHierarchyCatalog(t *testing.T) {
	metadata, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	all, apiErr := reportPermissionActions(t.Context(), nil)
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	if len(all) != len(metadata.ServicePrefixes()) {
		t.Fatalf("unrestricted services=%d want %d", len(all), len(metadata.ServicePrefixes()))
	}
	for _, namespace := range metadata.ServicePrefixes() {
		service, _ := metadata.LookupService(namespace)
		if len(all[namespace]) != len(service.Actions) {
			t.Fatalf("unrestricted %s actions=%d want %d", namespace, len(all[namespace]), len(service.Actions))
		}
	}
	full := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	hierarchy, apiErr := reportPermissionActions(t.Context(), [][]string{{full}, {full}, {full}, {full}, {full}})
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	for namespace, actions := range all {
		if !slices.Equal(actions, hierarchy[namespace]) {
			t.Fatalf("unrestricted hierarchy changed %s grants", namespace)
		}
	}
	for _, levels := range [][][]string{{{}}, {{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}, {}}} {
		result, apiErr := reportPermissionActions(t.Context(), levels)
		if apiErr != nil || len(result) != 0 {
			t.Fatalf("empty hierarchy level result=%v err=%v", result, apiErr)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, apiErr := reportPermissionActions(ctx, nil); apiErr == nil || result != nil {
		t.Fatalf("cancelled report returned %v %v", result, apiErr)
	}
}

func BenchmarkReportPermissionActionsFullSCPHierarchy(b *testing.B) {
	full := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	levels := [][]string{{full}, {full}, {full}, {full}, {full}}
	if _, err := catalog.Load(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		result, err := reportPermissionActions(b.Context(), levels)
		if err != nil || len(result) == 0 {
			b.Fatalf("empty/failed report %v", err)
		}
	}
}

func BenchmarkReportPermissionActionsLargeSCPHierarchy(b *testing.B) {
	// Five near-limit SCPs at each hierarchy level, including FullAWSAccess.
	// Repeated action selections exercise the actual catalog-wide matcher while
	// resource selectors stay distinct and cannot be collapsed accidentally.
	documents := []string{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}
	for policy := 0; policy < 4; policy++ {
		type statement struct{ Effect, Action, Resource string }
		entries := make([]statement, 0, 65)
		for i := 0; i < 65; i++ {
			entries = append(entries, statement{Effect: "Deny", Action: "s3:GetObject", Resource: "arn:aws:s3:::department-" + string(rune('a'+policy)) + "/classified-" + string(rune('A'+i)) + "/*"})
		}
		document, err := json.Marshal(struct{ Statement []statement }{entries})
		if err != nil {
			b.Fatal(err)
		}
		documents = append(documents, string(document))
	}
	levels := [][]string{documents, documents, documents, documents, documents}
	if _, err := catalog.Load(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		result, err := reportPermissionActions(b.Context(), levels)
		if err != nil || len(result) == 0 {
			b.Fatalf("empty/failed report %v", err)
		}
	}
}

func TestOrganizationReportPermissionAWSControls(t *testing.T) {
	type call struct {
		Operation string
		Input     struct{ Content, OrganizationsPolicyId, JobId string }
		Output    struct {
			JobId, JobStatus string
			Policy           struct{ PolicySummary struct{ Id string } }
			AccessDetails    []struct{ ServiceNamespace string }
		}
	}
	var fixture struct {
		Setup        []call
		Observations []struct {
			call
			Case               string
			StateChangesBefore []call `json:"state_changes_before"`
		}
	}
	data, err := os.ReadFile("../../../testdata/aws/iam/organizations_access.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	documents := make(map[string]string)
	capture := func(change call) {
		if change.Operation == "CreatePolicy" {
			documents[change.Output.Policy.PolicySummary.Id] = change.Input.Content
		}
	}
	for _, setup := range fixture.Setup {
		capture(setup)
	}
	jobs := make(map[string]string)
	checked := 0
	for _, row := range fixture.Observations {
		for _, change := range row.StateChangesBefore {
			capture(change)
		}
		if !strings.HasPrefix(row.Case, "fresh_selection_") {
			continue
		}
		if row.Operation == "GenerateOrganizationsAccessReport" {
			document, ok := documents[row.Input.OrganizationsPolicyId]
			if !ok {
				t.Fatalf("policy document absent for %s", row.Case)
			}
			jobs[row.Output.JobId] = document
		}
		if row.Operation != "GetOrganizationsAccessReport" || row.Output.JobStatus != "COMPLETED" {
			continue
		}
		checked++
		t.Run(row.Case, func(t *testing.T) {
			document, ok := jobs[row.Input.JobId]
			if !ok {
				t.Fatal("missing selected-policy request")
			}
			grants, apiErr := reportPermissionActions(t.Context(), [][]string{{document}})
			if apiErr != nil {
				t.Fatal(apiErr)
			}
			var expected []string
			for _, entry := range row.Output.AccessDetails {
				expected = append(expected, entry.ServiceNamespace)
			}
			slices.Sort(expected)
			if actual := sortedMapKeys(grants); !slices.Equal(actual, expected) {
				t.Fatalf("services=%v want %v", actual, expected)
			}
		})
	}
	if checked == 0 {
		t.Fatal("fixture has no completed fresh-policy report controls")
	}
}

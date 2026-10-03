package managed

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"stackd/iam/policy"
)

func TestCapturedCatalogueCompleteAndImmutable(t *testing.T) {
	if err := Check(); err != nil {
		t.Fatal(err)
	}
	all := List("aws")
	if len(all) < 1500 {
		t.Fatalf("commercial catalogue has only %d policies", len(all))
	}
	versions := 0
	for _, metadata := range all {
		p, ok := Lookup("aws", metadata.ARN)
		if !ok {
			t.Fatalf("missing %s", metadata.ARN)
		}
		if len(metadata.Versions) != 0 {
			t.Fatal("List leaked document versions")
		}
		versions += len(p.Versions)
		for _, v := range p.Versions {
			// AWS retains historical documents containing misspelled actions;
			// preserve their exact bytes while compiling the effective default.
			if !v.Default {
				continue
			}
			if _, err := policy.Parse([]byte(v.Document)); err != nil {
				t.Errorf("%s %s: %v", p.ARN, v.ID, err)
			}
		}
		p.Versions[0].Document = "corrupt"
		p.VersionsRequestIDs[0] = "corrupt"
		next, _ := Lookup("aws", p.ARN)
		if next.Versions[0].Document == "corrupt" || next.VersionsRequestIDs[0] == "corrupt" {
			t.Fatal("lookup aliases mutable catalogue")
		}
	}
	t.Logf("validated %d policies and %d retained versions", len(all), versions)
	for _, partition := range []string{"aws-cn", "aws-us-gov"} {
		if _, ok := Lookup(partition, "arn:"+partition+":iam::aws:policy/AdministratorAccess"); ok {
			t.Fatalf("uncaptured partition %s received fabricated policies", partition)
		}
		if _, ok := Lookup(partition, "arn:aws:iam::aws:policy/AdministratorAccess"); ok {
			t.Fatal("cross-partition lookup succeeded")
		}
	}
}

func TestARNComponentVariablesAWSReplay(t *testing.T) {
	raw, err := os.ReadFile("testdata/arn_component_variables.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Scenarios []struct {
			Name             string
			Policy           json.RawMessage
			Action, Resource string
			Context          []struct {
				ContextKeyName   string
				ContextKeyValues []string
			}
			Stdout string
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range fixture.Scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			doc, err := policy.Parse(scenario.Policy)
			if err != nil {
				t.Fatal(err)
			}
			context := make(map[string][]string)
			for _, entry := range scenario.Context {
				context[entry.ContextKeyName] = entry.ContextKeyValues
			}
			var observation struct {
				EvaluationResults []struct{ EvalDecision string }
			}
			if err = json.Unmarshal([]byte(scenario.Stdout), &observation); err != nil {
				t.Fatal(err)
			}
			got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: scenario.Action, Resource: scenario.Resource, Context: context})
			if err != nil || string(got) != observation.EvaluationResults[0].EvalDecision {
				t.Fatalf("got %s %v; AWS %s", got, err, observation.EvaluationResults[0].EvalDecision)
			}
		})
	}
}

func TestResourceAccountAcquisitionEvidence(t *testing.T) {
	raw, err := os.ReadFile("testdata/resource_account_value.json")
	if err != nil {
		t.Fatal(err)
	}
	var evidence struct {
		Account string `json:"service_managed_resource_account"`
		Rounds  []struct {
			Round     string
			Scenarios []struct {
				Selector, Decision string
				Pattern            string `json:"resource_account_pattern"`
			}
		}
	}
	if err = json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	value, ok := ResourceAccount("aws")
	if !ok || value != evidence.Account || len(evidence.Rounds) != 14 {
		t.Fatalf("resource account is not backed by complete captured evidence: %q", value)
	}
	for _, round := range evidence.Rounds {
		for _, scenario := range round.Scenarios {
			document, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": map[string]any{"Effect": "Allow", "Action": "iam:GetPolicy", "Resource": "*", "Condition": map[string]any{"StringLike": map[string]string{"aws:ResourceAccount": scenario.Pattern}}}})
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := policy.Parse(document)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := policy.Evaluate([]*policy.Document{compiled}, policy.Request{Action: "iam:GetPolicy", Resource: "arn:aws:iam::aws:policy/AdministratorAccess", Context: map[string][]string{"aws:ResourceAccount": {value}}})
			if err != nil || (decision == policy.Allow) != (scenario.Decision == "allowed") {
				t.Fatalf("%s/%s: %s %v differs from AWS %s", round.Round, scenario.Selector, decision, err, scenario.Decision)
			}
		}
	}
	raw, err = os.ReadFile("testdata/resource_account_families.json")
	if err != nil {
		t.Fatal(err)
	}
	var families struct {
		Account   string `json:"resource_account"`
		Scenarios []struct {
			ARN      string `json:"policy_arn"`
			Decision string
		}
	}
	if err = json.Unmarshal(raw, &families); err != nil {
		t.Fatal(err)
	}
	if families.Account != value || len(families.Scenarios) != 5 {
		t.Fatal("missing policy-family confirmation")
	}
	for _, scenario := range families.Scenarios {
		if scenario.Decision != "allowed" {
			t.Fatalf("resource account not confirmed for %s", scenario.ARN)
		}
	}
	for _, partition := range []string{"aws-cn", "aws-us-gov"} {
		if value, ok := ResourceAccount(partition); ok || value != "" {
			t.Fatal("unobserved partition received fabricated resource account")
		}
	}
}

func TestSnapshotEncodingDeterministic(t *testing.T) {
	catalogues, err := load()
	if err != nil {
		t.Fatal(err)
	}
	s, ok := catalogues["aws"]
	if !ok {
		t.Fatal("commercial snapshot absent")
	}
	a, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("snapshot encoding is nondeterministic")
	}
	decoded, err := Decode(a)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Encode(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, c) {
		t.Fatal("encode/decode changes captured snapshot")
	}
	decoded.Policies[0].Versions[0].Document = strings.ReplaceAll(decoded.Policies[0].Versions[0].Document, "Allow", "Deny") + " "
	if decoded.Validate() == nil {
		t.Fatal("corrupted document hash accepted")
	}
}

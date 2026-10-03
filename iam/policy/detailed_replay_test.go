package policy_test

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"stackd/iam/policy"
)

// Replay only the pure policy-engine projection of the owned AWS fixture. IAM
// service tests cover response composition, source naming, validation and page
// tokens; this test isolates decisions, original source positions and missing
// context so changes cannot drift from the authorization matcher unnoticed.
func TestDetailedAWSFixtureReplay(t *testing.T) {
	data, err := os.ReadFile("../../testdata/aws/iam/simulation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case  string `json:"case"`
			Code  string `json:"code"`
			Input struct {
				PolicyInputList []string
				ContextEntries  []struct {
					ContextKeyName   string
					ContextKeyValues []string
				}
			}
			Output struct {
				EvaluationResults []struct {
					EvalActionName          string
					EvalDecision            policy.Decision
					MatchedStatements       []replayStatement
					MissingContextValues    []string
					ResourceSpecificResults []struct {
						EvalResourceName     string
						EvalResourceDecision policy.Decision
						MatchedStatements    []replayStatement
						MissingContextValues []string
					}
				}
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	cases := 0
	for _, observation := range fixture.Observations {
		selected := strings.HasPrefix(observation.Case, "missing_") || slices.Contains([]string{
			"custom_default_resource", "custom_single_resource", "custom_two_resources_allowed", "custom_two_resources_mixed", "custom_duplicate_resources", "custom_duplicate_actions",
			"custom_allow_two_statements", "custom_deny_overrides_allow", "custom_multiple_policies_allow", "custom_multiple_policies_deny", "custom_pretty_positions", "custom_crlf_positions", "custom_singleton_statement",
			"custom_singleton_pretty_positions", "custom_cr_only_positions", "custom_latin1_positions",
		}, observation.Case)
		if !selected || observation.Code != "Success" {
			continue
		}
		cases++
		t.Run(observation.Case, func(t *testing.T) {
			documents := make([]*policy.Document, 0, len(observation.Input.PolicyInputList))
			for _, text := range observation.Input.PolicyInputList {
				document, err := policy.ParseSimulation([]byte(text))
				if err != nil {
					t.Fatal(err)
				}
				documents = append(documents, document)
			}
			context := map[string][]string{}
			for _, entry := range observation.Input.ContextEntries {
				context[entry.ContextKeyName] = entry.ContextKeyValues
			}
			for _, result := range observation.Output.EvaluationResults {
				if len(result.ResourceSpecificResults) == 0 {
					assertReplayEvaluation(t, documents, policy.Request{Action: result.EvalActionName, Resource: "*", Context: context}, result.EvalDecision, result.MatchedStatements, result.MissingContextValues)
					continue
				}
				for _, resource := range result.ResourceSpecificResults {
					assertReplayEvaluation(t, documents, policy.Request{Action: result.EvalActionName, Resource: resource.EvalResourceName, Context: context}, resource.EvalResourceDecision, resource.MatchedStatements, resource.MissingContextValues)
				}
			}
		})
	}
	if cases < 29 {
		t.Fatalf("replayed only %d cases; expected the complete initial engine observations", cases)
	}
}

type replayStatement struct {
	SourcePolicyID string `json:"SourcePolicyId"`
	StartPosition  policy.Position
	EndPosition    policy.Position
}

func assertReplayEvaluation(t *testing.T, documents []*policy.Document, request policy.Request, wantDecision policy.Decision, wantMatches []replayStatement, wantMissing []string) {
	t.Helper()
	got, err := policy.EvaluateDetailed(documents, request)
	if err != nil || got.Decision != wantDecision {
		t.Fatalf("%s %s: evaluation = %+v, %v; want %s", request.Action, request.Resource, got, err, wantDecision)
	}
	if !slices.Equal(got.MissingContextValues, sortedMissing(wantMissing)) {
		t.Errorf("missing = %q; want %q", got.MissingContextValues, wantMissing)
	}
	var matches []replayStatement
	for _, statement := range got.MatchedStatements {
		if statement.Effect == got.Decision {
			matches = append(matches, replayStatement{SourcePolicyID: fmt.Sprintf("PolicyInputList.%d", statement.DocumentIndex+1), StartPosition: statement.Start, EndPosition: statement.End})
		}
	}
	wantMatches = slices.Clone(wantMatches)
	sortReplayStatements(matches)
	sortReplayStatements(wantMatches)
	if len(matches) != len(wantMatches) || len(matches) > 0 && !reflect.DeepEqual(matches, wantMatches) {
		t.Errorf("matches = %+v; want %+v", matches, wantMatches)
	}
}

func sortedMissing(keys []string) []string {
	keys = slices.Clone(keys)
	slices.Sort(keys)
	return keys
}

func sortReplayStatements(statements []replayStatement) {
	slices.SortFunc(statements, func(a, b replayStatement) int {
		if c := cmp.Compare(a.SourcePolicyID, b.SourcePolicyID); c != 0 {
			return c
		}
		if c := cmp.Compare(a.StartPosition.Line, b.StartPosition.Line); c != 0 {
			return c
		}
		return cmp.Compare(a.StartPosition.Column, b.StartPosition.Column)
	})
}

package codepipeline

import (
	"cmp"
	"context"
	"encoding/json"
	"math"
	"os"
	"slices"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
	"strings"
	"testing"
	"time"
)

// These are response records, not expectations generated from the local filter.
// The source capture retains the unfiltered attempts beside each filtered view.
type nativeHistoryAction struct {
	ActionExecutionID   string  `json:"actionExecutionId"`
	PipelineExecutionID string  `json:"pipelineExecutionId"`
	StageName           string  `json:"stageName"`
	ActionName          string  `json:"actionName"`
	Status              string  `json:"status"`
	PipelineVersion     int32   `json:"pipelineVersion"`
	StartTime           float64 `json:"startTime"`
	LastUpdateTime      float64 `json:"lastUpdateTime"`
}

type nativeHistoryCall struct {
	Label      string          `json:"label"`
	Code       string          `json:"code"`
	Parameters json.RawMessage `json:"parameters"`
	Output     struct {
		Pipeline  api.PipelineDeclaration `json:"pipeline"`
		Actions   []nativeHistoryAction   `json:"actionExecutionDetails"`
		NextToken string                  `json:"nextToken"`
	} `json:"output"`
}

type nativeHistoryCapture struct {
	Complete        bool                `json:"complete"`
	CleanupVerified bool                `json:"cleanup_verified"`
	FirstExecution  string              `json:"first_execution"`
	SecondExecution string              `json:"second_execution"`
	Calls           []nativeHistoryCall `json:"calls"`
	Snapshots       []struct {
		Label     string `json:"label"`
		Execution string `json:"execution"`
	} `json:"snapshots"`
}

func loadNativeHistory(t *testing.T) nativeHistoryCapture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/codepipeline/history_filter_native.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture nativeHistoryCapture
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	if !capture.Complete || !capture.CleanupVerified {
		t.Fatal("native history capture is incomplete or leaked owned resources")
	}
	return capture
}

func (capture nativeHistoryCapture) call(t *testing.T, label string) nativeHistoryCall {
	t.Helper()
	for _, call := range capture.Calls {
		if call.Label == label && call.Code == "Success" {
			return call
		}
	}
	t.Fatalf("missing successful native call %q", label)
	return nativeHistoryCall{}
}

func nativeHistoryTime(seconds float64) time.Time {
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(math.Round(fraction*1000))*int64(time.Millisecond)).UTC()
}

func seedNativeHistory(t *testing.T, capture nativeHistoryCapture, snapshot string) (*Service, context.Context, Pipeline) {
	t.Helper()
	s, ctx, pipeline, definition := kernelFixture(t, "QUEUED")
	definition.Declaration = capture.call(t, "create_pipeline").Output.Pipeline
	definition.Declaration.Name = new(api.PipelineName(pipeline.Name))
	rows := capture.call(t, snapshot+"/all").Output.Actions
	// The repository retains chronological attempts; the API lists newest first.
	slices.SortStableFunc(rows, func(a, b nativeHistoryAction) int {
		return nativeHistoryTime(a.StartTime).Compare(nativeHistoryTime(b.StartTime))
	})
	executions := map[string]*Execution{}
	for _, row := range rows {
		e := executions[row.PipelineExecutionID]
		if e == nil {
			e = &Execution{Scope: pipeline.Scope, PipelineName: pipeline.Name, Incarnation: pipeline.Incarnation,
				ID: row.PipelineExecutionID, Version: row.PipelineVersion, StartedAt: nativeHistoryTime(row.StartTime)}
			executions[e.ID] = e
		}
		stageIndex, actionIndex := -1, -1
		for i, stage := range definition.Declaration.Stages {
			for j, action := range stage.Actions {
				if text(stage.Name) == row.StageName && text(action.Name) == row.ActionName {
					stageIndex, actionIndex = i, j
				}
			}
		}
		if stageIndex < 0 {
			t.Fatalf("native action %s/%s has no retained definition", row.StageName, row.ActionName)
		}
		attempt := int32(1)
		if previous := latestAction(*e, int32(stageIndex), int32(actionIndex)); previous != nil {
			attempt = previous.Attempt + 1
		}
		e.Actions = append(e.Actions, ActionExecution{ID: row.ActionExecutionID, StageName: row.StageName, ActionName: row.ActionName,
			Status: row.Status, StageIndex: int32(stageIndex), ActionIndex: int32(actionIndex), Attempt: attempt,
			StartedAt: nativeHistoryTime(row.StartTime), UpdatedAt: nativeHistoryTime(row.LastUpdateTime)})
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutDefinition(definition); err != nil {
			return err
		}
		for _, e := range executions {
			if err := tx.PutExecution(*e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s, ctx, pipeline
}

func compareNativeHistory(t *testing.T, got api.ActionExecutionDetailList, want []nativeHistoryAction) {
	t.Helper()
	want = slices.Clone(want)
	slices.SortStableFunc(want, func(a, b nativeHistoryAction) int {
		if n := cmp.Compare(b.StartTime, a.StartTime); n != 0 {
			return n
		}
		return cmp.Compare(a.ActionExecutionID, b.ActionExecutionID)
	})
	if len(got) != len(want) {
		t.Fatalf("selected %d actions, native selected %d: %+v", len(got), len(want), got)
	}
	for i, expected := range want {
		actual := got[i]
		if text(actual.ActionExecutionId) != expected.ActionExecutionID || text(actual.PipelineExecutionId) != expected.PipelineExecutionID ||
			text(actual.StageName) != expected.StageName || text(actual.ActionName) != expected.ActionName ||
			text(actual.Status) != expected.Status || int32(value(actual.PipelineVersion)) != expected.PipelineVersion ||
			actual.StartTime == nil || !actual.StartTime.Equal(nativeHistoryTime(expected.StartTime)) {
			t.Fatalf("action %d: got %+v, native %+v", i, actual, expected)
		}
	}
}

func TestActionHistoryNativeFilters(t *testing.T) {
	capture := loadNativeHistory(t)
	for _, snapshot := range capture.Snapshots {
		t.Run(snapshot.Label, func(t *testing.T) {
			s, ctx, pipeline := seedNativeHistory(t, capture, snapshot.Label)
			for _, suffix := range []string{"all", "execution", "All", "Latest"} {
				t.Run(suffix, func(t *testing.T) {
					observed := capture.call(t, snapshot.Label+"/"+suffix)
					var input api.ListActionExecutionsInput
					if err := json.Unmarshal(observed.Parameters, &input); err != nil {
						t.Fatal(err)
					}
					input.PipelineName = new(api.PipelineName(pipeline.Name))
					if err := s.repository.Update(ctx, func(tx Transaction) error {
						result, err := s.listActions(tx, &input)
						if err != nil {
							return err
						}
						compareNativeHistory(t, result.ActionExecutionDetails, observed.Output.Actions)
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestActionHistoryLatestScopeAndDefinition(t *testing.T) {
	capture := loadNativeHistory(t)
	s, ctx, pipeline := seedNativeHistory(t, capture, "later-old")
	input := &api.ListActionExecutionsInput{
		PipelineName: new(api.PipelineName(pipeline.Name)),
		Filter: &api.ActionExecutionFilter{LatestInPipelineExecution: &api.LatestInPipelineExecutionFilter{
			PipelineExecutionId: new(api.PipelineExecutionId(capture.FirstExecution)), StartTimeRange: new(api.StartTimeRange("All")),
		}},
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		retained, err := findDefinition(tx, pipeline, 1)
		if err != nil {
			return err
		}
		changed := retained
		changed.Declaration = CloneDeclaration(retained.Declaration)
		changed.Declaration.Version = new(api.PipelineVersion(2))
		changed.Declaration.Stages = changed.Declaration.Stages[:1]
		pipeline.Version = 2
		if err := tx.PutPipeline(pipeline); err != nil {
			return err
		}
		if err := tx.PutDefinition(changed); err != nil {
			return err
		}
		old, err := findExecution(tx, pipeline, capture.FirstExecution)
		if err != nil {
			return err
		}
		old.ID = "11111111-2222-4333-8444-555555555555"
		old.Incarnation = "deleted-incarnation"
		if err := tx.PutExecution(old); err != nil {
			return err
		}
		result, err := s.listActions(tx, input)
		if err != nil {
			return err
		}
		compareNativeHistory(t, result.ActionExecutionDetails, capture.call(t, "later-old/All").Output.Actions)
		input.Filter.LatestInPipelineExecution.PipelineExecutionId = new(api.PipelineExecutionId(old.ID))
		_, err = s.listActions(tx, input)
		if err == nil || wireError(err).Code != "PipelineExecutionNotFoundException" {
			t.Fatalf("previous incarnation's execution became visible: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []Scope{
		{pipeline.Partition, "999900001111", pipeline.Region},
		{pipeline.Partition, pipeline.AccountID, "eu-west-1"},
	} {
		t.Run(foreign.AccountID+"/"+foreign.Region, func(t *testing.T) {
			foreignContext := scopedContext(ctx, foreign)
			identity := awsctx.FromContext(foreignContext)
			identity.PrincipalARN = "arn:" + foreign.Partition + ":iam::" + foreign.AccountID + ":root"
			identity.PrincipalID = foreign.AccountID
			foreignContext = awsctx.WithMetadata(foreignContext, identity)
			if err := s.repository.Update(foreignContext, func(tx Transaction) error {
				other := pipeline
				other.Scope = foreign
				if err := tx.PutPipeline(other); err != nil {
					return err
				}
				input.Filter.LatestInPipelineExecution.PipelineExecutionId = new(api.PipelineExecutionId(capture.FirstExecution))
				_, err := s.listActions(tx, input)
				if err == nil || wireError(err).Code != "PipelineExecutionNotFoundException" {
					t.Fatalf("foreign execution became visible: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func invokeNativeHistory(s *Service, ctx context.Context, parameters []byte) (*api.ListActionExecutionsOutput, error) {
	decoded, err := api.DecodeRequest("ListActionExecutions", awsapi.Request{JSON: parameters})
	if err != nil {
		return nil, s.RequestError("ListActionExecutions", err)
	}
	output, rejected := s.ExecuteCommand(ctx, decoded)
	if rejected != nil {
		return nil, rejected
	}
	return output.(*api.ListActionExecutionsOutput), nil
}

func TestActionHistoryNativeFilterAdmission(t *testing.T) {
	capture := loadNativeHistory(t)
	s, ctx, pipeline := seedNativeHistory(t, capture, "later-new")
	for _, observed := range capture.Calls {
		if !strings.HasPrefix(observed.Label, "missing-") && !strings.HasPrefix(observed.Label, "both-") &&
			observed.Label != "invalid-range" && observed.Label != "empty-latest" {
			continue
		}
		t.Run(observed.Label, func(t *testing.T) {
			var parameters map[string]json.RawMessage
			if err := json.Unmarshal(observed.Parameters, &parameters); err != nil {
				t.Fatal(err)
			}
			parameters["pipelineName"], _ = json.Marshal(pipeline.Name)
			request, err := json.Marshal(parameters)
			if err != nil {
				t.Fatal(err)
			}
			result, err := invokeNativeHistory(s, ctx, request)
			if observed.Code != "Success" {
				if err == nil || wireError(err).Code != observed.Code {
					t.Fatalf("got %v, native error %s", err, observed.Code)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			compareNativeHistory(t, result.ActionExecutionDetails, observed.Output.Actions)
		})
	}
}

func TestActionHistoryNativePagination(t *testing.T) {
	capture := loadNativeHistory(t)
	s, ctx, pipeline := seedNativeHistory(t, capture, "later-old")
	for _, timeRange := range []string{"All", "Latest"} {
		t.Run(timeRange, func(t *testing.T) {
			input := &api.ListActionExecutionsInput{
				PipelineName: new(api.PipelineName(pipeline.Name)), MaxResults: new(api.MaxResults(1)),
				Filter: &api.ActionExecutionFilter{LatestInPipelineExecution: &api.LatestInPipelineExecutionFilter{
					PipelineExecutionId: new(api.PipelineExecutionId(capture.FirstExecution)), StartTimeRange: new(api.StartTimeRange(timeRange)),
				}},
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				var combined api.ActionExecutionDetailList
				for {
					result, err := s.listActions(tx, input)
					if err != nil {
						return err
					}
					combined = append(combined, result.ActionExecutionDetails...)
					if input.NextToken == nil {
						firstToken := result.NextToken
						foreign := *input
						foreign.NextToken = firstToken
						foreign.Filter = &api.ActionExecutionFilter{LatestInPipelineExecution: &api.LatestInPipelineExecutionFilter{
							PipelineExecutionId: new(api.PipelineExecutionId(capture.SecondExecution)), StartTimeRange: new(api.StartTimeRange(timeRange)),
						}}
						_, err := s.listActions(tx, &foreign)
						if err == nil || wireError(err).Code != "InvalidNextTokenException" {
							t.Fatalf("accepted token from another execution: %v", err)
						}
						if timeRange == "All" {
							equivalent := *input
							equivalent.NextToken = firstToken
							equivalent.Filter = &api.ActionExecutionFilter{PipelineExecutionId: new(api.PipelineExecutionId(capture.FirstExecution))}
							page, err := s.listActions(tx, &equivalent)
							if err != nil {
								return err
							}
							compareNativeHistory(t, page.ActionExecutionDetails, capture.call(t, "page-cross-filter/All").Output.Actions)
						}
					}
					if result.NextToken == nil {
						break
					}
					input.NextToken = result.NextToken
					if len(combined) > 20 {
						t.Fatal("pagination repeated retained actions")
					}
				}
				compareNativeHistory(t, combined, capture.call(t, "later-old/"+timeRange).Output.Actions)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestActionHistoryLatestExcludesUnstartedRetry(t *testing.T) {
	capture := loadNativeHistory(t)
	s, ctx, pipeline := seedNativeHistory(t, capture, "final-retry")
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		e, err := findExecution(tx, pipeline, capture.FirstExecution)
		if err != nil {
			return err
		}
		pending := e.Actions[len(e.Actions)-1]
		pending.ID = "not-yet-started"
		pending.Attempt++
		pending.Status = "Pending"
		pending.StartedAt = time.Time{}
		e.Actions = append(e.Actions, pending)
		if err := tx.PutExecution(e); err != nil {
			return err
		}
		result, err := s.listActions(tx, &api.ListActionExecutionsInput{
			PipelineName: new(api.PipelineName(pipeline.Name)),
			Filter: &api.ActionExecutionFilter{LatestInPipelineExecution: &api.LatestInPipelineExecutionFilter{
				PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), StartTimeRange: new(api.StartTimeRange("Latest")),
			}},
		})
		if err != nil {
			return err
		}
		compareNativeHistory(t, result.ActionExecutionDetails, capture.call(t, "final-retry/Latest").Output.Actions)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestActionHistoryNativeValidationPrecedence(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/codepipeline/history_filter_validation_native.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Calls []struct {
			Label      string          `json:"label"`
			Parameters json.RawMessage `json:"parameters"`
			Output     struct {
				Code string `json:"__type"`
			} `json:"output"`
		} `json:"calls"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	s, ctx, _, _ := kernelFixture(t, "QUEUED")
	for _, observed := range capture.Calls {
		t.Run(observed.Label, func(t *testing.T) {
			_, err := invokeNativeHistory(s, ctx, observed.Parameters)
			if err == nil || wireError(err).Code != observed.Output.Code {
				t.Fatalf("got %v, native error %s", err, observed.Output.Code)
			}
		})
	}
}

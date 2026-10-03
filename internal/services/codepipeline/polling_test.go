package codepipeline

import (
	"context"
	"errors"
	"stackd/clock"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
	"testing"
	"time"
)

type sourceObserverFunc func(context.Context, SourcePollRequest) (string, error)

func (f sourceObserverFunc) LatestSourceRevision(ctx context.Context, r SourcePollRequest) (string, error) {
	return f(ctx, r)
}

func pollingFixture(t *testing.T) (*Service, context.Context, Pipeline, Definition) {
	t.Helper()
	s, ctx, v, d := kernelFixture(t, "SUPERSEDED")
	v.CreatedAt, v.UpdatedAt = s.clock.Now(), s.clock.Now()
	d.Declaration.PipelineType = new(api.PipelineType("V2"))
	d.Declaration.Stages[0].Actions[0].Configuration = api.ActionConfigurationMap{"S3Bucket": "sources", "S3ObjectKey": "source.zip"}
	d.Declaration.Stages[0].Actions[0].OutputArtifacts = api.OutputArtifactList{{Name: new(api.ArtifactName("SourceZip"))}}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutPipeline(v); err != nil {
			return err
		}
		if err := tx.PutDefinition(d); err != nil {
			return err
		}
		if err := s.reconcileSourcePolls(tx, v, d); err != nil {
			return err
		}
		rows, err := tx.SourcePolls(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		rows[0].RevisionID = "original"
		return tx.PutSourcePoll(rows[0])
	}); err != nil {
		t.Fatal(err)
	}
	return s, ctx, v, d
}
func retainedPoll(t *testing.T, s *Service, ctx context.Context, v Pipeline) SourcePoll {
	t.Helper()
	var p SourcePoll
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.SourcePolls(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			t.Fatalf("source cursors: %+v", rows)
		}
		p = rows[0]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return p
}
func pollOnce(t *testing.T, s *Service, ctx context.Context, v Pipeline) error {
	t.Helper()
	return pipelineJobs{s}.Run(ctx, sourcePollJob(retainedPoll(t, s, ctx, v)))
}

func TestSourcePollingConsumesRevisionAndExecutionAtomically(t *testing.T) {
	s, ctx, v, d := pollingFixture(t)
	d.Declaration.Variables = api.PipelineVariableDeclarationList{{Name: new(api.PipelineVariableName("Environment")), DefaultValue: new(api.PipelineVariableValue("production"))}}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDefinition(d) }); err != nil {
		t.Fatal(err)
	}
	observations := 0
	s.sources = sourceObserverFunc(func(effect context.Context, request SourcePollRequest) (string, error) {
		observations++
		// Joining a write here would deadlock if provider observation held the
		// repository transaction; current role authority is evaluated outside it.
		if err := s.repository.Update(effect, func(tx Transaction) error { return nil }); err != nil {
			return "", err
		}
		identity := awsctx.FromContext(effect)
		if identity.PrincipalARN != "" || identity.ServicePrincipal.Name != "codepipeline.amazonaws.com" || request.RoleARN != text(d.Declaration.RoleArn) {
			t.Fatalf("poll borrowed caller authority: %+v %+v", identity, request)
		}
		request.Action.Configuration["S3ObjectKey"] = "mutated-copy"
		return "changed", nil
	})
	rejected := errors.New("event transaction unavailable")
	s.events = rejectingEvents{rejected}
	if err := pollOnce(t, s, ctx, v); !errors.Is(err, rejected) {
		t.Fatalf("poll admission error: %v", err)
	}
	p := retainedPoll(t, s, ctx, v)
	if p.RevisionID != "original" || p.PollID == "" {
		t.Fatalf("failed admission consumed cursor: %+v", p)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if len(rows) != 0 {
			t.Fatalf("failed event retained execution: %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.events = nil
	s.clock.(*clock.Manual).Advance(sourcePollLease)
	if err := pollOnce(t, s, ctx, v); err != nil {
		t.Fatal(err)
	}
	p = retainedPoll(t, s, ctx, v)
	if p.RevisionID != "changed" || p.PollID != "" || observations != 2 {
		t.Fatalf("revision recovery: %+v, observations=%d", p, observations)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			t.Fatalf("recovered executions: %+v", rows)
		}
		e := rows[0]
		if e.TriggerType != "PollForSourceChanges" || len(e.SourceOverrides) != 1 || text(e.SourceOverrides[0].RevisionValue) != "changed" || text(e.SourceOverrides[0].ActionName) != "Source" || len(e.Variables) != 1 || text(e.Variables[0].ResolvedValue) != "production" {
			t.Fatalf("polled admission lost revision/default variables: %+v", e)
		}
		got, _, err := r.Definition(v.Scope, v.Incarnation, v.Version)
		if got.Declaration.Stages[0].Actions[0].Configuration["S3ObjectKey"] != "source.zip" {
			t.Fatal("observer mutated definition")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePollingErrorsCancellationAndClaimRecovery(t *testing.T) {
	for _, mode := range []string{"error", "empty", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			s, ctx, v, _ := pollingFixture(t)
			cancelled, cancel := context.WithCancel(ctx)
			defer cancel()
			var firstID string
			s.sources = sourceObserverFunc(func(_ context.Context, r SourcePollRequest) (string, error) {
				firstID = r.PollID
				switch mode {
				case "error":
					return "untrusted", errors.New("current role denied")
				case "empty":
					return "", nil
				default:
					cancel()
					return "changed", nil
				}
			})
			err := pollOnce(t, s, cancelled, v)
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation: %v", err)
			}
			if mode != "cancel" && err != nil {
				t.Fatal(err)
			}
			p := retainedPoll(t, s, ctx, v)
			if p.RevisionID != "original" || !p.Due.After(s.clock.Now()) {
				t.Fatalf("observation consumed failed revision: %+v", p)
			}
			s.clock.(*clock.Manual).Advance(time.Minute)
			restarted := New(Config{Repository: s.repository, Clock: s.clock, Sources: sourceObserverFunc(func(_ context.Context, r SourcePollRequest) (string, error) {
				if mode == "cancel" && r.PollID != firstID {
					t.Fatal("restart lost durable observation claim")
				}
				return "changed", nil
			})})
			t.Cleanup(func() { restarted.Close() })
			if err := pollOnce(t, restarted, ctx, v); err != nil {
				t.Fatal(err)
			}
			if p := retainedPoll(t, restarted, ctx, v); p.RevisionID != "changed" {
				t.Fatalf("restart failed to recover revision: %+v", p)
			}
		})
	}
}

func TestSourcePollingFencesDefinitionDeletionAndConcurrentClaims(t *testing.T) {
	for _, mutation := range []string{"update", "delete", "recreate", "new-claim"} {
		t.Run(mutation, func(t *testing.T) {
			s, ctx, v, d := pollingFixture(t)
			s.sources = sourceObserverFunc(func(effect context.Context, _ SourcePollRequest) (string, error) {
				err := s.repository.Update(effect, func(tx Transaction) error {
					switch mutation {
					case "update":
						v.Version++
						d.Declaration.Version = new(api.PipelineVersion(v.Version))
						if err := tx.PutDefinition(d); err != nil {
							return err
						}
						if err := tx.PutPipeline(v); err != nil {
							return err
						}
						return s.reconcileSourcePolls(tx, v, d)
					case "delete", "recreate":
						if err := tx.DeletePipeline(v.Scope, v.Name); err != nil {
							return err
						}
						if mutation == "recreate" {
							replacement := v
							replacement.Incarnation = "replacement"
							return tx.PutPipeline(replacement)
						}
						return nil
					default:
						rows, err := tx.SourcePolls(v.Scope, v.Incarnation)
						if err != nil {
							return err
						}
						rows[0].Generation++
						return tx.PutSourcePoll(rows[0])
					}
				})
				return "stale", err
			})
			if err := pollOnce(t, s, ctx, v); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				rows, err := r.Executions(v.Scope, v.Incarnation)
				if len(rows) != 0 {
					t.Fatalf("stale effect admitted execution: %+v", rows)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if mutation == "update" || mutation == "new-claim" {
				if p := retainedPoll(t, s, ctx, v); p.RevisionID != "original" {
					t.Fatalf("stale effect consumed revision: %+v", p)
				}
			}
		})
	}
}

func TestSourcePollingRequiredVariablesAndInactiveDisable(t *testing.T) {
	t.Run("required-variable", func(t *testing.T) {
		s, ctx, v, d := pollingFixture(t)
		d.Declaration.Variables = api.PipelineVariableDeclarationList{{Name: new(api.PipelineVariableName("Required"))}}
		if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDefinition(d) }); err != nil {
			t.Fatal(err)
		}
		s.sources = sourceObserverFunc(func(context.Context, SourcePollRequest) (string, error) { return "changed", nil })
		if err := pollOnce(t, s, ctx, v); err != nil {
			t.Fatal(err)
		}
		if p := retainedPoll(t, s, ctx, v); p.RevisionID != "changed" {
			t.Fatalf("failed execution did not consume observed change: %+v", p)
		}
		if err := s.repository.View(ctx, func(r Reader) error {
			rows, err := r.Executions(v.Scope, v.Incarnation)
			if len(rows) != 1 || rows[0].Status != "Failed" || len(rows[0].Actions) != 0 {
				t.Fatalf("missing variable admitted provider work: %+v", rows)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("inactive", func(t *testing.T) {
		s, ctx, v, _ := pollingFixture(t)
		s.clock.(*clock.Manual).Advance(sourcePollInactive + time.Second)
		s.sources = sourceObserverFunc(func(context.Context, SourcePollRequest) (string, error) {
			t.Fatal("inactive pipeline contacted source")
			return "", nil
		})
		if err := pollOnce(t, s, ctx, v); err != nil {
			t.Fatal(err)
		}
		if p := retainedPoll(t, s, ctx, v); !p.Due.IsZero() || p.RevisionID != "original" {
			t.Fatalf("inactive cursor was not suspended: %+v", p)
		}
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			out, err := s.getPipeline(tx, &api.GetPipelineInput{Name: new(api.PipelineName(v.Name))})
			if err == nil && (out.Metadata.PollingDisabledAt == nil || !out.Metadata.PollingDisabledAt.Equal(s.clock.Now())) {
				t.Fatalf("disabled metadata: %+v", out.Metadata)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSourcePollingOwnsInitialAdmissionAndErrorState(t *testing.T) {
	s, ctx, _, d := pollingFixture(t)
	s.roles = approvalAdmissionRoles{}
	available := false
	s.sources = sourceObserverFunc(func(context.Context, SourcePollRequest) (string, error) {
		if !available {
			return "", failure("ConfigurationError", "Source object is absent")
		}
		return "initial-version", nil
	})
	d.Declaration.Name = new(api.PipelineName("created"))
	var v Pipeline
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.DeletePipeline(d.Scope, "release"); err != nil {
			return err
		}
		if _, err := s.createPipeline(tx, &api.CreatePipelineInput{Pipeline: &d.Declaration}); err != nil {
			return err
		}
		var err error
		v, err = findPipeline(tx, d.Scope, "created")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := pollOnce(t, s, ctx, v); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.Executions(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			t.Fatalf("missing initial source admitted an execution: %+v", rows)
		}
		out, err := s.getState(tx, &api.GetPipelineStateInput{Name: new(api.PipelineName(v.Name))})
		if err != nil {
			return err
		}
		stage := out.StageStates[0]
		action := stage.ActionStates[0]
		if stage.LatestExecution != nil || action.CurrentRevision != nil || action.LatestExecution == nil ||
			text(action.LatestExecution.Status) != "Failed" || action.LatestExecution.ActionExecutionId != nil ||
			action.LatestExecution.ErrorDetails == nil || text(action.LatestExecution.ErrorDetails.Code) != "ConfigurationError" {
			t.Fatalf("initial source failure fabricated execution identity: %+v", out)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	available = true
	s.clock.(*clock.Manual).Advance(sourcePollInterval)
	if err := pollOnce(t, s, ctx, v); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.Executions(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].TriggerType != "PollForSourceChanges" || rows[0].TriggerDetail != "Source" ||
			len(rows[0].SourceOverrides) != 1 || text(rows[0].SourceOverrides[0].RevisionValue) != "initial-version" {
			t.Fatalf("initial polling attribution/revision: %+v", rows)
		}
		_, err = s.stopPipeline(tx, &api.StopPipelineExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(rows[0].ID)), Abandon: new(api.Boolean(true))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.clock.(*clock.Manual).Advance(sourcePollInterval)
	if err := pollOnce(t, s, ctx, v); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if len(rows) != 1 {
			t.Fatalf("unchanged initial revision was admitted twice: %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePollingIndependentActionsAndDeadlineFairness(t *testing.T) {
	s, ctx, v, d := pollingFixture(t)
	second := CloneDeclaration(d.Declaration).Stages[0].Actions[0]
	second.Name = new(api.ActionName("Other"))
	second.Configuration["S3ObjectKey"] = "other.zip"
	second.OutputArtifacts[0].Name = new(api.ArtifactName("OtherZip"))
	d.Declaration.Stages[0].Actions = append(d.Declaration.Stages[0].Actions, second)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutDefinition(d); err != nil {
			return err
		}
		if err := s.reconcileSourcePolls(tx, v, d); err != nil {
			return err
		}
		rows, err := tx.SourcePolls(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		for _, p := range rows {
			p.RevisionID = "original-" + p.ActionName
			p.Due = s.clock.Now().Add(-time.Second)
			if err := tx.PutSourcePoll(p); err != nil {
				return err
			}
		}
		e := gateExecution(s, v, "waiting-execution", "SUPERSEDED", 1)
		return tx.PutExecution(e)
	}); err != nil {
		t.Fatal(err)
	}
	s.sources = sourceObserverFunc(func(_ context.Context, request SourcePollRequest) (string, error) {
		return "changed-" + text(request.Action.Name), nil
	})
	for range 2 {
		selected, found, err := (pipelineJobs{s}).Next(ctx)
		if err != nil || !found {
			t.Fatalf("next source work: %v %v", found, err)
		}
		if !selected.Due.Before(s.clock.Now()) {
			t.Fatalf("execution work starved overdue source: %+v", selected)
		}
		if err := (pipelineJobs{s}).Run(ctx, selected); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		polls, err := r.SourcePolls(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		for _, p := range polls {
			if p.RevisionID != "changed-"+p.ActionName {
				t.Fatalf("source cursor was shared: %+v", polls)
			}
		}
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		overrides := map[string]string{}
		for _, e := range rows {
			if e.TriggerType == "PollForSourceChanges" {
				if len(e.SourceOverrides) != 1 {
					t.Fatalf("poll bound unrelated source actions: %+v", e)
				}
				overrides[text(e.SourceOverrides[0].ActionName)] = text(e.SourceOverrides[0].RevisionValue)
			}
		}
		if len(overrides) != 2 || overrides["Source"] != "changed-Source" || overrides["Other"] != "changed-Other" {
			t.Fatalf("independent changes lost execution ownership: %+v", overrides)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePollingEnableDoesNotReuseExplicitExecutionBaseline(t *testing.T) {
	s, ctx, _, d := pollingFixture(t)
	s.roles = approvalAdmissionRoles{}
	s.sources = sourceObserverFunc(func(context.Context, SourcePollRequest) (string, error) { return "same-version", nil })
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		return ActionResult{Status: "Succeeded", Revision: &SourceRevision{RevisionID: "same-version"}, Artifacts: request.OutputArtifacts}, nil
	})
	d.Declaration.Name = new(api.PipelineName("disabled"))
	d.Declaration.Stages[0].Actions[0].Configuration["PollForSourceChanges"] = "false"
	var v Pipeline
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.DeletePipeline(d.Scope, "release"); err != nil {
			return err
		}
		if _, err := s.createPipeline(tx, &api.CreatePipelineInput{Pipeline: &d.Declaration}); err != nil {
			return err
		}
		var err error
		v, err = findPipeline(tx, d.Scope, "disabled")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.JobDriver().RunDue(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.Executions(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].TriggerType != "CreatePipeline" || len(rows[0].Revisions) != 1 || rows[0].Revisions[0].RevisionID != "same-version" {
			t.Fatalf("nonpolling creation did not execute initial source: %+v", rows)
		}
		if _, err = s.stopPipeline(tx, &api.StopPipelineExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(rows[0].ID)), Abandon: new(api.Boolean(true))}); err != nil {
			return err
		}
		d.Declaration.Stages[0].Actions[0].Configuration["PollForSourceChanges"] = "true"
		if _, err = s.updatePipeline(tx, &api.UpdatePipelineInput{Pipeline: &d.Declaration}); err != nil {
			return err
		}
		v, err = findPipeline(tx, d.Scope, v.Name)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := pollOnce(t, s, ctx, v); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if len(rows) != 2 || rows[1].TriggerType != "PollForSourceChanges" || rows[1].Version != 2 ||
			len(rows[1].SourceOverrides) != 1 || text(rows[1].SourceOverrides[0].RevisionValue) != "same-version" {
			t.Fatalf("enabling polling lost same-version initial observation: %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePollingDefinitionUpdatesRetainCursorAndDetectNewLocation(t *testing.T) {
	s, ctx, v, d := pollingFixture(t)
	s.roles = approvalAdmissionRoles{}
	s.sources = sourceObserverFunc(func(_ context.Context, r SourcePollRequest) (string, error) {
		if r.Action.Configuration["S3ObjectKey"] == "replacement.zip" {
			return "replacement-version", nil
		}
		return "original", nil
	})
	update := func(flag, key string) {
		t.Helper()
		d.Declaration.Stages[0].Actions[0].Configuration["PollForSourceChanges"] = api.ActionConfigurationValue(flag)
		d.Declaration.Stages[0].Actions[0].Configuration["S3ObjectKey"] = api.ActionConfigurationValue(key)
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			if _, err := s.updatePipeline(tx, &api.UpdatePipelineInput{Pipeline: &d.Declaration}); err != nil {
				return err
			}
			var err error
			v, err = findPipeline(tx, v.Scope, v.Name)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	update("true", "source.zip")
	if err := pollOnce(t, s, ctx, v); err != nil {
		t.Fatal(err)
	}
	update("false", "source.zip")
	if p := retainedPoll(t, s, ctx, v); !p.Due.IsZero() || p.RevisionID != "original" {
		t.Fatalf("disabling polling lost consumed revision: %+v", p)
	}
	update("true", "source.zip")
	if err := pollOnce(t, s, ctx, v); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if len(rows) != 0 {
			t.Fatalf("unchanged updates restarted consumed source: %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	update("true", "replacement.zip")
	if err := pollOnce(t, s, ctx, v); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if len(rows) != 1 || rows[0].Version != v.Version || len(rows[0].SourceOverrides) != 1 ||
			text(rows[0].SourceOverrides[0].RevisionValue) != "replacement-version" {
			t.Fatalf("new source location was not observed using updated definition: %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePollingInactivityUsesExecutionsNotObservationAttempts(t *testing.T) {
	for _, recentExecution := range []bool{false, true} {
		t.Run(map[bool]string{false: "thirty-day-boundary", true: "recent-execution"}[recentExecution], func(t *testing.T) {
			s, ctx, v, _ := pollingFixture(t)
			elapsed := sourcePollInactive
			if recentExecution {
				elapsed += 24 * time.Hour
			}
			s.clock.(*clock.Manual).Advance(elapsed)
			if recentExecution {
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					return tx.PutExecution(Execution{Scope: v.Scope, PipelineName: v.Name, Incarnation: v.Incarnation,
						ID: "recent", Version: v.Version, Status: "Failed", StartedAt: s.clock.Now().Add(-time.Hour)})
				}); err != nil {
					t.Fatal(err)
				}
			}
			observed := false
			s.sources = sourceObserverFunc(func(context.Context, SourcePollRequest) (string, error) { observed = true; return "original", nil })
			if err := pollOnce(t, s, ctx, v); err != nil {
				t.Fatal(err)
			}
			if !observed {
				t.Fatal("eligible pipeline was disabled at the boundary or despite a recent execution")
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				got, err := findPipeline(r, v.Scope, v.Name)
				if !got.PollingDisabledAt.IsZero() {
					t.Fatalf("active polling recorded disabled metadata: %+v", got)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSourcePollingFlagAdmissionUsesNativeEffectiveMode(t *testing.T) {
	for _, tc := range []struct {
		name, flag string
		enabled    bool
	}{
		{"omitted", "", true}, {"true", "true", true}, {"mixed-true", "True", true},
		{"false", "false", false}, {"mixed-false", "False", false}, {"yes", "yes", false}, {"one", "1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx, _, d := pollingFixture(t)
			s.roles = approvalAdmissionRoles{}
			d.Declaration.Name = new(api.PipelineName("flag-control"))
			if tc.flag != "" {
				d.Declaration.Stages[0].Actions[0].Configuration["PollForSourceChanges"] = api.ActionConfigurationValue(tc.flag)
			}
			s.sources = nil
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.admitDefinition(tx, &d.Declaration, 1)
				if tc.enabled {
					if err == nil || wireError(err).Code != "NotImplementedException" {
						t.Fatalf("missing observer silently admitted enabled polling: %v", err)
					}
					return nil
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			s.sources = sourceObserverFunc(func(context.Context, SourcePollRequest) (string, error) { return "initial-version", nil })
			var v Pipeline
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.DeletePipeline(d.Scope, "release"); err != nil {
					return err
				}
				if _, err := s.createPipeline(tx, &api.CreatePipelineInput{Pipeline: &d.Declaration}); err != nil {
					return err
				}
				var err error
				v, err = findPipeline(tx, d.Scope, "flag-control")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if tc.enabled {
				if err := pollOnce(t, s, ctx, v); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				rows, err := r.Executions(v.Scope, v.Incarnation)
				if err != nil {
					return err
				}
				trigger := "CreatePipeline"
				if tc.enabled {
					trigger = "PollForSourceChanges"
				}
				if len(rows) != 1 || rows[0].TriggerType != trigger {
					t.Fatalf("flag %q effective mode: %+v", tc.flag, rows)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

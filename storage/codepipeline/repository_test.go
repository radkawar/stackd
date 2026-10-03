package codepipeline_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"stackd/clock"
	api "stackd/internal/awsapi/codepipeline"
	service "stackd/internal/services/codepipeline"
	domain "stackd/storage/codepipeline"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlrepo "stackd/storage/sqlite/codepipeline"
	"testing"
	"time"
)

func TestPipelineArtifactOwnershipRollbackAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			var repo domain.Repository
			var reopen func()
			if backend == "memory" {
				repo = domain.NewMemory(memory.NewDomain())
				reopen = func() {}
			} else {
				path := filepath.Join(t.TempDir(), "pipeline.db")
				var db *sql.DB
				open := func() {
					var err error
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repo = sqlrepo.New(db)
				}
				open()
				reopen = func() {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					open()
				}
				t.Cleanup(func() { db.Close() })
			}
			sc := domain.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}
			now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
			v := domain.Pipeline{Scope: sc, Name: "release", Incarnation: "original", Version: 1, Tags: map[string]string{"team": "payments"}, CreatedAt: now, UpdatedAt: now}
			decl := api.ActionDeclaration{Name: new(api.ActionName("Deploy")), ActionTypeId: &api.ActionTypeId{Provider: new(api.ActionProvider("AppConfig")), Category: new(api.ActionCategory("Deploy")), Owner: new(api.ActionOwner("AWS")), Version: new(api.Version("1"))}, RunOrder: new(api.ActionRunOrder(1)), Configuration: api.ActionConfigurationMap{"InputArtifactConfigurationPath": "#{Source.Member}"}, InputArtifacts: api.InputArtifactList{{Name: new(api.ArtifactName("Configuration"))}}}
			d := domain.Definition{Scope: sc, Incarnation: v.Incarnation, Declaration: api.PipelineDeclaration{Name: new(api.PipelineName(v.Name)), Version: new(api.PipelineVersion(1)), RoleArn: new(api.RoleArn("arn:aws:iam::111122223333:role/pipeline")), ExecutionMode: new(api.ExecutionMode("SUPERSEDED")), PipelineType: new(api.PipelineType("V1")), ArtifactStore: &api.ArtifactStore{Location: new(api.ArtifactStoreLocation("artifacts")), Type: new(api.ArtifactStoreType("S3"))}, Stages: api.PipelineStageDeclarationList{{Name: new(api.StageName("Deploy")), Actions: api.StageActionDeclarationList{decl}}}}}
			e := domain.Execution{Scope: sc, PipelineName: v.Name, Incarnation: v.Incarnation, ID: "execution", Version: 1, Mode: "SUPERSEDED", Status: "InProgress", StageEntered: true, StartedAt: now, UpdatedAt: now, Due: now, Generation: 3, Sequence: 1, SourceOverrides: api.SourceRevisionOverrideList{{ActionName: new(api.ActionName("Source")), RevisionType: new(api.SourceRevisionType("S3_OBJECT_KEY")), RevisionValue: new(api.Revision("override.zip"))}}, Actions: []domain.ActionExecution{{ID: "deploy-action", StageName: "Deploy", ActionName: "Deploy", Status: "InProgress", StartedAt: now, UpdatedAt: now, Attempt: 1, ResolvedConfiguration: api.ActionConfigurationMap{"InputArtifactConfigurationPath": "nested/settings.json"}, OutputVariables: api.OutputVariablesMap{"Example": "retained"}, InputArtifacts: []domain.Artifact{{Name: "Configuration", Bucket: "artifacts", Key: "release/Config/source-action", VersionID: "artifact-version", RevisionID: "original-source-version", ActionExecutionID: "source-action"}}}}}
			d.Declaration.PipelineType = new(api.PipelineType("V2"))
			d.Declaration.Variables = api.PipelineVariableDeclarationList{
				{Name: new(api.PipelineVariableName("Target")), DefaultValue: new(api.PipelineVariableValue("staging")), Description: new(api.PipelineVariableDescription(""))},
				{Name: new(api.PipelineVariableName("Required"))},
				{Name: new(api.PipelineVariableName("Empty")), DefaultValue: new(api.PipelineVariableValue(""))},
			}
			e.Variables = api.ResolvedPipelineVariableList{
				{Name: new(api.String("Target")), ResolvedValue: new(api.String("production"))},
				{Name: new(api.String("Required")), ResolvedValue: new(api.String("release-42"))},
				{Name: new(api.String("Empty")), ResolvedValue: new(api.String(""))},
			}
			e.ClientToken = "retained-token"
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				if err := tx.PutPipeline(v); err != nil {
					return err
				}
				if err := tx.PutDefinition(d); err != nil {
					return err
				}
				return tx.PutExecution(e)
			}); err != nil {
				t.Fatal(err)
			}
			e.Attempt = 3
			e.StageStatus = "RESUMED"
			e.StageStartedAt = now
			e.LastRetryAt = now.Add(time.Minute)
			e.StageLastRetryAt = e.LastRetryAt
			e.Actions[0].UpdatedBy = "arn:aws:iam::111122223333:user/releaser"
			e.Actions[0].Status = "Failed"
			// Retry IDs need not sort after the original action. The scheduler
			// selects the last attempt, including a not-yet-started retry.
			e.Actions = append(e.Actions, domain.ActionExecution{
				ID: "aaa-retry", StageName: "Deploy", ActionName: "Deploy",
				Status: "Pending", Attempt: 2,
			})
			if err := repo.Update(ctx, func(tx domain.Transaction) error { return tx.PutExecution(e) }); err != nil {
				t.Fatal(err)
			}
			next := d
			next.Declaration = service.CloneDeclaration(d.Declaration)
			next.Declaration.Version = new(api.PipelineVersion(2))
			*next.Declaration.Variables[0].DefaultValue = "development"
			if err := repo.Update(ctx, func(tx domain.Transaction) error { return tx.PutDefinition(next) }); err != nil {
				t.Fatal(err)
			}
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				next.Declaration.Version = new(api.PipelineVersion(3))
				next.Declaration.Variables = api.PipelineVariableDeclarationList{}
				if err := tx.PutDefinition(next); err != nil {
					return err
				}
				next.Declaration.Version = new(api.PipelineVersion(4))
				next.Declaration.Variables = nil
				return tx.PutDefinition(next)
			}); err != nil {
				t.Fatal(err)
			}
			*d.Declaration.Variables[0].DefaultValue = "mutated-write"
			*d.Declaration.Variables[0].Name = "mutated-write"
			*d.Declaration.Variables[0].Description = "mutated-write"
			*e.Variables[0].ResolvedValue = "mutated-write"
			*e.Variables[0].Name = "mutated-write"
			v.Tags["team"] = "mutated"
			d.Declaration.Stages[0].Actions[0].Configuration["InputArtifactConfigurationPath"] = "wrong"
			e.Actions[0].InputArtifacts[0].Key = "wrong"
			e.Actions[0].ResolvedConfiguration["InputArtifactConfigurationPath"] = "wrong"
			assertRetained := func() {
				t.Helper()
				request, ok, err := service.ResolveDeployment(ctx, repo, sc, "release", "deploy-action")
				if err != nil || !ok {
					t.Fatalf("retained lookup: %+v %v %v", request, ok, err)
				}
				a := request.InputArtifacts[0]
				if a.Key != "release/Config/source-action" || a.VersionID != "artifact-version" || a.RevisionID != "original-source-version" || request.Action.Configuration["InputArtifactConfigurationPath"] != "nested/settings.json" {
					t.Fatalf("artifact ownership or resolved member changed: %+v", request)
				}
				request.InputArtifacts[0].Key = "mutated-read"
				request.Action.Configuration["InputArtifactConfigurationPath"] = "mutated-read"
				if err := repo.View(ctx, func(r domain.Reader) error {
					rows, err := r.Executions(sc, "original")
					if err != nil {
						return err
					}
					if len(rows) != 1 || rows[0].Attempt != 3 || rows[0].StageStatus != "RESUMED" {
						t.Fatalf("stage/attempt history was lost: %+v", rows)
					}
					retained := rows[0]
					if len(retained.Variables) != 3 || *retained.Variables[0].Name != "Target" || *retained.Variables[0].ResolvedValue != "production" || *retained.Variables[1].Name != "Required" || *retained.Variables[1].ResolvedValue != "release-42" || *retained.Variables[2].ResolvedValue != "" {
						t.Fatalf("execution variable order or binding changed: %+v", retained.Variables)
					}
					*retained.Variables[0].ResolvedValue = "mutated-read"
					*retained.Variables[0].Name = "mutated-read"
					definition, ok, err := r.Definition(sc, "original", 1)
					if err != nil || !ok {
						t.Fatalf("original variable definition: %v %v", ok, err)
					}
					variables := definition.Declaration.Variables
					if len(variables) != 3 || *variables[0].Name != "Target" || *variables[0].DefaultValue != "staging" || variables[0].Description == nil || *variables[0].Description != "" || variables[1].DefaultValue != nil || variables[1].Description != nil || variables[2].DefaultValue == nil || *variables[2].DefaultValue != "" {
						t.Fatalf("declaration order or optional values changed: %+v", variables)
					}
					*variables[0].Name = "mutated-read"
					*variables[0].DefaultValue = "mutated-read"
					*variables[0].Description = "mutated-read"
					definition, ok, err = r.Definition(sc, "original", 2)
					if err != nil || !ok || *definition.Declaration.Variables[0].DefaultValue != "development" {
						t.Fatalf("updated definition was not independently retained: %+v %v %v", definition, ok, err)
					}
					for _, version := range []int32{3, 4} {
						definition, ok, err = r.Definition(sc, "original", version)
						if err != nil || !ok || len(definition.Declaration.Variables) != 0 || (definition.Declaration.Variables == nil) != (version == 4) {
							t.Fatalf("empty versus omitted declarations changed at version %d: %+v %v %v", version, definition, ok, err)
						}
					}
					if retained.ClientToken != "retained-token" {
						t.Fatalf("retained execution token changed: %q", retained.ClientToken)
					}
					if len(retained.Actions) != 2 || retained.Actions[0].Status != "Failed" || retained.Actions[1].Attempt != 2 || retained.Actions[1].Status != "Pending" {
						t.Fatalf("retry no longer follows its failed attempt: %+v", retained.Actions)
					}
					if !retained.StageStartedAt.Equal(now) || !retained.LastRetryAt.Equal(now.Add(time.Minute)) || !retained.StageLastRetryAt.Equal(retained.LastRetryAt) {
						t.Fatalf("stage retry timestamps changed across persistence: %+v", retained)
					}
					if retained.Actions[0].UpdatedBy != "arn:aws:iam::111122223333:user/releaser" {
						t.Fatalf("action submitter was lost across persistence: %+v", retained.Actions[0])
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			assertRetained()
			assertRetained()
			rejected := errors.New("abort")
			err := repo.Update(ctx, func(tx domain.Transaction) error {
				rows, err := tx.Executions(sc, "original")
				if err != nil {
					return err
				}
				rows[0].Actions[0].InputArtifacts[0].Key = "rolled-back"
				*rows[0].Variables[0].ResolvedValue = "rolled-back"
				if err = tx.PutExecution(rows[0]); err != nil {
					return err
				}
				return rejected
			})
			if !errors.Is(err, rejected) {
				t.Fatal(err)
			}
			assertRetained()
			other := sc
			other.AccountID = "444455556666"
			if _, ok, err := service.ResolveDeployment(ctx, repo, other, "release", "deploy-action"); err != nil || ok {
				t.Fatalf("cross-account artifact reference leaked: %v %v", ok, err)
			}
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				if err := tx.DeletePipeline(sc, "release"); err != nil {
					return err
				}
				v.Incarnation = "replacement"
				v.Tags = map[string]string{}
				return tx.PutPipeline(v)
			}); err != nil {
				t.Fatal(err)
			}
			reopen()
			assertRetained()
			if _, ok, err := service.ResolveAction(ctx, repo, sc, "deploy-action"); err != nil || ok {
				t.Fatalf("deleted incarnation retained live authority: %v %v", ok, err)
			}
			if err := repo.View(ctx, func(r domain.Reader) error {
				pending, err := r.PendingExecutions()
				if err != nil {
					return err
				}
				if len(pending) != 0 {
					t.Fatalf("deleted incarnation kept scheduler work: %+v", pending)
				}
				rows, err := r.Executions(sc, "replacement")
				if len(rows) != 0 {
					t.Fatal("replacement exposed prior execution")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPipelineCommandSavepoint(t *testing.T) {
	ctx := context.Background()
	repo := domain.NewMemory(memory.NewDomain())
	sc := domain.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}
	rejected := errors.New("attempt")
	if err := repo.Update(ctx, func(tx domain.Transaction) error {
		v := domain.Pipeline{Scope: sc, Name: "pipeline", Incarnation: "one", Tags: map[string]string{"before": "yes"}}
		if err := tx.PutPipeline(v); err != nil {
			return err
		}
		err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
			v.Tags["before"] = "no"
			if err := child.PutPipeline(v); err != nil {
				return err
			}
			return rejected
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("attempt error %v", err)
		}
		rows, err := tx.Pipelines(sc)
		if err != nil {
			return err
		}
		if rows[0].Tags["before"] != "yes" {
			t.Fatal("failed command mutated enclosing transaction")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type approvalNotificationExecutor func(context.Context, service.ActionRequest) (service.ActionResult, error)

func (f approvalNotificationExecutor) Execute(ctx context.Context, request service.ActionRequest) (service.ActionResult, error) {
	return f(ctx, request)
}

func TestApprovalNotificationPublicationSurvivesSQLiteReopen(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "approval.db")
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	manual := clock.NewManual(now)
	var db *sql.DB
	var repo domain.Repository
	open := func() {
		t.Helper()
		var err error
		db, err = sqlite.Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		repo = sqlrepo.New(db)
	}
	open()
	t.Cleanup(func() { db.Close() })
	sc := domain.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}
	v := domain.Pipeline{Scope: sc, Name: "release", Incarnation: "original", Version: 1}
	configuration := api.ActionConfigurationMap{"NotificationArn": "arn:aws:sns:us-east-1:111122223333:approvals"}
	declaration := api.ActionDeclaration{
		Name: new(api.ActionName("Review")), RunOrder: new(api.ActionRunOrder(1)),
		ActionTypeId:  &api.ActionTypeId{Provider: new(api.ActionProvider("Manual")), Category: new(api.ActionCategory("Approval")), Owner: new(api.ActionOwner("AWS")), Version: new(api.Version("1"))},
		Configuration: configuration, TimeoutInMinutes: new(api.ActionTimeout(5)),
	}
	d := domain.Definition{Scope: sc, Incarnation: v.Incarnation, Declaration: api.PipelineDeclaration{
		Name: new(api.PipelineName(v.Name)), Version: new(api.PipelineVersion(1)),
		RoleArn:       new(api.RoleArn("arn:aws:iam::111122223333:role/pipeline")),
		ArtifactStore: &api.ArtifactStore{Type: new(api.ArtifactStoreType("S3")), Location: new(api.ArtifactStoreLocation("artifacts"))},
		Stages:        api.PipelineStageDeclarationList{{Name: new(api.StageName("Gate")), Actions: api.StageActionDeclarationList{declaration}}},
	}}
	e := domain.Execution{Scope: sc, PipelineName: v.Name, Incarnation: v.Incarnation, ID: "execution", Version: 1, Mode: "SUPERSEDED", Status: "InProgress", StageEntered: true, StartedAt: now, UpdatedAt: now, Due: now, Generation: 1, Sequence: 1, Actions: []domain.ActionExecution{{
		ID: "approval", StageName: "Gate", ActionName: "Review", Status: "InProgress", Attempt: 1,
		StartedAt: now, UpdatedAt: now, ApprovalToken: "approval", ResolvedConfiguration: configuration,
	}}}
	if err := repo.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutPipeline(v); err != nil {
			return err
		}
		if err := tx.PutDefinition(d); err != nil {
			return err
		}
		return tx.PutExecution(e)
	}); err != nil {
		t.Fatal(err)
	}
	publications := 0
	executor := approvalNotificationExecutor(func(context.Context, service.ActionRequest) (service.ActionResult, error) {
		publications++
		return service.ActionResult{Status: "InProgress", ApprovalNotificationID: "sns-message"}, nil
	})
	s := service.New(service.Config{Repository: repo, Clock: manual, Executor: executor})
	if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	open()
	s = service.New(service.Config{Repository: repo, Clock: manual, Executor: executor})
	t.Cleanup(func() { s.Close() })
	if err := manual.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
		t.Fatal(err)
	}
	assertAction := func(status string) {
		t.Helper()
		if err := repo.View(ctx, func(r domain.Reader) error {
			rows, err := r.Executions(sc, v.Incarnation)
			if err != nil {
				return err
			}
			if len(rows) != 1 || len(rows[0].Actions) != 1 {
				t.Fatalf("retained approval missing after reopen: %+v", rows)
			}
			action := rows[0].Actions[0]
			if action.ApprovalNotificationID != "sns-message" || action.ExternalExecutionID != "" || action.Status != status {
				t.Fatalf("publication ownership/status lost after reopen: %+v", action)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if publications != 1 {
			t.Fatalf("reopened approval published %d notifications", publications)
		}
	}
	assertAction("InProgress")
	if err := manual.Advance(5 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
		t.Fatal(err)
	}
	assertAction("Failed")
}

func TestSourcePollCursorIsolationRollbackAndReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			var repo domain.Repository
			reopen := func() {}
			if backend == "memory" {
				repo = domain.NewMemory(memory.NewDomain())
			} else {
				path := filepath.Join(t.TempDir(), "polling.db")
				var db *sql.DB
				open := func() {
					var err error
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repo = sqlrepo.New(db)
				}
				open()
				reopen = func() {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					open()
				}
				t.Cleanup(func() { db.Close() })
			}
			sc := domain.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}
			now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
			v := domain.Pipeline{Scope: sc, Name: "release", Incarnation: "original", Version: 3, CreatedAt: now, UpdatedAt: now, PollingDisabledAt: now.Add(time.Hour)}
			p := domain.SourcePoll{Scope: sc, PipelineName: v.Name, Incarnation: v.Incarnation, PipelineVersion: v.Version, StageName: "Sources", ActionName: "First", Bucket: "sources", ObjectKey: "first.zip", RevisionID: "consumed", PollID: "in-flight", ParentEventID: "update-event", Generation: 17, Due: now.Add(30 * time.Second)}
			p.ErrorCode, p.ErrorMessage, p.LastAttempt = "ConfigurationError", "Missing source", now.Add(-time.Minute)
			second := p
			second.ActionName, second.ObjectKey, second.RevisionID, second.PollID = "Second", "second.zip", "independent", ""
			second.Due = time.Time{}
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				if err := tx.PutPipeline(v); err != nil {
					return err
				}
				if err := tx.PutSourcePoll(p); err != nil {
					return err
				}
				return tx.PutSourcePoll(second)
			}); err != nil {
				t.Fatal(err)
			}
			assertRetained := func() {
				t.Helper()
				if err := repo.View(ctx, func(r domain.Reader) error {
					rows, err := r.SourcePolls(sc, v.Incarnation)
					if err != nil {
						return err
					}
					if len(rows) != 2 || rows[0] != p || rows[1] != second {
						t.Fatalf("independent source cursors changed: %+v", rows)
					}
					rows[0].RevisionID = "mutated-read"
					pending, err := r.PendingSourcePolls()
					if err != nil {
						return err
					}
					if len(pending) != 1 || pending[0] != p {
						t.Fatalf("inactive cursor was scheduled or lease lost: %+v", pending)
					}
					pipelines, err := r.Pipelines(sc)
					if err != nil {
						return err
					}
					if len(pipelines) != 1 || !pipelines[0].PollingDisabledAt.Equal(v.PollingDisabledAt) {
						t.Fatalf("disabled timestamp was lost: %+v", pipelines)
					}
					for _, other := range []domain.Scope{
						{Partition: "aws-cn", AccountID: sc.AccountID, Region: sc.Region},
						{Partition: sc.Partition, AccountID: "444455556666", Region: sc.Region},
						{Partition: sc.Partition, AccountID: sc.AccountID, Region: "us-west-2"},
					} {
						hidden, err := r.SourcePolls(other, v.Incarnation)
						if err != nil {
							return err
						}
						if len(hidden) != 0 {
							t.Fatalf("cursor leaked across scope: %+v", hidden)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			assertRetained()
			assertRetained()
			rejected := errors.New("rollback cursor and execution")
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				changed := p
				changed.RevisionID, changed.Generation = "uncommitted", p.Generation+1
				if err := tx.PutSourcePoll(changed); err != nil {
					return err
				}
				e := domain.Execution{Scope: sc, PipelineName: v.Name, Incarnation: v.Incarnation, ID: "not-admitted", Version: v.Version, Status: "InProgress", StartedAt: now, Due: now}
				if err := tx.PutExecution(e); err != nil {
					return err
				}
				return rejected
			}); !errors.Is(err, rejected) {
				t.Fatal(err)
			}
			reopen()
			assertRetained()
			if err := repo.View(ctx, func(r domain.Reader) error {
				rows, err := r.Executions(sc, v.Incarnation)
				if len(rows) != 0 {
					t.Fatalf("rollback left execution without consumed cursor: %+v", rows)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				if err := tx.DeletePipeline(sc, v.Name); err != nil {
					return err
				}
				replacement := v
				replacement.Incarnation = "replacement"
				return tx.PutPipeline(replacement)
			}); err != nil {
				t.Fatal(err)
			}
			reopen()
			if err := repo.View(ctx, func(r domain.Reader) error {
				old, err := r.SourcePolls(sc, v.Incarnation)
				if err != nil {
					return err
				}
				pending, err := r.PendingSourcePolls()
				if len(old) != 0 || len(pending) != 0 {
					t.Fatalf("delete/recreate retained old observation authority: %+v %+v", old, pending)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

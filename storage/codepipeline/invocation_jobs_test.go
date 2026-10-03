package codepipeline_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	api "stackd/internal/awsapi/codepipeline"
	domain "stackd/storage/codepipeline"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlrepo "stackd/storage/sqlite/codepipeline"
)

func TestInvocationJobIsolationRollbackAndContinuationReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			var repo domain.Repository
			reopen := func() {}
			if backend == "memory" {
				repo = domain.NewMemory(memory.NewDomain())
			} else {
				path := filepath.Join(t.TempDir(), "jobs.db")
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
			now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
			job := domain.InvocationJob{
				Scope: sc, ID: "first", PipelineName: "release", Incarnation: "original",
				PipelineExecutionID: "execution", ActionExecutionID: "action", StageName: "Invoke", ActionName: "Transform",
				Status: "Running", Sequence: 1, Generation: 2, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
				ActionExpiresAt:  now.Add(24 * time.Hour),
				ExecutionDetails: &api.ExecutionDetails{Summary: new(api.ExecutionSummary("working")), PercentComplete: new(api.Percentage(0))},
				FailureDetails:   &api.FailureDetails{Type: new(api.FailureType("JobFailed")), Message: new(api.Message("failure")), ExternalExecutionId: new(api.ExecutionId(""))},
				CurrentRevision:  &api.CurrentRevision{Revision: new(api.Revision("revision")), ChangeIdentifier: new(api.RevisionChangeIdentifier("change")), Created: new(now)},
				OutputVariables:  api.OutputVariablesMap{"Release": "42"},
			}
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				if err := tx.PutPipeline(domain.Pipeline{Scope: sc, Name: job.PipelineName, Incarnation: job.Incarnation, Version: 1}); err != nil {
					return err
				}
				return tx.PutInvocationJob(job)
			}); err != nil {
				t.Fatal(err)
			}
			*job.ExecutionDetails.Summary = "mutated-write"
			*job.FailureDetails.Message = "mutated-write"
			*job.CurrentRevision.Revision = "mutated-write"
			*job.CurrentRevision.Created = now.Add(time.Hour)
			job.OutputVariables["Release"] = "mutated-write"
			check := func() {
				t.Helper()
				if err := repo.View(ctx, func(r domain.Reader) error {
					got, found, err := r.InvocationJob(sc, job.ID)
					if err != nil {
						return err
					}
					if !found || got.Status != "Running" || got.Generation != 2 || *got.ExecutionDetails.Summary != "working" || *got.ExecutionDetails.PercentComplete != 0 || got.ExecutionDetails.ExternalExecutionId != nil || *got.FailureDetails.Message != "failure" || got.FailureDetails.ExternalExecutionId == nil || *got.FailureDetails.ExternalExecutionId != "" || *got.CurrentRevision.Revision != "revision" || !got.CurrentRevision.Created.Equal(now) || got.OutputVariables["Release"] != "42" {
						t.Fatalf("retained job changed: %+v", got)
					}
					*got.ExecutionDetails.Summary = "mutated-read"
					*got.FailureDetails.Message = "mutated-read"
					*got.CurrentRevision.Created = now.Add(time.Hour)
					got.OutputVariables["Release"] = "mutated-read"
					foreign := sc
					foreign.AccountID = "999900001111"
					if _, found, err := r.InvocationJob(foreign, job.ID); err != nil || found {
						t.Fatalf("cross-account job lookup: found=%v err=%v", found, err)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			check()
			check()
			rollback := errors.New("abort callback transaction")
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				job.Status = "Failed"
				if err := tx.PutInvocationJob(job); err != nil {
					return err
				}
				return rollback
			}); !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			reopen()
			check()
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				first, _, err := tx.InvocationJob(sc, "first")
				if err != nil {
					return err
				}
				first.Status = "Continued"
				first.ResultContinuationToken = "resume-42"
				first.Generation++
				if err := tx.PutInvocationJob(first); err != nil {
					return err
				}
				next := domain.InvocationJob{Scope: sc, ID: "next", PipelineName: first.PipelineName, Incarnation: first.Incarnation, PipelineExecutionID: first.PipelineExecutionID, ActionExecutionID: first.ActionExecutionID, Sequence: 2, Generation: 1, Status: "Ready", ContinuationToken: "resume-42", CreatedAt: now, ExpiresAt: first.ExpiresAt, ActionExpiresAt: first.ActionExpiresAt, OutputVariables: api.OutputVariablesMap{}}
				if err := tx.PutInvocationJob(next); err != nil {
					return err
				}
				return tx.DeletePipeline(sc, job.PipelineName)
			}); err != nil {
				t.Fatal(err)
			}
			reopen()
			if err := repo.View(ctx, func(r domain.Reader) error {
				jobs, err := r.InvocationJobs(sc, "action")
				if err != nil {
					return err
				}
				if len(jobs) != 2 || jobs[0].ID != "first" || jobs[0].Status != "Continued" || jobs[0].ResultContinuationToken != "resume-42" || jobs[1].ID != "next" || jobs[1].Status != "Ready" || jobs[1].ContinuationToken != "resume-42" || jobs[1].Generation != 1 || jobs[1].ExecutionDetails != nil || jobs[1].OutputVariables == nil || !jobs[1].ExpiresAt.Equal(now.Add(time.Hour)) || !jobs[1].ActionExpiresAt.Equal(now.Add(24*time.Hour)) {
					t.Fatalf("continuation/deleted history lost on reopen: %+v", jobs)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

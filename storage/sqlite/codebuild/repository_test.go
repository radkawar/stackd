package codebuild_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/codebuild"
	"stackd/journal"
	domain "stackd/storage/codebuild"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/codebuild"
	sqljournal "stackd/storage/sqlite/journal"
)

func scope() domain.Scope {
	return domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
}

func buildFixture() domain.BuildRecord {
	k := domain.BuildKey{Scope: scope(), ID: "project:build-1"}
	at := time.Date(2030, 4, 5, 6, 7, 8, 123000000, time.UTC)
	return domain.BuildRecord{
		Key: k, AcceptedEventID: "accepted-build", IdempotencyToken: "start-token", RequestHash: "request-hash",
		Deadline: at.Add(time.Hour), QueuedDeadline: at.Add(5 * time.Minute), StopRequested: true, LogOffset: 42,
		CredentialToken: "fixture-metadata-reference", FleetARN: "arn:aws:codebuild:us-east-1:111111111111:fleet/builders:00000000-0000-4000-8000-000000000001",
		Artifacts:          api.ProjectArtifacts{Type: new(api.ArtifactsType("S3")), Location: new(api.String("output-bucket")), Path: new(api.String("build/output"))},
		SecondaryArtifacts: api.ProjectArtifactsList{{Type: new(api.ArtifactsType("S3")), ArtifactIdentifier: new(api.String("secondary")), Location: new(api.String("secondary-bucket")), Name: new(api.String("accepted.zip")), Packaging: new(api.ArtifactPackaging("ZIP"))}},
		Logs:               api.LogsConfig{CloudWatchLogs: &api.CloudWatchLogsConfig{Status: new(api.LogsConfigStatusType("ENABLED")), GroupName: new(api.String("build-logs"))}},
		Data: api.Build{
			Id: new(api.NonEmptyString(k.ID)), Arn: new(api.NonEmptyString(k.ARN())), ProjectName: new(api.NonEmptyString("project")),
			BuildNumber: new(api.WrapperLong(7)), BuildComplete: new(api.Boolean(false)), BuildStatus: new(api.StatusType("IN_PROGRESS")),
			CurrentPhase: new(api.String("BUILD")), StartTime: &at, TimeoutInMinutes: new(api.WrapperInt(60)), QueuedTimeoutInMinutes: new(api.WrapperInt(5)),
			ServiceRole: new(api.NonEmptyString("arn:aws:iam::111111111111:role/builder")), SourceVersion: new(api.NonEmptyString("main")),
			ResolvedSourceVersion: new(api.NonEmptyString("commit-42")),
			Source:                &api.ProjectSource{Type: new(api.SourceType("S3")), Location: new(api.String("source-bucket/source.zip")), Buildspec: new(api.String("version: 0.2\nphases:\n  build:\n    commands: [echo real]\n"))},
			Environment: &api.ProjectEnvironment{Type: new(api.EnvironmentType("LINUX_CONTAINER")), Image: new(api.NonEmptyString("build-image@sha256:123")), ComputeType: new(api.ComputeType("BUILD_GENERAL1_SMALL")), EnvironmentVariables: api.EnvironmentVariables{
				{Name: new(api.NonEmptyString("ORDER_Z")), Value: new(api.String("z")), Type: new(api.EnvironmentVariableType("PLAINTEXT"))},
				{Name: new(api.NonEmptyString("ORDER_A")), Value: new(api.String("secret-reference")), Type: new(api.EnvironmentVariableType("SECRETS_MANAGER"))},
			}},
			ExportedEnvironmentVariables: api.ExportedEnvironmentVariables{{Name: new(api.NonEmptyString("RELEASE")), Value: new(api.String("release-42"))}},
			SecondarySourceVersions:      api.ProjectSecondarySourceVersions{{SourceIdentifier: new(api.String("second")), SourceVersion: new(api.String("v2"))}},
			SecondarySources:             api.ProjectSources{{Type: new(api.SourceType("S3")), SourceIdentifier: new(api.String("second")), Location: new(api.String("source-bucket/secondary.zip"))}},
			SecondaryArtifacts:           api.BuildArtifactsList{{ArtifactIdentifier: new(api.String("secondary")), Location: new(api.String("arn:aws:s3:::secondary-bucket/accepted.zip")), Sha256sum: new(api.String("retained-output-digest"))}},
			ReportArns:                   api.BuildReportArns{"report-z", "report-a"},
			Phases: api.BuildPhases{
				{PhaseType: new(api.BuildPhaseType("INSTALL")), PhaseStatus: new(api.StatusType("SUCCEEDED")), StartTime: &at, DurationInSeconds: new(api.WrapperLong(0)), Contexts: api.PhaseContexts{}},
				{PhaseType: new(api.BuildPhaseType("BUILD")), PhaseStatus: new(api.StatusType("IN_PROGRESS")), Contexts: api.PhaseContexts{{Message: new(api.String("started")), StatusCode: new(api.String("COMMAND_EXECUTION"))}}},
			},
		},
	}
}

func TestRetainedRecoveryPreservesAcceptedBuildAfterProjectDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo := backend.New(db)
	active := buildFixture()
	active.PipelineActionID = "00000000-0000-4000-8000-000000000042"
	active.Data.Source = &api.ProjectSource{Type: new(api.SourceType("CODEPIPELINE"))}
	active.Data.SourceVersion = new(api.NonEmptyString("arn:aws:s3:::artifacts/input"))
	active.Data.ResolvedSourceVersion = new(api.NonEmptyString("original-source-version"))
	active.Artifacts = api.ProjectArtifacts{Type: new(api.ArtifactsType("CODEPIPELINE")), Location: new(api.String("arn:aws:s3:::artifacts/output")), Packaging: new(api.ArtifactPackaging("NONE"))}
	active.PipelineInputs = []domain.PipelineInput{
		{Name: "Source", Location: "arn:aws:s3:::artifacts/input", VersionID: "copied-artifact-version", RevisionID: "original-source-version"},
		{Name: "Aux", Location: "arn:aws:s3:::artifacts/aux", RevisionID: "aux-source-version"},
	}
	active.PipelineOutputs = []domain.PipelineOutput{{Name: "Output", Location: "arn:aws:s3:::artifacts/output", EncryptionKey: "alias/aws/s3"}}
	cleanup := active
	cleanup.Key.ID = "project:build-2"
	cleanup.Data.BuildComplete = new(api.Boolean(true))
	cleanup.CleanupPending = true
	tombstone := cleanup
	tombstone.Key.ID = "project:build-3"
	tombstone.CleanupPending, tombstone.DeleteRequested = false, true
	finished := cleanup
	finished.Key.ID = "project:build-4"
	finished.CleanupPending = false
	project := domain.ProjectRecord{Key: domain.ProjectKey{Scope: scope(), Name: "project"}, BuildNumber: 7, Data: api.Project{Name: new(api.ProjectName("project"))}}
	retainedProject := domain.ProjectRecord{
		Key: domain.ProjectKey{Scope: scope(), Name: "retained"}, BuildNumber: 8,
		Data: api.Project{Name: new(api.ProjectName("retained")), Environment: active.Data.Environment, Source: active.Data.Source, ServiceRole: active.Data.ServiceRole,
			Artifacts: &active.Artifacts, LogsConfig: &active.Logs, SecondarySourceVersions: active.Data.SecondarySourceVersions,
			Tags: api.TagList{{Key: new(api.KeyInput("purpose")), Value: new(api.ValueInput("recovery"))}}},
	}
	fleet := domain.FleetRecord{
		Key: domain.FleetKey{Scope: scope(), Name: "builders"},
		Data: api.Fleet{Name: new(api.FleetName("builders")), Arn: new(api.NonEmptyString(active.FleetARN)), Id: new(api.NonEmptyString("00000000-0000-4000-8000-000000000001")), BaseCapacity: new(api.FleetCapacity(2)), FleetServiceRole: active.Data.ServiceRole,
			ComputeConfiguration: &api.ComputeConfiguration{Disk: new(api.WrapperLong(64)), InstanceType: new(api.NonEmptyString("c5.large"))},
			Status:               &api.FleetStatus{StatusCode: new(api.FleetStatusCode("ACTIVE"))}, Tags: retainedProject.Data.Tags},
	}
	credential := domain.CredentialRecord{Key: domain.CredentialKey{Scope: scope(), ServerType: "GITHUB", AuthType: "PERSONAL_ACCESS_TOKEN"}, ARN: "imported-credential", Ciphertext: []byte{0, 1, 2, 255}}
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutProject(project); err != nil {
			return err
		}
		if err := tx.PutProject(retainedProject); err != nil {
			return err
		}
		if err := tx.PutFleet(fleet); err != nil {
			return err
		}
		if err := tx.PutCredential(credential); err != nil {
			return err
		}
		for _, build := range []domain.BuildRecord{finished, tombstone, cleanup, active} {
			if err := tx.PutBuild(build); err != nil {
				return err
			}
		}
		return tx.DeleteProject(project.Key)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo = backend.New(db)
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		if _, err := r.Project(project.Key); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deleted project: %v", err)
		}
		projectAfter, err := r.Project(retainedProject.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(projectAfter, retainedProject) {
			t.Fatal("retained project lost role, configuration or children")
		}
		fleetAfter, err := r.Fleet(fleet.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(fleetAfter, fleet) {
			t.Fatal("retained fleet lost native capacity configuration")
		}
		allFleets, err := r.AllFleets()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(allFleets, []domain.FleetRecord{fleet}) {
			t.Fatal("fleet recovery did not find retained reservations")
		}
		credentialAfter, err := r.Credential(credential.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(credentialAfter, credential) {
			t.Fatal("retained source credential lost ciphertext")
		}
		got, err := r.Build(active.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, active) {
			t.Fatal("retained build lost accepted configuration, execution state or ordered phase children")
		}
		pending, err := r.ActiveBuilds()
		if err != nil {
			return err
		}
		want := []domain.BuildRecord{active, cleanup, tombstone}
		if !reflect.DeepEqual(pending, want) {
			t.Fatal("recovery did not retain active, cleanup and deletion work in stable order")
		}
		got, err = r.Build(finished.Key)
		if err == nil && !reflect.DeepEqual(got, finished) {
			t.Fatal("terminal history was not retained independently of recovery selection")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func repositoryCases(t *testing.T, fn func(*testing.T, domain.Repository, journal.Storage)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		d := memory.NewDomain()
		fn(t, domain.NewMemory(d), journal.NewMemory(d))
	})
	t.Run("sqlite", func(t *testing.T) {
		db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		fn(t, backend.New(db), sqljournal.New(db))
	})
}

func TestScopedRecordsReplaceChildrenWithoutLeakingAcrossScopes(t *testing.T) {
	repositoryCases(t, func(t *testing.T, repo domain.Repository, _ journal.Storage) {
		scopes := []domain.Scope{scope(), {Partition: "aws", AccountID: "222222222222", Region: "us-east-1"}, {Partition: "aws", AccountID: "111111111111", Region: "us-west-2"}, {Partition: "aws-cn", AccountID: "111111111111", Region: "us-east-1"}}
		for _, s := range scopes {
			b := buildFixture()
			b.Key.Scope = s
			p := domain.ProjectRecord{Key: domain.ProjectKey{Scope: s, Name: "project"}, Data: api.Project{Name: new(api.ProjectName("project")), Environment: b.Data.Environment, SecondarySourceVersions: b.Data.SecondarySourceVersions, Tags: api.TagList{{Key: new(api.KeyInput("owner")), Value: new(api.ValueInput(s.AccountID + s.Region + s.Partition))}}}}
			f := domain.FleetRecord{Key: domain.FleetKey{Scope: s, Name: "fleet"}, Data: api.Fleet{Name: new(api.FleetName("fleet")), BaseCapacity: new(api.FleetCapacity(2)), Tags: p.Data.Tags}}
			c := domain.CredentialRecord{Key: domain.CredentialKey{Scope: s, ServerType: "GITHUB", AuthType: "PERSONAL_ACCESS_TOKEN"}, ARN: "credential-arn", Ciphertext: []byte{1, 2, 3}}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutProject(p); err != nil {
					return err
				}
				if err := tx.PutBuild(b); err != nil {
					return err
				}
				if err := tx.PutFleet(f); err != nil {
					return err
				}
				return tx.PutCredential(c)
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			p, err := tx.Project(domain.ProjectKey{Scope: scope(), Name: "project"})
			if err != nil {
				return err
			}
			p.Data.Tags, p.Data.SecondarySourceVersions = api.TagList{}, nil
			p.Data.Environment.EnvironmentVariables = api.EnvironmentVariables{}
			if err := tx.PutProject(p); err != nil {
				return err
			}
			b, err := tx.Build(buildFixture().Key)
			if err != nil {
				return err
			}
			b.Data.Phases = api.BuildPhases{{PhaseType: new(api.BuildPhaseType("COMPLETED")), Contexts: nil}}
			b.Data.Environment.EnvironmentVariables, b.Data.ExportedEnvironmentVariables = nil, api.ExportedEnvironmentVariables{}
			b.Data.SecondarySourceVersions, b.Data.ReportArns = nil, api.BuildReportArns{}
			if err := tx.PutBuild(b); err != nil {
				return err
			}
			if err := tx.DeleteFleet(domain.FleetKey{Scope: scope(), Name: "fleet"}); err != nil {
				return err
			}
			return tx.DeleteCredential(domain.CredentialKey{Scope: scope(), ServerType: "GITHUB", AuthType: "PERSONAL_ACCESS_TOKEN"})
		}); err != nil {
			t.Fatal(err)
		}
		for i, s := range scopes {
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				projects, err := r.Projects(s)
				if err != nil {
					return err
				}
				if len(projects) != 1 || projects[0].Key.Scope != s {
					t.Fatal("project list crossed a scope boundary")
				}
				b, err := r.Build(domain.BuildKey{Scope: s, ID: "project:build-1"})
				if err != nil {
					return err
				}
				fleets, err := r.Fleets(s)
				if err != nil {
					return err
				}
				credentials, err := r.Credentials(s)
				if err != nil {
					return err
				}
				if i == 0 {
					if projects[0].Data.Tags == nil || len(projects[0].Data.Tags) != 0 || projects[0].Data.SecondarySourceVersions != nil || projects[0].Data.Environment.EnvironmentVariables == nil || len(projects[0].Data.Environment.EnvironmentVariables) != 0 {
						t.Fatal("project replacement retained stale children or lost explicit empty values")
					}
					if len(b.Data.Phases) != 1 || *b.Data.Phases[0].PhaseType != "COMPLETED" || b.Data.Phases[0].Contexts != nil || b.Data.Environment.EnvironmentVariables != nil || b.Data.ExportedEnvironmentVariables == nil || len(b.Data.ExportedEnvironmentVariables) != 0 || b.Data.SecondarySourceVersions != nil || b.Data.ReportArns == nil || len(b.Data.ReportArns) != 0 {
						t.Fatal("build replacement retained stale children or lost explicit empty values")
					}
					if len(fleets) != 0 || len(credentials) != 0 {
						t.Fatal("deleted fleet or credential remains")
					}
				} else {
					expected := buildFixture()
					expected.Key.Scope = s
					if !reflect.DeepEqual(b, expected) || len(projects[0].Data.Tags) != 1 || len(fleets) != 1 || fleets[0].Key.Scope != s || len(credentials) != 1 || credentials[0].Key.Scope != s || !reflect.DeepEqual(credentials[0].Ciphertext, []byte{1, 2, 3}) {
						t.Fatal("mutation leaked into another scope")
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestCommandAttemptAndJournalShareAtomicBoundary(t *testing.T) {
	repositoryCases(t, func(t *testing.T, repo domain.Repository, events journal.Storage) {
		rejected := errors.New("rejected command")
		appendEvent := func(ctx context.Context, id string) error {
			return events.AppendAPICallCompleted(ctx, journal.Envelope{At: time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC), Partition: "aws", AccountID: scope().AccountID, Region: scope().Region}, journal.APICallCompleted{EventID: id, EventSource: "codebuild.amazonaws.com", EventName: "StartBuild", Category: journal.CategoryManagement, RequestParameters: json.RawMessage(`{}`), ResponseElements: json.RawMessage(`{}`)})
		}
		accepted := buildFixture()
		child := accepted
		child.Key.ID = "project:rejected"
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutBuild(accepted); err != nil {
				return err
			}
			err := repo.Attempt(tx.Context(), func(nested domain.Transaction) error {
				if err := nested.PutBuild(child); err != nil {
					return err
				}
				if err := appendEvent(nested.Context(), "rejected"); err != nil {
					return err
				}
				return rejected
			})
			if !errors.Is(err, rejected) {
				return err
			}
			if _, err := tx.Build(child.Key); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("rejected command remained visible: %v", err)
			}
			return appendEvent(tx.Context(), "accepted")
		}); err != nil {
			t.Fatal(err)
		}
		err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.DeleteBuild(accepted.Key); err != nil {
				return err
			}
			if err := appendEvent(tx.Context(), "rolled-back"); err != nil {
				return err
			}
			return rejected
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("rollback result: %v", err)
		}
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			got, err := r.Build(accepted.Key)
			if err == nil && !reflect.DeepEqual(got, accepted) {
				t.Fatal("outer rollback changed accepted build")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		records, err := events.Read(t.Context(), 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 || records[0].APICallCompleted == nil || records[0].APICallCompleted.EventID != "accepted" {
			t.Fatal("journal committed rejected or rolled-back state transitions")
		}
	})
}

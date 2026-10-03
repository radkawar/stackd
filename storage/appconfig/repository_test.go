package appconfig_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	domain "stackd/storage/appconfig"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	appconfigsqlite "stackd/storage/sqlite/appconfig"
)

type repositoryFixture struct {
	repository domain.Repository
	peer       domain.Repository
	reopen     func() domain.Repository
}

func repositories(t *testing.T, fn func(*testing.T, repositoryFixture)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		d := memory.NewDomain()
		fn(t, repositoryFixture{repository: domain.NewMemory(d), peer: domain.NewMemory(d)})
	})
	t.Run("sqlite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "appconfig.db")
		var db *sql.DB
		open := func() domain.Repository {
			var err error
			db, err = sqlite.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			return appconfigsqlite.New(db)
		}
		repository := open()
		t.Cleanup(func() {
			if err := db.Close(); err != nil {
				t.Error(err)
			}
		})
		fn(t, repositoryFixture{repository: repository, peer: appconfigsqlite.New(db), reopen: func() domain.Repository {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			return open()
		}})
	})
}

var scope = domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
var otherScope = domain.Scope{Partition: "aws", AccountID: "210987654321", Region: "us-east-1"}

func TestCommandSavepointsAndSharedAbort(t *testing.T) {
	repositories(t, func(t *testing.T, f repositoryFixture) {
		ctx := context.Background()
		rejected := errors.New("rejected command")
		err := f.repository.Update(ctx, func(tx domain.Transaction) error {
			if err := tx.PutApplication(domain.Application{Scope: scope, ID: "kept", Name: "original"}); err != nil {
				return err
			}
			err := f.repository.Attempt(tx.Context(), func(child domain.Transaction) error {
				if err := child.PutApplication(domain.Application{Scope: scope, ID: "kept", Name: "rejected"}); err != nil {
					return err
				}
				if err := f.peer.Update(child.Context(), func(peer domain.Transaction) error {
					return peer.PutApplication(domain.Application{Scope: otherScope, ID: "rejected"})
				}); err != nil {
					return err
				}
				return rejected
			})
			if !errors.Is(err, rejected) {
				t.Fatalf("attempt error: %v", err)
			}
			rows, err := tx.Applications(scope)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].Name != "original" {
				t.Fatalf("failed attempt leaked: %#v", rows)
			}
			if err := f.repository.Attempt(tx.Context(), func(child domain.Transaction) error {
				return child.PutApplication(domain.Application{Scope: scope, ID: "accepted", Name: "accepted"})
			}); err != nil {
				return err
			}
			rows, err = tx.Applications(scope)
			if err != nil {
				return err
			}
			if len(rows) != 2 || rows[0].ID != "accepted" || rows[1].ID != "kept" {
				t.Fatalf("accepted attempt not merged: %#v", rows)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		err = f.peer.View(ctx, func(r domain.Reader) error {
			rows, err := r.Applications(otherScope)
			if err == nil && len(rows) != 0 {
				t.Fatalf("peer savepoint leaked: %#v", rows)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		err = f.repository.Update(ctx, func(tx domain.Transaction) error {
			if err := tx.DeleteApplication(scope, "kept"); err != nil {
				return err
			}
			_ = f.peer.Update(tx.Context(), func(peer domain.Transaction) error {
				if err := peer.PutApplication(domain.Application{Scope: otherScope, ID: "aborted"}); err != nil {
					return err
				}
				return rejected
			})
			return nil // Catching an ordinary nested write failure still aborts its owner.
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("nested failure did not abort: %v", err)
		}
		err = f.repository.View(ctx, func(r domain.Reader) error {
			rows, err := r.Applications(scope)
			if err == nil && (len(rows) != 2 || rows[1].ID != "kept") {
				t.Fatalf("outer abort lost data: %#v", rows)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		err = f.peer.View(ctx, func(r domain.Reader) error {
			rows, err := r.Applications(otherScope)
			if err == nil && len(rows) != 0 {
				t.Fatalf("peer abort leaked: %#v", rows)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestTypedStateIsolationReplacementAndRestart(t *testing.T) {
	repositories(t, func(t *testing.T, f repositoryFixture) {
		ctx := context.Background()
		now := time.Date(2026, 9, 28, 10, 11, 12, 123456789, time.UTC)
		app := domain.Application{Scope: scope, ID: "app", Name: "application", Description: "retained"}
		env := domain.Environment{Scope: scope, ApplicationID: app.ID, ID: "env", Name: "environment", Description: "monitored", State: "DEPLOYING", CreatedAt: now.Add(-time.Hour), LastPoll: now, Monitors: []domain.Monitor{{AlarmARN: "alarm-b", RoleARN: "role-b"}, {AlarmARN: "alarm-a", RoleARN: "role-a"}}}
		profile := domain.Profile{Scope: scope, ApplicationID: app.ID, ID: "profile", Name: "configuration", Description: "validated", LocationURI: "hosted", RetrievalRoleARN: "role", Type: "AWS.Freeform", KMSKeyIdentifier: "key", KMSKeyARN: "key-arn", CreatedAt: now.Add(-time.Hour), LastPoll: now, NextVersion: 3, Validators: []domain.Validator{{Type: "JSON_SCHEMA", Content: "{\"type\":\"object\"}"}, {Type: "LAMBDA", Content: "validator-arn"}}}
		version := domain.HostedVersion{Scope: scope, ApplicationID: app.ID, ProfileID: profile.ID, Number: 2, Description: "binary", ContentType: "application/octet-stream", VersionLabel: "stable", KMSKeyARN: "key-arn", Content: []byte{0, 255, 1, 0, 254}}
		strategy := domain.Strategy{Scope: scope, ID: "strategy", Name: "linear", Description: "rollout", GrowthType: "LINEAR", ReplicateTo: "NONE", DurationMinutes: 2, FinalBakeMinutes: 1, GrowthFactor: 25.5}
		action := domain.ExtensionAction{Point: "ON_DEPLOYMENT_START", Name: "notify", Description: "real effect", URI: "lambda-arn", RoleARN: "effect-role"}
		extension := domain.Extension{Scope: scope, ID: "extension", Name: "effect", Description: "snapshot", ARN: "extension-arn", Version: 2, Actions: []domain.ExtensionAction{action}, Parameters: []domain.ExtensionParameter{{Name: "target", Description: "where", Required: true, Dynamic: true}}}
		association := domain.Association{Scope: scope, ID: "association", ARN: "association-arn", ExtensionID: extension.ID, ExtensionARN: extension.ARN, ResourceARN: "environment-arn", ExtensionVersion: 2, Parameters: map[string]string{"target": "queue-arn"}}
		deployment := domain.Deployment{Scope: scope, ApplicationID: app.ID, EnvironmentID: env.ID, ProfileID: profile.ID, StrategyID: strategy.ID, Number: 2, PreviousDeployment: 1, ConfigurationName: profile.Name, ConfigurationVersion: "2", VersionLabel: "stable", LocationURI: "hosted", Description: "snapshot", ContentType: version.ContentType, State: "ROLLING_BACK", GrowthType: strategy.GrowthType, KMSKeyIdentifier: "key", KMSKeyARN: "key-arn", Content: []byte{0, 255, 1, 0, 254}, DurationMinutes: 2, FinalBakeMinutes: 1, GrowthFactor: 25.5, Percentage: 50, StartedAt: now, CompletedAt: now.Add(time.Minute), Due: now.Add(2 * time.Minute), Generation: 4, Events: []domain.DeploymentEvent{{Type: "PERCENTAGE_UPDATED", Description: "advance", TriggeredBy: "APPCONFIG", At: now, Invocations: []domain.ActionInvocation{{ID: "invocation", ExtensionID: extension.ID, ActionName: action.Name, URI: action.URI, RoleARN: action.RoleARN, ErrorCode: "error-code", ErrorMessage: "error-message"}}}}, Extensions: []domain.AppliedExtension{{AssociationID: association.ID, ExtensionID: extension.ID, Version: 2, Parameters: map[string]string{"target": "queue-arn"}, Actions: []domain.ExtensionAction{action}}}, DynamicParameters: map[string][]string{"target": {"first", "second"}, "empty": {}}}
		deployment.Type = "USER"
		deployment.ExperimentFlags = "retained-experiment-header"
		session := domain.Session{Scope: scope, Token: "token", ClientID: "client", ApplicationID: app.ID, EnvironmentID: env.ID, ProfileID: profile.ID, LastDeployment: 2, PollSeconds: 30, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour), NextPoll: now.Add(30 * time.Second)}
		settings := domain.Settings{Scope: scope, DeletionProtectionEnabled: true, ProtectionMinutes: 60, VendedMetricsEnabled: false, VendedMetricsSet: true}
		tags := map[string]string{"team": "configuration", "binary": "owned"}
		err := f.repository.Update(ctx, func(tx domain.Transaction) error {
			for _, put := range []func() error{
				func() error { return tx.PutApplication(app) }, func() error { return tx.PutEnvironment(env) }, func() error { return tx.PutProfile(profile) }, func() error { return tx.PutHostedVersion(version) }, func() error { return tx.PutStrategy(strategy) }, func() error { return tx.PutExtension(extension) }, func() error { return tx.PutAssociation(association) }, func() error { return tx.PutDeployment(deployment) }, func() error { return tx.PutSession(session) }, func() error { return tx.PutTags(scope, "application-arn", tags) }, func() error { return tx.PutSettings(settings) },
			} {
				if err := put(); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		// Caller-owned inputs may be changed immediately after publication.
		version.Content[0] = 99
		env.Monitors[0].AlarmARN = "mutated"
		profile.Validators[0].Content = "mutated"
		extension.Actions[0].URI = "mutated"
		extension.Parameters[0].Name = "mutated"
		association.Parameters["target"] = "mutated"
		deployment.Content[0] = 99
		deployment.Events[0].Invocations[0].URI = "mutated"
		deployment.Extensions[0].Parameters["target"] = "mutated"
		deployment.Extensions[0].Actions[0].URI = "mutated"
		deployment.DynamicParameters["target"][0] = "mutated"
		tags["team"] = "mutated"
		assertState := func(repository domain.Repository) {
			t.Helper()
			err := repository.View(ctx, func(r domain.Reader) error {
				applications, err := r.Applications(scope)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(applications, []domain.Application{app}) {
					t.Fatalf("applications: %#v", applications)
				}
				environments, err := r.Environments(scope, app.ID)
				if err != nil {
					return err
				}
				wantEnv := env
				wantEnv.Monitors = []domain.Monitor{{AlarmARN: "alarm-b", RoleARN: "role-b"}, {AlarmARN: "alarm-a", RoleARN: "role-a"}}
				if !reflect.DeepEqual(environments, []domain.Environment{wantEnv}) {
					t.Fatalf("environments: %#v", environments)
				}
				profiles, err := r.Profiles(scope, app.ID)
				if err != nil {
					return err
				}
				wantProfile := profile
				wantProfile.Validators = []domain.Validator{{Type: "JSON_SCHEMA", Content: "{\"type\":\"object\"}"}, {Type: "LAMBDA", Content: "validator-arn"}}
				if !reflect.DeepEqual(profiles, []domain.Profile{wantProfile}) {
					t.Fatalf("profiles: %#v", profiles)
				}
				versions, err := r.HostedVersions(scope, app.ID, profile.ID)
				if err != nil {
					return err
				}
				wantVersion := version
				wantVersion.Content = []byte{0, 255, 1, 0, 254}
				if !reflect.DeepEqual(versions, []domain.HostedVersion{wantVersion}) {
					t.Fatalf("versions: %#v", versions)
				}
				strategies, err := r.Strategies(scope)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(strategies, []domain.Strategy{strategy}) {
					t.Fatalf("strategies: %#v", strategies)
				}
				extensions, err := r.Extensions(scope)
				if err != nil {
					return err
				}
				wantExtension := extension
				wantExtension.Actions = []domain.ExtensionAction{action}
				wantExtension.Parameters = []domain.ExtensionParameter{{Name: "target", Description: "where", Required: true, Dynamic: true}}
				if !reflect.DeepEqual(extensions, []domain.Extension{wantExtension}) {
					t.Fatalf("extensions: %#v", extensions)
				}
				associations, err := r.Associations(scope)
				if err != nil {
					return err
				}
				wantAssociation := association
				wantAssociation.Parameters = map[string]string{"target": "queue-arn"}
				if !reflect.DeepEqual(associations, []domain.Association{wantAssociation}) {
					t.Fatalf("associations: %#v", associations)
				}
				deployments, err := r.Deployments(scope, app.ID, env.ID)
				if err != nil {
					return err
				}
				wantDeployment := deployment
				wantDeployment.Content = []byte{0, 255, 1, 0, 254}
				wantDeployment.Events = []domain.DeploymentEvent{{Type: "PERCENTAGE_UPDATED", Description: "advance", TriggeredBy: "APPCONFIG", At: now, Invocations: []domain.ActionInvocation{{ID: "invocation", ExtensionID: extension.ID, ActionName: action.Name, URI: action.URI, RoleARN: action.RoleARN, ErrorCode: "error-code", ErrorMessage: "error-message"}}}}
				wantDeployment.Extensions = []domain.AppliedExtension{{AssociationID: association.ID, ExtensionID: extension.ID, Version: 2, Parameters: map[string]string{"target": "queue-arn"}, Actions: []domain.ExtensionAction{action}}}
				wantDeployment.DynamicParameters = map[string][]string{"target": {"first", "second"}, "empty": {}}
				if !reflect.DeepEqual(deployments, []domain.Deployment{wantDeployment}) {
					t.Fatalf("deployments: %#v", deployments)
				}
				gotSession, ok, err := r.Session(scope, session.Token)
				if err != nil {
					return err
				}
				if !ok || gotSession != session {
					t.Fatalf("session: %#v present=%v", gotSession, ok)
				}
				if _, ok, err := r.Session(otherScope, session.Token); err != nil {
					return err
				} else if ok {
					t.Fatal("session token escaped its scope")
				}
				gotTags, err := r.Tags(scope, "application-arn")
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(gotTags, map[string]string{"team": "configuration", "binary": "owned"}) {
					t.Fatalf("tags: %#v", gotTags)
				}
				gotSettings, ok, err := r.Settings(scope)
				if err != nil {
					return err
				}
				if !ok || gotSettings != settings {
					t.Fatalf("settings: %#v present=%v", gotSettings, ok)
				}
				foreign, err := r.Applications(otherScope)
				if err != nil {
					return err
				}
				if len(foreign) != 0 {
					t.Fatalf("scope leaked: %#v", foreign)
				}
				// Reader results are detached even inside a read transaction.
				environments[0].Monitors[0].AlarmARN = "read mutation"
				profiles[0].Validators[0].Content = "read mutation"
				versions[0].Content[0] = 88
				extensions[0].Actions[0].URI = "read mutation"
				extensions[0].Parameters[0].Name = "read mutation"
				associations[0].Parameters["target"] = "read mutation"
				deployments[0].Content[0] = 88
				deployments[0].Events[0].Invocations[0].URI = "read mutation"
				deployments[0].Extensions[0].Actions[0].URI = "read mutation"
				deployments[0].Extensions[0].Parameters["target"] = "read mutation"
				deployments[0].DynamicParameters["target"][0] = "read mutation"
				gotTags["team"] = "read mutation"
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		assertState(f.repository)
		if f.reopen != nil {
			f.repository = f.reopen()
		}
		assertState(f.repository)
		err = f.repository.Update(ctx, func(tx domain.Transaction) error {
			// Replacements remove old normalized children, including grandchildren.
			deployment.Content = nil
			deployment.Events = nil
			deployment.Extensions = nil
			deployment.DynamicParameters = nil
			deployment.Due = time.Time{}
			if err := tx.PutDeployment(deployment); err != nil {
				return err
			}
			env.Monitors = nil
			if err := tx.PutEnvironment(env); err != nil {
				return err
			}
			profile.Validators = nil
			if err := tx.PutProfile(profile); err != nil {
				return err
			}
			extension.Actions = nil
			extension.Parameters = nil
			if err := tx.PutExtension(extension); err != nil {
				return err
			}
			association.Parameters = nil
			if err := tx.PutAssociation(association); err != nil {
				return err
			}
			return tx.PutTags(scope, "application-arn", nil)
		})
		if err != nil {
			t.Fatal(err)
		}
		err = f.repository.View(ctx, func(r domain.Reader) error {
			deployments, err := r.Deployments(scope, app.ID, env.ID)
			if err != nil {
				return err
			}
			if len(deployments) != 1 || len(deployments[0].Content) != 0 || len(deployments[0].Events) != 0 || len(deployments[0].Extensions) != 0 || len(deployments[0].DynamicParameters) != 0 {
				t.Fatalf("stale deployment children: %#v", deployments)
			}
			environments, err := r.Environments(scope, app.ID)
			if err != nil {
				return err
			}
			if len(environments) != 1 || len(environments[0].Monitors) != 0 {
				t.Fatalf("stale monitors: %#v", environments)
			}
			profiles, err := r.Profiles(scope, app.ID)
			if err != nil {
				return err
			}
			if len(profiles) != 1 || len(profiles[0].Validators) != 0 {
				t.Fatalf("stale validators: %#v", profiles)
			}
			extensions, err := r.Extensions(scope)
			if err != nil {
				return err
			}
			if len(extensions) != 1 || len(extensions[0].Actions) != 0 || len(extensions[0].Parameters) != 0 {
				t.Fatalf("stale extension children: %#v", extensions)
			}
			associations, err := r.Associations(scope)
			if err != nil {
				return err
			}
			if len(associations) != 1 || len(associations[0].Parameters) != 0 {
				t.Fatalf("stale association parameters: %#v", associations)
			}
			gotTags, err := r.Tags(scope, "application-arn")
			if err != nil {
				return err
			}
			if len(gotTags) != 0 {
				t.Fatalf("stale tags: %#v", gotTags)
			}
			pending, err := r.PendingDeployments()
			if err != nil {
				return err
			}
			if len(pending) != 0 {
				t.Fatalf("completed deployment scheduled: %#v", pending)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		err = f.repository.Update(ctx, func(tx domain.Transaction) error {
			for _, remove := range []func() error{
				func() error { return tx.DeleteApplication(scope, app.ID) }, func() error { return tx.DeleteEnvironment(scope, app.ID, env.ID) }, func() error { return tx.DeleteProfile(scope, app.ID, profile.ID) }, func() error { return tx.DeleteHostedVersion(scope, app.ID, profile.ID, version.Number) }, func() error { return tx.DeleteStrategy(scope, strategy.ID) }, func() error { return tx.DeleteDeployment(scope, app.ID, env.ID, deployment.Number) }, func() error { return tx.DeleteSession(scope, session.Token) }, func() error { return tx.DeleteExtension(scope, extension.ID, extension.Version) }, func() error { return tx.DeleteAssociation(scope, association.ID) },
			} {
				if err := remove(); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		err = f.repository.View(ctx, func(r domain.Reader) error {
			applications, err := r.Applications(scope)
			if err != nil {
				return err
			}
			environments, err := r.Environments(scope, app.ID)
			if err != nil {
				return err
			}
			profiles, err := r.Profiles(scope, app.ID)
			if err != nil {
				return err
			}
			versions, err := r.HostedVersions(scope, app.ID, profile.ID)
			if err != nil {
				return err
			}
			strategies, err := r.Strategies(scope)
			if err != nil {
				return err
			}
			deployments, err := r.Deployments(scope, app.ID, env.ID)
			if err != nil {
				return err
			}
			sessions, err := r.Sessions(scope)
			if err != nil {
				return err
			}
			extensions, err := r.Extensions(scope)
			if err != nil {
				return err
			}
			associations, err := r.Associations(scope)
			if err != nil {
				return err
			}
			if len(applications)+len(environments)+len(profiles)+len(versions)+len(strategies)+len(deployments)+len(sessions)+len(extensions)+len(associations) != 0 {
				t.Fatal("deleted resources retained")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestPendingDeploymentOrderAndIndependentSnapshots(t *testing.T) {
	repositories(t, func(t *testing.T, f repositoryFixture) {
		ctx := context.Background()
		due := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
		rows := []domain.Deployment{
			{Scope: scope, ApplicationID: "b", EnvironmentID: "e", Number: 2, Due: due, State: "ROLLING_BACK", Content: []byte("retained")},
			{Scope: otherScope, ApplicationID: "a", EnvironmentID: "e", Number: 1, Due: due},
			{Scope: scope, ApplicationID: "a", EnvironmentID: "e", Number: 3, Due: due, State: "BAKING"},
			{Scope: scope, ApplicationID: "a", EnvironmentID: "e", Number: 1, Due: due.Add(time.Second), State: "DEPLOYING"},
			{Scope: scope, ApplicationID: "a", EnvironmentID: "e", Number: 2, Due: due},
			{Scope: scope, ApplicationID: "a", EnvironmentID: "e", Number: 4, State: "COMPLETE"},
		}
		err := f.repository.Update(ctx, func(tx domain.Transaction) error {
			for _, v := range rows {
				if err := tx.PutDeployment(v); err != nil {
					return err
				}
			}
			if err := tx.PutApplication(domain.Application{Scope: scope, ID: "b"}); err != nil {
				return err
			}
			return tx.DeleteApplication(scope, "b")
		})
		if err != nil {
			t.Fatal(err)
		}
		if f.reopen != nil {
			f.repository = f.reopen()
		}
		err = f.repository.View(ctx, func(r domain.Reader) error {
			pending, err := r.PendingDeployments()
			if err != nil {
				return err
			}
			type key struct {
				Scope         domain.Scope
				ApplicationID string
				Number        int32
			}
			got := make([]key, 0, len(pending))
			for _, v := range pending {
				got = append(got, key{v.Scope, v.ApplicationID, v.Number})
			}
			want := []key{{scope, "a", 2}, {scope, "a", 3}, {scope, "b", 2}, {otherScope, "a", 1}, {scope, "a", 1}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("deadline order: %#v want %#v", got, want)
			}
			if string(pending[2].Content) != "retained" {
				t.Fatalf("application deletion removed deployment snapshot: %#v", pending[2])
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

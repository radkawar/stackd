package appconfig_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/appconfig"
	dataapi "stackd/internal/awsapi/appconfigdata"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/appconfig"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlappconfig "stackd/storage/sqlite/appconfig"
)

type deploymentHarness struct {
	t       *testing.T
	ctx     context.Context
	scope   service.Scope
	repo    service.Repository
	clock   *clock.Manual
	service *service.Service
	reopen  func() service.Repository
}

func newDeploymentHarness(t *testing.T, backend string) *deploymentHarness {
	t.Helper()
	h := &deploymentHarness{t: t, scope: service.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, clock: clock.NewManual(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))}
	h.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: h.scope.Partition, AccountID: h.scope.AccountID, Region: h.scope.Region, PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalID: h.scope.AccountID})
	if backend == "memory" {
		h.repo = service.NewMemoryRepository(memory.NewDomain())
		h.reopen = func() service.Repository { return h.repo }
	} else {
		path := filepath.Join(t.TempDir(), "appconfig.sqlite")
		db, err := sqlite.Open(h.ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		h.repo = sqlappconfig.New(db)
		h.reopen = func() service.Repository {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			var err error
			db, err = sqlite.Open(h.ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			return sqlappconfig.New(db)
		}
		t.Cleanup(func() { db.Close() })
	}
	h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock})
	t.Cleanup(func() { h.service.Close() })
	err := h.repo.Update(h.ctx, func(tx service.Transaction) error {
		if e := tx.PutApplication(service.Application{Scope: h.scope, ID: "app1234", Name: "application"}); e != nil {
			return e
		}
		if e := tx.PutEnvironment(service.Environment{Scope: h.scope, ApplicationID: "app1234", ID: "env1234", Name: "production", State: "ReadyForDeployment", CreatedAt: h.clock.Now()}); e != nil {
			return e
		}
		if e := tx.PutProfile(service.Profile{Scope: h.scope, ApplicationID: "app1234", ID: "pro1234", Name: "document", LocationURI: "hosted", Type: "AWS.Freeform", CreatedAt: h.clock.Now()}); e != nil {
			return e
		}
		if e := tx.PutStrategy(service.Strategy{Scope: h.scope, ID: "all1234", Name: "immediate", GrowthType: "LINEAR", GrowthFactor: 100, ReplicateTo: "NONE"}); e != nil {
			return e
		}
		if e := tx.PutStrategy(service.Strategy{Scope: h.scope, ID: "slow123", Name: "gradual", GrowthType: "LINEAR", GrowthFactor: 25, DurationMinutes: 4, FinalBakeMinutes: 2, ReplicateTo: "NONE"}); e != nil {
			return e
		}
		for i, content := range []string{`{"value":"first"}`, `{"value":"second"}`} {
			if e := tx.PutHostedVersion(service.HostedVersion{Scope: h.scope, ApplicationID: "app1234", ProfileID: "pro1234", Number: int32(i + 1), ContentType: "application/json", VersionLabel: []string{"release-one", "release-two"}[i], Content: []byte(content)}); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func (h *deploymentHarness) command(ctx context.Context, action string, input any) (any, *awswire.Error) {
	name := "appconfig"
	if action == "StartConfigurationSession" || action == "GetLatestConfiguration" {
		name = "appconfigdata"
	}
	model, _ := awscatalog.LookupService(name)
	op, _ := model.Operation(action)
	return h.service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
}
func (h *deploymentHarness) call(action string, input any) any {
	h.t.Helper()
	out, err := h.command(h.ctx, action, input)
	if err != nil {
		h.t.Fatalf("%s: %v", action, err)
	}
	return out
}
func (h *deploymentHarness) deploy(version, strategy string) *api.StartDeploymentOutput {
	h.t.Helper()
	return h.call("StartDeployment", &api.StartDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), ConfigurationProfileId: new(api.LongName("pro1234")), DeploymentStrategyId: new(api.DeploymentStrategyId(strategy)), ConfigurationVersion: new(api.Version(version))}).(*api.StartDeploymentOutput)
}
func (h *deploymentHarness) session() string {
	h.t.Helper()
	out := h.call("StartConfigurationSession", &dataapi.StartConfigurationSessionInput{ApplicationIdentifier: new(dataapi.Identifier("application")), EnvironmentIdentifier: new(dataapi.Identifier("production")), ConfigurationProfileIdentifier: new(dataapi.Identifier("document")), RequiredMinimumPollIntervalInSeconds: new(dataapi.OptionalPollSeconds(15))}).(*dataapi.StartConfigurationSessionOutput)
	return string(*out.InitialConfigurationToken)
}
func (h *deploymentHarness) poll(token string) *dataapi.GetLatestConfigurationOutput {
	h.t.Helper()
	return h.call("GetLatestConfiguration", &dataapi.GetLatestConfigurationInput{ConfigurationToken: new(dataapi.Token(token))}).(*dataapi.GetLatestConfigurationOutput)
}
func (h *deploymentHarness) advance(d time.Duration) {
	h.t.Helper()
	if err := h.clock.Advance(d); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.service.JobDriver().RunDue(h.ctx, 1000); err != nil {
		h.t.Fatal(err)
	}
}
func (h *deploymentHarness) restart() {
	h.t.Helper()
	h.service.Close()
	h.repo = h.reopen()
	h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock})
}

func TestConfigurationPollingPortable(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newDeploymentHarness(t, backend)
			var e *awswire.Error
			for _, tc := range []struct{ app, env, profile, kind, parameter, reference string }{
				{"app1234", "env1234", "pro1234", "Deployment", "EnvironmentIdentifier", "env1234"},
				{"missing-app", "env1234", "pro1234", "Application", "ApplicationIdentifier", "missing-app"},
				{"application", "missing-environment", "missing-profile", "ConfigurationProfile", "ConfigurationProfileIdentifier", "missing-profile"},
				{"application", "missing-environment", "document", "Environment", "EnvironmentIdentifier", "missing-environment"},
				{"gone123", "gone456", "gone789", "Deployment", "ConfigurationProfileIdentifier", "gone789"},
			} {
				_, e = h.command(h.ctx, "StartConfigurationSession", &dataapi.StartConfigurationSessionInput{ApplicationIdentifier: new(dataapi.Identifier(tc.app)), EnvironmentIdentifier: new(dataapi.Identifier(tc.env)), ConfigurationProfileIdentifier: new(dataapi.Identifier(tc.profile))})
				if e == nil || e.Code != "ResourceNotFoundException" {
					t.Fatalf("missing %s: %v", tc.kind, e)
				}
				var kind string
				var refs map[string]string
				if err := json.Unmarshal(e.Details["ResourceType"], &kind); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(e.Details["ReferencedBy"], &refs); err != nil {
					t.Fatal(err)
				}
				if kind != tc.kind || refs[tc.parameter] != tc.reference {
					t.Fatalf("missing %s details: %s %v", tc.kind, kind, refs)
				}
			}
			d := h.deploy("release-one", "all1234")
			if *d.State != "COMPLETE" || *d.ConfigurationVersion != "1" {
				t.Fatalf("instant deployment: %+v", d)
			}
			token := h.session()
			// One durable token cannot fork the session even when callers race.
			var wg sync.WaitGroup
			results := make(chan *dataapi.GetLatestConfigurationOutput, 2)
			rejected := make(chan *awswire.Error, 2)
			for range 2 {
				wg.Go(func() {
					out, err := h.command(h.ctx, "GetLatestConfiguration", &dataapi.GetLatestConfigurationInput{ConfigurationToken: new(dataapi.Token(token))})
					if err != nil {
						rejected <- err
					} else {
						results <- out.(*dataapi.GetLatestConfigurationOutput)
					}
				})
			}
			wg.Wait()
			close(results)
			close(rejected)
			if len(results) != 1 || len(rejected) != 1 {
				t.Fatalf("token fork: accepted=%d rejected=%d", len(results), len(rejected))
			}
			first := <-results
			if string(first.Configuration) != `{"value":"first"}` || *first.VersionLabel != "release-one" || *first.ContentType != "application/json" {
				t.Fatalf("first configuration: %+v", first)
			}
			if e := <-rejected; e.Code != "BadRequestException" {
				t.Fatalf("replay: %v", e)
			}
			next := string(*first.NextPollConfigurationToken)
			_, e = h.command(h.ctx, "GetLatestConfiguration", &dataapi.GetLatestConfigurationInput{ConfigurationToken: new(dataapi.Token(next))})
			if e == nil || e.Code != "BadRequestException" || e.Reason != "InvalidParameters" {
				t.Fatalf("early poll: %v", e)
			}
			h.restart()
			h.advance(15 * time.Second)
			// Exercise the generated frontend payload binding, not just the Go output.
			model, _ := awscatalog.LookupService("appconfigdata")
			op, _ := model.Operation("GetLatestConfiguration")
			request := httptest.NewRequest("GET", "/configuration", nil).WithContext(awsapi.WithDecodedRequest(h.ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: &dataapi.GetLatestConfigurationInput{ConfigurationToken: new(dataapi.Token(next))}}))
			response := httptest.NewRecorder()
			h.service.DataHandler().ServeHTTP(response, request)
			if response.Code != 200 || response.Body.Len() != 0 || response.Header().Get("Version-Label") != "" || response.Header().Get("Next-Poll-Interval-In-Seconds") != "15" {
				t.Fatalf("no change frontend: %d %s %v", response.Code, response.Body.String(), response.Header())
			}
			next = response.Header().Get("Next-Poll-Configuration-Token")
			if next == "" {
				t.Fatal("missing continuation token")
			}
			h.deploy("release-two", "all1234")
			h.advance(15 * time.Second)
			changed := h.poll(next)
			if string(changed.Configuration) != `{"value":"second"}` || *changed.VersionLabel != "release-two" {
				t.Fatalf("changed configuration: %+v", changed)
			}
			// Deleting the source version cannot alter rollback's owned deployed bytes.
			if err := h.repo.Update(h.ctx, func(tx service.Transaction) error { return tx.DeleteHostedVersion(h.scope, "app1234", "pro1234", 1) }); err != nil {
				t.Fatal(err)
			}
			h.call("StopDeployment", &api.StopDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), DeploymentNumber: new(api.Integer(2)), AllowRevert: new(api.Boolean(true))})
			h.advance(15 * time.Second)
			reverted := h.poll(string(*changed.NextPollConfigurationToken))
			if string(reverted.Configuration) != `{"value":"first"}` || *reverted.VersionLabel != "release-one" {
				t.Fatalf("reverted immutable content: %+v", reverted)
			}
			h.restart()
			_, e = h.command(h.ctx, "GetLatestConfiguration", &dataapi.GetLatestConfigurationInput{ConfigurationToken: new(dataapi.Token(token))})
			if e == nil || e.Code != "BadRequestException" {
				t.Fatalf("replay after restart: %v", e)
			}
			for _, scope := range []awsctx.Metadata{{Partition: "aws", AccountID: "444455556666", Region: "us-east-1", PrincipalARN: "arn:aws:iam::444455556666:root"}, {Partition: "aws", AccountID: h.scope.AccountID, Region: "eu-west-1", PrincipalARN: "arn:aws:iam::111122223333:root"}} {
				_, e = h.command(awsctx.WithMetadata(t.Context(), scope), "GetLatestConfiguration", &dataapi.GetLatestConfigurationInput{ConfigurationToken: reverted.NextPollConfigurationToken})
				if e == nil || e.Code != "BadRequestException" {
					t.Fatalf("cross-scope token: %v", e)
				}
			}
			h.advance(24 * time.Hour)
			_, e = h.command(h.ctx, "GetLatestConfiguration", &dataapi.GetLatestConfigurationInput{ConfigurationToken: reverted.NextPollConfigurationToken})
			if e == nil || e.Code != "BadRequestException" {
				t.Fatalf("expired token: %v", e)
			}
		})
	}
}

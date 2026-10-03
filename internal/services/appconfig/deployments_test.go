package appconfig_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/appconfig"
	dataapi "stackd/internal/awsapi/appconfigdata"
	"stackd/internal/awswire"
	service "stackd/internal/services/appconfig"
)

func (h *deploymentHarness) getDeployment(n int32) *api.GetDeploymentOutput {
	return h.call("GetDeployment", &api.GetDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), DeploymentNumber: new(api.Integer(n))}).(*api.GetDeploymentOutput)
}
func (h *deploymentHarness) legacy(client, version string) *api.GetConfigurationOutput {
	return h.call("GetConfiguration", &api.GetConfigurationInput{Application: new(api.StringWithLengthBetween1And64("application")), Environment: new(api.StringWithLengthBetween1And64("production")), Configuration: new(api.StringWithLengthBetween1And64("document")), ClientId: new(api.StringWithLengthBetween1And64(client)), ClientConfigurationVersion: new(api.Version(version))}).(*api.GetConfigurationOutput)
}

func TestDeploymentRolloutPortable(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newDeploymentHarness(t, backend)
			h.deploy("1", "all1234")
			h.deploy("2", "slow123")
			_, e := h.command(h.ctx, "StartDeployment", &api.StartDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), ConfigurationProfileId: new(api.LongName("pro1234")), ConfigurationVersion: new(api.Version("1")), DeploymentStrategyId: new(api.DeploymentStrategyId("all1234"))})
			if e == nil || e.Code != "ConflictException" {
				t.Fatalf("overlapping deployment: %v", e)
			}
			if got := h.legacy("stable-client", ""); string(got.Content) != `{"value":"first"}` {
				t.Fatalf("zero-percent rollout changed content: %s", got.Content)
			}
			h.advance(time.Minute)
			d := h.getDeployment(2)
			if *d.State != "DEPLOYING" || *d.PercentageComplete != 25 {
				t.Fatalf("first rollout boundary: %+v", d)
			}
			previous := map[string]string{}
			for i := range 64 {
				client := fmt.Sprintf("client-%d", i)
				previous[client] = string(*h.legacy(client, "").ConfigurationVersion)
			}
			h.restart()
			h.advance(time.Minute)
			d = h.getDeployment(2)
			if *d.PercentageComplete != 50 {
				t.Fatalf("restart lost rollout progress: %+v", d)
			}
			for client, version := range previous {
				got := h.legacy(client, "")
				if version == "2" && *got.ConfigurationVersion != "2" {
					t.Fatalf("cohort regressed for %s", client)
				}
			}
			h.advance(2 * time.Minute)
			d = h.getDeployment(2)
			if *d.State != "BAKING" || *d.PercentageComplete != 100 {
				t.Fatalf("baking boundary: %+v", d)
			}
			for client := range previous {
				if got := h.legacy(client, ""); *got.ConfigurationVersion != "2" || string(got.Content) != `{"value":"second"}` {
					t.Fatalf("complete rollout: %+v", got)
				}
			}
			h.advance(time.Minute)
			if d = h.getDeployment(2); *d.State != "BAKING" {
				t.Fatalf("premature final bake completion: %+v", d)
			}
			h.advance(time.Minute)
			if d = h.getDeployment(2); *d.State != "COMPLETE" || d.CompletedAt == nil {
				t.Fatalf("final bake: %+v", d)
			}
			nochange := h.legacy("stable-client", "2")
			if len(nochange.Content) != 0 || *nochange.ConfigurationVersion != "2" || *nochange.ContentType != "application/json" {
				t.Fatalf("legacy no-change: %+v", nochange)
			}
			_, e = h.command(h.ctx, "StopDeployment", &api.StopDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), DeploymentNumber: new(api.Integer(2))})
			if e == nil || e.Code != "BadRequestException" {
				t.Fatalf("stop completed: %v", e)
			}
			h.advance(time.Minute)
			reverted := h.call("StopDeployment", &api.StopDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), DeploymentNumber: new(api.Integer(2)), AllowRevert: new(api.Boolean(true))}).(*api.StopDeploymentOutput)
			if reverted.CompletedAt == nil || !reverted.CompletedAt.Equal(*d.CompletedAt) {
				t.Fatalf("revert rewrote deployment completion time: before=%v after=%v", d.CompletedAt, reverted.CompletedAt)
			}
			if got := h.legacy("stable-client", "2"); string(got.Content) != `{"value":"first"}` {
				t.Fatalf("revert bytes: %s", got.Content)
			}
			third := h.deploy("2", "slow123")
			h.advance(time.Minute)
			h.call("StopDeployment", &api.StopDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), DeploymentNumber: third.DeploymentNumber})
			h.advance(10 * time.Minute)
			if d = h.getDeployment(int32(*third.DeploymentNumber)); *d.State != "ROLLED_BACK" {
				t.Fatalf("stopped rollout resurrected: %+v", d)
			}
			rows := h.call("ListDeployments", &api.ListDeploymentsInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), MaxResults: new(api.MaxResults(2))}).(*api.ListDeploymentsOutput)
			if len(rows.Items) != 2 || *rows.Items[0].DeploymentNumber != 3 || *rows.Items[1].DeploymentNumber != 2 || rows.NextToken == nil {
				t.Fatalf("deployment page: %+v", rows)
			}
			page := h.call("ListDeployments", &api.ListDeploymentsInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), MaxResults: new(api.MaxResults(2)), NextToken: rows.NextToken}).(*api.ListDeploymentsOutput)
			if len(page.Items) != 1 || *page.Items[0].DeploymentNumber != 1 || page.NextToken != nil {
				t.Fatalf("deployment final page: %+v", page)
			}
		})
	}
}

// A real dependency boundary can complete after its owning resources change.
// This effect performs a competing repository write, proving retrieval is not
// under the AppConfig transaction and the stale validation cannot publish.
type admissionEffects struct {
	retrieve func(context.Context, service.Profile, string) (service.ConfigurationContent, error)
	alarm    func(context.Context, service.Scope, service.Monitor) (string, error)
}

func (admissionEffects) AssumeRetrievalRole(context.Context, service.Scope, string) error {
	return fmt.Errorf("unexpected retrieval role assumption")
}
func (e admissionEffects) Retrieve(ctx context.Context, p service.Profile, v string) (service.ConfigurationContent, error) {
	return e.retrieve(ctx, p, v)
}
func (admissionEffects) ValidateLambda(context.Context, service.Profile, string, string, []byte) error {
	return fmt.Errorf("unexpected Lambda validation")
}
func (admissionEffects) Protect(context.Context, service.Scope, string, string, []byte) ([]byte, string, error) {
	return nil, "", fmt.Errorf("unexpected KMS protect")
}
func (admissionEffects) Unprotect(context.Context, service.Scope, string, string, []byte) ([]byte, error) {
	return nil, fmt.Errorf("unexpected KMS unprotect")
}
func (e admissionEffects) Alarm(ctx context.Context, s service.Scope, m service.Monitor) (string, error) {
	return e.alarm(ctx, s, m)
}
func (admissionEffects) InvokeExtension(context.Context, service.Scope, service.ExtensionAction, []byte) ([]byte, error) {
	return nil, fmt.Errorf("unexpected extension invocation")
}

type changingAuthorization struct{ denied, denyTag, denyStart bool }

func (a *changingAuthorization) Authorize(_ context.Context, r authorization.Request) *awswire.Error {
	if a.denied && r.Action == "appconfig:GetLatestConfiguration" || a.denyTag && r.Action == "appconfig:TagResource" || a.denyStart && r.Action == "appconfig:StartDeployment" {
		return &awswire.Error{Code: "AccessDeniedException", Message: "Revoked", StatusCode: 403}
	}
	return nil
}

func TestDeploymentAdmissionAndCurrentAuthorityPortable(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newDeploymentHarness(t, backend)
			// Current schema validation rejects content before any deployment exists.
			err := h.repo.Update(h.ctx, func(tx service.Transaction) error {
				profiles, e := tx.Profiles(h.scope, "app1234")
				if e != nil {
					return e
				}
				p := profiles[0]
				p.Validators = []service.Validator{{Type: "JSON_SCHEMA", Content: `{"type":"object","required":["missing"]}`}}
				return tx.PutProfile(p)
			})
			if err != nil {
				t.Fatal(err)
			}
			_, rejected := h.command(h.ctx, "StartDeployment", &api.StartDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), ConfigurationProfileId: new(api.LongName("pro1234")), ConfigurationVersion: new(api.Version("1")), DeploymentStrategyId: new(api.DeploymentStrategyId("all1234"))})
			if rejected == nil || rejected.Code != "BadRequestException" {
				t.Fatalf("invalid deployment content: %v", rejected)
			}
			err = h.repo.Update(h.ctx, func(tx service.Transaction) error {
				profiles, e := tx.Profiles(h.scope, "app1234")
				if e != nil {
					return e
				}
				p := profiles[0]
				p.Validators = nil
				p.LocationURI = "s3://source/document"
				return tx.PutProfile(p)
			})
			if err != nil {
				t.Fatal(err)
			}
			h.service.Close()
			h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock, Effects: admissionEffects{retrieve: func(ctx context.Context, p service.Profile, v string) (service.ConfigurationContent, error) {
				p.LocationURI = "s3://source/replaced"
				err := h.repo.Update(ctx, func(tx service.Transaction) error { return tx.PutProfile(p) })
				return service.ConfigurationContent{Content: []byte(`{"value":"untrusted"}`), ContentType: "application/json", Version: v}, err
			}}})
			_, rejected = h.command(h.ctx, "StartDeployment", &api.StartDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), ConfigurationProfileId: new(api.LongName("pro1234")), ConfigurationVersion: new(api.Version("1")), DeploymentStrategyId: new(api.DeploymentStrategyId("all1234"))})
			if rejected == nil || rejected.Code != "ConflictException" {
				t.Fatalf("stale source admitted: %v", rejected)
			}
			err = h.repo.View(h.ctx, func(r service.Reader) error {
				rows, e := r.Deployments(h.scope, "app1234", "env1234")
				if e == nil && len(rows) != 0 {
					t.Fatalf("rejected deployment published: %+v", rows)
				}
				return e
			})
			if err != nil {
				t.Fatal(err)
			}
			err = h.repo.Update(h.ctx, func(tx service.Transaction) error {
				profiles, e := tx.Profiles(h.scope, "app1234")
				if e != nil {
					return e
				}
				p := profiles[0]
				p.LocationURI = "hosted"
				return tx.PutProfile(p)
			})
			if err != nil {
				t.Fatal(err)
			}
			authority := &changingAuthorization{}
			h.service.Close()
			h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock, Authorizer: authority})
			authority.denyTag = true
			_, rejected = h.command(h.ctx, "StartDeployment", &api.StartDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), ConfigurationProfileId: new(api.LongName("pro1234")), ConfigurationVersion: new(api.Version("1")), DeploymentStrategyId: new(api.DeploymentStrategyId("all1234")), Tags: api.TagMap{"owner": "test"}})
			if rejected == nil || rejected.Code != "AccessDeniedException" {
				t.Fatalf("deployment bypassed tagging permission: %v", rejected)
			}
			authority.denyTag = false
			h.deploy("1", "all1234")
			token := h.session()
			authority.denied = true
			_, rejected = h.command(h.ctx, "GetLatestConfiguration", &dataapi.GetLatestConfigurationInput{ConfigurationToken: new(dataapi.Token(token))})
			if rejected == nil || rejected.Code != "AccessDeniedException" {
				t.Fatalf("session bypassed current IAM: %v", rejected)
			}
			authority.denied = false
			if got := h.poll(token); !strings.Contains(string(got.Configuration), "first") {
				t.Fatalf("denied poll consumed token: %s", got.Configuration)
			}
		})
	}
}

func TestPipelineDeploymentRecoveryPreservesAcceptedContent(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newDeploymentHarness(t, backend)
			if err := h.repo.Update(h.ctx, func(tx service.Transaction) error {
				profiles, err := tx.Profiles(h.scope, "app1234")
				if err != nil {
					return err
				}
				profile := profiles[0]
				profile.LocationURI = "codepipeline://delivery"
				return tx.PutProfile(profile)
			}); err != nil {
				t.Fatal(err)
			}
			authority := &changingAuthorization{}
			artifactRemoved := false
			effects := admissionEffects{retrieve: func(_ context.Context, _ service.Profile, version string) (service.ConfigurationContent, error) {
				if artifactRemoved {
					return service.ConfigurationContent{}, &awswire.Error{Code: "InternalServerException", StatusCode: 500}
				}
				return service.ConfigurationContent{Content: []byte(`{"value":"accepted"}`), ContentType: "application/octet-stream", Version: version}, nil
			}}
			h.service.Close()
			h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock, Authorizer: authority, Effects: effects})
			const actionID = "928cda7d-274c-4d4b-a34d-7e8494a1cdfe"
			producer := service.WithPipelineAction(h.ctx, actionID)
			input := &api.StartDeploymentInput{
				ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")),
				ConfigurationProfileId: new(api.LongName("pro1234")), ConfigurationVersion: new(api.Version(actionID)),
				DeploymentStrategyId: new(api.DeploymentStrategyId("all1234")),
			}
			out, rejected := h.command(producer, "StartDeployment", input)
			if rejected != nil {
				t.Fatal(rejected)
			}
			first := out.(*api.StartDeploymentOutput)
			h.advance(0)
			h.service.Close()
			h.repo = h.reopen()
			h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock, Authorizer: authority, Effects: effects})
			artifactRemoved, authority.denyStart = true, true
			if _, rejected = h.command(producer, "StartDeployment", input); rejected == nil || rejected.Code != "AccessDeniedException" {
				t.Fatalf("recovery bypassed current deployment permission: %v", rejected)
			}
			authority.denyStart = false
			out, rejected = h.command(producer, "StartDeployment", input)
			if rejected != nil {
				t.Fatalf("accepted deployment reread its removed source: %v", rejected)
			}
			recovered := out.(*api.StartDeploymentOutput)
			if *recovered.DeploymentNumber != *first.DeploymentNumber || *recovered.State != "COMPLETE" {
				t.Fatalf("producer recovery created or reset the deployment: first=%+v recovered=%+v", first, recovered)
			}
			if got := h.legacy("consumer", ""); string(got.Content) != `{"value":"accepted"}` {
				t.Fatalf("accepted deployment lost its content: %s", got.Content)
			}
			if _, rejected = h.command(h.ctx, "StartDeployment", input); rejected == nil || rejected.Code != "InternalServerException" {
				t.Fatalf("public redeploy silently reused accepted content: %v", rejected)
			}
			artifactRemoved = false
			out, rejected = h.command(h.ctx, "StartDeployment", input)
			if rejected != nil {
				t.Fatal(rejected)
			}
			if next := out.(*api.StartDeploymentOutput); *next.DeploymentNumber != *first.DeploymentNumber+1 {
				t.Fatalf("public same-version redeploy became idempotent: first=%+v next=%+v", first, next)
			}
		})
	}
}

func TestDeploymentAlarmRollbackPortable(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newDeploymentHarness(t, backend)
			h.deploy("1", "all1234")
			err := h.repo.Update(h.ctx, func(tx service.Transaction) error {
				envs, e := tx.Environments(h.scope, "app1234")
				if e != nil {
					return e
				}
				env := envs[0]
				env.Monitors = []service.Monitor{{AlarmARN: "arn:aws:cloudwatch:us-east-1:111122223333:alarm:health", RoleARN: "arn:aws:iam::111122223333:role/monitor"}}
				return tx.PutEnvironment(env)
			})
			if err != nil {
				t.Fatal(err)
			}
			h.service.Close()
			h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock, Effects: admissionEffects{alarm: func(ctx context.Context, _ service.Scope, _ service.Monitor) (string, error) {
				if err := h.repo.View(ctx, func(service.Reader) error { return nil }); err != nil {
					return "", err
				}
				return "ALARM", nil
			}}})
			h.deploy("2", "slow123")
			h.advance(time.Minute)
			d := h.getDeployment(2)
			if *d.State != "ROLLED_BACK" {
				t.Fatalf("alarm failed to rollback: %+v", d)
			}
			if len(d.EventLog) == 0 || d.EventLog[0].TriggeredBy == nil || *d.EventLog[0].TriggeredBy != api.TriggeredByCLOUDWATCH_ALARM {
				t.Fatalf("alarm rollback lost its trigger: %+v", d.EventLog)
			}
			if got := h.legacy("client", ""); string(got.Content) != `{"value":"first"}` {
				t.Fatalf("alarm rollback bytes: %s", got.Content)
			}
		})
	}
}

func TestDeploymentStopFencesInFlightAlarmPortable(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newDeploymentHarness(t, backend)
			h.deploy("1", "all1234")
			err := h.repo.Update(h.ctx, func(tx service.Transaction) error {
				envs, e := tx.Environments(h.scope, "app1234")
				if e != nil {
					return e
				}
				env := envs[0]
				env.Monitors = []service.Monitor{{AlarmARN: "arn:aws:cloudwatch:us-east-1:111122223333:alarm:health", RoleARN: "arn:aws:iam::111122223333:role/monitor"}}
				return tx.PutEnvironment(env)
			})
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			h.service.Close()
			h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock, Effects: admissionEffects{alarm: func(ctx context.Context, _ service.Scope, _ service.Monitor) (string, error) {
				once.Do(func() { close(entered) })
				select {
				case <-release:
					return "OK", nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			}}})
			h.deploy("2", "slow123")
			if err := h.clock.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("scheduler did not reach the external alarm")
			}
			// Stop must remain possible while the external effect is blocked. Its state
			// transition owns a newer generation than the returning successful alarm.
			stopped := h.call("StopDeployment", &api.StopDeploymentInput{ApplicationId: new(api.Name("app1234")), EnvironmentId: new(api.Name("env1234")), DeploymentNumber: new(api.Integer(2))}).(*api.StopDeploymentOutput)
			close(release)
			if *stopped.State != "ROLLED_BACK" {
				t.Fatalf("stop response: %+v", stopped)
			}
			if _, err := h.service.JobDriver().RunDue(h.ctx, 100); err != nil {
				t.Fatal(err)
			}
			h.advance(10 * time.Minute)
			d := h.getDeployment(2)
			if *d.State != "ROLLED_BACK" || *d.PercentageComplete != 0 {
				t.Fatalf("late alarm resurrected stopped deployment: %+v", d)
			}
			if got := h.legacy("client", ""); string(got.Content) != `{"value":"first"}` {
				t.Fatalf("stale completion published content: %s", got.Content)
			}
		})
	}
}

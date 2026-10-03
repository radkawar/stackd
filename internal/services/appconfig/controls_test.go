package appconfig_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/appconfig"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/appconfig"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlappconfig "stackd/storage/sqlite/appconfig"
)

const (
	controlAccount = "111122223333"
	controlRole    = "arn:aws:iam::111122223333:role/appconfig-retrieval"
	controlKey     = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
)

// controlEffects stands in for the IAM/STS and KMS owners at their Effects
// boundary. Ciphertext is bound to the encryption-context resource so a
// mismatched decrypt fails as it would in KMS.
type controlEffects struct{ service.Effects }

func (controlEffects) AssumeRetrievalRole(_ context.Context, _ service.Scope, role string) error {
	if role == controlRole {
		return nil
	}
	return &awswire.Error{Code: "AccessDenied", Message: "The role cannot be assumed.", StatusCode: 403}
}

func (controlEffects) Protect(_ context.Context, _ service.Scope, key, resource string, plaintext []byte) ([]byte, string, error) {
	if key != "alias/appconfig" {
		return nil, "", &awswire.Error{Code: "NotFoundException", Message: "Alias " + key + " is not found.", StatusCode: 400}
	}
	out := []byte(resource + "|")
	for _, b := range plaintext {
		out = append(out, b^0x5a)
	}
	return out, controlKey, nil
}

func (controlEffects) Unprotect(_ context.Context, _ service.Scope, key, resource string, ciphertext []byte) ([]byte, error) {
	body, ok := bytes.CutPrefix(ciphertext, []byte(resource+"|"))
	if key != controlKey || !ok {
		return nil, &awswire.Error{Code: "InvalidCiphertextException", Message: "The encryption context does not match.", StatusCode: 400}
	}
	out := make([]byte, 0, len(body))
	for _, b := range body {
		out = append(out, b^0x5a)
	}
	return out, nil
}

type controlPolicy struct{ document string }

func (p controlPolicy) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []policy.Policy{{Document: p.document}}}, nil
}

type controlHarness struct {
	t       *testing.T
	ctx     context.Context
	scope   service.Scope
	clock   *clock.Manual
	repo    service.Repository
	service *service.Service
	auth    authorization.Authorizer
	docs    service.StrategyDocuments
	reopen  func() service.Repository
}

func newControlHarness(t *testing.T, backend string) *controlHarness {
	t.Helper()
	h := &controlHarness{t: t, scope: service.Scope{Partition: "aws", AccountID: controlAccount, Region: "us-east-1"}, clock: clock.NewManual(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))}
	h.ctx = controlContext(t, controlAccount, "us-east-1", "arn:aws:iam::111122223333:root")
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
			if db, err = sqlite.Open(h.ctx, path); err != nil {
				t.Fatal(err)
			}
			return sqlappconfig.New(db)
		}
		t.Cleanup(func() { db.Close() })
	}
	h.start()
	return h
}

func controlContext(t *testing.T, account, region, principal string) context.Context {
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: account, Region: region, PrincipalARN: principal, PrincipalID: account})
}

func (h *controlHarness) start() {
	h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock, Effects: controlEffects{}, Authorizer: h.auth, StrategyDocuments: h.docs})
	h.t.Cleanup(func() { h.service.Close() })
}

func (h *controlHarness) restart() {
	h.t.Helper()
	h.service.Close()
	h.repo = h.reopen()
	h.start()
}

func (h *controlHarness) command(ctx context.Context, action string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("appconfig")
	op, _ := model.Operation(action)
	return h.service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
}

func (h *controlHarness) call(action string, input any) any {
	h.t.Helper()
	out, err := h.command(h.ctx, action, input)
	if err != nil {
		h.t.Fatalf("%s: %v", action, err)
	}
	return out
}

func (h *controlHarness) reject(action string, input any, code string) *awswire.Error {
	h.t.Helper()
	_, err := h.command(h.ctx, action, input)
	if err == nil || !strings.HasPrefix(err.Code, code) {
		h.t.Fatalf("%s: got %v, want %s", action, err, code)
	}
	return err
}

func (h *controlHarness) app(name string) string {
	return string(*h.call("CreateApplication", &api.CreateApplicationInput{Name: new(api.Name(name))}).(*api.Application).Id)
}

func (h *controlHarness) env(app, name string) string {
	return string(*h.call("CreateEnvironment", &api.CreateEnvironmentInput{ApplicationId: new(api.Name(app)), Name: new(api.Name(name))}).(*api.Environment).Id)
}

func (h *controlHarness) profile(in *api.CreateConfigurationProfileInput) *api.ConfigurationProfile {
	return h.call("CreateConfigurationProfile", in).(*api.ConfigurationProfile)
}

func (h *controlHarness) hosted(app, profile, content, label string, latest *api.Integer) *api.HostedConfigurationVersion {
	in := &api.CreateHostedConfigurationVersionInput{ApplicationId: new(api.Name(app)), ConfigurationProfileId: new(api.LongName(profile)), Content: api.Blob(content), ContentType: new(api.StringWithLengthBetween1And255("application/json")), LatestVersionNumber: latest}
	if label != "" {
		in.VersionLabel = new(api.VersionLabel(label))
	}
	return h.call("CreateHostedConfigurationVersion", in).(*api.HostedConfigurationVersion)
}

type controlCase struct {
	Name        string          `json:"name"`
	Operation   string          `json:"operation"`
	Input       json.RawMessage `json:"input"`
	ContentSize int             `json:"contentSize"`
	Status      int             `json:"status"`
	Code        string          `json:"code"`
	// Message wording stays in the fixture as native evidence only.
	Details map[string]any `json:"details"`
}

// TestControlNativeRejections replays captured native AppConfig rejections
// against an equivalent seeded state: status, error code and modeled details
// must match, and every rejection must leave state unchanged.
func TestControlNativeRejections(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/appconfig/controls_native.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []controlCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	h := newControlHarness(t, "memory")
	app, other := h.app("probe"), h.app("other")
	h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(other)), Name: new(api.LongName("orphan")), LocationUri: new(api.Uri("hosted"))})
	env, env2 := h.env(app, "env"), h.env(app, "env2")
	profile := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("free")), LocationUri: new(api.Uri("hosted")), Validators: api.ValidatorList{{Type: new(api.ValidatorTypeJSON_SCHEMA), Content: new(api.StringWithLengthBetween0And32768(`{"type":"object"}`))}}})
	pipeline := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("cp")), LocationUri: new(api.Uri("codepipeline://stackd-missing"))})
	flags := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("flags")), LocationUri: new(api.Uri("hosted")), Type: new(api.ConfigurationProfileType("AWS.AppConfig.FeatureFlags"))})
	h.hosted(app, string(*profile.Id), `{"x":1}`, "v1.0", nil)
	replacer := strings.NewReplacer("${app}", app, "${other}", other, "${env}", env, "${env2}", env2, "${profile}", string(*profile.Id), "${pipeline}", string(*pipeline.Id), "${flags}", string(*flags.Id), "${account}", controlAccount)
	before := controlSnapshot(t, h)
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			input, err := api.NewInput(c.Operation)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(replacer.Replace(string(c.Input))), input); err != nil {
				t.Fatal(err)
			}
			if c.ContentSize > 0 {
				input.(*api.CreateHostedConfigurationVersionInput).Content = bytes.Repeat([]byte("x"), c.ContentSize)
			}
			_, rejected := h.command(h.ctx, c.Operation, input)
			if rejected == nil {
				t.Fatalf("accepted; native %s", c.Code)
			}
			if rejected.StatusCode != c.Status || rejected.Code != c.Code {
				t.Fatalf("got %d %s %q, native %d %s", rejected.StatusCode, rejected.Code, rejected.Message, c.Status, c.Code)
			}
			for k, want := range c.Details {
				var got any
				if err := json.Unmarshal(rejected.Details[k], &got); err != nil || got != want {
					t.Fatalf("detail %s: got %s want %v", k, rejected.Details[k], want)
				}
			}
		})
	}
	if after := controlSnapshot(t, h); after != before {
		t.Fatalf("rejections changed state:\n%s\n%s", before, after)
	}
}

// controlSnapshot summarizes every control resource in the harness scope.
func controlSnapshot(t *testing.T, h *controlHarness) string {
	t.Helper()
	var out strings.Builder
	err := h.repo.View(h.ctx, func(r service.Reader) error {
		apps, err := r.Applications(h.scope)
		if err != nil {
			return err
		}
		for _, a := range apps {
			envs, _ := r.Environments(h.scope, a.ID)
			profiles, _ := r.Profiles(h.scope, a.ID)
			out.WriteString(a.ID + "/" + a.Name + ":")
			for _, e := range envs {
				out.WriteString(" env " + e.ID + "/" + e.Name)
			}
			for _, p := range profiles {
				versions, _ := r.HostedVersions(h.scope, a.ID, p.ID)
				out.WriteString(" profile " + p.ID + "/" + p.Name + "/" + p.KMSKeyIdentifier)
				for _, v := range versions {
					out.WriteString(" v" + strconv.Itoa(int(v.Number)) + v.VersionLabel)
				}
			}
			out.WriteString("\n")
		}
		strategies, err := r.Strategies(h.scope)
		for _, s := range strategies {
			out.WriteString("strategy " + s.ID + "/" + s.Description + "\n")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestControlLifecyclePortable(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newControlHarness(t, backend)
			app := h.call("CreateApplication", &api.CreateApplicationInput{Name: new(api.Name("shop")), Tags: api.TagMap{"team": "blue"}}).(*api.Application)
			appID := string(*app.Id)
			env := h.call("CreateEnvironment", &api.CreateEnvironmentInput{ApplicationId: new(api.Name("shop")), Name: new(api.Name("prod")), Monitors: api.MonitorList{{AlarmArn: new(api.StringWithLengthBetween1And2048("arn:aws:cloudwatch:us-east-1:111122223333:alarm:errors")), AlarmRoleArn: new(api.RoleArn(controlRole))}}}).(*api.Environment)
			if *env.State != "ReadyForDeployment" || len(env.Monitors) != 1 {
				t.Fatalf("environment: %+v", env)
			}
			p := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name("shop")), Name: new(api.LongName("settings")), LocationUri: new(api.Uri("hosted")), KmsKeyIdentifier: new(api.KmsKeyIdentifier("alias/appconfig"))})
			profileID := string(*p.Id)
			if *p.Type != "AWS.Freeform" || *p.KmsKeyArn != "arn:aws:kms:us-east-1:111122223333:alias/appconfig" {
				t.Fatalf("profile defaults: %+v", p)
			}
			// Role-backed sources assume the retrieval role before commit.
			ssm := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(appID)), Name: new(api.LongName("params")), LocationUri: new(api.Uri("ssm-parameter://app/settings")), RetrievalRoleArn: new(api.RoleArn(controlRole))})

			v1 := h.hosted(appID, "settings", `{"x":1}`, "v1.0", nil)
			if *v1.VersionNumber != 1 || string(v1.Content) != `{"x":1}` || *v1.KmsKeyArn != controlKey {
				t.Fatalf("encrypted version: %+v", v1)
			}
			h.hosted(appID, profileID, `{"x":2}`, "v2.0", new(api.Integer(1)))
			h.call("DeleteHostedConfigurationVersion", &api.DeleteHostedConfigurationVersionInput{ApplicationId: new(api.Name(appID)), ConfigurationProfileId: new(api.LongName(profileID)), VersionNumber: new(api.Integer(2))})
			// Deleted numbers are never reused; the lock compares the latest remaining version.
			if v := h.hosted(appID, profileID, `{"x":3}`, "", new(api.Integer(1))); *v.VersionNumber != 3 {
				t.Fatalf("reused version number: %d", *v.VersionNumber)
			}
			if err := h.repo.View(h.ctx, func(r service.Reader) error {
				rows, err := r.HostedVersions(h.scope, appID, profileID)
				if err == nil && (len(rows) != 2 || bytes.Contains(rows[0].Content, []byte(`"x"`))) {
					t.Fatalf("hosted content stored in plaintext: %q", rows[0].Content)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			h.restart()

			got := h.call("GetHostedConfigurationVersion", &api.GetHostedConfigurationVersionInput{ApplicationId: new(api.Name("shop")), ConfigurationProfileId: new(api.LongName("settings")), VersionNumber: new(api.Integer(1))}).(*api.HostedConfigurationVersion)
			if string(got.Content) != `{"x":1}` || *got.VersionLabel != "v1.0" || *got.KmsKeyArn != controlKey {
				t.Fatalf("decrypted version after restart: %+v", got)
			}
			if v := h.hosted(appID, profileID, `{"x":4}`, "v4.0", nil); *v.VersionNumber != 4 {
				t.Fatalf("persisted sequence: %d", *v.VersionNumber)
			}
			list := h.call("ListHostedConfigurationVersions", &api.ListHostedConfigurationVersionsInput{ApplicationId: new(api.Name(appID)), ConfigurationProfileId: new(api.LongName(profileID)), MaxResults: new(api.MaxResults(2))}).(*api.HostedConfigurationVersions)
			if len(list.Items) != 2 || *list.Items[0].VersionNumber != 4 || *list.Items[1].VersionNumber != 3 || list.NextToken == nil {
				t.Fatalf("newest-first page: %+v", list)
			}
			list = h.call("ListHostedConfigurationVersions", &api.ListHostedConfigurationVersionsInput{ApplicationId: new(api.Name(appID)), ConfigurationProfileId: new(api.LongName(profileID)), MaxResults: new(api.MaxResults(2)), NextToken: list.NextToken}).(*api.HostedConfigurationVersions)
			if len(list.Items) != 1 || *list.Items[0].VersionNumber != 1 || list.NextToken != nil {
				t.Fatalf("second page: %+v", list)
			}
			list = h.call("ListHostedConfigurationVersions", &api.ListHostedConfigurationVersionsInput{ApplicationId: new(api.Name(appID)), ConfigurationProfileId: new(api.LongName(profileID)), VersionLabel: new(api.QueryName("v*"))}).(*api.HostedConfigurationVersions)
			if len(list.Items) != 2 || *list.Items[0].VersionLabel != "v4.0" || *list.Items[1].VersionLabel != "v1.0" {
				t.Fatalf("label prefix filter: %+v", list)
			}

			// Clearing the key stops encrypting new versions only.
			h.call("UpdateConfigurationProfile", &api.UpdateConfigurationProfileInput{ApplicationId: new(api.Name(appID)), ConfigurationProfileId: new(api.LongName(profileID)), KmsKeyIdentifier: new(api.KmsKeyIdentifierOrEmpty("")), Validators: api.ValidatorList{}})
			if v := h.hosted(appID, profileID, `{"x":5}`, "", nil); v.KmsKeyArn != nil {
				t.Fatalf("cleared key still encrypts: %+v", v)
			}
			p = h.call("GetConfigurationProfile", &api.GetConfigurationProfileInput{ApplicationId: new(api.Name(appID)), ConfigurationProfileId: new(api.LongName(profileID))}).(*api.ConfigurationProfile)
			if p.KmsKeyIdentifier != nil || p.KmsKeyArn != nil {
				t.Fatalf("cleared profile key: %+v", p)
			}
			// Hosted versions are also accepted on non-hosted profiles, as natively observed.
			pipeline := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(appID)), Name: new(api.LongName("pipeline")), LocationUri: new(api.Uri("codepipeline://deploy"))})
			h.hosted(appID, string(*pipeline.Id), `{}`, "", nil)

			env = h.call("UpdateEnvironment", &api.UpdateEnvironmentInput{ApplicationId: new(api.Name(appID)), EnvironmentId: new(api.Name("prod")), Monitors: api.MonitorList{}}).(*api.Environment)
			if len(env.Monitors) != 0 {
				t.Fatalf("monitors not cleared: %+v", env)
			}
			h.reject("DeleteApplication", &api.DeleteApplicationInput{ApplicationId: new(api.Name(appID))}, "BadRequestException")

			// A recently polled environment older than an hour is protected.
			if err := h.clock.Advance(2 * time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := h.repo.Update(h.ctx, func(tx service.Transaction) error {
				rows, err := tx.Environments(h.scope, appID)
				if err != nil {
					return err
				}
				rows[0].LastPoll = h.clock.Now().Add(-time.Minute)
				return tx.PutEnvironment(rows[0])
			}); err != nil {
				t.Fatal(err)
			}
			h.reject("DeleteEnvironment", &api.DeleteEnvironmentInput{ApplicationId: new(api.Name(appID)), EnvironmentId: new(api.Name(*env.Id))}, "BadRequestException")
			h.call("DeleteEnvironment", &api.DeleteEnvironmentInput{ApplicationId: new(api.Name(appID)), EnvironmentId: new(api.Name(*env.Id)), DeletionProtectionCheck: new(api.DeletionProtectionCheckBYPASS)})

			for _, id := range []string{profileID, string(*pipeline.Id), string(*ssm.Id)} {
				versions := h.call("ListHostedConfigurationVersions", &api.ListHostedConfigurationVersionsInput{ApplicationId: new(api.Name(appID)), ConfigurationProfileId: new(api.LongName(id))}).(*api.HostedConfigurationVersions)
				for _, v := range versions.Items {
					h.call("DeleteHostedConfigurationVersion", &api.DeleteHostedConfigurationVersionInput{ApplicationId: new(api.Name(appID)), ConfigurationProfileId: new(api.LongName(id)), VersionNumber: v.VersionNumber})
				}
				h.call("DeleteConfigurationProfile", &api.DeleteConfigurationProfileInput{ApplicationId: new(api.Name(appID)), ConfigurationProfileId: new(api.LongName(id))})
			}
			h.call("DeleteApplication", &api.DeleteApplicationInput{ApplicationId: new(api.Name(appID))})
			if err := h.repo.View(h.ctx, func(r service.Reader) error {
				tags, err := r.Tags(h.scope, "arn:aws:appconfig:us-east-1:111122223333:application/"+appID)
				if err == nil && len(tags) != 0 {
					t.Fatalf("deleted application kept tags: %v", tags)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			h.reject("GetApplication", &api.GetApplicationInput{ApplicationId: new(api.Name(appID))}, "ResourceNotFoundException")
		})
	}
}

// strategyDocuments stands in for the Systems Manager document owner,
// retaining each replicated document's latest version.
type strategyDocuments struct{ versions map[string]int }

func (d *strategyDocuments) CreateStrategyDocument(_ context.Context, v service.Strategy) error {
	if d.versions[v.Name] > 0 {
		return &awswire.Error{Code: "DocumentAlreadyExists", Message: "Document with same name " + v.Name + " already exists", StatusCode: 400}
	}
	d.versions[v.Name] = 1
	return nil
}

func (d *strategyDocuments) UpdateStrategyDocument(_ context.Context, v service.Strategy) error {
	d.versions[v.Name]++
	return nil
}

func (d *strategyDocuments) DeleteStrategyDocument(_ context.Context, v service.Strategy) error {
	if d.versions[v.Name] == 0 {
		return &awswire.Error{Code: "InvalidDocument", Message: "Document with name " + v.Name + " does not exist.", StatusCode: 400}
	}
	delete(d.versions, v.Name)
	return nil
}

func TestControlStrategies(t *testing.T) {
	h := newControlHarness(t, "memory")
	list := h.call("ListDeploymentStrategies", &api.ListDeploymentStrategiesInput{}).(*api.DeploymentStrategies)
	want := []string{"AppConfig.AllAtOnce/0/10/100/LINEAR", "AppConfig.Linear50PercentEvery30Seconds/1/1/50/LINEAR", "AppConfig.Canary10Percent20Minutes/20/10/10/EXPONENTIAL", "AppConfig.Linear20PercentEvery6Minutes/30/30/20/LINEAR"}
	if len(list.Items) != len(want) {
		t.Fatalf("predefined strategies: %+v", list.Items)
	}
	for i, v := range list.Items {
		if got := strings.Join([]string{string(*v.Id), strconv.Itoa(int(*v.DeploymentDurationInMinutes)), strconv.Itoa(int(*v.FinalBakeTimeInMinutes)), strconv.Itoa(int(*v.GrowthFactor)), string(*v.GrowthType)}, "/"); got != want[i] || *v.ReplicateTo != "NONE" {
			t.Fatalf("predefined %d: %s", i, got)
		}
	}
	// Names are not unique; both custom strategies precede predefined ones.
	first := h.call("CreateDeploymentStrategy", &api.CreateDeploymentStrategyInput{Name: new(api.Name("fast")), DeploymentDurationInMinutes: new(api.MinutesBetween0And24Hours(0)), GrowthFactor: new(api.GrowthFactor(1.5))}).(*api.DeploymentStrategy)
	h.call("CreateDeploymentStrategy", &api.CreateDeploymentStrategyInput{Name: new(api.Name("fast")), DeploymentDurationInMinutes: new(api.MinutesBetween0And24Hours(0)), GrowthFactor: new(api.GrowthFactor(100))})
	if *first.GrowthType != "LINEAR" || *first.FinalBakeTimeInMinutes != 0 || *first.GrowthFactor != 1.5 || *first.ReplicateTo != "NONE" {
		t.Fatalf("strategy defaults: %+v", first)
	}
	page := h.call("ListDeploymentStrategies", &api.ListDeploymentStrategiesInput{MaxResults: new(api.MaxResults(2))}).(*api.DeploymentStrategies)
	if len(page.Items) != 2 || strings.HasPrefix(string(*page.Items[0].Id), "AppConfig.") || strings.HasPrefix(string(*page.Items[1].Id), "AppConfig.") || page.NextToken == nil {
		t.Fatalf("custom strategies first: %+v", page)
	}
	updated := h.call("UpdateDeploymentStrategy", &api.UpdateDeploymentStrategyInput{DeploymentStrategyId: new(api.DeploymentStrategyId(*first.Id)), GrowthType: new(api.GrowthTypeEXPONENTIAL), GrowthFactor: new(api.GrowthFactor(10))}).(*api.DeploymentStrategy)
	if *updated.GrowthType != "EXPONENTIAL" || *updated.GrowthFactor != 10 || *updated.Name != "fast" {
		t.Fatalf("updated strategy: %+v", updated)
	}
	// SSM replication joins the strategy transaction: a document collision
	// leaves no strategy, and only content changes add document versions.
	docs := &strategyDocuments{versions: map[string]int{}}
	h.docs = docs
	h.service.Close()
	h.start()
	replicate := func(name string) *api.CreateDeploymentStrategyInput {
		return &api.CreateDeploymentStrategyInput{Name: new(api.Name(name)), DeploymentDurationInMinutes: new(api.MinutesBetween0And24Hours(0)), GrowthFactor: new(api.GrowthFactor(100)), ReplicateTo: new(api.ReplicateToSSM_DOCUMENT)}
	}
	replicated := h.call("CreateDeploymentStrategy", replicate("doc")).(*api.DeploymentStrategy)
	before := controlSnapshot(t, h)
	h.reject("CreateDeploymentStrategy", replicate("doc"), "BadRequestException")
	if after := controlSnapshot(t, h); after != before {
		t.Fatalf("document collision created a strategy:\n%s\n%s", before, after)
	}
	id := new(api.DeploymentStrategyId(*replicated.Id))
	h.call("UpdateDeploymentStrategy", &api.UpdateDeploymentStrategyInput{DeploymentStrategyId: id})
	h.call("UpdateDeploymentStrategy", &api.UpdateDeploymentStrategyInput{DeploymentStrategyId: id, GrowthFactor: new(api.GrowthFactor(50))})
	if docs.versions["doc"] != 2 {
		t.Fatalf("document versions: %v", docs.versions)
	}
	delete(docs.versions, "doc")
	h.call("DeleteDeploymentStrategy", &api.DeleteDeploymentStrategyInput{DeploymentStrategyId: id})
	h.call("DeleteDeploymentStrategy", &api.DeleteDeploymentStrategyInput{DeploymentStrategyId: new(api.DeploymentStrategyId(*first.Id))})
	h.reject("GetDeploymentStrategy", &api.GetDeploymentStrategyInput{DeploymentStrategyId: new(api.DeploymentStrategyId(*first.Id))}, "ResourceNotFoundException")
}

func TestControlScopeAndCurrentIAM(t *testing.T) {
	h := newControlHarness(t, "memory")
	app := h.app("shared")
	h.env(app, "prod")
	for _, ctx := range []context.Context{controlContext(t, "444455556666", "us-east-1", "arn:aws:iam::444455556666:root"), controlContext(t, controlAccount, "eu-west-1", "arn:aws:iam::111122223333:root")} {
		for _, id := range []string{app, "shared"} {
			if _, e := h.command(ctx, "GetApplication", &api.GetApplicationInput{ApplicationId: new(api.Name(id))}); e == nil || e.Code != "ResourceNotFoundException" || !strings.Contains(e.Message, awsctx.FromContext(ctx).AccountID) {
				t.Fatalf("cross-scope read: %v", e)
			}
		}
		out, e := h.command(ctx, "ListApplications", &api.ListApplicationsInput{})
		if e != nil || len(out.(*api.Applications).Items) != 0 {
			t.Fatalf("cross-scope list: %+v %v", out, e)
		}
		// Names are unique per account and Region only.
		if _, e := h.command(ctx, "CreateApplication", &api.CreateApplicationInput{Name: new(api.Name("shared"))}); e != nil {
			t.Fatalf("same name in another scope: %v", e)
		}
	}

	profile := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("doc")), LocationUri: new(api.Uri("hosted")), Tags: api.TagMap{"team": "red"}})
	appARN := "arn:aws:appconfig:us-east-1:111122223333:application/" + app
	h.auth = authorization.NewWithClock(controlPolicy{`{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"appconfig:*","Resource":"*"},
		{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"appconfig.amazonaws.com"}}},
		{"Effect":"Deny","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/forbidden"},
		{"Effect":"Deny","Action":"appconfig:GetConfigurationProfile","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"red"}}},
		{"Effect":"Deny","Action":"appconfig:DeleteApplication","Resource":"arn:aws:appconfig:us-east-1:111122223333:application/zzzzzzz"},
		{"Effect":"Deny","Action":"appconfig:CreateHostedConfigurationVersion","Resource":"` + appARN + `"}]}`}, nil, h.clock)
	h.service.Close()
	h.start()
	h.ctx = controlContext(t, controlAccount, "us-east-1", "arn:aws:iam::111122223333:user/operator")
	get := &api.GetConfigurationProfileInput{ApplicationId: new(api.Name(app)), ConfigurationProfileId: new(api.LongName("doc"))}
	h.reject("GetConfigurationProfile", get, "AccessDenied")
	h.call("UntagResource", &api.UntagResourceInput{ResourceArn: new(api.Arn(appARN + "/configurationprofile/" + string(*profile.Id))), TagKeys: api.TagKeyList{"team"}})
	h.call("GetConfigurationProfile", get)
	// Denial on a missing resource precedes existence disclosure.
	h.reject("DeleteApplication", &api.DeleteApplicationInput{ApplicationId: new(api.Name("zzzzzzz"))}, "AccessDenied")
	// Hosted-version creation requires the application element as well as the profile.
	h.reject("CreateHostedConfigurationVersion", &api.CreateHostedConfigurationVersionInput{ApplicationId: new(api.Name(app)), ConfigurationProfileId: new(api.LongName("doc")), Content: api.Blob("{}"), ContentType: new(api.StringWithLengthBetween1And255("application/json"))}, "AccessDenied")
	before := controlSnapshot(t, h)
	h.reject("CreateEnvironment", &api.CreateEnvironmentInput{ApplicationId: new(api.Name(app)), Name: new(api.Name("watched")), Monitors: api.MonitorList{{AlarmArn: new(api.StringWithLengthBetween1And2048("arn:aws:cloudwatch:us-east-1:111122223333:alarm:a")), AlarmRoleArn: new(api.RoleArn("arn:aws:iam::111122223333:role/forbidden"))}}}, "AccessDenied")
	h.reject("CreateConfigurationProfile", &api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("params")), LocationUri: new(api.Uri("ssm-parameter://p")), RetrievalRoleArn: new(api.RoleArn("arn:aws:iam::111122223333:role/forbidden"))}, "AccessDenied")
	if after := controlSnapshot(t, h); after != before {
		t.Fatalf("denied commands changed state:\n%s\n%s", before, after)
	}
}

// TestControlConcurrentAdmission proves the version lock and name uniqueness
// are enforced at commit, not only in the external-effect preflight.
func TestControlConcurrentAdmission(t *testing.T) {
	h := newControlHarness(t, "memory")
	app := h.app("race")
	profile := string(*h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("doc")), LocationUri: new(api.Uri("hosted")), KmsKeyIdentifier: new(api.KmsKeyIdentifier("alias/appconfig"))}).Id)
	var wg sync.WaitGroup
	accepted, rejected := make(chan *api.HostedConfigurationVersion, 8), make(chan *awswire.Error, 8)
	for i := range 8 {
		wg.Go(func() {
			out, e := h.command(h.ctx, "CreateHostedConfigurationVersion", &api.CreateHostedConfigurationVersionInput{ApplicationId: new(api.Name(app)), ConfigurationProfileId: new(api.LongName(profile)), Content: api.Blob(strconv.Itoa(i)), ContentType: new(api.StringWithLengthBetween1And255("application/json")), LatestVersionNumber: new(api.Integer(0))})
			if e != nil {
				rejected <- e
				return
			}
			accepted <- out.(*api.HostedConfigurationVersion)
		})
	}
	wg.Wait()
	close(accepted)
	close(rejected)
	if len(accepted) != 1 {
		t.Fatalf("version lock admitted %d writers", len(accepted))
	}
	for e := range rejected {
		if e.Code != "ConflictException" {
			t.Fatalf("lock loser: %v", e)
		}
	}
	names := make(chan *awswire.Error, 8)
	for range 8 {
		wg.Go(func() {
			_, e := h.command(h.ctx, "CreateEnvironment", &api.CreateEnvironmentInput{ApplicationId: new(api.Name(app)), Name: new(api.Name("prod"))})
			names <- e
		})
	}
	wg.Wait()
	close(names)
	ok := 0
	for e := range names {
		if e == nil {
			ok++
		} else if e.Code != "BadRequestException" {
			t.Fatalf("duplicate environment: %v", e)
		}
	}
	if ok != 1 {
		t.Fatalf("created %d environments named prod", ok)
	}
}

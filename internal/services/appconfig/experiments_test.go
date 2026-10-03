package appconfig_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/appconfig"
	service "stackd/internal/services/appconfig"
)

func experimentDefinitionInput(app, env, profile string) *api.CreateExperimentDefinitionInput {
	return &api.CreateExperimentDefinitionInput{ApplicationIdentifier: new(api.Identifier(app)), EnvironmentIdentifier: new(api.Identifier(env)), ConfigurationProfileIdentifier: new(api.Identifier(profile)), Name: new(api.NameWithReservedAwsPrefix("checkout-experiment")), FlagKey: new(api.FlagKey("checkout")), AudienceRule: new(api.Rule(`(eq $country "US")`)), Control: &api.TreatmentInput{Weight: new(api.Weight(50)), FlagValue: &api.FlagValue{Enabled: new(api.Boolean(false))}}, Treatments: api.TreatmentInputList{{Weight: new(api.Weight(50)), FlagValue: &api.FlagValue{Enabled: new(api.Boolean(true))}}}}
}

// Native evidence is retained in testdata/aws/appconfig/experiments_native.json
// and experiments_agent_native.json. These assertions cover lifecycle state,
// immutable snapshots and served-document effects, not incidental wording.
func TestExperimentLifecyclePortable(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newControlHarness(t, backend)
			app := h.app("app")
			env := h.env(app, "production")
			p := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("flags")), LocationUri: new(api.Uri("hosted")), Type: new(api.ConfigurationProfileType("AWS.AppConfig.FeatureFlags"))})
			profile := string(*p.Id)
			in := experimentDefinitionInput(app, env, profile)
			d := h.call("CreateExperimentDefinition", in).(*api.ExperimentDefinition)
			id := *d.Id
			start := &api.StartExperimentRunInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), ExposurePercentage: new(api.NullablePercentage(20)), TreatmentOverrides: &api.TreatmentOverrides{Inline: api.TreatmentOverrideMap{"forced": "t1"}}}
			h.reject("StartExperimentRun", start, "BadRequestException")
			h.hosted(app, profile, `{"version":"1","flags":{"checkout":{"name":"Checkout"}},"values":{"checkout":{"enabled":false}}}`, "", nil)
			strategy := h.call("CreateDeploymentStrategy", &api.CreateDeploymentStrategyInput{Name: new(api.Name("instant")), DeploymentDurationInMinutes: new(api.MinutesBetween0And24Hours(0)), FinalBakeTimeInMinutes: new(api.MinutesBetween0And24Hours(0)), GrowthFactor: new(api.GrowthFactor(100)), ReplicateTo: new(api.ReplicateToNONE)}).(*api.DeploymentStrategy)
			h.call("StartDeployment", &api.StartDeploymentInput{ApplicationId: new(api.Name(app)), EnvironmentId: new(api.Name(env)), ConfigurationProfileId: new(api.LongName(profile)), ConfigurationVersion: new(api.Version("1")), DeploymentStrategyId: new(api.DeploymentStrategyId(*strategy.Id))})
			run := h.call("StartExperimentRun", start).(*api.ExperimentRun)
			if *run.Status != "RUNNING" || *run.Run != 1 || *run.ExposurePercentage != 20 {
				t.Fatalf("start state: %+v", run)
			}
			getDef := &api.GetExperimentDefinitionInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id))}
			if got := h.call("GetExperimentDefinition", getDef).(*api.ExperimentDefinition); *got.Status != "ACTIVE" {
				t.Fatalf("definition not active: %+v", got)
			}
			h.reject("StartExperimentRun", start, "ConflictException")
			h.reject("UpdateExperimentDefinition", &api.UpdateExperimentDefinitionInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), Hypothesis: new(api.Description("changed"))}, "ConflictException")
			h.reject("DeleteExperimentDefinition", &api.DeleteExperimentDefinitionInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id))}, "BadRequestException")
			update := &api.UpdateExperimentRunInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), Run: new(api.PositiveInteger(1)), ExposurePercentage: new(api.NullablePercentage(10))}
			h.reject("UpdateExperimentRun", update, "BadRequestException")
			update.ExposurePercentage = new(api.NullablePercentage(40))
			update.TreatmentOverrides = &api.TreatmentOverrides{Inline: api.TreatmentOverrideMap{"forced": "t1"}}
			h.reject("UpdateExperimentRun", update, "BadRequestException")
			update.TreatmentOverrides = nil
			h.call("UpdateExperimentRun", update)
			if err := h.repo.View(h.ctx, func(r service.Reader) error {
				rows, e := r.Deployments(h.scope, app, env)
				if e != nil {
					return e
				}
				last := rows[len(rows)-1]
				if len(rows) != 3 || last.Type != "MANAGED" || !strings.Contains(last.ExperimentFlags, "/experimentrun/1|t1=__t1__,c=__c__") {
					t.Fatalf("managed effect: %+v", last)
				}
				var doc map[string]any
				if e = json.Unmarshal(last.Content, &doc); e != nil {
					return e
				}
				variants := doc["values"].(map[string]any)["checkout"].(map[string]any)["_variants"].([]any)
				rule := variants[1].(map[string]any)["rule"].(string)
				if !strings.Contains(rule, "pct::20 ") {
					t.Fatalf("exposure did not alter served rule: %s", rule)
				}
				versions, e := r.HostedVersions(h.scope, app, profile)
				if e == nil && len(versions) != 1 {
					t.Fatalf("experiment fabricated hosted versions: %+v", versions)
				}
				return e
			}); err != nil {
				t.Fatal(err)
			}
			h.restart()
			getRun := &api.GetExperimentRunInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), Run: new(api.PositiveInteger(1))}
			if got := h.call("GetExperimentRun", getRun).(*api.ExperimentRun); *got.ExposurePercentage != 40 || got.TreatmentOverrides.Inline["forced"] != "t1" {
				t.Fatalf("restart lost run: %+v", got)
			}
			eventPage := h.call("ListExperimentRunEvents", &api.ListExperimentRunEventsInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), Run: new(api.PositiveInteger(1)), MaxResults: new(api.MaxResults(1))}).(*api.ExperimentRunEvents)
			if eventPage.NextToken == nil || len(eventPage.Items) != 1 || *eventPage.Items[0].EventType != "EXPOSURE_UPDATED" {
				t.Fatalf("first event page: %+v", eventPage)
			}
			result := &api.ExperimentRunResult{ExecutiveSummary: new(api.Description("Customer-owned analytics"))}
			stopped := h.call("StopExperimentRun", &api.StopExperimentRunInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), Run: new(api.PositiveInteger(1)), Result: result}).(*api.ExperimentRun)
			if *stopped.Status != "DONE" || stopped.EndedAt == nil || *stopped.Result.ExecutiveSummary != "Customer-owned analytics" {
				t.Fatalf("stop result: %+v", stopped)
			}
			// Stopping prepends an event. Continuation must not repeat the
			// exposure event or skip the original start event.
			remainingEvents := h.call("ListExperimentRunEvents", &api.ListExperimentRunEventsInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), Run: new(api.PositiveInteger(1)), MaxResults: new(api.MaxResults(2)), NextToken: eventPage.NextToken}).(*api.ExperimentRunEvents)
			if len(remainingEvents.Items) != 1 || *remainingEvents.Items[0].EventType != "RUN_STARTED" || remainingEvents.NextToken != nil {
				t.Fatalf("event continuation after prepend: %+v", remainingEvents)
			}
			h.reject("ListExperimentRuns", &api.ListExperimentRunsInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), NextToken: eventPage.NextToken}, "BadRequestException")
			h.reject("UpdateExperimentRun", update, "BadRequestException")
			h.call("UpdateExperimentDefinition", &api.UpdateExperimentDefinitionInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), Hypothesis: new(api.Description("next hypothesis"))})
			snapshot := h.call("GetExperimentRun", getRun).(*api.ExperimentRun).ExperimentDefinitionSnapshot
			if snapshot.Hypothesis != nil {
				t.Fatalf("definition update changed prior snapshot: %+v", snapshot)
			}
			events := h.call("ListExperimentRunEvents", &api.ListExperimentRunEventsInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id)), Run: new(api.PositiveInteger(1))}).(*api.ExperimentRunEvents)
			if len(events.Items) != 3 || *events.Items[0].EventType != "RUN_STOPPED" || *events.Items[1].EventType != "EXPOSURE_UPDATED" || *events.Items[2].EventType != "RUN_STARTED" {
				t.Fatalf("events: %+v", events)
			}
			if err := h.repo.View(h.ctx, func(r service.Reader) error {
				rows, e := r.Deployments(h.scope, app, env)
				if e != nil {
					return e
				}
				last := rows[len(rows)-1]
				if last.ExperimentFlags != "" || strings.Contains(string(last.Content), "_variants") {
					t.Fatalf("stop left treatment document active: %s", last.Content)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, ctx := range []struct{ account, region string }{{"999900001111", "us-east-1"}, {controlAccount, "eu-west-1"}} {
				_, e := h.command(controlContext(t, ctx.account, ctx.region, "arn:aws:iam::"+ctx.account+":root"), "GetExperimentDefinition", getDef)
				if e == nil || e.Code != "ResourceNotFoundException" {
					t.Fatalf("scope leaked: %v", e)
				}
			}
			del := &api.DeleteExperimentDefinitionInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(id))}
			h.call("DeleteExperimentDefinition", del)
			if *h.call("GetExperimentDefinition", getDef).(*api.ExperimentDefinition).Status != "ARCHIVED" {
				t.Fatal("default deletion did not archive")
			}
			h.reject("StartExperimentRun", start, "ConflictException")
			del.DeleteType = new(api.DeleteTypeDESTROY)
			h.call("DeleteExperimentDefinition", del)
			h.reject("GetExperimentDefinition", getDef, "ResourceNotFoundException")
			h.reject("GetExperimentRun", getRun, "ResourceNotFoundException")
		})
	}
}

func TestExperimentResourceAuthorization(t *testing.T) {
	h := newControlHarness(t, "memory")
	app := h.app("app")
	env := h.env(app, "env")
	profile := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("flags")), LocationUri: new(api.Uri("hosted")), Type: new(api.ConfigurationProfileType("AWS.AppConfig.FeatureFlags"))})
	d := h.call("CreateExperimentDefinition", experimentDefinitionInput(app, env, string(*profile.Id))).(*api.ExperimentDefinition)
	arn := fmt.Sprintf("arn:aws:appconfig:us-east-1:%s:application/%s/experimentdefinition/%s", controlAccount, app, *d.Id)
	h.auth = authorization.NewWithClock(controlPolicy{fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"appconfig:*","Resource":"*"},{"Effect":"Deny","Action":"appconfig:GetExperimentDefinition","Resource":%q}]}`, arn)}, nil, h.clock)
	h.restart()
	_, err := h.command(controlContext(t, controlAccount, "us-east-1", "arn:aws:iam::"+controlAccount+":user/caller"), "GetExperimentDefinition", &api.GetExperimentDefinitionInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(*d.Id))})
	if err == nil || !strings.HasPrefix(err.Code, "AccessDenied") {
		t.Fatalf("definition ARN deny ignored: %v", err)
	}
}

func TestExperimentPaginationEqualTimestampsAndFilters(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newControlHarness(t, backend)
			app := h.app("app")
			env := h.env(app, "production")
			p := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("flags")), LocationUri: new(api.Uri("hosted")), Type: new(api.ConfigurationProfileType("AWS.AppConfig.FeatureFlags"))})
			profile := string(*p.Id)
			for i := range 3 {
				in := experimentDefinitionInput(app, env, profile)
				in.Name = new(api.NameWithReservedAwsPrefix(fmt.Sprintf("experiment-%d", i)))
				h.call("CreateExperimentDefinition", in)
			}
			all := h.call("ListExperimentDefinitions", &api.ListExperimentDefinitionsInput{ApplicationIdentifier: new(api.Identifier(app))}).(*api.ExperimentDefinitions)
			first := h.call("ListExperimentDefinitions", &api.ListExperimentDefinitionsInput{ApplicationIdentifier: new(api.Identifier("app")), EnvironmentIdentifier: new(api.Identifier("production")), ConfigurationProfileIdentifier: new(api.Identifier("flags")), MaxResults: new(api.MaxResults(1))}).(*api.ExperimentDefinitions)
			if len(all.Items) != 3 || len(first.Items) != 1 || first.NextToken == nil || *first.Items[0].Id != *all.Items[0].Id {
				t.Fatalf("initial experiment pages: all=%+v first=%+v", all, first)
			}
			h.call("DeleteExperimentDefinition", &api.DeleteExperimentDefinitionInput{ApplicationIdentifier: new(api.Identifier(app)), ExperimentDefinitionIdentifier: new(api.Identifier(*first.Items[0].Id)), DeleteType: new(api.DeleteTypeDESTROY)})
			h.restart()
			rest := h.call("ListExperimentDefinitions", &api.ListExperimentDefinitionsInput{ApplicationIdentifier: new(api.Identifier(app)), EnvironmentIdentifier: new(api.Identifier(env)), ConfigurationProfileIdentifier: new(api.Identifier(profile)), MaxResults: new(api.MaxResults(2)), NextToken: first.NextToken}).(*api.ExperimentDefinitions)
			if len(rest.Items) != 2 || *rest.Items[0].Id != *all.Items[1].Id || *rest.Items[1].Id != *all.Items[2].Id || rest.NextToken != nil {
				t.Fatalf("experiment continuation after deletion: %+v", rest)
			}
			h.reject("ListExperimentDefinitions", &api.ListExperimentDefinitionsInput{ApplicationIdentifier: new(api.Identifier(app)), EnvironmentIdentifier: new(api.Identifier(env)), ConfigurationProfileIdentifier: new(api.Identifier(profile)), Status: new(api.ExperimentDefinitionStatus("ARCHIVED")), NextToken: first.NextToken}, "BadRequestException")
		})
	}
}

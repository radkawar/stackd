package appconfig_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/appconfig"
	service "stackd/internal/services/appconfig"
)

type expandingControlEffects struct {
	controlEffects
	size int
}

func (e *expandingControlEffects) InvokeExtension(context.Context, service.Scope, service.ExtensionAction, []byte) ([]byte, error) {
	return json.Marshal(struct{ Content []byte }{bytes.Repeat([]byte("x"), e.size)})
}

func TestControlTransformedHostedLimit(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newControlHarness(t, backend)
			app := h.app("transform")
			profile := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("hosted")), LocationUri: new(api.Uri("hosted")), KmsKeyIdentifier: new(api.KmsKeyIdentifier("alias/appconfig"))})
			effect := &expandingControlEffects{size: (2 << 20) + 1}
			h.service.Close()
			h.service = service.New(service.Config{Repository: h.repo, Clock: h.clock, Effects: effect})
			extension := h.call("CreateExtension", &api.CreateExtensionInput{Name: new(api.ExtensionOrParameterName("expand")), Actions: api.ActionsMap{api.ActionPointPRE_CREATE_HOSTED_CONFIGURATION_VERSION: {{Name: new(api.Name("expand")), Uri: new(api.Uri("arn:aws:lambda:us-east-1:111122223333:function:expand"))}}}}).(*api.Extension)
			h.call("CreateExtensionAssociation", &api.CreateExtensionAssociationInput{ExtensionIdentifier: new(api.Identifier(*extension.Id)), ResourceIdentifier: new(api.Identifier("arn:aws:appconfig:us-east-1:111122223333:application/" + app))})
			input := &api.CreateHostedConfigurationVersionInput{ApplicationId: new(api.Name(app)), ConfigurationProfileId: new(api.LongName(*profile.Id)), Content: api.Blob("{}"), ContentType: new(api.StringWithLengthBetween1And255("application/json"))}
			before := controlSnapshot(t, h)
			err := h.reject("CreateHostedConfigurationVersion", input, "PayloadTooLargeException")
			if err.StatusCode != 413 || string(err.Details["Size"]) != "2049.0" {
				t.Fatalf("transformed size rejection: %+v", err)
			}
			if after := controlSnapshot(t, h); after != before {
				t.Fatal("oversized transformation changed hosted state")
			}
			effect.size = 2 << 20
			created := h.call("CreateHostedConfigurationVersion", input).(*api.HostedConfigurationVersion)
			if *created.VersionNumber != 1 || !bytes.Equal(created.Content, bytes.Repeat([]byte("x"), effect.size)) {
				t.Fatal("limit-sized transformation must persist as first version")
			}
			h.restart()
			read := h.call("GetHostedConfigurationVersion", &api.GetHostedConfigurationVersionInput{ApplicationId: input.ApplicationId, ConfigurationProfileId: input.ConfigurationProfileId, VersionNumber: new(api.Integer(1))}).(*api.HostedConfigurationVersion)
			if !bytes.Equal(read.Content, created.Content) {
				t.Fatal("transformed encrypted content changed after restart")
			}
		})
	}
}

func TestControlApplicationQuota(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newControlHarness(t, backend)
			var first string
			for i := range 100 {
				id := h.app("app-" + strconv.Itoa(i))
				if i == 0 {
					first = id
				}
			}
			err := h.reject("CreateApplication", &api.CreateApplicationInput{Name: new(api.Name("overflow"))}, "ServiceQuotaExceededException")
			if err.StatusCode != 402 {
				t.Fatalf("quota HTTP status: %d", err.StatusCode)
			}
			h.reject("GetApplication", &api.GetApplicationInput{ApplicationId: new(api.Name("overflow"))}, "ResourceNotFoundException")
			other := controlContext(t, controlAccount, "eu-west-1", "arn:aws:iam::111122223333:root")
			if _, err := h.command(other, "CreateApplication", &api.CreateApplicationInput{Name: new(api.Name("overflow"))}); err != nil {
				t.Fatalf("quota leaked across regions: %v", err)
			}
			h.call("DeleteApplication", &api.DeleteApplicationInput{ApplicationId: new(api.Name(first))})
			h.app("overflow")
		})
	}
}

func TestControlAssociationDeletionBlockers(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newControlHarness(t, backend)
			app := h.app("associated")
			env := h.env(app, "env")
			profile := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("profile")), LocationUri: new(api.Uri("hosted"))})
			extension := h.call("CreateExtension", &api.CreateExtensionInput{Name: new(api.ExtensionOrParameterName("guard")), Actions: api.ActionsMap{api.ActionPointPRE_START_DEPLOYMENT: {{Name: new(api.Name("guard")), Uri: new(api.Uri("arn:aws:lambda:us-east-1:111122223333:function:guard"))}}}}).(*api.Extension)
			base := "arn:aws:appconfig:us-east-1:111122223333:application/" + app
			for _, row := range []struct {
				action, resource string
				input            any
			}{
				{"DeleteEnvironment", base + "/environment/" + env, &api.DeleteEnvironmentInput{ApplicationId: new(api.Name(app)), EnvironmentId: new(api.Name(env))}},
				{"DeleteConfigurationProfile", base + "/configurationprofile/" + string(*profile.Id), &api.DeleteConfigurationProfileInput{ApplicationId: new(api.Name(app)), ConfigurationProfileId: new(api.LongName(*profile.Id))}},
				{"DeleteApplication", base, &api.DeleteApplicationInput{ApplicationId: new(api.Name(app))}},
			} {
				association := h.call("CreateExtensionAssociation", &api.CreateExtensionAssociationInput{ExtensionIdentifier: new(api.Identifier(*extension.Id)), ResourceIdentifier: new(api.Identifier(row.resource))}).(*api.ExtensionAssociation)
				h.restart()
				before := controlSnapshot(t, h)
				h.reject(row.action, row.input, "BadRequestException")
				if controlSnapshot(t, h) != before {
					t.Fatalf("%s rejection changed resources", row.action)
				}
				retained := h.call("GetExtensionAssociation", &api.GetExtensionAssociationInput{ExtensionAssociationId: new(api.Id(*association.Id))}).(*api.ExtensionAssociation)
				if *retained.ResourceArn != api.Arn(row.resource) {
					t.Fatal("rejected delete changed association")
				}
				h.call("DeleteExtensionAssociation", &api.DeleteExtensionAssociationInput{ExtensionAssociationId: new(api.Id(*association.Id))})
				h.call(row.action, row.input)
			}
			h.call("DeleteExtension", &api.DeleteExtensionInput{ExtensionIdentifier: new(api.Identifier(*extension.Id))})
		})
	}
}

func TestControlCreateTagAuthorization(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newControlHarness(t, backend)
			app := h.app("parent")
			base := "arn:aws:appconfig:us-east-1:111122223333:"
			for _, row := range []struct {
				action, resource string
				input            func(api.TagMap) any
			}{
				{"CreateApplication", base + "application/*", func(tags api.TagMap) any {
					return &api.CreateApplicationInput{Name: new(api.Name("tagged")), Tags: tags}
				}},
				{"CreateEnvironment", base + "application/" + app + "/environment/*", func(tags api.TagMap) any {
					return &api.CreateEnvironmentInput{ApplicationId: new(api.Name(app)), Name: new(api.Name("tagged")), Tags: tags}
				}},
				{"CreateConfigurationProfile", base + "application/" + app + "/configurationprofile/*", func(tags api.TagMap) any {
					return &api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("tagged")), LocationUri: new(api.Uri("hosted")), Tags: tags}
				}},
				{"CreateDeploymentStrategy", base + "deploymentstrategy/*", func(tags api.TagMap) any {
					return &api.CreateDeploymentStrategyInput{Name: new(api.Name("tagged")), DeploymentDurationInMinutes: new(api.MinutesBetween0And24Hours(0)), GrowthFactor: new(api.GrowthFactor(100)), ReplicateTo: new(api.ReplicateToNONE), Tags: tags}
				}},
			} {
				h.auth = authorization.NewWithClock(controlPolicy{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"appconfig:Create*","Resource":"*"},{"Effect":"Allow","Action":"appconfig:TagResource","Resource":"` + row.resource + `","Condition":{"StringEquals":{"aws:RequestTag/team":"green"}}}]}`}, nil, h.clock)
				h.service.Close()
				h.start()
				h.ctx = controlContext(t, controlAccount, "us-east-1", "arn:aws:iam::111122223333:user/operator")
				before := controlSnapshot(t, h)
				h.reject(row.action, row.input(api.TagMap{"team": "red"}), "AccessDenied")
				if controlSnapshot(t, h) != before {
					t.Fatalf("%s tag denial left a resource", row.action)
				}
				h.call(row.action, row.input(api.TagMap{"team": "green"}))
			}
		})
	}
}

// Native mutations echo an explicitly empty description, but subsequent reads
// omit it. This is response presence, not a nullable persistent domain field.
func TestControlEmptyDescription(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newControlHarness(t, backend)
			empty := new(api.Description(""))
			check := func(p *api.Description, present bool) {
				t.Helper()
				if (p != nil) != present || p != nil && *p != "" {
					t.Fatalf("empty description presence: got %v, want present=%v", p, present)
				}
			}
			app := h.call("CreateApplication", &api.CreateApplicationInput{Name: new(api.Name("empty")), Description: empty}).(*api.Application)
			check(app.Description, true)
			appID := new(api.Name(*app.Id))
			env := h.call("CreateEnvironment", &api.CreateEnvironmentInput{ApplicationId: appID, Name: new(api.Name("empty")), Description: empty}).(*api.Environment)
			check(env.Description, true)
			profile := h.profile(&api.CreateConfigurationProfileInput{ApplicationId: appID, Name: new(api.LongName("empty")), LocationUri: new(api.Uri("hosted")), Description: empty})
			check(profile.Description, true)
			strategy := h.call("CreateDeploymentStrategy", &api.CreateDeploymentStrategyInput{Name: new(api.Name("empty")), Description: empty, DeploymentDurationInMinutes: new(api.MinutesBetween0And24Hours(0)), GrowthFactor: new(api.GrowthFactor(100)), ReplicateTo: new(api.ReplicateToNONE)}).(*api.DeploymentStrategy)
			check(strategy.Description, true)
			hosted := h.call("CreateHostedConfigurationVersion", &api.CreateHostedConfigurationVersionInput{ApplicationId: appID, ConfigurationProfileId: new(api.LongName(*profile.Id)), Description: empty, Content: api.Blob("{}"), ContentType: new(api.StringWithLengthBetween1And255("application/json"))}).(*api.HostedConfigurationVersion)
			check(hosted.Description, true)
			h.restart()
			check(h.call("GetApplication", &api.GetApplicationInput{ApplicationId: appID}).(*api.Application).Description, false)
			check(h.call("GetEnvironment", &api.GetEnvironmentInput{ApplicationId: appID, EnvironmentId: new(api.Name(*env.Id))}).(*api.Environment).Description, false)
			check(h.call("GetConfigurationProfile", &api.GetConfigurationProfileInput{ApplicationId: appID, ConfigurationProfileId: new(api.LongName(*profile.Id))}).(*api.ConfigurationProfile).Description, false)
			check(h.call("GetDeploymentStrategy", &api.GetDeploymentStrategyInput{DeploymentStrategyId: new(api.DeploymentStrategyId(*strategy.Id))}).(*api.DeploymentStrategy).Description, false)
			check(h.call("GetHostedConfigurationVersion", &api.GetHostedConfigurationVersionInput{ApplicationId: appID, ConfigurationProfileId: new(api.LongName(*profile.Id)), VersionNumber: new(api.Integer(1))}).(*api.HostedConfigurationVersion).Description, false)
			check(h.call("UpdateApplication", &api.UpdateApplicationInput{ApplicationId: appID, Description: empty}).(*api.Application).Description, true)
			check(h.call("UpdateEnvironment", &api.UpdateEnvironmentInput{ApplicationId: appID, EnvironmentId: new(api.Name(*env.Id)), Description: empty}).(*api.Environment).Description, true)
			check(h.call("UpdateConfigurationProfile", &api.UpdateConfigurationProfileInput{ApplicationId: appID, ConfigurationProfileId: new(api.LongName(*profile.Id)), Description: empty}).(*api.ConfigurationProfile).Description, true)
			check(h.call("UpdateDeploymentStrategy", &api.UpdateDeploymentStrategyInput{DeploymentStrategyId: new(api.DeploymentStrategyId(*strategy.Id)), Description: empty}).(*api.DeploymentStrategy).Description, true)
			check(h.call("UpdateApplication", &api.UpdateApplicationInput{ApplicationId: appID}).(*api.Application).Description, false)
		})
	}
}

package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/cloudformation"
	"stackd/storage/sqlite"
	appstore "stackd/storage/sqlite/appconfig"
)

type cfnApplicationCommands struct {
	*appconfig.Service
	lose         string
	beforeAction string
	before       func()
}

func (c *cfnApplicationCommands) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	action := string(r.Operation.Name)
	if c.before != nil && action == c.beforeAction {
		fn := c.before
		c.before = nil
		fn()
	}
	out, err := c.Service.ExecuteCommand(ctx, r)
	if err == nil && action == c.lose {
		c.lose = ""
		return nil, &awswire.Error{Code: "InternalServerException", Message: "lost admitted reply", StatusCode: 500}
	}
	return out, err
}

type cfnApplicationFixture struct {
	t          *testing.T
	ctx        context.Context
	db         *sql.DB
	path       string
	repository appconfig.Repository
	owner      *appconfig.Service
	executor   *cfnApplicationCommands
	commands   StepFunctionsCommands
	source     *clock.Manual
}

func newCFNApplicationFixture(t *testing.T, backend string) *cfnApplicationFixture {
	f := &cfnApplicationFixture{t: t, ctx: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}), repository: appconfig.NewMemoryRepository(nil), source: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))}
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "application.sqlite")
		f.open()
	}
	f.start()
	t.Cleanup(func() {
		_ = f.owner.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}
func (f *cfnApplicationFixture) open() {
	var err error
	f.db, err = sqlite.Open(f.ctx, f.path)
	if err != nil {
		f.t.Fatal(err)
	}
	f.repository = appstore.New(f.db)
}
func (f *cfnApplicationFixture) start() {
	f.owner = appconfig.New(appconfig.Config{Repository: f.repository, Clock: f.source})
	f.executor = &cfnApplicationCommands{Service: f.owner}
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"appconfig": f.executor})
}
func (f *cfnApplicationFixture) reopen() {
	_ = f.owner.Close()
	if f.db != nil {
		_ = f.db.Close()
		f.open()
	}
	f.start()
}
func (f *cfnApplicationFixture) call(ctx context.Context, action string, in map[string]any) map[string]any {
	f.t.Helper()
	body, _ := json.Marshal(in)
	out, err := f.commands.Call(ctx, "appconfig", action, body)
	if err != nil {
		f.t.Fatalf("%s: %v", action, err)
	}
	encoded, _ := json.Marshal(out.Output)
	var value map[string]any
	if len(encoded) > 0 && json.Unmarshal(encoded, &value) != nil {
		f.t.Fatalf("%s response: %s", action, encoded)
	}
	return value
}
func cfnApplicationRequest(kind string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{Type: "AWS::AppConfig::" + kind, StackID: "stack", StackName: "stack", LogicalID: kind, Token: "incarnation-a", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Properties: p}
}

func TestCFNApplicationPrivateRecoveryAndForeignIncarnations(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNApplicationFixture(t, backend)
			r := cfnApplicationRequest("Application", cloudformation.Properties{"Name": "owned"})
			h := cfnACfgApplication{f.commands}
			forged := f.call(f.ctx, "CreateApplication", map[string]any{"Name": "owned", "Tags": cfnComputeOwnedTags(r)})
			foreignID := forged["Id"].(string)
			if out, err := h.Create(f.ctx, r); err == nil || out.PhysicalID != "" {
				t.Fatalf("counterfeit adopted: %+v %v", out, err)
			}
			stale := r
			stale.PhysicalID = foreignID
			if err := h.Delete(f.ctx, stale); err == nil {
				t.Fatal("counterfeit deletion accepted")
			}
			f.call(f.ctx, "GetApplication", map[string]any{"ApplicationId": foreignID})
			f.call(f.ctx, "UpdateApplication", map[string]any{"ApplicationId": foreignID, "Description": "native permitted"})
			f.call(f.ctx, "DeleteApplication", map[string]any{"ApplicationId": foreignID})
			f.executor.lose = "CreateApplication"
			if _, err := h.Create(f.ctx, r); err == nil {
				t.Fatal("lost response not injected")
			}
			recovered, err := h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID == "" {
				t.Fatalf("exact recovery: %+v %v", recovered, err)
			}
			f.reopen()
			h = cfnACfgApplication{f.commands}
			again, err := h.Create(f.ctx, r)
			if err != nil || again.PhysicalID != recovered.PhysicalID {
				t.Fatalf("reopen recovery: %+v %v", again, err)
			}
			r.PhysicalID = recovered.PhysicalID
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"Name": "owned", "Description": "claim survives tags"}
			unprivileged := awsctx.WithMetadata(f.ctx, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:user/outsider", PrincipalID: "outsider"})
			if _, err := h.RecoverCreation(unprivileged, r); err == nil || cfnACfgMissing(err) {
				t.Fatalf("private recovery bypassed current IAM: %v", err)
			}
			if _, err := h.Update(unprivileged, r); err == nil {
				t.Fatal("private mutation bypassed current IAM")
			}
			arn := cfnACfgARN(r, "application/"+r.PhysicalID)
			f.call(f.ctx, "TagResource", map[string]any{"ResourceArn": arn, "Tags": map[string]string{cfnComputeTagPrefix + "incarnation": "counterfeit"}})
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatalf("public tags became authority: %v", err)
			}
			p, err := h.Read(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(p)
			if strings.Contains(string(body), "Ownership") || strings.Contains(string(body), "cfn_owner") {
				t.Fatalf("private claim leaked: %s", body)
			}
			f.call(f.ctx, "DeleteApplication", map[string]any{"ApplicationId": r.PhysicalID})
			recreated := f.call(f.ctx, "CreateApplication", map[string]any{"Name": "owned", "Tags": cfnComputeOwnedTags(r)})
			newID := recreated["Id"].(string)
			r.PhysicalID = newID
			if _, err := h.Create(f.ctx, r); err == nil {
				t.Fatal("foreign recreation adopted")
			}
			if err := h.Delete(f.ctx, r); err == nil {
				t.Fatal("foreign recreation deleted")
			}
			f.reopen()
			f.call(f.ctx, "GetApplication", map[string]any{"ApplicationId": newID})
			r.CloudControl = true
			h = cfnACfgApplication{f.commands}
			if _, err := h.Create(f.ctx, r); err == nil {
				t.Fatal("CC create bypassed private claim")
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatalf("CC native delete: %v", err)
			}
		})
	}
}

// Every taggable native row must carry its own claim, not its parent's claim.
// These are actual owner commands and durable reads, including real deployments
// and experiment-run transformations; no mock resource echoes are involved.
func TestCFNApplicationPrivateClaimsAllNativeRows(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, kind := range []string{"Application", "Environment", "ConfigurationProfile", "DeploymentStrategy", "Deployment", "Extension", "ExtensionAssociation", "ExperimentDefinition", "ExperimentRun"} {
				t.Run(kind, func(t *testing.T) {
					f := newCFNApplicationFixture(t, backend)
					app := f.call(f.ctx, "CreateApplication", map[string]any{"Name": "parent"})["Id"].(string)
					env := f.call(f.ctx, "CreateEnvironment", map[string]any{"ApplicationId": app, "Name": "parent"})["Id"].(string)
					profile := f.call(f.ctx, "CreateConfigurationProfile", map[string]any{"ApplicationId": app, "Name": "parent", "LocationUri": "hosted", "Type": "AWS.AppConfig.FeatureFlags"})["Id"].(string)
					hosted := cfnACfgHosted{f.commands}
					_, err := hosted.Create(f.ctx, cfnApplicationRequest("HostedConfigurationVersion", cloudformation.Properties{"ApplicationId": app, "ConfigurationProfileId": profile, "Content": `{"version":"1","flags":{"checkout":{"name":"Checkout"}},"values":{"checkout":{"enabled":false}}}`, "ContentType": "application/json"}))
					if err != nil {
						t.Fatal(err)
					}
					strategy := f.call(f.ctx, "CreateDeploymentStrategy", map[string]any{"Name": "instant", "DeploymentDurationInMinutes": 0, "FinalBakeTimeInMinutes": 0, "GrowthFactor": 100, "ReplicateTo": "NONE"})["Id"].(string)
					var p cloudformation.Properties
					switch kind {
					case "Application":
						p = cloudformation.Properties{"Name": "row"}
					case "Environment":
						p = cloudformation.Properties{"ApplicationId": app, "Name": "row"}
					case "ConfigurationProfile":
						p = cloudformation.Properties{"ApplicationId": app, "Name": "row", "LocationUri": "hosted"}
					case "DeploymentStrategy":
						p = cloudformation.Properties{"Name": "row", "DeploymentDurationInMinutes": 0, "FinalBakeTimeInMinutes": 0, "GrowthFactor": 100, "ReplicateTo": "NONE"}
					case "Deployment":
						p = cloudformation.Properties{"ApplicationId": app, "EnvironmentId": env, "ConfigurationProfileId": profile, "ConfigurationVersion": "1", "DeploymentStrategyId": strategy}
					case "Extension", "ExtensionAssociation":
						p = cloudformation.Properties{"Name": "row", "Actions": map[string]any{"PRE_START_DEPLOYMENT": []any{map[string]any{"Name": "native", "Uri": "arn:aws:lambda:us-east-1:123456789012:function:unused"}}}, "Parameters": map[string]any{"token": map[string]any{"Required": true}}}
						if kind == "ExtensionAssociation" {
							extension := f.call(f.ctx, "CreateExtension", map[string]any(p))["Id"].(string)
							p = cloudformation.Properties{"ExtensionIdentifier": extension, "ResourceIdentifier": cfnACfgARN(cfnApplicationRequest(kind, nil), "application/"+app), "Parameters": map[string]any{"token": "native"}}
						}
						if kind == "Extension" {
							delete(p, "Parameters")
						}
					case "ExperimentDefinition", "ExperimentRun":
						p = cloudformation.Properties{"ApplicationIdentifier": app, "Name": "row", "ConfigurationProfileIdentifier": profile, "EnvironmentIdentifier": env, "FlagKey": "checkout", "AudienceRule": `(eq $country "US")`, "Control": map[string]any{"Enabled": false, "Weight": 50}, "Treatments": []any{map[string]any{"Enabled": true, "Weight": 50}}}
						if kind == "ExperimentRun" {
							f.call(f.ctx, "StartDeployment", map[string]any{"ApplicationId": app, "EnvironmentId": env, "ConfigurationProfileId": profile, "ConfigurationVersion": "1", "DeploymentStrategyId": strategy})
							definition, err := (cfnACfgExperiment{f.commands}).Create(f.ctx, cfnApplicationRequest("ExperimentDefinition", p))
							if err != nil {
								t.Fatal(err)
							}
							parts, _ := cfnAppParts(definition.PhysicalID, 2)
							p = cloudformation.Properties{"ApplicationIdentifier": app, "ExperimentDefinitionIdentifier": parts[1], "ExposurePercentage": 20}
						}
					}
					r := cfnApplicationRequest(kind, p)
					handlers := CloudFormationApplicationHandlers(f.commands)
					h := handlers[r.Type]
					first, err := h.Create(f.ctx, r)
					if err != nil {
						t.Fatalf("native create: %v", err)
					}
					if kind == "Extension" {
						update := r
						update.PhysicalID = first.PhysicalID
						update.Properties = cloudformation.Properties{"Name": p["Name"], "Actions": p["Actions"], "Description": "updated without parameters"}
						if _, err := h.Update(f.ctx, update); err != nil {
							t.Fatal(err)
						}
						projected, err := h.(cloudformation.ResourceReader).Read(f.ctx, update)
						if err != nil || projected["Description"] != "updated without parameters" {
							t.Fatalf("parameterless extension update: %#v %v", projected, err)
						}
						next := map[string]any{}
						for key, value := range p {
							next[key] = value
						}
						next["Description"] = "independent newer version"
						next["LatestVersionNumber"] = 1
						f.call(f.ctx, "CreateExtension", next)
					}
					f.reopen()
					h = CloudFormationApplicationHandlers(f.commands)[r.Type]
					recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
					if err != nil || recovered.PhysicalID != first.PhysicalID {
						t.Fatalf("private durable recovery: %+v %+v %v", first, recovered, err)
					}
					r.PhysicalID = first.PhysicalID
					wrong := r
					wrong.Token = "other-incarnation"
					wrong.Previous = wrong.Properties
					if _, err := h.Update(f.ctx, wrong); err == nil {
						t.Fatal("another token mutated native row")
					}
					// Ordinary owner reads expose public DTOs and preserve native effects.
					if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestCFNApplicationRecoveryDependencyAbsenceIsNotAdmissionCertificate(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNApplicationFixture(t, backend)
			r := cfnApplicationRequest("Environment", cloudformation.Properties{"ApplicationId": "missing", "Name": "row"})
			out, err := (cfnACfgEnvironment{f.commands}).RecoverCreation(f.ctx, r)
			if err == nil || cfnACfgMissing(err) || out.PhysicalID != "" {
				t.Fatalf("missing dependency falsely certified native absence: %+v %v", out, err)
			}
			// A successful native empty application list really does certify no private row.
			parent := cfnApplicationRequest("Application", cloudformation.Properties{"Name": "absent"})
			if out, err := (cfnACfgApplication{f.commands}).RecoverCreation(f.ctx, parent); !cfnACfgMissing(err) || out.PhysicalID != "" {
				t.Fatalf("exact native absence certificate lost: %+v %v", out, err)
			}
		})
	}
}

func TestCFNHostedNoopUpdateChecksCurrentAuthorityAndIncarnation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNApplicationFixture(t, backend)
			application := f.call(f.ctx, "CreateApplication", map[string]any{"Name": "hosted-owner"})
			profile := f.call(f.ctx, "CreateConfigurationProfile", map[string]any{
				"ApplicationId": application["Id"], "Name": "hosted", "LocationUri": "hosted",
			})
			r := cfnApplicationRequest("HostedConfigurationVersion", cloudformation.Properties{
				"ApplicationId": application["Id"], "ConfigurationProfileId": profile["Id"],
				"Content": `{"enabled":true}`, "ContentType": "application/json",
			})
			h := cfnACfgHosted{f.commands}
			created, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID, r.Previous = created.PhysicalID, r.Properties
			f.reopen()
			h = cfnACfgHosted{f.commands}
			foreign := r
			foreign.Token = "foreign-incarnation"
			if _, err := h.Update(f.ctx, foreign); !appconfig.IsCloudFormationOwnershipMismatch(err) {
				t.Fatalf("immutable no-op update bypassed the private incarnation: %v", err)
			}
			denied := awsctx.WithMetadata(t.Context(), awsctx.Metadata{
				Partition: "aws", AccountID: "123456789012", Region: "us-east-1",
				PrincipalARN: "arn:aws:iam::123456789012:user/denied", PrincipalID: "denied",
			})
			var wire *awswire.Error
			if _, err := h.Update(denied, r); !errors.As(err, &wire) || wire.StatusCode != 403 {
				t.Fatalf("immutable no-op update bypassed current IAM: %v", err)
			}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			model, err := h.Read(f.ctx, r)
			if err != nil || model["Content"] != `{"enabled":true}` {
				t.Fatalf("private no-op update changed the immutable native content: %+v %v", model, err)
			}
		})
	}
}

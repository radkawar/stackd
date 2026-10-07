package integrations

import (
	"context"
	"database/sql"
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
	"stackd/internal/services/apigateway"
	"stackd/internal/services/cloudformation"
	"stackd/storage/sqlite"
	gatewaystore "stackd/storage/sqlite/apigateway"
)

func TestRESTGatewayResourcesUseAuthoritativeOwners(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			scope := cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.Account})
			var repository apigateway.Repository = apigateway.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "gateway.sqlite")
			if backend == "sqlite" {
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repository = gatewaystore.New(db)
			}
			now := clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))
			owner := apigateway.New(apigateway.Config{Repository: repository, Clock: now})
			t.Cleanup(func() {
				_ = owner.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"apigateway": owner})
			handlers := CloudFormationAPIGatewayRESTHandlers(commands)
			request := func(kind, logical string, p cloudformation.Properties) cloudformation.ResourceRequest {
				return cloudformation.ResourceRequest{StackID: "stack", StackName: "stack", LogicalID: logical, Token: logical + "-incarnation", Type: "AWS::ApiGateway::" + kind, Scope: scope, Properties: p}
			}
			create := func(r *cloudformation.ResourceRequest) cloudformation.ResourceResult {
				t.Helper()
				out, err := handlers[r.Type].Create(ctx, *r)
				if err != nil {
					t.Fatalf("create %s: %v", r.Type, err)
				}
				r.PhysicalID = out.PhysicalID
				return out
			}
			api := request("RestApi", "API", cloudformation.Properties{"Name": "owned", "Version": "first", "EndpointConfiguration": map[string]any{"Types": []any{"REGIONAL"}}})
			apiResult := create(&api)
			resource := request("Resource", "Resource", cloudformation.Properties{"RestApiId": apiResult.Ref, "ParentId": apiResult.Attributes["RootResourceId"], "PathPart": "pets"})
			resourceResult := create(&resource)
			auth := request("Authorizer", "Authorizer", cloudformation.Properties{"RestApiId": apiResult.Ref, "Name": "guard", "Type": "TOKEN", "AuthorizerUri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:guard/invocations", "IdentitySource": "method.request.header.Authorization", "AuthorizerResultTtlInSeconds": float64(0)})
			authResult := create(&auth)
			integration := map[string]any{"Type": "AWS_PROXY", "IntegrationHttpMethod": "POST", "Uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:target/invocations"}
			method := request("Method", "Method", cloudformation.Properties{"RestApiId": apiResult.Ref, "ResourceId": resourceResult.Ref, "HttpMethod": "GET", "AuthorizationType": "CUSTOM", "AuthorizerId": authResult.Ref, "ApiKeyRequired": true, "Integration": integration})
			create(&method)
			deployment := request("Deployment", "Deployment", cloudformation.Properties{"RestApiId": apiResult.Ref, "StageName": "live", "StageDescription": map[string]any{"Variables": map[string]any{"mode": "first"}, "MethodSettings": []any{map[string]any{"ResourcePath": "/*", "HttpMethod": "*", "MetricsEnabled": true}}}})
			deploymentResult := create(&deployment)
			stage := request("Stage", "Stage", cloudformation.Properties{"RestApiId": apiResult.Ref, "DeploymentId": deploymentResult.Ref, "StageName": "other", "Variables": map[string]any{"mode": "first"}})
			create(&stage)
			key := request("ApiKey", "Key", cloudformation.Properties{"Name": "key", "CustomerId": "customer", "Value": "012345678901234567890123456789", "Enabled": true, "StageKeys": []any{map[string]any{"RestApiId": apiResult.Ref, "StageName": "live"}}})
			keyResult := create(&key)
			plan := request("UsagePlan", "Plan", cloudformation.Properties{"UsagePlanName": "plan", "Throttle": map[string]any{"BurstLimit": float64(5), "RateLimit": float64(2)}, "Quota": map[string]any{"Limit": float64(10), "Period": "DAY"}, "ApiStages": []any{map[string]any{"ApiId": apiResult.Ref, "Stage": "live", "Throttle": map[string]any{"/pets/GET": map[string]any{"BurstLimit": float64(3), "RateLimit": float64(1)}}}}})
			planResult := create(&plan)
			membership := request("UsagePlanKey", "Membership", cloudformation.Properties{"UsagePlanId": planResult.Ref, "KeyId": keyResult.Ref, "KeyType": "API_KEY"})
			memberResult := create(&membership)
			if memberResult.Ref != keyResult.Ref+":"+planResult.Ref || memberResult.Attributes["Id"] != keyResult.Ref {
				t.Fatalf("association Ref/GetAtt: %+v", memberResult)
			}
			account := request("Account", "Account", cloudformation.Properties{})
			create(&account)
			resources := []cloudformation.ResourceRequest{api, resource, method, auth, deployment, stage, key, plan, membership, account}
			// Reopen SQLite, rebuilding the service and adapter rather than relying on
			// retained CloudFormation state or an in-memory idempotency cache.
			if backend == "sqlite" {
				_ = owner.Close()
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repository = gatewaystore.New(db)
				owner = apigateway.New(apigateway.Config{Repository: repository, Clock: now})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"apigateway": owner})
				handlers = CloudFormationAPIGatewayRESTHandlers(commands)
			}
			for _, r := range resources {
				t.Run(r.LogicalID, func(t *testing.T) {
					retry := r
					retry.PhysicalID = ""
					out, err := handlers[r.Type].Create(ctx, retry)
					if err != nil || out.PhysicalID != r.PhysicalID {
						t.Fatalf("recovery = %+v, %v; want %s", out, err, r.PhysicalID)
					}
					reader := handlers[r.Type].(cloudformation.ResourceReader)
					if _, err := reader.Read(ctx, r); err != nil {
						t.Fatal(err)
					}
					listed, err := reader.List(ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, item := range listed {
						found = found || item.Identifier == r.PhysicalID
					}
					if !found {
						t.Fatalf("list omitted %s", r.PhysicalID)
					}
					foreign := r
					foreign.Token = "another-incarnation"
					if err := handlers[r.Type].Delete(ctx, foreign); err == nil {
						t.Fatal("foreign incarnation deleted authoritative row")
					}
					metadata := awsctx.FromContext(ctx)
					metadata.Region = "us-west-2"
					if _, err := reader.Read(awsctx.WithMetadata(ctx, metadata), r); err == nil {
						t.Fatal("cross-region read borrowed owner scope")
					}
				})
			}
			// API endpoint admission changes only when a stage is deployed/updated.
			api.Previous = api.Properties
			api.Properties = cloudformation.Properties{"Name": "changed", "Version": "second", "DisableExecuteApiEndpoint": true}
			if _, err := handlers[api.Type].Update(ctx, api); err != nil {
				t.Fatal(err)
			}
			nativeScope := apigateway.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
			apiKey := apigateway.APIKey{Scope: nativeScope, ID: apiResult.Ref}
			if err := repository.View(ctx, func(r apigateway.Reader) error {
				row, err := r.API(apiKey)
				if err == nil && (!row.Disabled || row.EffectiveDisabled || row.Version != "second") {
					t.Fatalf("REST endpoint update was not owner-backed: %+v", row)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			stage.Previous = stage.Properties
			stage.Properties = cloudformation.Properties{"RestApiId": apiResult.Ref, "DeploymentId": deploymentResult.Ref, "StageName": "other", "Variables": map[string]any{"mode": "second"}, "MethodSettings": []any{map[string]any{"ResourcePath": "/~1pets", "HttpMethod": "GET", "MetricsEnabled": true}}}
			if _, err := handlers[stage.Type].Update(ctx, stage); err != nil {
				t.Fatal(err)
			}
			auth.Previous = auth.Properties
			auth.Properties = cloudformation.Properties{"RestApiId": apiResult.Ref, "Name": "guard", "Type": "REQUEST", "AuthorizerUri": auth.Previous["AuthorizerUri"], "IdentitySource": "method.request.querystring.token", "AuthorizerResultTtlInSeconds": float64(30)}
			if _, err := handlers[auth.Type].Update(ctx, auth); err != nil {
				t.Fatal(err)
			}
			method.Previous = method.Properties
			method.Properties = cloudformation.Properties{"RestApiId": apiResult.Ref, "ResourceId": resourceResult.Ref, "HttpMethod": "GET", "AuthorizationType": "NONE", "ApiKeyRequired": false, "Integration": integration}
			if _, err := handlers[method.Type].Update(ctx, method); err != nil {
				t.Fatal(err)
			}
			if err := repository.View(ctx, func(r apigateway.Reader) error {
				live, err := r.Method(apigateway.MethodKey{ResourceKey: apigateway.ResourceKey{APIKey: apiKey, ResourceID: resourceResult.Ref}, HTTPMethod: "GET"})
				if err != nil {
					return err
				}
				snapshot, err := r.Deployment(apigateway.DeploymentKey{APIKey: apiKey, DeploymentID: deploymentResult.Ref})
				if err != nil {
					return err
				}
				if live.AuthorizationType != "NONE" || live.APIKeyRequired || !snapshot.Routes[0].APIKeyRequired || snapshot.Routes[0].LambdaAuthorizer == nil || snapshot.Routes[0].LambdaAuthorizer.Type != "TOKEN" || snapshot.Routes[0].LambdaAuthorizer.TTLSeconds != 0 {
					t.Fatal("method/authorizer guard update rewrote immutable deployment")
				}
				authorizer, err := r.Authorizer(apigateway.AuthorizerKey{APIKey: apiKey, AuthorizerID: authResult.Ref})
				if err != nil {
					return err
				}
				if authorizer.LambdaAuthorizer.Type != "REQUEST" || authorizer.LambdaAuthorizer.TTLSeconds != 30 || authorizer.LambdaAuthorizer.IdentitySources[0] != "method.request.querystring.token" {
					t.Fatal("authorizer guard properties did not reach owner")
				}
				row, err := r.API(apiKey)
				if err == nil && !row.EffectiveDisabled {
					t.Fatal("stage update did not activate endpoint setting")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			key.Previous = key.Properties
			key.Properties = cloudformation.Properties{"Name": "key", "Value": "012345678901234567890123456789", "Enabled": false}
			if _, err := handlers[key.Type].Update(ctx, key); err != nil {
				t.Fatal(err)
			}
			state, err := handlers[key.Type].(cloudformation.ResourceReader).Read(ctx, key)
			if err != nil || state["CustomerId"] != nil || state["Enabled"] != false {
				t.Fatalf("key update/removal: %+v %v", state, err)
			}
			plan.Previous = plan.Properties
			plan.Properties = cloudformation.Properties{"UsagePlanName": "changed-plan", "Throttle": map[string]any{}, "ApiStages": plan.Previous["ApiStages"]}
			if _, err := handlers[plan.Type].Update(ctx, plan); err != nil {
				t.Fatal(err)
			}
			if err := repository.View(ctx, func(r apigateway.Reader) error {
				row, err := r.UsagePlan(apigateway.PlanKey{Scope: nativeScope, ID: planResult.Ref})
				if err == nil && (row.Quota != nil || row.Throttle == nil || row.Throttle.Burst != 0 || row.Throttle.Rate != 0) {
					t.Fatal("usage plan update echoed settings without changing admission owner")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			deployment.Previous = deployment.Properties
			deployment.Properties = cfnComputeCopy(deployment.Properties, "RestApiId", "StageName", "StageDescription")
			deployment.Properties["Description"] = "updated immutable snapshot"
			if _, err := handlers[deployment.Type].Update(ctx, deployment); err != nil {
				t.Fatal(err)
			}
			account.Previous = account.Properties
			if _, err := handlers[account.Type].Update(ctx, account); err != nil {
				t.Fatal(err)
			}
			// Delete follows live dependencies and deletes only deployment-owned stages.
			if err := handlers[membership.Type].Delete(ctx, membership); err != nil {
				t.Fatal(err)
			}
			if err := handlers[plan.Type].Delete(ctx, plan); err != nil {
				t.Fatal(err)
			}
			if err := handlers[deployment.Type].Delete(ctx, deployment); err == nil {
				t.Fatal("deployment deletion ignored separately owned stage")
			}
			if err := handlers[stage.Type].Delete(ctx, stage); err != nil {
				t.Fatal(err)
			}
			if err := handlers[deployment.Type].Delete(ctx, deployment); err != nil {
				t.Fatal(err)
			}
			for _, r := range []cloudformation.ResourceRequest{method, auth, resource, key, account, api} {
				if err := handlers[r.Type].Delete(ctx, r); err != nil {
					t.Fatalf("delete %s: %v", r.Type, err)
				}
			}
		})
	}
}

func TestRESTGatewayRejectsUnownedBehavioralProperties(t *testing.T) {
	h := cfnRESTGateway{kind: "Method"}
	base := cloudformation.Properties{"RestApiId": "api", "ResourceId": "resource", "HttpMethod": "GET"}
	for _, property := range []string{"RequestModels", "RequestParameters", "RequestValidatorId", "MethodResponses"} {
		p := cfnComputeCopy(base, "RestApiId", "ResourceId", "HttpMethod")
		p[property] = map[string]any{}
		if err := h.Validate(p); err == nil {
			t.Fatalf("accepted %s without an execution owner", property)
		}
	}
	for _, kind := range []string{"MOCK", "HTTP", "AWS", "HTTP_PROXY"} {
		p := cfnComputeCopy(base, "RestApiId", "ResourceId", "HttpMethod")
		p["Integration"] = map[string]any{"Type": kind, "IntegrationHttpMethod": "POST", "Uri": "target"}
		if err := h.Validate(p); err == nil {
			t.Fatalf("accepted unowned %s integration", kind)
		}
	}
	for _, property := range []string{"RequestTemplates", "RequestParameters", "IntegrationResponses", "TlsConfig", "ContentHandling", "ConnectionId"} {
		integration := map[string]any{"Type": "AWS_PROXY", "IntegrationHttpMethod": "POST", "Uri": "target", property: map[string]any{}}
		p := cfnComputeCopy(base, "RestApiId", "ResourceId", "HttpMethod")
		p["Integration"] = integration
		if err := h.Validate(p); err == nil {
			t.Fatalf("accepted inert Integration.%s", property)
		}
	}
}

type cfnRESTGatewayFixture struct {
	ctx      context.Context
	scope    cloudformation.Scope
	owner    *apigateway.Service
	commands StepFunctionsCommands
	handlers map[string]cloudformation.ResourceHandler
}

func newCFNRESTGatewayFixture(t *testing.T, backend string) cfnRESTGatewayFixture {
	t.Helper()
	scope := cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.Account})
	var repository apigateway.Repository = apigateway.NewMemoryRepository(nil)
	var db *sql.DB
	if backend == "sqlite" {
		var err error
		db, err = sqlite.Open(ctx, filepath.Join(t.TempDir(), "gateway.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		repository = gatewaystore.New(db)
	}
	owner := apigateway.New(apigateway.Config{Repository: repository, Clock: clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))})
	t.Cleanup(func() {
		_ = owner.Close()
		if db != nil {
			_ = db.Close()
		}
	})
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"apigateway": owner})
	return cfnRESTGatewayFixture{ctx, scope, owner, commands, CloudFormationAPIGatewayRESTHandlers(commands)}
}

func (f cfnRESTGatewayFixture) request(kind, logical string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "deployment-stack", StackName: "deployment-stack", LogicalID: logical, Token: logical + "-incarnation", Type: "AWS::ApiGateway::" + kind, Scope: f.scope, Properties: p}
}

func (f cfnRESTGatewayFixture) native(t *testing.T, action string, input map[string]any) map[string]any {
	t.Helper()
	out, err := (cfnRESTGateway{f.commands, ""}).call(f.ctx, action, input)
	if err != nil {
		t.Fatalf("native %s: %v", action, err)
	}
	return out
}

func (f cfnRESTGatewayFixture) create(t *testing.T, r *cloudformation.ResourceRequest) cloudformation.ResourceResult {
	t.Helper()
	out, err := f.handlers[r.Type].Create(f.ctx, *r)
	if err != nil {
		t.Fatalf("create %s: %v", r.Type, err)
	}
	r.PhysicalID = out.PhysicalID
	return out
}

func TestRESTDeploymentMethodSettingsRecoverAndReplaceNativeDefaults(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRESTGatewayFixture(t, backend)
			api, root, _ := f.deployableAPI(t)
			pets := f.native(t, "CreateResource", map[string]any{"restApiId": api, "parentId": root, "pathPart": "pets"})["id"].(string)
			child := f.native(t, "CreateResource", map[string]any{"restApiId": api, "parentId": pets, "pathPart": "child"})["id"].(string)
			for _, resource := range []string{pets, child} {
				for _, method := range []string{"GET", "POST"} {
					f.native(t, "PutMethod", map[string]any{"restApiId": api, "resourceId": resource, "httpMethod": method, "authorizationType": "NONE"})
					f.native(t, "PutIntegration", map[string]any{"restApiId": api, "resourceId": resource, "httpMethod": method, "type": "AWS_PROXY", "integrationHttpMethod": "POST", "uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:target/invocations"})
				}
			}
			r := f.request("Deployment", "SettingsDeployment", cloudformation.Properties{
				"RestApiId": api, "StageName": "live",
				"StageDescription": map[string]any{"MethodSettings": []any{
					map[string]any{"ResourcePath": "/*", "HttpMethod": "*", "MetricsEnabled": true},
					map[string]any{"ResourcePath": "/~1pets", "HttpMethod": "GET", "MetricsEnabled": false},
					map[string]any{"ResourcePath": "/~1pets~1child", "HttpMethod": "GET", "MetricsEnabled": false},
				}},
			})
			result := f.create(t, &r)
			scope := apigateway.Scope{Partition: f.scope.Partition, AccountID: f.scope.Account, Region: f.scope.Region}
			incarnation, err := f.owner.StageIncarnation(f.ctx, scope, api, "live")
			if err != nil {
				t.Fatal(err)
			}
			assertMetrics := func(rootGET, petsGET, childGET, defaultPOST bool) {
				t.Helper()
				for _, route := range []struct {
					path, method string
					enabled      bool
				}{
					{"/", "GET", rootGET},
					{"/pets", "GET", petsGET},
					{"/pets/child", "GET", childGET},
					{"/pets", "POST", defaultPOST},
					{"/pets/child", "POST", defaultPOST},
				} {
					resolved, err := f.owner.Resolve(f.ctx, api, "live", route.method, route.path)
					if err != nil {
						t.Fatalf("resolve %s %s: %v", route.method, route.path, err)
					}
					if resolved.DetailedMetricsEnabled != route.enabled || resolved.Logging.Level != "OFF" || resolved.Logging.DataTrace {
						t.Fatalf("settings for %s %s: %+v", route.method, route.path, resolved)
					}
				}
			}
			assertMetrics(true, false, false, true)
			retry := r
			retry.PhysicalID = ""
			recovered, err := f.handlers[r.Type].Create(f.ctx, retry)
			if err != nil || recovered.PhysicalID != result.PhysicalID {
				t.Fatalf("recover deployment settings: %+v, %v", recovered, err)
			}
			assertMetrics(true, false, false, true)
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{
				"RestApiId": api, "StageName": "live",
				"StageDescription": map[string]any{"MethodSettings": []any{
					map[string]any{"ResourcePath": "/*", "HttpMethod": "*", "MetricsEnabled": false},
					map[string]any{"ResourcePath": "/", "HttpMethod": "GET", "MetricsEnabled": true},
					map[string]any{"ResourcePath": "/~1pets~1child", "HttpMethod": "GET", "MetricsEnabled": true},
				}},
			}
			if _, err := f.handlers[r.Type].Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			assertMetrics(true, false, true, false)
			stage := f.native(t, "GetStage", map[string]any{"restApiId": api, "stageName": "live"})
			settings, _ := stage["methodSettings"].(map[string]any)
			if len(settings) != 3 || settings["*/*"] == nil || settings["~1/GET"] == nil || settings["~1pets~1child/GET"] == nil || stage["deploymentId"] != result.Ref {
				t.Fatalf("native settings were not replaced on the same deployment: %+v", stage)
			}
			after, err := f.owner.StageIncarnation(f.ctx, scope, api, "live")
			if err != nil || after != incarnation {
				t.Fatalf("configuration changed private stage incarnation: %q -> %q, %v", incarnation, after, err)
			}
		})
	}
}

func (f cfnRESTGatewayFixture) deployableAPI(t *testing.T) (string, string, string) {
	t.Helper()
	api := f.native(t, "CreateRestApi", map[string]any{"name": "native-api", "endpointConfiguration": map[string]any{"types": []any{"REGIONAL"}}})
	id, root := api["id"].(string), api["rootResourceId"].(string)
	f.native(t, "PutMethod", map[string]any{"restApiId": id, "resourceId": root, "httpMethod": "GET", "authorizationType": "NONE"})
	f.native(t, "PutIntegration", map[string]any{"restApiId": id, "resourceId": root, "httpMethod": "GET", "type": "AWS_PROXY", "integrationHttpMethod": "POST", "uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:target/invocations"})
	deployment := f.native(t, "CreateDeployment", map[string]any{"restApiId": id})
	return id, root, deployment["id"].(string)
}

func TestRESTDeploymentCleanupPreservesPreexistingNativeStage(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRESTGatewayFixture(t, backend)
			api, _, baseline := f.deployableAPI(t)
			f.native(t, "CreateStage", map[string]any{"restApiId": api, "deploymentId": baseline, "stageName": "live", "variables": map[string]any{"mode": "native"}})
			nativeScope := apigateway.Scope{Partition: f.scope.Partition, AccountID: f.scope.Account, Region: f.scope.Region}
			incarnation, err := f.owner.StageIncarnation(f.ctx, nativeScope, api, "live")
			if err != nil {
				t.Fatal(err)
			}
			r := f.request("Deployment", "Deployment", cloudformation.Properties{"RestApiId": api, "StageName": "live", "StageDescription": map[string]any{"Variables": map[string]any{"mode": "deployed"}, "MethodSettings": []any{map[string]any{"ResourcePath": "/*", "HttpMethod": "*", "MetricsEnabled": true}}}})
			result := f.create(t, &r)
			stage := f.native(t, "GetStage", map[string]any{"restApiId": api, "stageName": "live"})
			variables, _ := stage["variables"].(map[string]any)
			if stage["deploymentId"] != result.Ref || variables["mode"] != "deployed" {
				t.Fatalf("deployment did not update native stage: %+v", stage)
			}
			after, err := f.owner.StageIncarnation(f.ctx, nativeScope, api, "live")
			if err != nil || after != incarnation {
				t.Fatalf("native stage incarnation changed: %q -> %q, %v", incarnation, after, err)
			}
			// Native stages are real deployment dependencies, not rollback-owned rows.
			// Cleanup must fail rather than deleting the stage to evade that dependency.
			if err := f.handlers[r.Type].Delete(f.ctx, r); err == nil {
				t.Fatal("deployment cleanup deleted its preexisting native stage")
			}
			stage = f.native(t, "GetStage", map[string]any{"restApiId": api, "stageName": "live"})
			if stage["deploymentId"] != result.Ref {
				t.Fatalf("failed cleanup changed the native stage: %+v", stage)
			}
			f.native(t, "UpdateStage", map[string]any{"restApiId": api, "stageName": "live", "patchOperations": []any{cfnRESTPatch("replace", "/deploymentId", baseline)}})
			if err := f.handlers[r.Type].Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			stage = f.native(t, "GetStage", map[string]any{"restApiId": api, "stageName": "live"})
			if stage["deploymentId"] != baseline {
				t.Fatalf("successful cleanup removed the preexisting native stage: %+v", stage)
			}
			// Stages genuinely created by a deployment are still removed by its cleanup.
			owned := f.request("Deployment", "OwnedDeployment", cloudformation.Properties{"RestApiId": api, "StageName": "owned"})
			f.create(t, &owned)
			first, err := f.owner.StageIncarnation(f.ctx, nativeScope, api, "owned")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.handlers[owned.Type].Delete(f.ctx, owned); err != nil {
				t.Fatal(err)
			}
			if _, err := (cfnRESTGateway{f.commands, ""}).call(f.ctx, "GetStage", map[string]any{"restApiId": api, "stageName": "owned"}); !cfnRESTMissing(err) {
				t.Fatalf("deployment-owned stage survived cleanup: %v", err)
			}
			recreated := f.request("Deployment", "RecreatedDeployment", cloudformation.Properties{"RestApiId": api, "StageName": "owned"})
			f.create(t, &recreated)
			second, err := f.owner.StageIncarnation(f.ctx, nativeScope, api, "owned")
			if err != nil || first == second {
				t.Fatalf("same-clock stage recreation reused incarnation %q: %q, %v", first, second, err)
			}
			if err := f.handlers[recreated.Type].Delete(f.ctx, recreated); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRESTDeploymentRejectsSeparatelyOwnedStage(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, logical := range []string{"SeparateStage", "Deployment"} {
				t.Run(logical, func(t *testing.T) {
					f := newCFNRESTGatewayFixture(t, backend)
					api, _, baseline := f.deployableAPI(t)
					stage := f.request("Stage", logical, cloudformation.Properties{"RestApiId": api, "DeploymentId": baseline, "StageName": "live", "Description": "stage-owner", "Variables": map[string]any{"mode": "owned"}})
					stage.Token = "stage-incarnation"
					f.create(t, &stage)
					deployment := f.request("Deployment", "Deployment", cloudformation.Properties{"RestApiId": api, "StageName": "live", "StageDescription": map[string]any{"Description": "stolen", "Variables": map[string]any{"mode": "stolen"}}})
					result, err := f.handlers[deployment.Type].Create(f.ctx, deployment)
					var rejected *awswire.Error
					if !errors.As(err, &rejected) || rejected.Code != "ConflictException" || result.PhysicalID != "" {
						t.Fatalf("separately owned stage was admitted: %+v, %v", result, err)
					}
					current := f.native(t, "GetStage", map[string]any{"restApiId": api, "stageName": "live"})
					variables, _ := current["variables"].(map[string]any)
					if current["deploymentId"] != baseline || current["description"] != "stage-owner" || variables["mode"] != "owned" {
						t.Fatalf("rejected deployment mutated a separately owned stage: %+v", current)
					}
					deployments := f.native(t, "GetDeployments", map[string]any{"restApiId": api})
					if rows, _ := deployments["item"].([]any); len(rows) != 1 {
						t.Fatalf("stage conflict admitted a deployment: %+v", deployments)
					}
					if err := f.handlers[stage.Type].Delete(f.ctx, stage); err != nil {
						t.Fatalf("stage owner lost authority after rejected deployment: %v", err)
					}
				})
			}
		})
	}
}

// This wrapper loses responses from the real owner; it never simulates CRUD.
type cfnRESTGatewayLostReply struct {
	owner                          awscommands.CommandExecutor
	loseCreate, loseRead, admitted bool
}

func (e *cfnRESTGatewayLostReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.owner.ExecuteCommand(ctx, r)
	if err != nil {
		return out, err
	}
	if r.Operation.Name == "CreateDeployment" {
		e.admitted = true
		if e.loseCreate {
			e.loseCreate = false
			return nil, &awswire.Error{Code: "RequestTimeout", Message: "create response lost after native commit", StatusCode: 504}
		}
	}
	if r.Operation.Name == "GetDeployment" && e.admitted && e.loseRead {
		return nil, &awswire.Error{Code: "ServiceUnavailableException", Message: "read response lost after native observation", StatusCode: 503}
	}
	return out, nil
}

func TestRESTDeploymentAdmittedIDSurvivesLostReplyAndRecoveryFailure(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, failure := range []string{"create-reply", "result-read"} {
				t.Run(failure, func(t *testing.T) {
					f := newCFNRESTGatewayFixture(t, backend)
					api, _, baseline := f.deployableAPI(t)
					boundary := &cfnRESTGatewayLostReply{owner: f.owner, loseCreate: failure == "create-reply", loseRead: failure == "result-read"}
					handlers := CloudFormationAPIGatewayRESTHandlers(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"apigateway": boundary}))
					r := f.request("Deployment", "Deployment", cloudformation.Properties{"RestApiId": api, "StageName": "live"})
					admitted, err := handlers[r.Type].Create(f.ctx, r)
					var rejected *awswire.Error
					if !errors.As(err, &rejected) || admitted.PhysicalID == "" {
						t.Fatalf("lost response discarded admitted identity: %+v, %v", admitted, err)
					}
					_, id, ok := strings.Cut(admitted.PhysicalID, "/")
					if !ok || id == "" {
						t.Fatalf("invalid admitted identity: %+v", admitted)
					}
					current := f.native(t, "GetStage", map[string]any{"restApiId": api, "stageName": "live"})
					if current["deploymentId"] != id {
						t.Fatalf("returned identity is not the admitted native deployment: %+v, stage %+v", admitted, current)
					}
					if failure == "result-read" {
						recovered, recoveryErr := handlers[r.Type].Create(f.ctx, r)
						if recovered.PhysicalID != admitted.PhysicalID || recoveryErr == nil {
							t.Fatalf("authorized list lost admitted ID on later read failure: %+v, %v", recovered, recoveryErr)
						}
						boundary.loseRead = false
					}
					// Recreating the stage under another exact owner must reject replay
					// convergence while retaining the already admitted deployment's rollback ID.
					f.native(t, "DeleteStage", map[string]any{"restApiId": api, "stageName": "live"})
					stage := f.request("Stage", "StageOwner", cloudformation.Properties{"RestApiId": api, "DeploymentId": baseline, "StageName": "live", "Variables": map[string]any{"mode": "foreign"}})
					f.create(t, &stage)
					recovered, recoveryErr := handlers[r.Type].Create(f.ctx, r)
					if recovered.PhysicalID != admitted.PhysicalID || !errors.As(recoveryErr, &rejected) || rejected.Code != "ConflictException" {
						t.Fatalf("replay borrowed a foreign stage claim or discarded admission: %+v, %v", recovered, recoveryErr)
					}
					current = f.native(t, "GetStage", map[string]any{"restApiId": api, "stageName": "live"})
					variables, _ := current["variables"].(map[string]any)
					if current["deploymentId"] != baseline || variables["mode"] != "foreign" {
						t.Fatalf("replay mutated a recreated foreign stage: %+v", current)
					}
					deployments := f.native(t, "GetDeployments", map[string]any{"restApiId": api})
					if rows, _ := deployments["item"].([]any); len(rows) != 2 {
						t.Fatalf("same-token replay admitted another deployment: %+v", deployments)
					}
					r.PhysicalID = admitted.PhysicalID
					if err := handlers[r.Type].Delete(f.ctx, r); err != nil {
						t.Fatalf("rollback of exact admitted deployment: %v", err)
					}
					if _, err := f.handlers[stage.Type].(cloudformation.ResourceReader).Read(f.ctx, stage); err != nil {
						t.Fatalf("rollback deleted the recreated foreign stage: %v", err)
					}
					if err := f.handlers[stage.Type].Delete(f.ctx, stage); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestRESTMethodNestedCreateFailureRetainsAdmittedIdentity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRESTGatewayFixture(t, backend)
			api, root, _ := f.deployableAPI(t)
			r := f.request("Method", "FailedMethod", cloudformation.Properties{"RestApiId": api, "ResourceId": root, "HttpMethod": "POST", "Integration": map[string]any{"Type": "AWS_PROXY", "IntegrationHttpMethod": "POST", "Uri": "not-a-lambda-invocation-uri"}})
			first, err := f.handlers[r.Type].Create(f.ctx, r)
			if err == nil || first.PhysicalID != api+"/"+root+"/POST" {
				t.Fatalf("nested integration failure discarded admitted method: %+v, %v", first, err)
			}
			second, recoveryErr := f.handlers[r.Type].Create(f.ctx, r)
			if recoveryErr == nil || second.PhysicalID != first.PhysicalID {
				t.Fatalf("same-token failed-method replay changed identity: %+v, %v", second, recoveryErr)
			}
			f.native(t, "GetMethod", map[string]any{"restApiId": api, "resourceId": root, "httpMethod": "POST"})
			r.PhysicalID = first.PhysicalID
			if err := f.handlers[r.Type].Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := (cfnRESTGateway{f.commands, ""}).call(f.ctx, "GetMethod", map[string]any{"restApiId": api, "resourceId": root, "httpMethod": "POST"}); !cfnRESTMissing(err) {
				t.Fatalf("rollback left admitted failed method: %v", err)
			}
		})
	}
}

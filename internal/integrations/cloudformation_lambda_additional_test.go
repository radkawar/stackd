package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/lambda"
	"stackd/storage/sqlite"
	sqllambda "stackd/storage/sqlite/lambda"
)

// These tests exercise the real Lambda commands and both repositories. Seeded
// function deployments need no runtime: the tested effects are configuration,
// not customer-code execution or manufactured capacity-backend success.
type cfnLambdaAdditionalFixture struct {
	ctx        context.Context
	repo       lambda.Repository
	service    *lambda.Service
	commands   StepFunctionsCommands
	manual     *clock.Manual
	db         *sql.DB
	path       string
	authority  *cfnLambdaAdditionalAuthority
	authorizer authorization.Authorizer
	source     lambda.SQSSource
}

type cfnLambdaAdditionalAuthority struct{ denied string }

func (a *cfnLambdaAdditionalAuthority) Authorize(_ context.Context, request authorization.Request) *awswire.Error {
	if request.Action == a.denied {
		return &awswire.Error{Code: "AccessDeniedException", Message: "current authority revoked", StatusCode: 403}
	}
	return nil
}

func newCFNLambdaAdditionalFixture(t *testing.T, backend string) *cfnLambdaAdditionalFixture {
	t.Helper()
	f := &cfnLambdaAdditionalFixture{manual: clock.NewManual(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)), authority: &cfnLambdaAdditionalAuthority{}}
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "state.sqlite")
		db, err := sqlite.Open(f.ctx, f.path)
		if err != nil {
			t.Fatal(err)
		}
		f.db, f.repo = db, sqllambda.New(db)
	} else {
		f.repo = lambda.NewMemoryRepository(nil)
	}
	f.open()
	t.Cleanup(func() {
		if err := f.service.Close(); err != nil {
			t.Error(err)
		}
		if f.db != nil {
			if err := f.db.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	key := lambda.FunctionKey{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "configured"}
	if err := f.repo.Update(f.ctx, func(tx lambda.Transaction) error {
		return tx.PutFunction(lambda.FunctionRecord{Key: key, Runtime: "python3.12", Handler: "index.handler", Role: "arn:aws:iam::111111111111:role/execution", State: "Active", Architecture: "x86_64", Timeout: 3, MemoryMB: 128, EphemeralMB: 512, Revision: "native", DeploymentRevision: "deployment", Modified: f.manual.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *cfnLambdaAdditionalFixture) open() {
	authority := f.authorizer
	if authority == nil {
		authority = f.authority
	}
	f.service = lambda.New(lambda.Config{Repository: f.repo, Clock: f.manual, PublicEndpoint: "http://localhost:4567", Authorizer: authority, PolicyBinder: authorization.New(nil, nil), SQS: f.source})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"lambda": f.service})
}
func (f *cfnLambdaAdditionalFixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.service.Close(); err != nil {
		t.Fatal(err)
	}
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			t.Fatal(err)
		}
		db, err := sqlite.Open(f.ctx, f.path)
		if err != nil {
			t.Fatal(err)
		}
		f.db, f.repo = db, sqllambda.New(db)
	}
	f.open()
}
func cfnLambdaAdditionalRequest(kind string, properties cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "stack-owned", StackName: "configuration", LogicalID: "Config", Token: "incarnation-1", Type: kind, Scope: cloudformation.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Properties: properties}
}

func TestCFNLambdaAdditionalEventInvokeLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			h := cfnLambdaEventInvokeConfig{f.commands}
			r := cfnLambdaAdditionalRequest("AWS::Lambda::EventInvokeConfig", cloudformation.Properties{"FunctionName": "configured", "Qualifier": "$LATEST", "MaximumRetryAttempts": 0})
			result, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = result.PhysicalID
			properties, err := h.Read(f.ctx, r)
			if err != nil || properties["MaximumRetryAttempts"] != float64(0) {
				t.Fatalf("explicit zero lost: %+v %v", properties, err)
			}
			f.reopen(t)
			h.commands = f.commands
			recovered, err := h.Create(f.ctx, r)
			if err != nil || recovered.PhysicalID != result.PhysicalID {
				t.Fatalf("recovery: %+v %v", recovered, err)
			}
			rows, err := h.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true, Properties: cloudformation.Properties{"FunctionName": "configured"}})
			if err != nil || len(rows) != 1 || rows[0].Identifier != result.PhysicalID {
				t.Fatalf("authoritative list: %+v %v", rows, err)
			}
			foreign := r
			foreign.Token = "foreign"
			if _, err := h.Update(f.ctx, foreign); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("foreign incarnation updated: %v", err)
			}
			f.authority.denied = "lambda:PutFunctionEventInvokeConfig"
			if _, err := h.Create(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("recovery bypassed authority: %v", err)
			}
			f.authority.denied = ""
			r.Properties = cloudformation.Properties{"FunctionName": "configured", "Qualifier": "$LATEST", "MaximumEventAgeInSeconds": "120"}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			properties, err = h.Read(f.ctx, r)
			if err != nil || properties["MaximumRetryAttempts"] != nil || properties["MaximumEventAgeInSeconds"] != float64(120) {
				t.Fatalf("full update: %+v %v", properties, err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := cfnMessagingExec(f.ctx, f.commands, "lambda", "PutFunctionEventInvokeConfig", &api.PutFunctionEventInvokeConfigInput{FunctionName: new(api.NamespacedFunctionName("configured")), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("$LATEST")), MaximumRetryAttempts: new(api.MaximumRetryAttempts(2))}); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("native recreation adopted: %v", err)
			}
		})
	}
}

func TestCFNLambdaAdditionalURLLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			h := cfnLambdaURL{f.commands}
			r := cfnLambdaAdditionalRequest("AWS::Lambda::Url", cloudformation.Properties{"TargetFunctionArn": "configured", "AuthType": "NONE", "Cors": map[string]any{"AllowOrigins": []any{"https://example.test"}}, "InvokeMode": "RESPONSE_STREAM"})
			result, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = result.PhysicalID
			if result.Attributes["FunctionUrl"] == "" || result.Attributes["FunctionArn"] != result.PhysicalID {
				t.Fatalf("URL attributes: %+v", result)
			}
			f.reopen(t)
			h.commands = f.commands
			recovered, err := h.Create(f.ctx, r)
			if err != nil || recovered.Attributes["FunctionUrl"] != result.Attributes["FunctionUrl"] {
				t.Fatalf("URL recovered different endpoint: %+v %v", recovered, err)
			}
			rows, err := h.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true, Properties: cloudformation.Properties{"TargetFunctionArn": "configured"}})
			if err != nil || len(rows) != 1 {
				t.Fatalf("URL discovery: %+v %v", rows, err)
			}
			r.Properties = cloudformation.Properties{"TargetFunctionArn": "configured", "AuthType": "AWS_IAM"}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			properties, err := h.Read(f.ctx, r)
			if err != nil || properties["Cors"] != nil || properties["InvokeMode"] != "BUFFERED" || properties["AuthType"] != "AWS_IAM" {
				t.Fatalf("URL omission reset: %+v %v", properties, err)
			}
			f.authority.denied = "lambda:UpdateFunctionUrlConfig"
			if _, err := h.Update(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("URL update bypassed revocation: %v", err)
			}
			f.authority.denied = ""
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := cfnMessagingCall[api.CreateFunctionUrlConfigOutput](f.ctx, f.commands, "lambda", "CreateFunctionUrlConfig", &api.CreateFunctionUrlConfigInput{FunctionName: new(api.FunctionUrlFunctionName("configured")), AuthType: new(api.FunctionUrlAuthType("NONE"))}); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("URL native recreation adopted: %v", err)
			}
		})
	}
}

func TestCFNLambdaAdditionalSigningLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			h := cfnLambdaCodeSigningConfig{f.commands}
			publishers := map[string]any{"SigningProfileVersionArns": []any{"arn:aws:signer:us-east-1:111111111111:/signing-profiles/allowed/abcdef1234"}}
			r := cfnLambdaAdditionalRequest("AWS::Lambda::CodeSigningConfig", cloudformation.Properties{"AllowedPublishers": publishers, "Description": "initial", "Tags": []any{map[string]any{"Key": "managed", "Value": "initial"}}})
			result, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = result.PhysicalID
			f.reopen(t)
			h.commands = f.commands
			recovered, err := h.Create(f.ctx, r)
			if err != nil || recovered.PhysicalID != result.PhysicalID {
				t.Fatalf("signing duplicate on recovery: %+v %v", recovered, err)
			}
			rows, err := h.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true})
			if err != nil || len(rows) != 1 {
				t.Fatalf("signing discovery: %+v %v", rows, err)
			}
			r.Properties = cloudformation.Properties{"AllowedPublishers": publishers, "CodeSigningPolicies": map[string]any{"UntrustedArtifactOnDeployment": "Enforce"}}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			properties, err := h.Read(f.ctx, r)
			if err != nil || properties["Description"] != "" || len(properties["Tags"].([]any)) != 0 {
				t.Fatalf("signing removals: %+v %v", properties, err)
			}
			foreign := r
			foreign.Token = "other"
			if err := h.Delete(f.ctx, foreign); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("foreign signing delete: %v", err)
			}
			f.authority.denied = "lambda:CreateCodeSigningConfig"
			if _, err := h.Create(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("signing recovery bypassed revocation: %v", err)
			}
			f.authority.denied = ""
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			rows, err = h.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true})
			if err != nil || len(rows) != 0 {
				t.Fatalf("deleted signing discovered: %+v %v", rows, err)
			}
		})
	}
}

func TestCFNLambdaAdditionalCapacityOwnerLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			h := cfnLambdaCapacityProvider{f.commands}
			r := cfnLambdaAdditionalRequest("AWS::Lambda::CapacityProvider", cloudformation.Properties{"CapacityProviderName": "managed", "PermissionsConfig": map[string]any{"CapacityProviderOperatorRoleArn": "arn:aws:iam::111111111111:role/operator"}, "VpcConfig": map[string]any{"SubnetIds": []any{"subnet-abc"}, "SecurityGroupIds": []any{}}})
			if _, err := h.Create(f.ctx, r); !cfnMessagingMissing(err, "NotImplementedException") {
				t.Fatalf("absent actual backend returned success: %v", err)
			}
			key := lambda.CapacityProviderKey{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "managed"}
			owner := lambda.AdditionalOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}
			if err := f.repo.Update(f.ctx, func(tx lambda.Transaction) error {
				return tx.PutCapacityProvider(lambda.CapacityProviderRecord{Key: key, Owner: owner, Generation: "retained", State: "Active", OperatorRoleARN: "arn:aws:iam::111111111111:role/operator", Architecture: "x86_64", SubnetIDs: []string{"subnet-abc"}, ScalingMode: "Auto", MaxVCPUs: 400, TargetCPU: 50, Modified: f.manual.Now()})
			}); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			h.commands = f.commands
			result, err := h.Create(f.ctx, r)
			if err != nil || result.Ref != "managed" || result.Attributes["Arn"] != key.ARN() {
				t.Fatalf("retained capacity recovery: %+v %v", result, err)
			}
			r.PhysicalID = result.PhysicalID
			if ready, err := h.Stabilize(f.ctx, r); !ready || err != nil {
				t.Fatalf("capacity readiness: %v %v", ready, err)
			}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			rows, err := h.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true})
			if err != nil || len(rows) != 1 || rows[0].Identifier != "managed" {
				t.Fatalf("capacity live list: %+v %v", rows, err)
			}
			foreign := r
			foreign.Token = "other"
			if err := h.Delete(f.ctx, foreign); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("capacity foreign deletion: %v", err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := f.service.Start(); err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.JobDriver().RunDue(f.ctx, 20); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				ready, err := h.StabilizeDeletion(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				if ready {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("actual capacity owner did not finish empty-provider deletion")
				}
				time.Sleep(time.Millisecond)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNLambdaAdditionalCloudControlCompoundIdentity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			h := cfnLambdaEventInvokeConfig{f.commands}
			r := cfnLambdaAdditionalRequest("AWS::Lambda::EventInvokeConfig", cloudformation.Properties{"FunctionName": "configured", "Qualifier": "$LATEST", "MaximumRetryAttempts": 0})
			r.CloudControl = true
			r.StackID, r.StackName = "cloudcontrol-request", "cloudcontrol"
			r.PhysicalID = "configured|$LATEST"
			result, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = result.PhysicalID
			properties, err := h.Read(f.ctx, r)
			if err != nil || properties["Qualifier"] != "$LATEST" {
				t.Fatalf("compound identifier read: %+v %v", properties, err)
			}
			f.reopen(t)
			h.commands = f.commands
			recovered, err := h.Create(f.ctx, r)
			if err != nil || recovered.PhysicalID != result.PhysicalID {
				t.Fatalf("Cloud Control recovery changed compound identity: %+v %v", recovered, err)
			}
			r.Token, r.StackID = "update-request", "different-cloudcontrol-request"
			r.Properties["MaximumRetryAttempts"] = 1
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatalf("Cloud Control mutation incorrectly required create ownership: %v", err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNLambdaAdditionalExistingResourcePolicyRead(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			h := cfnLambdaResourcePolicy{f.commands}
			resource := "arn:aws:lambda:us-east-1:111111111111:function:configured"
			r := cfnLambdaAdditionalRequest("AWS::Lambda::ResourcePolicy", cloudformation.Properties{"ResourceArn": resource, "PolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": resource, "Principal": map[string]any{"Service": "sns.amazonaws.com"}}}}})
			result, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = result.PhysicalID
			f.reopen(t)
			h.commands = f.commands
			properties, err := h.Read(f.ctx, r)
			if err != nil || properties["ResourceArn"] != resource || properties["PolicyDocument"] == nil {
				t.Fatalf("authoritative policy read: %+v %v", properties, err)
			}
			if _, err := h.List(f.ctx, r); !cfnMessagingMissing(err, "UnsupportedActionException") {
				t.Fatalf("fabricated native resource-policy list: %v", err)
			}
			f.authority.denied = "lambda:GetResourcePolicy"
			if _, err := h.Read(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("policy reader bypassed current authority: %v", err)
			}
			f.authority.denied = ""
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNLambdaAdditionalValidationAndReplacement(t *testing.T) {
	commands := StepFunctionsCommands{}
	handlers := CloudFormationLambdaAdditionalHandlers(commands)
	if len(handlers) != 4 {
		t.Fatalf("unexpected additional registry: %v", handlers)
	}
	for _, bad := range []cloudformation.Properties{
		{"FunctionName": "configured", "Qualifier": "$LATEST", "MaximumRetryAttempts": -1},
		{"FunctionName": "configured", "Qualifier": "$LATEST", "MaximumRetryAttempts": 3},
		{"FunctionName": "configured", "Qualifier": "$LATEST", "MaximumRetryAttempts": 0.5},
		{"FunctionName": "configured", "MaximumRetryAttempts": 0},
		{"FunctionName": "configured", "Qualifier": "$LATEST", "MaximumRetryAttempts": 0, "Unknown": true},
	} {
		if err := handlers["AWS::Lambda::EventInvokeConfig"].Validate(bad); err == nil {
			t.Fatalf("accepted invalid event properties: %+v", bad)
		}
	}
	for _, kind := range []string{"AWS::Lambda::EventInvokeConfig", "AWS::Lambda::Url", "AWS::Lambda::CodeSigningConfig", "AWS::Lambda::CapacityProvider"} {
		if _, ok := handlers[kind].(cloudformation.ResourceReader); !ok {
			t.Fatalf("%s lacks owner read/list", kind)
		}
	}
	before := cloudformation.Properties{"FunctionName": "configured", "Qualifier": "$LATEST", "MaximumRetryAttempts": 0}
	after := cloudformation.Properties{"FunctionName": "configured", "Qualifier": "live", "MaximumRetryAttempts": 0}
	if replacement, err := handlers["AWS::Lambda::EventInvokeConfig"].Replacement(before, after); !replacement || err != nil {
		t.Fatalf("qualifier replacement: %v %v", replacement, err)
	}
	function, qualifier, err := cfnLambdaAdditionalIdentity(cloudformation.ResourceRequest{PhysicalID: "arn:aws:lambda:us-east-1:111111111111:function:old:live", Properties: cloudformation.Properties{"FunctionName": "new", "Qualifier": "changed"}}, "FunctionName")
	if err != nil || function != "arn:aws:lambda:us-east-1:111111111111:function:old" || qualifier != "live" {
		t.Fatalf("replacement cleanup retargeted: %s %s %v", function, qualifier, err)
	}
}

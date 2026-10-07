package integrations

import (
	"encoding/json"
	"strings"
	"testing"

	"stackd/internal/authorization"
	cfnapi "stackd/internal/awsapi/cloudformation"
	cognitoapi "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cognitoidp"
	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
	"stackd/internal/services/ssm"
	cfnsqlite "stackd/storage/sqlite/cloudformation"
)

func TestCloudFormationDynamicSSMGoogleProviderActualOwner(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSSMParameterOwnerFixture(t, backend)
			f.native(t, "PutParameter", map[string]any{"Name": "google_client_secret", "Type": "String", "Value": "actual-provider-secret-v1"})
			idp := cognitoidp.New(cognitoidp.Config{Repository: cognitoidp.NewMemoryRepository(nil), Clock: f.source})
			owners := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ssm": f.owner, "cognitoidp": idp})
			var repository cloudformation.Repository = cloudformation.NewMemoryRepository(nil)
			if backend == "sqlite" {
				repository = cfnsqlite.New(f.db)
			}
			controller := cloudformation.New(cloudformation.Config{Repository: repository, Clock: f.source, Handlers: CloudFormationCognitoHandlers(owners), Parameters: CloudFormationParameterSource{Commands: owners}})
			t.Cleanup(func() { _ = controller.Close() })
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"cloudformation": controller, "cognitoidp": idp})
			template := `{"Resources":{"Pool":{"Type":"AWS::Cognito::UserPool","Properties":{"UserPoolName":"repro-idp","UsernameAttributes":["email"]}},"GoogleIdp":{"Type":"AWS::Cognito::UserPoolIdentityProvider","Properties":{"UserPoolId":{"Ref":"Pool"},"ProviderName":"Google","ProviderType":"Google","AttributeMapping":{"email":"email"},"ProviderDetails":{"client_id":"example.apps.googleusercontent.com","client_secret":"{{resolve:ssm:google_client_secret}}","authorize_scopes":"email profile openid"}}}}}`
			created, err := cfnComputeCall[cfnapi.CreateStackOutput](f.ctx, commands, "cloudformation", "CreateStack", map[string]any{"StackName": "dynamic-google", "TemplateBody": template})
			if err != nil {
				t.Fatal(err)
			}
			stackID := cfnComputeValue(created.StackId)
			for range 30 {
				if _, err := controller.JobDriver().RunDue(f.ctx, 1); err != nil {
					t.Fatal(err)
				}
				out, err := cfnComputeCall[cfnapi.DescribeStacksOutput](f.ctx, commands, "cloudformation", "DescribeStacks", map[string]any{"StackName": stackID})
				if err != nil {
					t.Fatal(err)
				}
				if cfnComputeValue(out.Stacks[0].StackStatus) == "CREATE_COMPLETE" {
					break
				}
			}
			var pool string
			if err := repository.View(f.ctx, func(reader cloudformation.Reader) error {
				stack, err := reader.Stack(stackID)
				if err != nil {
					return err
				}
				if stack.Status != "CREATE_COMPLETE" || stack.Template != template {
					t.Fatalf("stack did not retain raw template: %+v", stack)
				}
				resources, err := reader.Resources(stackID)
				if err != nil {
					return err
				}
				events, err := reader.Events(stackID)
				if err != nil {
					return err
				}
				op, err := reader.Operation(stack.OperationID)
				if err != nil {
					return err
				}
				body, err := json.Marshal([]any{resources, events, op})
				if err != nil {
					return err
				}
				if strings.Contains(string(body), "actual-provider-secret") {
					t.Fatal("CloudFormation persisted resolved provider client secret")
				}
				for _, resource := range resources {
					if resource.LogicalID == "Pool" {
						pool = resource.PhysicalID
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			provider, err := cfnComputeCall[cognitoapi.DescribeIdentityProviderOutput](f.ctx, commands, "cognitoidp", "DescribeIdentityProvider", map[string]any{"UserPoolId": pool, "ProviderName": "Google"})
			if err != nil || string(provider.IdentityProvider.ProviderDetails["client_secret"]) != "actual-provider-secret-v1" {
				t.Fatalf("actual Google owner did not receive resolved value: %+v %v", provider, err)
			}
			f.native(t, "PutParameter", map[string]any{"Name": "google_client_secret", "Type": "String", "Value": "actual-provider-secret-v2", "Overwrite": true})
			next := strings.Replace(template, "email profile openid", "openid email profile", 1)
			if _, err := cfnComputeCall[cfnapi.UpdateStackOutput](f.ctx, commands, "cloudformation", "UpdateStack", map[string]any{"StackName": stackID, "TemplateBody": next}); err != nil {
				t.Fatal(err)
			}
			for range 30 {
				if _, err := controller.JobDriver().RunDue(f.ctx, 1); err != nil {
					t.Fatal(err)
				}
			}
			provider, err = cfnComputeCall[cognitoapi.DescribeIdentityProviderOutput](f.ctx, commands, "cognitoidp", "DescribeIdentityProvider", map[string]any{"UserPoolId": pool, "ProviderName": "Google"})
			if err != nil || string(provider.IdentityProvider.ProviderDetails["client_secret"]) != "actual-provider-secret-v2" {
				t.Fatalf("resource update did not select latest String: %+v %v", provider, err)
			}
			metadata := awsctx.FromContext(f.ctx)
			metadata.Region = "us-west-2"
			if _, _, err := (CloudFormationParameterSource{Commands: owners}).ResolveParameterVersion(awsctx.WithMetadata(f.ctx, metadata), "google_client_secret"); err == nil {
				t.Fatal("SSM dynamic source crossed region boundary")
			}
			for _, name := range []string{"missing", "google_client_secret:99"} {
				if _, _, err := (CloudFormationParameterSource{Commands: owners}).ResolveParameterVersion(f.ctx, name); err == nil {
					t.Fatalf("missing selector accepted: %s", name)
				}
			}
		})
	}
}

func TestCloudFormationPlainSSMRejectsActualSecureStringWithoutPlaintext(t *testing.T) {
	ctx := cfnWorkflowOwnerContext(t)
	metadata := awsctx.FromContext(ctx)
	metadata.AccessKeyID, metadata.PrincipalID = metadata.AccountID, metadata.AccountID
	ctx = awsctx.WithMetadata(ctx, metadata)
	identities := iam.NewWithConfig(iam.Config{})
	t.Cleanup(func() { _ = identities.Close() })
	keys := kms.NewWithConfig(kms.Config{Storage: kms.NewMemoryStorage(nil), Authorizer: authorization.New(identities, nil)})
	owner := ssm.New(ssm.Config{Repository: ssm.NewMemoryRepository(nil), Keys: ServiceDataKeys{KMS: keys, Activity: identities, Service: "ssm"}})
	t.Cleanup(func() { _ = owner.Close(); _ = keys.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ssm": owner})
	if err := cfnComputeRun(ctx, commands, "ssm", "PutParameter", map[string]any{"Name": "secure-google", "Type": "SecureString", "Value": "never-leak-this-client-secret"}); err != nil {
		t.Fatal(err)
	}
	value, version, err := (CloudFormationParameterSource{Commands: commands}).ResolveParameterVersion(ctx, "secure-google")
	if err == nil || value != "" || version != 0 || strings.Contains(err.Error(), "never-leak-this-client-secret") {
		t.Fatalf("plain SSM exposed SecureString material: value=%q version=%d err=%v", value, version, err)
	}
}

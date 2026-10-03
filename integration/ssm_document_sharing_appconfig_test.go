package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	apptypes "github.com/aws/aws-sdk-go-v2/service/appconfig/types"
	"github.com/aws/aws-sdk-go-v2/service/appconfigdata"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"stackd"
)

func TestSSMSharedDocumentAppConfigRetrievalAndRevocation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const owner, consumer = "111122223333", "444455556666"
			const content = `{"color":"shared-owner-bytes"}`
			ctx := t.Context()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner})
			writer := cl.ssm("us-east-1", owner, "test")
			_, err := writer.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new("SharedConfigSchema"), Content: new(`{"type":"object","properties":{"color":{"type":"string"}},"additionalProperties":false}`), DocumentType: ssmtypes.DocumentTypeApplicationConfigurationSchema})
			if err != nil {
				t.Fatal(err)
			}
			_, err = writer.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new("SharedConfig"), Content: new(content), DocumentType: ssmtypes.DocumentTypeApplicationConfiguration, Requires: []ssmtypes.DocumentRequires{{Name: new("SharedConfigSchema"), Version: new("1")}}})
			if err != nil {
				t.Fatal(err)
			}
			// A shared schema dependency binds its foreign ARN, never a same-name
			// schema in the consuming account.
			schemaARN := "arn:aws:ssm:us-east-1:" + owner + ":document/SharedConfigSchema"
			_, err = writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new("SharedConfigSchema"), PermissionType: ssmtypes.DocumentPermissionTypeShare, AccountIdsToAdd: []string{consumer}})
			if err != nil {
				t.Fatal(err)
			}
			consumerSSM := cl.ssm("us-east-1", consumer, "test")
			_, err = consumerSSM.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new("SharedConfigSchema"), Content: new(`{"type":"object","additionalProperties":false}`), DocumentType: ssmtypes.DocumentTypeApplicationConfigurationSchema})
			if err != nil {
				t.Fatal(err)
			}
			_, err = consumerSSM.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new("ForeignSchemaConfig"), Content: new(content), DocumentType: ssmtypes.DocumentTypeApplicationConfiguration, Requires: []ssmtypes.DocumentRequires{{Name: new(schemaARN), Version: new("1")}}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new("SharedConfigSchema"), PermissionType: ssmtypes.DocumentPermissionTypeShare, AccountIdsToRemove: []string{consumer}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = consumerSSM.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new("ForeignSchemaConfig"), DocumentVersion: new("$LATEST"), Content: new(`{"color":"updated"}`)})
			assertAPIError(t, err, "ValidationException")
			arn := "arn:aws:ssm:us-east-1:" + owner + ":document/SharedConfig"
			identity := cl.iam(consumer, "test", "")
			role, err := identity.CreateRole(ctx, &iam.CreateRoleInput{RoleName: new("shared-config-retrieval"), AssumeRolePolicyDocument: new(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"appconfig.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			allow := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetDocument","Resource":%q}]}`, arn)
			_, err = identity.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: new("source"), PolicyDocument: new(allow)})
			if err != nil {
				t.Fatal(err)
			}
			control := cl.appconfig("us-east-1", consumer, "test")
			application, err := control.CreateApplication(ctx, &appconfig.CreateApplicationInput{Name: new("shared-source")})
			if err != nil {
				t.Fatal(err)
			}
			environment, err := control.CreateEnvironment(ctx, &appconfig.CreateEnvironmentInput{ApplicationId: application.Id, Name: new("consumer")})
			if err != nil {
				t.Fatal(err)
			}
			profile, err := control.CreateConfigurationProfile(ctx, &appconfig.CreateConfigurationProfileInput{ApplicationId: application.Id, Name: new("shared-source"), LocationUri: new("ssm-document://" + arn), RetrievalRoleArn: role.Role.Arn})
			if err != nil {
				t.Fatal(err)
			}
			strategy, err := control.CreateDeploymentStrategy(ctx, &appconfig.CreateDeploymentStrategyInput{Name: new("immediate"), DeploymentDurationInMinutes: new(int32(0)), GrowthFactor: new(float32(100)), FinalBakeTimeInMinutes: 0, ReplicateTo: apptypes.ReplicateToNone})
			if err != nil {
				t.Fatal(err)
			}
			deploy := func() error {
				_, e := control.StartDeployment(ctx, &appconfig.StartDeploymentInput{ApplicationId: application.Id, EnvironmentId: environment.Id, ConfigurationProfileId: profile.Id, ConfigurationVersion: new("1"), DeploymentStrategyId: strategy.Id})
				return e
			}
			if err := deploy(); err == nil {
				t.Fatal("retrieval IAM permission bypassed missing owner share")
			}
			_, err = writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new("SharedConfig"), PermissionType: ssmtypes.DocumentPermissionTypeShare, AccountIdsToAdd: []string{consumer}})
			if err != nil {
				t.Fatal(err)
			}
			if err := deploy(); err != nil {
				t.Fatal(err)
			}
			cl = reopen()
			control = cl.appconfig("us-east-1", consumer, "test")
			data := cl.appconfigdata("us-east-1", consumer, "test")
			session, err := data.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{ApplicationIdentifier: application.Id, EnvironmentIdentifier: environment.Id, ConfigurationProfileIdentifier: profile.Id})
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := data.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: session.InitialConfigurationToken})
			if err != nil || string(configuration.Configuration) != content || aws.ToString(configuration.ContentType) != "application/json" {
				t.Fatalf("shared AppConfig bytes after reopen: %+v %v", configuration, err)
			}
			identity = cl.iam(consumer, "test", "")
			_, err = identity.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: new("source"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ssm:GetDocument","Resource":"*"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			if err := deploy(); err == nil {
				t.Fatal("owner share bypassed current retrieval-role denial")
			}
			_, err = identity.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: new("source"), PolicyDocument: new(allow)})
			if err != nil {
				t.Fatal(err)
			}
			writer = cl.ssm("us-east-1", owner, "test")
			_, err = writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new("SharedConfig"), PermissionType: ssmtypes.DocumentPermissionTypeShare, AccountIdsToRemove: []string{consumer}})
			if err != nil {
				t.Fatal(err)
			}
			if err := deploy(); err == nil {
				t.Fatal("AppConfig reused revoked source authority")
			}
		})
	}
}

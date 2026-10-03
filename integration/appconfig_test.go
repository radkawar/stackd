package stackd_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	apptypes "github.com/aws/aws-sdk-go-v2/service/appconfig/types"
	"github.com/aws/aws-sdk-go-v2/service/appconfigdata"

	"stackd"
	"stackd/clock"
)

func (c cloudClients) appconfig(region, key, secret string) *appconfig.Client {
	return appconfig.New(appconfig.Options{Region: region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func (c cloudClients) appconfigdata(region, key, secret string) *appconfigdata.Client {
	return appconfigdata.New(appconfigdata.Options{Region: region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestAppConfigSDKPollingAuthorityAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			source := clock.NewManual(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: source})
			control := clients.appconfig("us-east-1", account, "test")
			data := clients.appconfigdata("us-east-1", account, "test")
			application, err := control.CreateApplication(ctx, &appconfig.CreateApplicationInput{Name: new("consumer"), Tags: map[string]string{"team": "payments"}})
			if err != nil {
				t.Fatal(err)
			}
			environment, err := control.CreateEnvironment(ctx, &appconfig.CreateEnvironmentInput{ApplicationId: application.Id, Name: new("production")})
			if err != nil {
				t.Fatal(err)
			}
			profile, err := control.CreateConfigurationProfile(ctx, &appconfig.CreateConfigurationProfileInput{ApplicationId: application.Id, Name: new("settings"), LocationUri: new("hosted"), Validators: []apptypes.Validator{{Type: apptypes.ValidatorTypeJsonSchema, Content: new(`{"type":"object","required":["color"],"properties":{"color":{"type":"string"}},"additionalProperties":false}`)}}})
			if err != nil {
				t.Fatal(err)
			}
			strategy, err := control.CreateDeploymentStrategy(ctx, &appconfig.CreateDeploymentStrategyInput{Name: new("immediate"), GrowthFactor: new(float32(100)), DeploymentDurationInMinutes: new(int32(0)), FinalBakeTimeInMinutes: 0, ReplicateTo: apptypes.ReplicateToNone})
			if err != nil {
				t.Fatal(err)
			}
			createVersion := func(content, label string) int32 {
				t.Helper()
				out, e := control.CreateHostedConfigurationVersion(ctx, &appconfig.CreateHostedConfigurationVersionInput{ApplicationId: application.Id, ConfigurationProfileId: profile.Id, ContentType: new("application/json"), Content: []byte(content), VersionLabel: new(label)})
				if e != nil {
					t.Fatal(e)
				}
				return out.VersionNumber
			}
			start := func(n int32) *appconfig.StartDeploymentOutput {
				t.Helper()
				out, e := control.StartDeployment(ctx, &appconfig.StartDeploymentInput{ApplicationId: application.Id, EnvironmentId: environment.Id, ConfigurationProfileId: profile.Id, DeploymentStrategyId: strategy.Id, ConfigurationVersion: new(fmt.Sprint(n))})
				if e != nil {
					t.Fatal(e)
				}
				return out
			}
			firstVersion := createVersion(`{"color":"blue"}`, "blue")
			_, err = data.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{ApplicationIdentifier: application.Id, EnvironmentIdentifier: environment.Id, ConfigurationProfileIdentifier: profile.Id})
			assertAPIError(t, err, "ResourceNotFoundException")
			deployment := start(firstVersion)
			if deployment.State != apptypes.DeploymentStateComplete {
				t.Fatalf("immediate state %v", deployment.State)
			}
			begin := func(client *appconfigdata.Client) string {
				t.Helper()
				out, e := client.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{ApplicationIdentifier: application.Id, EnvironmentIdentifier: environment.Id, ConfigurationProfileIdentifier: profile.Id, RequiredMinimumPollIntervalInSeconds: new(int32(15))})
				if e != nil {
					t.Fatal(e)
				}
				return aws.ToString(out.InitialConfigurationToken)
			}
			token := begin(data)
			out, err := data.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: new(token)})
			if err != nil {
				t.Fatal(err)
			}
			if string(out.Configuration) != `{"color":"blue"}` || aws.ToString(out.VersionLabel) != "blue" || aws.ToString(out.ContentType) != "application/json" {
				t.Fatalf("deployed payload %+v", out)
			}
			next := aws.ToString(out.NextPollConfigurationToken)
			_, err = data.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: new(token)})
			assertAPIError(t, err, "BadRequestException")
			_, err = data.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: new(next)})
			assertAPIError(t, err, "BadRequestException")
			// A rejected early poll must not consume its otherwise valid token.
			if err := source.Advance(15 * time.Second); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			control = clients.appconfig("us-east-1", account, "test")
			data = clients.appconfigdata("us-east-1", account, "test")
			out, err = data.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: new(next)})
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Configuration) != 0 {
				t.Fatalf("unchanged response leaked payload %q", out.Configuration)
			}
			next = aws.ToString(out.NextPollConfigurationToken)
			secondVersion := createVersion(`{"color":"green"}`, "green")
			second := start(secondVersion)
			if err := source.Advance(15 * time.Second); err != nil {
				t.Fatal(err)
			}
			out, err = data.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: new(next)})
			if err != nil {
				t.Fatal(err)
			}
			if string(out.Configuration) != `{"color":"green"}` || aws.ToString(out.VersionLabel) != "green" {
				t.Fatalf("changed response %+v", out)
			}
			next = aws.ToString(out.NextPollConfigurationToken)
			_, err = control.StopDeployment(ctx, &appconfig.StopDeploymentInput{ApplicationId: application.Id, EnvironmentId: environment.Id, DeploymentNumber: new(second.DeploymentNumber), AllowRevert: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Advance(15 * time.Second); err != nil {
				t.Fatal(err)
			}
			out, err = data.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: new(next)})
			if err != nil {
				t.Fatal(err)
			}
			if string(out.Configuration) != `{"color":"blue"}` {
				t.Fatalf("revert did not restore prior bytes %q", out.Configuration)
			}
			_, err = clients.appconfig("us-west-2", account, "test").GetApplication(ctx, &appconfig.GetApplicationInput{ApplicationId: application.Id})
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = clients.appconfig("us-east-1", "444455556666", "test").GetApplication(ctx, &appconfig.GetApplicationInput{ApplicationId: application.Id})
			assertAPIError(t, err, "ResourceNotFoundException")
			_, key, secret := clients.user(t, account, "appconfig-reader")
			resource := fmt.Sprintf("arn:aws:appconfig:us-east-1:%s:application/%s/environment/%s/configuration/%s", account, aws.ToString(application.Id), aws.ToString(environment.Id), aws.ToString(profile.Id))
			putUserPolicy(t, clients.iam(account, "test", ""), "appconfig-reader", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["appconfig:StartConfigurationSession","appconfig:GetLatestConfiguration"],"Resource":%q}]}`, resource))
			reader := clients.appconfigdata("us-east-1", key, secret)
			readerToken := begin(reader)
			putUserPolicy(t, clients.iam(account, "test", ""), "appconfig-reader", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"appconfig:*","Resource":"*"}]}`)
			_, err = reader.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: new(readerToken)})
			assertAPIError(t, err, "AccessDenied")
			// IAM is evaluated against current policy, not policy copied into the token.
			putUserPolicy(t, clients.iam(account, "test", ""), "appconfig-reader", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["appconfig:StartConfigurationSession","appconfig:GetLatestConfiguration"],"Resource":%q}]}`, resource))
			received, err := reader.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: new(readerToken)})
			if err != nil {
				t.Fatal(err)
			}
			if string(received.Configuration) != `{"color":"blue"}` {
				t.Fatalf("restored permission payload %q", received.Configuration)
			}
		})
	}
}

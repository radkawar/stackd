package stackd_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	apptypes "github.com/aws/aws-sdk-go-v2/service/appconfig/types"
	"github.com/aws/aws-sdk-go-v2/service/appconfigdata"

	"stackd"
	"stackd/clock"
)

func TestAppConfigTagIAMAndDeletionProtection(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			source := clock.NewManual(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: source})
			root := clients.appconfig("us-east-1", account, "test")
			_, key, secret := clients.user(t, account, "appconfig-owner")
			actor := clients.appconfig("us-east-1", key, secret)
			putUserPolicy(t, clients.iam(account, "test", ""), "appconfig-owner", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["appconfig:CreateApplication","appconfig:TagResource"],"Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/team":"payments"},"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}}]}`)
			_, err := actor.CreateApplication(ctx, &appconfig.CreateApplicationInput{Name: new("denied"), Tags: map[string]string{"team": "other"}})
			assertAPIError(t, err, "AccessDenied")
			allowed, err := actor.CreateApplication(ctx, &appconfig.CreateApplicationInput{Name: new("owned"), Tags: map[string]string{"team": "payments"}})
			if err != nil {
				t.Fatal(err)
			}
			resource := fmt.Sprintf("arn:aws:appconfig:us-east-1:%s:application/%s", account, aws.ToString(allowed.Id))
			putUserPolicy(t, clients.iam(account, "test", ""), "appconfig-owner", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"appconfig:UpdateApplication","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"payments"}}}]}`, resource))
			_, err = actor.UpdateApplication(ctx, &appconfig.UpdateApplicationInput{ApplicationId: allowed.Id, Description: new("authorized")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.TagResource(ctx, &appconfig.TagResourceInput{ResourceArn: new(resource), Tags: map[string]string{"team": "other"}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = actor.UpdateApplication(ctx, &appconfig.UpdateApplicationInput{ApplicationId: allowed.Id, Description: new("denied")})
			assertAPIError(t, err, "AccessDenied")
			observed, err := root.GetApplication(ctx, &appconfig.GetApplicationInput{ApplicationId: allowed.Id})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(observed.Description) != "authorized" {
				t.Fatal("denied mutation committed")
			}
			env, err := root.CreateEnvironment(ctx, &appconfig.CreateEnvironmentInput{ApplicationId: allowed.Id, Name: new("protected")})
			if err != nil {
				t.Fatal(err)
			}
			profile, err := root.CreateConfigurationProfile(ctx, &appconfig.CreateConfigurationProfileInput{ApplicationId: allowed.Id, Name: new("settings"), LocationUri: new("hosted")})
			if err != nil {
				t.Fatal(err)
			}
			version, err := root.CreateHostedConfigurationVersion(ctx, &appconfig.CreateHostedConfigurationVersionInput{ApplicationId: allowed.Id, ConfigurationProfileId: profile.Id, ContentType: new("text/plain"), Content: []byte("active")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.StartDeployment(ctx, &appconfig.StartDeploymentInput{ApplicationId: allowed.Id, EnvironmentId: env.Id, ConfigurationProfileId: profile.Id, ConfigurationVersion: new(fmt.Sprint(version.VersionNumber)), DeploymentStrategyId: new("AppConfig.AllAtOnce")})
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Advance(61 * time.Minute); err != nil {
				t.Fatal(err)
			}
			data := clients.appconfigdata("us-east-1", account, "test")
			session, err := data.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{ApplicationIdentifier: allowed.Id, EnvironmentIdentifier: env.Id, ConfigurationProfileIdentifier: profile.Id})
			if err != nil {
				t.Fatal(err)
			}
			_, err = data.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{ConfigurationToken: session.InitialConfigurationToken})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.UpdateAccountSettings(ctx, &appconfig.UpdateAccountSettingsInput{DeletionProtection: &apptypes.DeletionProtectionSettings{Enabled: new(false)}, VendedMetrics: &apptypes.VendedMetricsSettings{Enabled: new(true)}})
			assertAPIError(t, err, "NotImplementedException")
			settings, err := root.GetAccountSettings(ctx, &appconfig.GetAccountSettingsInput{})
			if err != nil {
				t.Fatal(err)
			}
			if !aws.ToBool(settings.DeletionProtection.Enabled) || aws.ToBool(settings.VendedMetrics.Enabled) {
				t.Fatal("unavailable telemetry opt-in changed account settings")
			}
			_, err = root.DeleteEnvironment(ctx, &appconfig.DeleteEnvironmentInput{ApplicationId: allowed.Id, EnvironmentId: env.Id})
			assertAPIError(t, err, "BadRequestException")
			_, err = root.UpdateAccountSettings(ctx, &appconfig.UpdateAccountSettingsInput{DeletionProtection: &apptypes.DeletionProtectionSettings{Enabled: new(false)}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.DeleteEnvironment(ctx, &appconfig.DeleteEnvironmentInput{ApplicationId: allowed.Id, EnvironmentId: env.Id, DeletionProtectionCheck: apptypes.DeletionProtectionCheckApply})
			assertAPIError(t, err, "BadRequestException")
			_, err = root.DeleteEnvironment(ctx, &appconfig.DeleteEnvironmentInput{ApplicationId: allowed.Id, EnvironmentId: env.Id, DeletionProtectionCheck: apptypes.DeletionProtectionCheckBypass})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.GetEnvironment(ctx, &appconfig.GetEnvironmentInput{ApplicationId: allowed.Id, EnvironmentId: env.Id})
			assertAPIError(t, err, "ResourceNotFoundException")
		})
	}
}

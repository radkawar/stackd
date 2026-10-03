package stackd_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	apptypes "github.com/aws/aws-sdk-go-v2/service/appconfig/types"

	"stackd"
)

func TestAppConfigPaginationIsolationAndDeletion(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			client := clients.appconfig("us-east-1", account, "test")
			apps := make([]*appconfig.CreateApplicationOutput, 2)
			for i := range apps {
				var err error
				apps[i], err = client.CreateApplication(ctx, &appconfig.CreateApplicationInput{Name: aws.String(fmt.Sprintf("parent-%d", i))})
				if err != nil {
					t.Fatal(err)
				}
				for j := range 3 {
					_, err = client.CreateEnvironment(ctx, &appconfig.CreateEnvironmentInput{ApplicationId: apps[i].Id, Name: aws.String(fmt.Sprintf("env-%d", j))})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			all, err := client.ListEnvironments(ctx, &appconfig.ListEnvironmentsInput{ApplicationId: apps[0].Id})
			if err != nil {
				t.Fatal(err)
			}
			first, err := client.ListEnvironments(ctx, &appconfig.ListEnvironmentsInput{ApplicationId: apps[0].Id, MaxResults: aws.Int32(1)})
			if err != nil {
				t.Fatal(err)
			}
			if first.NextToken == nil {
				t.Fatal("missing continuation token")
			}
			_, err = client.ListEnvironments(ctx, &appconfig.ListEnvironmentsInput{ApplicationId: apps[1].Id, NextToken: first.NextToken})
			assertAPIError(t, err, "BadRequestException")
			_, err = client.ListApplications(ctx, &appconfig.ListApplicationsInput{NextToken: first.NextToken})
			assertAPIError(t, err, "BadRequestException")

			applications, err := client.ListApplications(ctx, &appconfig.ListApplicationsInput{MaxResults: aws.Int32(1)})
			if err != nil {
				t.Fatal(err)
			}
			for _, scope := range []struct{ account, region string }{{"999900001111", "us-east-1"}, {account, "eu-west-1"}, {account, "cn-north-1"}} {
				other := clients.appconfig(scope.region, scope.account, "test")
				_, err = other.ListApplications(ctx, &appconfig.ListApplicationsInput{NextToken: applications.NextToken})
				assertAPIError(t, err, "BadRequestException")
			}
			_, err = client.DeleteEnvironment(ctx, &appconfig.DeleteEnvironmentInput{ApplicationId: apps[0].Id, EnvironmentId: first.Items[0].Id})
			if err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			client = clients.appconfig("us-east-1", account, "test")
			// Parent names and IDs are equivalent, and page size is not a filter.
			rest, err := client.ListEnvironments(ctx, &appconfig.ListEnvironmentsInput{ApplicationId: apps[0].Name, MaxResults: aws.Int32(2), NextToken: first.NextToken})
			if err != nil {
				t.Fatal(err)
			}
			var got, want []string
			for _, row := range rest.Items {
				got = append(got, aws.ToString(row.Id))
			}
			for _, row := range all.Items[1:] {
				want = append(want, aws.ToString(row.Id))
			}
			if !slices.Equal(got, want) || rest.NextToken != nil {
				t.Fatalf("remaining IDs %v, want %v; next=%v", got, want, rest.NextToken)
			}
			_, err = client.ListApplications(ctx, &appconfig.ListApplicationsInput{NextToken: aws.String("not-a-token")})
			assertAPIError(t, err, "BadRequestException")
			_, err = client.ListApplications(ctx, &appconfig.ListApplicationsInput{MaxResults: aws.Int32(51)})
			assertAPIError(t, err, "BadRequestException")
		})
	}
}

func TestAppConfigPaginationHostedVersionsAndStrategies(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: account})
			client := clients.appconfig("us-east-1", account, "test")
			app, err := client.CreateApplication(ctx, &appconfig.CreateApplicationInput{Name: aws.String("versions")})
			if err != nil {
				t.Fatal(err)
			}
			profiles := make([]*appconfig.CreateConfigurationProfileOutput, 2)
			for i := range profiles {
				profiles[i], err = client.CreateConfigurationProfile(ctx, &appconfig.CreateConfigurationProfileInput{ApplicationId: app.Id, Name: aws.String(fmt.Sprintf("profile-%d", i)), LocationUri: aws.String("hosted")})
				if err != nil {
					t.Fatal(err)
				}
				for n := 1; n <= 3; n++ {
					_, err = client.CreateHostedConfigurationVersion(ctx, &appconfig.CreateHostedConfigurationVersionInput{ApplicationId: app.Id, ConfigurationProfileId: profiles[i].Id, ContentType: aws.String("text/plain"), Content: []byte("payload"), VersionLabel: aws.String(fmt.Sprintf("release-%d", n))})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			first, err := client.ListHostedConfigurationVersions(ctx, &appconfig.ListHostedConfigurationVersionsInput{ApplicationId: app.Id, ConfigurationProfileId: profiles[0].Id, VersionLabel: aws.String("release-*"), MaxResults: aws.Int32(1)})
			if err != nil {
				t.Fatal(err)
			}
			if first.NextToken == nil || len(first.Items) != 1 || first.Items[0].VersionNumber != 3 {
				t.Fatalf("first versions: %+v", first)
			}
			for _, in := range []*appconfig.ListHostedConfigurationVersionsInput{
				{ApplicationId: app.Id, ConfigurationProfileId: profiles[1].Id, VersionLabel: aws.String("release-*")},
				{ApplicationId: app.Id, ConfigurationProfileId: profiles[0].Id, VersionLabel: aws.String("release-2")},
				{ApplicationId: app.Id, ConfigurationProfileId: profiles[0].Id},
			} {
				in.NextToken = first.NextToken
				_, err = client.ListHostedConfigurationVersions(ctx, in)
				assertAPIError(t, err, "BadRequestException")
			}
			_, err = client.CreateHostedConfigurationVersion(ctx, &appconfig.CreateHostedConfigurationVersionInput{ApplicationId: app.Id, ConfigurationProfileId: profiles[0].Id, ContentType: aws.String("text/plain"), Content: []byte("new payload"), VersionLabel: aws.String("release-4")})
			if err != nil {
				t.Fatal(err)
			}
			rest, err := client.ListHostedConfigurationVersions(ctx, &appconfig.ListHostedConfigurationVersionsInput{ApplicationId: app.Name, ConfigurationProfileId: profiles[0].Name, VersionLabel: aws.String("release-*"), MaxResults: aws.Int32(2), NextToken: first.NextToken})
			if err != nil {
				t.Fatal(err)
			}
			if len(rest.Items) != 2 || rest.Items[0].VersionNumber != 2 || rest.Items[1].VersionNumber != 1 || rest.NextToken != nil {
				t.Fatalf("continuation after insertion: %+v", rest)
			}

			strategy, err := client.CreateDeploymentStrategy(ctx, &appconfig.CreateDeploymentStrategyInput{Name: aws.String("custom"), DeploymentDurationInMinutes: aws.Int32(0), GrowthFactor: aws.Float32(100), ReplicateTo: apptypes.ReplicateToNone})
			if err != nil {
				t.Fatal(err)
			}
			strategies, err := client.ListDeploymentStrategies(ctx, &appconfig.ListDeploymentStrategiesInput{MaxResults: aws.Int32(2)})
			if err != nil {
				t.Fatal(err)
			}
			if len(strategies.Items) != 2 || aws.ToString(strategies.Items[0].Id) != aws.ToString(strategy.Id) || aws.ToString(strategies.Items[1].Id) != "AppConfig.AllAtOnce" {
				t.Fatalf("strategy boundary: %+v", strategies)
			}
			_, err = client.DeleteDeploymentStrategy(ctx, &appconfig.DeleteDeploymentStrategyInput{DeploymentStrategyId: strategy.Id})
			if err != nil {
				t.Fatal(err)
			}
			remaining, err := client.ListDeploymentStrategies(ctx, &appconfig.ListDeploymentStrategiesInput{NextToken: strategies.NextToken})
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, row := range remaining.Items {
				ids = append(ids, aws.ToString(row.Id))
			}
			want := []string{"AppConfig.Linear50PercentEvery30Seconds", "AppConfig.Canary10Percent20Minutes", "AppConfig.Linear20PercentEvery6Minutes"}
			if !slices.Equal(ids, want) || remaining.NextToken != nil {
				t.Fatalf("strategy continuation %v, want %v", ids, want)
			}
		})
	}
}

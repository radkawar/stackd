package stackd_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
)

func TestEC2ScreenshotDryRunSharesAuthorizationSnapshot(t *testing.T) {
	var fixture struct {
		Account, Region string
		Owned           struct{ Instances []string }
	}
	awsReadFixture(t, "ec2/console_screenshot_boundaries.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repository domain.Repository
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				repository = config.Storage.EC2
				cloud, err := stackd.New(config)
				if err != nil {
					t.Fatal(err)
				}
				return cloud, httptest.NewServer(cloud)
			})
			key := domain.ResourceKey{Scope: domain.Scope{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region}, ID: fixture.Owned.Instances[0]}
			if err := repository.Update(t.Context(), func(tx domain.Transaction) error {
				return tx.PutInstance(domain.InstanceRecord{Key: key, Data: api.Instance{
					InstanceId: new(api.String(key.ID)), InstanceType: new(api.InstanceType("t3.nano")), Architecture: new(api.ArchitectureValues("x86_64")),
					State: &api.InstanceState{Name: new(api.InstanceStateName("running")), Code: new(api.Integer(16))},
					Tags:  api.TagList{{Key: new(api.String("purpose")), Value: new(api.String("screenshot"))}},
				}})
			}); err != nil {
				t.Fatal(err)
			}
			identity := clients.iam(fixture.Account, "test", "")
			role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName:                 aws.String("screenshot-reader"),
				AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + fixture.Account + `:root"},"Action":"sts:AssumeRole"}}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = identity.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("screenshot"),
				PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"ec2:GetConsoleScreenshot","Resource":"arn:aws:ec2:` + fixture.Region + `:` + fixture.Account + `:instance/` + key.ID + `","Condition":{"StringEquals":{"ec2:ResourceTag/purpose":"screenshot"}}}}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			session, err := clients.sts(fixture.Account, "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("screen")})
			if err != nil {
				t.Fatal(err)
			}
			client := sdkec2.New(sdkec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1,
				Credentials: credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken)),
			})
			// No VMM is needed for an authorized DryRun. IAM must reuse EC2's
			// snapshot rather than waiting for a second SQLite transaction.
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, err = client.GetConsoleScreenshot(ctx, &sdkec2.GetConsoleScreenshotInput{InstanceId: aws.String(key.ID), DryRun: aws.Bool(true)})
			assertAPIError(t, err, "DryRunOperation")
		})
	}
}

package stackd_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"stackd"
	"stackd/clock"
	ebsdomain "stackd/internal/services/ebs"
)

func TestSSMImageParameterValidationRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			source := clock.NewManual(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC))
			var active *stackd.Stack
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: source}, func(c stackd.Config) (*stackd.Stack, *httptest.Server) {
				cloud, server := startPublicCloud(t, c)
				active = cloud
				return cloud, server
			})
			direct := ebs.New(ebs.Options{Region: "us-east-1", BaseEndpoint: new(cl.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: cl.server.Client(), RetryMaxAttempts: 1})
			snapshot, err := direct.StartSnapshot(ctx, &ebs.StartSnapshotInput{VolumeSize: new(int64(1))})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := direct.CompleteSnapshot(ctx, &ebs.CompleteSnapshotInput{SnapshotId: snapshot.SnapshotId, ChangedBlocksCount: new(int32(0))}); err != nil {
				t.Fatal(err)
			}
			if _, err := active.AdvanceTime(ctx, ebsdomain.CompletionDelay+ebsdomain.ReadinessDelay); err != nil {
				t.Fatal(err)
			}
			if _, err := active.RunDueJobs(ctx, 100); err != nil {
				t.Fatal(err)
			}
			images := ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: new(cl.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: cl.server.Client(), RetryMaxAttempts: 1})
			image, err := images.RegisterImage(ctx, &ec2.RegisterImageInput{Name: new("parameter-image"), Architecture: ec2types.ArchitectureValuesX8664, VirtualizationType: new("hvm"), RootDeviceName: new("/dev/sda1"), BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: new("/dev/sda1"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: snapshot.SnapshotId}}}})
			if err != nil {
				t.Fatal(err)
			}
			root := cl.ssm("us-east-1", account, "test")
			name := "/image/current"
			accepted, err := root.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: image.ImageId, Type: ssmtypes.ParameterTypeString, DataType: new("aws:ec2:image")})
			if err != nil || accepted.Version != 1 {
				t.Fatalf("validation admission: %+v %v", accepted, err)
			}
			_, err = root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name)})
			assertAPIError(t, err, "ParameterNotFound")
			cl = reopen()
			root = cl.ssm("us-east-1", account, "test")
			if _, err := active.AdvanceTime(ctx, time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := active.RunDueJobs(ctx, 100); err != nil {
				t.Fatal(err)
			}
			got, err := root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name)})
			if err != nil || aws.ToString(got.Parameter.Value) != aws.ToString(image.ImageId) || aws.ToString(got.Parameter.DataType) != "aws:ec2:image" {
				t.Fatalf("published validated image: %+v %v", got, err)
			}
			_, userKey, userSecret := cl.user(t, account, "image-writer")
			putUserPolicy(t, cl.iam(account, "test", ""), "image-writer", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:PutParameter","Resource":"*"}]}`)
			writer := cl.ssm("us-east-1", userKey, userSecret)
			denied, err := writer.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: image.ImageId, DataType: new("aws:ec2:image"), Overwrite: new(true)})
			if err != nil || denied.Version != 2 {
				t.Fatalf("async authorization admission: %+v %v", denied, err)
			}
			cl = reopen()
			root = cl.ssm("us-east-1", account, "test")
			if _, err := active.AdvanceTime(ctx, time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := active.RunDueJobs(ctx, 100); err != nil {
				t.Fatal(err)
			}
			got, err = root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name)})
			if err != nil || got.Parameter.Version != 1 || aws.ToString(got.Parameter.Value) != aws.ToString(image.ImageId) {
				t.Fatalf("unauthorized validation replaced active version: %+v %v", got, err)
			}
			history, err := root.GetParameterHistory(ctx, &ssm.GetParameterHistoryInput{Name: new(name)})
			if err != nil || len(history.Parameters) != 1 {
				t.Fatalf("failed validation retained visible history: %+v %v", history, err)
			}
		})
	}
}

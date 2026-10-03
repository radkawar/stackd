package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	ebsdomain "stackd/internal/services/ebs"
	"stackd/storage"
)

// Native inputs, expected errors and qualified-policy transitions replay over
// signed SDKs. Lambda is the ordinary OCI owner, never an in-process handler.
// Real ASG EC2 selection, hooks and drain are exercised by the executable smoke.
func TestAutoScalingNativeLambdaTerminationPolicies(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for the installed real Lambda runtime")
	}
	fixture := asgFixture(t, "termination_qualified_native")
	var native struct{ Handler string }
	awsReadFixture(t, "autoscaling/termination_qualified_native.json", &native)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Calls[0].StartedAt.Add(-time.Minute))
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "termination.sqlite"))
			}
			stack, server := newLambdaDockerStack(t, stackd.Config{AccountID: fixture.Account, Clock: source, Storage: backends}, nil)
			clients := cloudClients{server}
			bindings := map[string]string{}
			root := clients.iam("test", "test", "")
			_, err := root.CreateServiceLinkedRole(t.Context(), &iam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("autoscaling.amazonaws.com")})
			if err != nil {
				t.Fatal(err)
			}
			direct := ebs.New(ebs.Options{Region: fixture.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			snapshot, err := direct.StartSnapshot(t.Context(), &ebs.StartSnapshotInput{VolumeSize: aws.Int64(8)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = direct.CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: snapshot.SnapshotId, ChangedBlocksCount: aws.Int32(0)})
			if err != nil {
				t.Fatal(err)
			}
			source.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
			if _, err := stack.RunDueJobs(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			image, err := asgEC2(clients, fixture.Region).RegisterImage(t.Context(), &ec2.RegisterImageInput{Name: aws.String("termination-controls"), Architecture: ec2types.ArchitectureValuesX8664, VirtualizationType: aws.String("hvm"), RootDeviceName: aws.String("/dev/xvda"), BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String("/dev/xvda"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: snapshot.SnapshotId, VolumeSize: aws.Int32(8), VolumeType: ec2types.VolumeTypeGp3, DeleteOnTermination: aws.Bool(true)}}}})
			if err != nil {
				t.Fatal(err)
			}
			template := fixture.row(t, "owned-termination-template")
			bindings[ecsControlBody(t, template.Input)["LaunchTemplateData"].(map[string]any)["ImageId"].(string)] = aws.ToString(image.ImageId)
			for _, label := range []string{"owned-vpc", "owned-subnet", "owned-group", "owned-lambda-role", "owned-termination-template"} {
				asgPrerequisite(t, clients, fixture.Region, fixture.row(t, label), bindings, nil)
			}
			function := awslambda.New(awslambda.Options{Region: fixture.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			var create awslambda.CreateFunctionInput
			input := ecsControlBody(t, fixture.row(t, "owned-lambda").Input)
			delete(input, "Code")
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if err := awstest.DecodeSDK(encoded, &create); err != nil {
				t.Fatal(err)
			}
			create.Code = &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, map[string]string{"index.py": native.Handler})}
			if _, err := function.CreateFunction(t.Context(), &create); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(function, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: create.FunctionName}, 2*time.Minute); err != nil {
				t.Fatal(err)
			}
			for _, row := range fixture.Calls {
				switch {
				case row.Label == "owned-function-permission", row.Label == "owned-function-version", row.Label == "owned-function-alias", strings.HasPrefix(row.Label, "owned-qualified-permission-"):
					if _, err := awstest.CallSDK(t.Context(), function, row.Operation, row.Input); err != nil {
						t.Fatalf("%s: %v", row.Label, err)
					}
				case row.Label == "termination-create-zero", strings.HasPrefix(row.Label, "termination-policy-"):
					t.Run(row.Label, func(t *testing.T) { asgReplay(t, clients, fixture.Region, row, bindings, asgRoot()) })
				}
			}
		})
	}
}

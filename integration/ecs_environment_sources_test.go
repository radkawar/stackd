package stackd_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"stackd"
)

func TestECSEnvironmentFilesSDKAdmission(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{})
			client := func() *ecs.Client {
				return ecs.New(ecs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			input := ecs.RegisterTaskDefinitionInput{Family: aws.String("env-files-admission"), Cpu: aws.String("256"), Memory: aws.String("512"), NetworkMode: ecstypes.NetworkModeAwsvpc, RequiresCompatibilities: []ecstypes.Compatibility{ecstypes.CompatibilityFargate}, ContainerDefinitions: []ecstypes.ContainerDefinition{{Name: aws.String("app"), Image: aws.String("local-image")}}}
			file := ecstypes.EnvironmentFile{Type: ecstypes.EnvironmentFileTypeS3, Value: aws.String("arn:aws:s3:::bucket/app.env")}
			for _, files := range [][]ecstypes.EnvironmentFile{
				{{Type: ecstypes.EnvironmentFileTypeS3, Value: aws.String("arn:aws:s3:::bucket/app.txt")}},
				{{Type: ecstypes.EnvironmentFileType("https"), Value: file.Value}},
				{{Type: ecstypes.EnvironmentFileTypeS3, Value: aws.String("arn:aws:s3:us-east-1::bucket/app.env")}},
				{file, file, file, file, file, file, file, file, file, file, file},
			} {
				input.ContainerDefinitions[0].EnvironmentFiles = files
				_, err := client().RegisterTaskDefinition(t.Context(), &input)
				code := "InvalidParameterException"
				if files[0].Type != ecstypes.EnvironmentFileTypeS3 {
					code = "ClientException" // Generated enum admission precedes service validation.
				}
				assertAPIError(t, err, code)
			}
			input.ContainerDefinitions[0].EnvironmentFiles = []ecstypes.EnvironmentFile{file, file, file, file, file, file, file, file, file, file}
			out, err := client().RegisterTaskDefinition(t.Context(), &input)
			if err != nil {
				t.Fatal(err)
			}
			if out.TaskDefinition.Revision != 1 {
				t.Fatalf("failed admissions consumed revisions: %d", out.TaskDefinition.Revision)
			}
			clients = reopen()
			out, err = client().RegisterTaskDefinition(t.Context(), &input)
			if err != nil || out.TaskDefinition.Revision != 2 {
				t.Fatalf("registration after reopen: %v %v", out, err)
			}
		})
	}
}

package stackd_test

import (
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	buildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"

	"stackd"
	buildruntime "stackd/compute/codebuild"
	"stackd/compute/docker"
)

// The shell's exit status distinguishes retained admitted inputs from the
// changed project's buildspec and environment. No in-process executor is used.
func TestCodeBuildRetryRetainedExecutionAndTokens(t *testing.T) {
	image := os.Getenv("STACKD_CODEBUILD_FLEET_TEST_IMAGE")
	if image == "" {
		t.Skip("set STACKD_CODEBUILD_FLEET_TEST_IMAGE to enable real Docker execution")
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("STACKD_CODEBUILD_FLEET_TEST_DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			executor, err := buildruntime.NewDockerExecutor(engine, buildruntime.DockerConfig{Namespace: fmt.Sprintf("retry-%s-%d", backend, time.Now().UnixNano())})
			if err != nil {
				t.Fatal(err)
			}
			c, reopen := retainedCloud(t, backend, stackd.Config{CodeBuildExecutor: executor}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				server := httptest.NewUnstartedServer(nil)
				server.Listener.Close()
				listener, err := net.Listen("tcp", "0.0.0.0:0")
				if err != nil {
					t.Fatal(err)
				}
				server.Listener = listener
				port := listener.Addr().(*net.TCPAddr).Port
				config.PublicEndpoint = fmt.Sprintf("http://127.0.0.1:%d", port)
				config.ComputeEndpoint = fmt.Sprintf("http://host.docker.internal:%d", port)
				cloud, err := stackd.New(config)
				if err != nil {
					server.Close()
					t.Fatal(err)
				}
				server.Config.Handler = cloud
				server.Start()
				return cloud, server
			})
			input := gitSecondaryProject(t, c)
			input.SecondarySources, input.SecondarySourceVersions = nil, nil
			input.LogsConfig = &buildtypes.LogsConfig{CloudWatchLogs: &buildtypes.CloudWatchLogsConfig{Status: buildtypes.LogsConfigStatusTypeDisabled}}
			input.Environment.Image = aws.String(image)
			input.Source.Buildspec = aws.String("version: 0.2\nphases:\n  build:\n    commands: ['test \"$VALUE\" = admitted']\n")
			client := fleetTaggingClient(c, "us-east-1", "test", "test")
			if _, err = client.CreateProject(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			wait := func(id *string, status buildtypes.StatusType) buildtypes.Build {
				t.Helper()
				deadline := time.Now().Add(90 * time.Second)
				for {
					out, err := client.BatchGetBuilds(t.Context(), &codebuild.BatchGetBuildsInput{Ids: []string{*id}})
					if err != nil || len(out.Builds) != 1 {
						t.Fatalf("read build: %+v %v", out, err)
					}
					build := out.Builds[0]
					if build.BuildComplete {
						if build.BuildStatus != status {
							t.Fatalf("build status %s, want %s; phases: %+v", build.BuildStatus, status, build.Phases)
						}
						return build
					}
					if time.Now().After(deadline) {
						t.Fatalf("build did not settle: %+v", build)
					}
					time.Sleep(25 * time.Millisecond)
				}
			}
			started, err := client.StartBuild(t.Context(), &codebuild.StartBuildInput{ProjectName: input.Name, EnvironmentVariablesOverride: []buildtypes.EnvironmentVariable{{Name: aws.String("VALUE"), Value: aws.String("admitted"), Type: buildtypes.EnvironmentVariableTypePlaintext}}})
			if err != nil {
				t.Fatal(err)
			}
			original := wait(started.Build.Id, buildtypes.StatusTypeSucceeded)
			_, err = client.UpdateProject(t.Context(), &codebuild.UpdateProjectInput{Name: input.Name, Source: &buildtypes.ProjectSource{Type: buildtypes.SourceTypeNoSource, Buildspec: aws.String("version: 0.2\nphases:\n  build:\n    commands: ['exit 37']\n")}})
			if err != nil {
				t.Fatal(err)
			}
			c = reopen()
			client = fleetTaggingClient(c, "us-east-1", "test", "test")
			request := &codebuild.RetryBuildInput{Id: original.Id, IdempotencyToken: aws.String("independent-token")}
			retried, err := client.RetryBuild(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if *retried.Build.Id == *original.Id || *retried.Build.BuildNumber != *original.BuildNumber+1 {
				t.Fatalf("retry execution identity: %+v", retried.Build)
			}
			wait(retried.Build.Id, buildtypes.StatusTypeSucceeded)
			c = reopen()
			client = fleetTaggingClient(c, "us-east-1", "test", "test")
			replayed, err := client.RetryBuild(t.Context(), request)
			if err != nil || *replayed.Build.Id != *retried.Build.Id {
				t.Fatalf("durable replay: %+v %v", replayed, err)
			}
			_, err = client.RetryBuild(t.Context(), &codebuild.RetryBuildInput{Id: original.Arn, IdempotencyToken: request.IdempotencyToken})
			assertAPIError(t, err, "InvalidInputException")
			other := fleetTaggingClient(c, "us-east-1", "111122223333", "test")
			_, err = other.RetryBuild(t.Context(), &codebuild.RetryBuildInput{Id: original.Arn})
			assertAPIError(t, err, "ResourceNotFoundException")
			current, err := client.StartBuild(t.Context(), &codebuild.StartBuildInput{ProjectName: input.Name, IdempotencyToken: request.IdempotencyToken})
			if err != nil {
				t.Fatal(err)
			}
			wait(current.Build.Id, buildtypes.StatusTypeFailed)
			if _, err = client.DeleteProject(t.Context(), &codebuild.DeleteProjectInput{Name: input.Name}); err != nil {
				t.Fatal(err)
			}
			_, err = client.RetryBuild(t.Context(), request)
			assertAPIError(t, err, "ResourceNotFoundException")
		})
	}
}

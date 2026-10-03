package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"stackd"
	"stackd/compute/docker"
	computeecs "stackd/compute/ecs"
	computenetwork "stackd/compute/network"
	"stackd/internal/awstest"
)

// The fixture distinguishes native AWS observations from the local architecture
// failure regression. No image is pulled and an opted-in missing image is fatal.
func TestECSRuntimeDockerSDK(t *testing.T) {
	if os.Getenv("STACKD_ECS_DOCKER") != "1" {
		t.Skip("set STACKD_ECS_DOCKER=1 to exercise the real Docker ECS runtime")
	}
	var fixture struct {
		Scenarios []struct {
			Name             string
			Definition       json.RawMessage
			StopCode         ecstypes.TaskStopCode
			StartedAtPresent bool
			ExitCodes        map[string]*int32
		}
		Conflicts []json.RawMessage
	}
	data, err := os.ReadFile("../testdata/ecs/runtime.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatalf("STACKD_ECS_DOCKER=1 requires a working native Docker Engine: %v", err)
	}
	t.Cleanup(engine.Close)
	networks, err := computenetwork.NewBridges(engine)
	if err != nil {
		t.Fatal(err)
	}
	images := map[string]bool{}
	for _, scenario := range fixture.Scenarios {
		var definition ecs.RegisterTaskDefinitionInput
		if err := json.Unmarshal(scenario.Definition, &definition); err != nil {
			t.Fatal(err)
		}
		for _, container := range definition.ContainerDefinitions {
			image := aws.ToString(container.Image)
			if images[image] {
				continue
			}
			if err := engine.JSON(t.Context(), http.MethodGet, "/images/"+url.PathEscape(image)+"/json", nil, nil); err != nil {
				t.Fatalf("STACKD_ECS_DOCKER=1 requires locally installed image %s: %v", image, err)
			}
			images[image] = true
		}
	}
	for backendIndex, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			executor, err := computeecs.NewDockerExecutor(t.Context(), computeecs.DockerConfig{Client: engine, Networks: networks})
			if err != nil {
				t.Fatal(err)
			}
			owned := map[string]computeecs.Specification{}
			// Registered before retainedCloud: its controller closes first, so a
			// failed assertion cannot race fallback removal with task preparation.
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				for _, spec := range owned {
					if err := executor.Remove(ctx, spec); err != nil {
						t.Errorf("remove owned task %s: %v", spec.TaskARN, err)
					}
				}
			})
			const account = "000000000000"
			// These dependency fixtures do not make outbound AWS calls.
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, ECSExecutor: executor, ComputeEndpoint: "http://stackd.invalid"})
			newClient := func() *ecs.Client {
				return ecs.New(ecs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			client := newClient()
			network := availabilityClient(clients, "us-east-1", account)
			cidr := fmt.Sprintf("10.%d.0.0/24", 241+backendIndex)
			vpc, err := network.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: &cidr})
			if err != nil {
				t.Fatal(err)
			}
			subnet, err := network.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: &cidr, AvailabilityZone: aws.String("us-east-1a")})
			if err != nil {
				t.Fatal(err)
			}
			cluster, err := client.CreateCluster(t.Context(), &ecs.CreateClusterInput{ClusterName: aws.String("runtime-" + backend)})
			if err != nil {
				t.Fatal(err)
			}
			for _, scenario := range fixture.Scenarios {
				t.Run(scenario.Name, func(t *testing.T) {
					result, err := awstest.CallSDK(t.Context(), client, "RegisterTaskDefinition", scenario.Definition)
					if err != nil {
						t.Fatal(err)
					}
					definition := result.(*ecs.RegisterTaskDefinitionOutput).TaskDefinition
					input := ecs.RunTaskInput{
						Cluster: cluster.Cluster.ClusterArn, TaskDefinition: definition.TaskDefinitionArn,
						ClientToken: aws.String("runtime-" + scenario.Name), LaunchType: ecstypes.LaunchTypeFargate,
						NetworkConfiguration: &ecstypes.NetworkConfiguration{AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{Subnets: []string{aws.ToString(subnet.Subnet.SubnetId)}}},
					}
					// Retain every successful response, including unexpected replay
					// allocations, so a broken idempotency path cannot leak resources.
					run := func(request *ecs.RunTaskInput) (*ecs.RunTaskOutput, error) {
						out, err := client.RunTask(t.Context(), request)
						if out != nil {
							for _, task := range out.Tasks {
								arn := aws.ToString(task.TaskArn)
								owned[arn] = computeecs.Specification{TaskARN: arn, Network: computenetwork.Specification{NetworkID: "arn:aws:ec2:us-east-1:" + account + ":vpc/" + aws.ToString(vpc.Vpc.VpcId)}}
							}
						}
						return out, err
					}
					out, err := run(&input)
					if err != nil {
						t.Fatal(err)
					}
					if len(out.Failures) != 0 || len(out.Tasks) != 1 {
						t.Fatalf("RunTask: tasks=%v failures=%v", out.Tasks, out.Failures)
					}
					arn := aws.ToString(out.Tasks[0].TaskArn)
					t.Cleanup(func() {
						ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
						defer cancel()
						if _, err := client.StopTask(ctx, &ecs.StopTaskInput{Cluster: input.Cluster, Task: &arn}); err != nil {
							t.Errorf("stop owned task: %v", err)
							return
						}
						if _, err := waitECSRuntimeStopped(ctx, client, input.Cluster, arn); err != nil {
							t.Errorf("wait for owned task cleanup: %v", err)
						}
					})
					ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
					defer cancel()
					stopped, err := waitECSRuntimeStopped(ctx, client, input.Cluster, arn)
					if err != nil {
						t.Fatal(err)
					}
					if stopped.StopCode != scenario.StopCode || (stopped.StartedAt != nil) != scenario.StartedAtPresent || stopped.StoppedAt == nil {
						t.Fatalf("terminal task: stopCode=%s startedAt=%v stoppedAt=%v; want code=%s started=%t", stopped.StopCode, stopped.StartedAt, stopped.StoppedAt, scenario.StopCode, scenario.StartedAtPresent)
					}
					codes := make(map[string]*int32, len(stopped.Containers))
					for _, container := range stopped.Containers {
						if aws.ToString(container.LastStatus) != "STOPPED" {
							t.Errorf("container %s is %s", aws.ToString(container.Name), aws.ToString(container.LastStatus))
						}
						codes[aws.ToString(container.Name)] = container.ExitCode
					}
					if !reflect.DeepEqual(codes, scenario.ExitCodes) {
						t.Fatalf("exit codes (nil means never started): got %v want %v", codes, scenario.ExitCodes)
					}
					if len(stopped.Attachments) != 1 || aws.ToString(stopped.Attachments[0].Status) != "DELETED" {
						t.Fatalf("task ENI not released: %v", stopped.Attachments)
					}
					interfaces, err := network.DescribeNetworkInterfaces(t.Context(), &ec2.DescribeNetworkInterfacesInput{Filters: []ec2types.Filter{{Name: aws.String("subnet-id"), Values: []string{aws.ToString(subnet.Subnet.SubnetId)}}}})
					if err != nil || len(interfaces.NetworkInterfaces) != 0 {
						t.Fatalf("task ENI remains after STOPPED: output=%v error=%v", interfaces, err)
					}
					clients = reopen()
					client = newClient()
					network = availabilityClient(clients, "us-east-1", account)
					replayed, err := run(&input)
					if err != nil || len(replayed.Failures) != 0 || len(replayed.Tasks) != 1 || aws.ToString(replayed.Tasks[0].TaskArn) != arn {
						t.Fatalf("token replay across reopen: output=%v error=%v", replayed, err)
					}
					for _, conflict := range fixture.Conflicts {
						changed := input
						if err := json.Unmarshal(conflict, &changed); err != nil {
							t.Fatal(err)
						}
						_, err := run(&changed)
						assertAPIError(t, err, "ConflictException")
						var conflictError *ecstypes.ConflictException
						if !errors.As(err, &conflictError) || !reflect.DeepEqual(conflictError.ResourceIds, []string{arn}) {
							t.Fatalf("token conflict lost original task identity: %v", err)
						}
					}
				})
			}
		})
	}
}

func waitECSRuntimeStopped(ctx context.Context, client *ecs.Client, cluster *string, arn string) (ecstypes.Task, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var task ecstypes.Task
	for {
		out, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: cluster, Tasks: []string{arn}})
		if err != nil {
			return task, err
		}
		if len(out.Failures) != 0 || len(out.Tasks) != 1 {
			return task, fmt.Errorf("DescribeTasks: tasks=%v failures=%v", out.Tasks, out.Failures)
		}
		task = out.Tasks[0]
		if aws.ToString(task.LastStatus) == "STOPPED" {
			return task, nil
		}
		select {
		case <-ctx.Done():
			return task, fmt.Errorf("task %s remained %s: %w", arn, aws.ToString(task.LastStatus), ctx.Err())
		case <-ticker.C:
		}
	}
}

package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"

	"stackd"
	"stackd/compute/docker"
	computeecs "stackd/compute/ecs"
	computenetwork "stackd/compute/network"
	"stackd/internal/awstest"
)

// These are actual container workflows. The local fixture owns the scenarios;
// no replacement executor supplies task completion or process exit codes.
func TestStepFunctionsECSDocker(t *testing.T) {
	if os.Getenv("STACKD_ECS_DOCKER") != "1" {
		t.Skip("set STACKD_ECS_DOCKER=1 to exercise real ECS workflow tasks")
	}
	var fixture struct {
		Image     string
		Scenarios []struct {
			Name, Pattern, Command, Status, Error, DefinitionError string
			Count                                                  *int32
			Reopen, Callback, Cancel, DenyPoll                     bool
		}
	}
	data, err := os.ReadFile("../testdata/integration/stepfunctions_ecs.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	networks, err := computenetwork.NewBridges(engine)
	if err != nil {
		t.Fatal(err)
	}
	for index, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			executor, err := computeecs.NewDockerExecutor(t.Context(), computeecs.DockerConfig{Client: engine, Networks: networks})
			if err != nil {
				t.Fatal(err)
			}
			owned := map[string]computeecs.Specification{}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				for arn, spec := range owned {
					if err := executor.Remove(ctx, spec); err != nil {
						t.Errorf("remove task %s: %v", arn, err)
					}
				}
			})
			const account = "000000000000"
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, ECSExecutor: executor, ComputeEndpoint: "http://stackd.invalid"})
			ecsClient := func() *ecs.Client {
				return ecs.New(ecs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			workflowClient := func() *sfn.Client {
				return sfn.New(sfn.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			identity := clients.iam(account, "test", "")
			role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("ecs-workflow"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = identity.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("tasks"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ecs:RunTask","ecs:DescribeTasks","ecs:StopTask","events:PutRule","events:PutTargets","events:DescribeRule"],"Resource":"*"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			network := availabilityClient(clients, "us-east-1", account)
			cidr := fmt.Sprintf("10.%d.0.0/24", 235+index)
			vpc, err := network.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: &cidr})
			if err != nil {
				t.Fatal(err)
			}
			subnet, err := network.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: &cidr, AvailabilityZone: aws.String("us-east-1a")})
			if err != nil {
				t.Fatal(err)
			}
			networkARN := "arn:aws:ec2:us-east-1:" + account + ":vpc/" + aws.ToString(vpc.Vpc.VpcId)
			for _, scenario := range fixture.Scenarios {
				if !t.Run(scenario.Name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
					defer cancel()
					if scenario.DenyPoll {
						identity := clients.iam(account, "test", "")
						_, err := identity.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("deny-poll"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"ecs:DescribeTasks","Resource":"*"}}`)})
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() {
							cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
							defer cancel()
							if _, err := identity.DeleteRolePolicy(cleanup, &iam.DeleteRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("deny-poll")}); err != nil {
								t.Error(err)
							}
						})
					}
					taskClient, workflows := ecsClient(), workflowClient()
					cluster, err := taskClient.CreateCluster(ctx, &ecs.CreateClusterInput{ClusterName: aws.String("workflow-" + scenario.Name)})
					if err != nil {
						t.Fatal(err)
					}
					definition, err := taskClient.RegisterTaskDefinition(ctx, &ecs.RegisterTaskDefinitionInput{
						Family: aws.String("workflow-" + scenario.Name), NetworkMode: ecstypes.NetworkModeAwsvpc,
						RequiresCompatibilities: []ecstypes.Compatibility{ecstypes.CompatibilityFargate}, Cpu: aws.String("256"), Memory: aws.String("512"),
						ContainerDefinitions: []ecstypes.ContainerDefinition{{Name: aws.String("worker"), Image: &fixture.Image, Essential: aws.Bool(true), EntryPoint: []string{"python3"}, Command: []string{"-c", scenario.Command}}},
					})
					if err != nil {
						t.Fatal(err)
					}
					parameters := map[string]any{"Cluster": aws.ToString(cluster.Cluster.ClusterArn), "TaskDefinition": aws.ToString(definition.TaskDefinition.TaskDefinitionArn), "LaunchType": "FARGATE", "NetworkConfiguration": map[string]any{"AwsvpcConfiguration": map[string]any{"Subnets": []string{aws.ToString(subnet.Subnet.SubnetId)}}}}
					expectedTasks := 1
					if scenario.Count != nil {
						parameters["Count"] = *scenario.Count
						expectedTasks = int(*scenario.Count)
					}
					if scenario.Callback {
						parameters["Overrides"] = map[string]any{"ContainerOverrides": []any{map[string]any{"Name": "worker", "Environment": []any{map[string]any{"Name": "TASK_TOKEN", "Value.$": "$$.Task.Token"}}}}}
					}
					asl, err := json.Marshal(map[string]any{"StartAt": "Run", "States": map[string]any{"Run": map[string]any{"Type": "Task", "Resource": "arn:aws:states:::ecs:runTask" + scenario.Pattern, "Parameters": parameters, "End": true}}})
					if err != nil {
						t.Fatal(err)
					}
					machine, err := workflows.CreateStateMachine(ctx, &sfn.CreateStateMachineInput{Name: aws.String("ecs-" + scenario.Name), RoleArn: role.Role.Arn, Definition: aws.String(string(asl))})
					if scenario.DefinitionError != "" {
						assertAPIError(t, err, scenario.DefinitionError)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					execution, err := workflows.StartExecution(ctx, &sfn.StartExecutionInput{StateMachineArn: machine.StateMachineArn})
					if err != nil {
						t.Fatal(err)
					}
					ticker := time.NewTicker(20 * time.Millisecond)
					defer ticker.Stop()
					pause := func() {
						select {
						case <-ticker.C:
						case <-ctx.Done():
							t.Fatal(ctx.Err())
						}
					}
					tasks := func() []ecstypes.Task {
						var arns []string
						for _, status := range []ecstypes.DesiredStatus{ecstypes.DesiredStatusRunning, ecstypes.DesiredStatusStopped} {
							out, err := taskClient.ListTasks(ctx, &ecs.ListTasksInput{Cluster: cluster.Cluster.ClusterArn, DesiredStatus: status})
							if err != nil {
								t.Fatal(err)
							}
							for _, arn := range out.TaskArns {
								found := false
								for _, prior := range arns {
									if prior == arn {
										found = true
										break
									}
								}
								if !found {
									arns = append(arns, arn)
									owned[arn] = computeecs.Specification{TaskARN: arn, Network: computenetwork.Specification{NetworkID: networkARN}}
								}
							}
						}
						if len(arns) == 0 {
							return nil
						}
						out, err := taskClient.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: cluster.Cluster.ClusterArn, Tasks: arns})
						if err != nil || len(out.Failures) != 0 {
							t.Fatalf("DescribeTasks: %v %v", out, err)
						}
						return out.Tasks
					}
					var admitted []ecstypes.Task
					for {
						admitted = tasks()
						if len(admitted) >= expectedTasks {
							break
						}
						state, err := workflows.DescribeExecution(ctx, &sfn.DescribeExecutionInput{ExecutionArn: execution.ExecutionArn})
						if err != nil {
							t.Fatal(err)
						}
						if state.Status == sfntypes.ExecutionStatusFailed || state.Status == sfntypes.ExecutionStatusAborted {
							t.Fatalf("workflow failed before ECS submission: status=%s error=%s cause=%s", state.Status, aws.ToString(state.Error), aws.ToString(state.Cause))
						}
						pause()
					}
					if len(admitted) != expectedTasks {
						t.Fatalf("expected %d real tasks: %v", expectedTasks, admitted)
					}
					taskARN := aws.ToString(admitted[0].TaskArn)
					if scenario.Reopen || scenario.Cancel {
						for aws.ToString(admitted[0].LastStatus) != "RUNNING" {
							pause()
							admitted = tasks()
							if len(admitted) != 1 {
								t.Fatalf("task disappeared before transition: %v", admitted)
							}
							if aws.ToString(admitted[0].LastStatus) == "STOPPED" {
								t.Fatal("task stopped before recovery/cancellation")
							}
						}
					}
					if scenario.Reopen {
						clients = reopen()
						taskClient, workflows = ecsClient(), workflowClient()
					}
					if scenario.Callback {
						var token string
						for _, override := range admitted[0].Overrides.ContainerOverrides {
							for _, value := range override.Environment {
								if aws.ToString(value.Name) == "TASK_TOKEN" {
									token = aws.ToString(value.Value)
								}
							}
						}
						if token == "" {
							t.Fatal("actual ECS override lost task token")
						}
						if _, err := waitECSRuntimeStopped(ctx, taskClient, cluster.Cluster.ClusterArn, taskARN); err != nil {
							t.Fatal(err)
						}
						state, err := workflows.DescribeExecution(ctx, &sfn.DescribeExecutionInput{ExecutionArn: execution.ExecutionArn})
						if err != nil || state.Status != sfntypes.ExecutionStatusRunning {
							t.Fatalf("callback task completed on container exit: %+v %v", state, err)
						}
						if _, err := workflows.SendTaskSuccess(ctx, &sfn.SendTaskSuccessInput{TaskToken: &token, Output: aws.String(`{"callback":"accepted"}`)}); err != nil {
							t.Fatal(err)
						}
					}
					if scenario.Cancel {
						if _, err := workflows.StopExecution(ctx, &sfn.StopExecutionInput{ExecutionArn: execution.ExecutionArn}); err != nil {
							t.Fatal(err)
						}
					}
					var terminal *sfn.DescribeExecutionOutput
					for {
						terminal, err = workflows.DescribeExecution(ctx, &sfn.DescribeExecutionInput{ExecutionArn: execution.ExecutionArn})
						if err != nil {
							t.Fatal(err)
						}
						if terminal.Status != sfntypes.ExecutionStatusRunning {
							break
						}
						pause()
					}
					if string(terminal.Status) != scenario.Status || aws.ToString(terminal.Error) != scenario.Error {
						t.Fatalf("terminal status=%s error=%s cause=%s; want %s %s", terminal.Status, aws.ToString(terminal.Error), aws.ToString(terminal.Cause), scenario.Status, scenario.Error)
					}
					if scenario.Callback {
						if aws.ToString(terminal.Output) != `{"callback":"accepted"}` {
							t.Fatalf("callback output=%s", aws.ToString(terminal.Output))
						}
					}
					for _, task := range admitted {
						arn := aws.ToString(task.TaskArn)
						if !scenario.Callback && scenario.Status == "SUCCEEDED" && !strings.Contains(aws.ToString(terminal.Output), arn) {
							t.Fatalf("workflow output lost actual task identity %s: %s", arn, aws.ToString(terminal.Output))
						}
						stopped, err := waitECSRuntimeStopped(ctx, taskClient, cluster.Cluster.ClusterArn, arn)
						if err != nil {
							t.Fatal(err)
						}
						if scenario.Cancel && stopped.StopCode != ecstypes.TaskStopCodeUserInitiated {
							t.Fatalf("parent abort did not cancel real task: %+v", stopped)
						}
						if scenario.Pattern == ".sync" && !scenario.Cancel {
							payload := aws.ToString(terminal.Output)
							if scenario.Error != "" {
								payload = aws.ToString(terminal.Cause)
							}
							var projection struct {
								TaskArn, LastStatus, StartedBy string
								StoppedAt                      int64
								Containers                     []struct {
									Name     string
									ExitCode *int32
								}
							}
							if err := json.Unmarshal([]byte(payload), &projection); err != nil {
								t.Fatal(err)
							}
							if projection.TaskArn != arn || projection.LastStatus != "STOPPED" || projection.StartedBy != "AWS Step Functions" || stopped.StoppedAt == nil || projection.StoppedAt != stopped.StoppedAt.UnixMilli() {
								t.Fatalf("optimized completion must project the actual stopped task with millisecond timestamps: %s; ECS=%+v", payload, stopped)
							}
							if len(projection.Containers) != 1 || projection.Containers[0].ExitCode == nil || *projection.Containers[0].ExitCode != aws.ToInt32(stopped.Containers[0].ExitCode) {
								t.Fatalf("workflow completion lost actual container exit: %s; ECS=%+v", payload, stopped.Containers)
							}
						}
					}
					finalTasks := tasks()
					if len(finalTasks) != expectedTasks {
						t.Fatalf("workflow duplicated accepted ECS task: %v", finalTasks)
					}
					for _, original := range admitted {
						found := false
						for _, final := range finalTasks {
							if aws.ToString(final.TaskArn) == aws.ToString(original.TaskArn) {
								found = true
								break
							}
						}
						if !found {
							t.Fatalf("workflow replaced accepted task %s", aws.ToString(original.TaskArn))
						}
					}
				}) {
					return
				}
			}
		})
	}
}

func TestStepFunctionsNativeECSAPIErrors(t *testing.T) {
	stepFunctionsNativeECSContracts(t, "ecs_api_errors")
}

func TestStepFunctionsNativeECSSchema(t *testing.T) {
	stepFunctionsNativeECSContracts(t, "ecs_schema_admission")
}

func stepFunctionsNativeECSContracts(t *testing.T, name string) {
	t.Helper()
	var fixture stepFunctionsNativeFixture
	awsReadFixture(t, "stepfunctions/"+name+".json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account})
			config := aws.Config{Region: fixture.Region, Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1}
			identity := iam.NewFromConfig(config, func(o *iam.Options) { o.BaseEndpoint = aws.String(clients.server.URL) })
			workflows := sfn.NewFromConfig(config, func(o *sfn.Options) {
				o.BaseEndpoint = aws.String(clients.server.URL)
				o.APIOptions = append(o.APIOptions, stepFunctionsLocalEndpoint)
			})
			for _, row := range fixture.Observations {
				if stepFunctionsOperation(row.Operation) == "getcalleridentity" {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					var client any
					switch row.Service {
					case "iam":
						client = identity
					case "stepfunctions":
						client = workflows
					default:
						t.Fatal("unmapped native service", row.Service)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					output, err := awstest.CallSDK(ctx, client, row.Operation, row.Input)
					awsNativeResult(t, row.awsNativeObservation, err)
					if err != nil {
						return
					}
					if actual, ok := output.(*sfn.TestStateOutput); ok {
						var native struct{ Status, Error string }
						awsDecodeJSON(t, row.Result.Output, &native)
						if string(actual.Status) != native.Status || aws.ToString(actual.Error) != native.Error {
							t.Fatalf("optimized ECS error: status=%s error=%s; native=%+v", actual.Status, aws.ToString(actual.Error), native)
						}
					}
					if actual, ok := output.(*sfn.ValidateStateMachineDefinitionOutput); ok {
						var native sfn.ValidateStateMachineDefinitionOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						if actual.Result != native.Result || len(actual.Diagnostics) != len(native.Diagnostics) {
							t.Fatalf("ECS definition admission: %+v; native=%+v", actual, native)
						}
						for i, diagnostic := range actual.Diagnostics {
							want := native.Diagnostics[i]
							if aws.ToString(diagnostic.Code) != aws.ToString(want.Code) || diagnostic.Severity != want.Severity || aws.ToString(diagnostic.Location) != aws.ToString(want.Location) {
								t.Fatalf("ECS diagnostic: %+v; native=%+v", diagnostic, want)
							}
						}
					}
				}) {
					return
				}
			}
		})
	}
}

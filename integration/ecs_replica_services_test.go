package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	computeecs "stackd/compute/ecs"
	computenetwork "stackd/compute/network"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awstest"
)

type ecsReplicaCapture struct {
	Label, Code   string
	Input, Output json.RawMessage
	StartedAt     time.Time
}

func ecsReplicaCaptures(t *testing.T, name string) map[string]ecsReplicaCapture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/ecs/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Calls, SupplementaryMonitoringCalls []ecsReplicaCapture }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]ecsReplicaCapture, len(fixture.Calls)+len(fixture.SupplementaryMonitoringCalls))
	for _, calls := range [2][]ecsReplicaCapture{fixture.Calls, fixture.SupplementaryMonitoringCalls} {
		for _, row := range calls {
			rows[row.Label] = row
		}
	}
	return rows
}

func ecsReplicaInput[T any](t *testing.T, rows map[string]ecsReplicaCapture, label string) T {
	t.Helper()
	row, ok := rows[label]
	if !ok {
		t.Fatalf("missing ECS service capture %q", label)
	}
	var input T
	if err := json.Unmarshal(row.Input, &input); err != nil {
		t.Fatal(err)
	}
	return input
}

// Send generated model inputs directly: circuit threshold fields are newer than
// some SDK releases, and silently dropping them would turn rejection tests into
// unrelated successful updates. Signing and transport remain the real API path.
func ecsReplicaRequest(t *testing.T, server *httptest.Server, operation string, input any, code string) map[string]any {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", "AmazonEC2ContainerServiceV20141113."+operation)
	digest := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, request, hex.EncodeToString(digest[:]), "ecs", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("%s response: %s: %v", operation, data, err)
	}
	errorStatus := http.StatusBadRequest
	if code == "ServerException" {
		errorStatus = http.StatusInternalServerError
	}
	if code == "Success" {
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", operation, response.StatusCode, data)
		}
	} else if response.StatusCode != errorStatus || !strings.HasSuffix(fmt.Sprint(out["__type"]), code) {
		t.Fatalf("%s: status=%d body=%s want %s", operation, response.StatusCode, data, code)
	}
	return out
}

func TestECSNativeReplicaServiceAdmissionAndLifecycle(t *testing.T) {
	if os.Getenv("STACKD_ECS_DOCKER") != "1" {
		t.Skip("set STACKD_ECS_DOCKER=1 to provision real ECS execution dependencies")
	}
	rows := ecsReplicaCaptures(t, "services")
	metricRows := ecsReplicaCaptures(t, "service_metrics")
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	networks, err := computenetwork.NewBridges(engine)
	if err != nil {
		t.Fatal(err)
	}
	definition := ecsReplicaInput[api.RegisterTaskDefinitionInput](t, rows, "register-definition-v2")
	for _, container := range definition.ContainerDefinitions {
		image := string(*container.Image)
		if err := engine.JSON(t.Context(), http.MethodGet, "/images/"+url.PathEscape(image)+"/json", nil, nil); err != nil {
			t.Fatalf("STACKD_ECS_DOCKER=1 requires locally installed native workload image %s: %v", image, err)
		}
	}
	for index, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			executor, err := computeecs.NewDockerExecutor(t.Context(), computeecs.DockerConfig{Client: engine, Networks: networks})
			if err != nil {
				t.Fatal(err)
			}
			metered := &ecsMetricExecutor{Executor: executor}
			owned := map[string]computeecs.Specification{}
			// The cloud closes its controllers before fallback Docker removal.
			// A failed transition must not leak retained customer processes.
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				for _, spec := range owned {
					if err := executor.Remove(ctx, spec); err != nil {
						t.Errorf("remove service task %s: %v", spec.TaskARN, err)
					}
				}
			})
			source := clock.NewManual(time.Date(2026, 9, 16, 22, 28, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source, ECSExecutor: metered, ComputeEndpoint: "http://stackd.invalid"})
			client := ecs.New(ecs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			for _, label := range []string{"create-cluster", "register-definition-v1", "register-definition-v2"} {
				operation := "RegisterTaskDefinition"
				if label == "create-cluster" {
					operation = "CreateCluster"
				}
				if _, err := awstest.CallSDK(t.Context(), client, operation, rows[label].Input); err != nil {
					t.Fatal(err)
				}
			}
			network := availabilityClient(clients, "us-east-1", "000000000000")
			cidr := fmt.Sprintf("10.%d.0.0/24", 231+index)
			vpc, err := network.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: &cidr})
			if err != nil {
				t.Fatal(err)
			}
			subnet, err := network.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: &cidr, AvailabilityZone: aws.String("us-east-1a")})
			if err != nil {
				t.Fatal(err)
			}
			group, err := network.CreateSecurityGroup(t.Context(), &ec2.CreateSecurityGroupInput{VpcId: vpc.Vpc.VpcId, GroupName: aws.String("replica-services"), Description: aws.String("ECS service capture execution dependencies")})
			if err != nil {
				t.Fatal(err)
			}
			createInput := func(t *testing.T, label string) api.CreateServiceInput {
				input := ecsReplicaInput[api.CreateServiceInput](t, rows, label)
				input.NetworkConfiguration.AwsvpcConfiguration.Subnets = api.StringList{api.String(aws.ToString(subnet.Subnet.SubnetId))}
				input.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups = api.StringList{api.String(aws.ToString(group.GroupId))}
				return input
			}
			call := func(operation string, input any, code string) map[string]any {
				return ecsReplicaRequest(t, clients.server, operation, input, code)
			}
			base := createInput(t, "create-fargate-zero-family-latest")
			created := call("CreateService", &base, rows["create-fargate-zero-family-latest"].Code)["service"].(map[string]any)
			ecsReplicaMonitoring(t, clients.server, base, metricRows)
			serviceName, clusterARN := *base.ServiceName, *base.Cluster
			describe := func(t *testing.T, cluster api.String, name api.String) map[string]any {
				out := ecsReplicaRequest(t, clients.server, "DescribeServices", &api.DescribeServicesInput{Cluster: &cluster, Services: api.StringList{name}}, "Success")
				services, ok := out["services"].([]any)
				if !ok || len(services) != 1 {
					t.Fatalf("DescribeServices: %v", out)
				}
				return services[0].(map[string]any)
			}
			deploymentID := func(t *testing.T, service map[string]any) any {
				deployments, ok := service["deployments"].([]any)
				if !ok || len(deployments) != 1 {
					t.Fatalf("expected one zero-count deployment: %v", service)
				}
				return deployments[0].(map[string]any)["id"]
			}
			originalID := deploymentID(t, created)
			clients = reopen()
			replayed := call("CreateService", &base, rows["replay-zero-same-token"].Code)["service"].(map[string]any)
			if deploymentID(t, replayed) != originalID || replayed["serviceArn"] != created["serviceArn"] {
				t.Fatalf("token replay allocated another service deployment: %v", replayed)
			}
			resourceARN := api.String(created["serviceArn"].(string))
			tagQuery := &api.ListTagsForResourceInput{ResourceArn: &resourceARN}
			originalTags := call("ListTagsForResource", tagQuery, "Success")["tags"]
			changedTags := base
			changedTags.Tags = ecsReplicaInput[api.CreateServiceInput](t, rows, "replay-zero-changed-tags").Tags
			replayedTags := call("CreateService", &changedTags, rows["replay-zero-changed-tags"].Code)["service"].(map[string]any)
			if deploymentID(t, replayedTags) != originalID || replayedTags["serviceArn"] != created["serviceArn"] {
				t.Fatalf("changed-tags token replay created another service deployment: %v", replayedTags)
			}
			retainedTags := call("ListTagsForResource", tagQuery, "Success")["tags"]
			if !reflect.DeepEqual(retainedTags, originalTags) {
				t.Fatalf("changed-tags token replay mutated original tags: before=%v after=%v", originalTags, retainedTags)
			}
			for _, label := range []string{"replay-same-token-changed-count", "replay-same-token-changed-definition"} {
				t.Run(label, func(t *testing.T) {
					input := createInput(t, label)
					ecsReplicaRequest(t, clients.server, "CreateService", &input, rows[label].Code)
					service := describe(t, clusterARN, serviceName)
					if service["desiredCount"] != float64(0) || service["taskDefinition"] != created["taskDefinition"] || deploymentID(t, service) != originalID {
						t.Fatalf("rejected replay mutated the admitted service: %v", service)
					}
				})
			}
			circuit := createInput(t, "create-zero-circuit-count-one")
			call("CreateService", &circuit, rows["create-zero-circuit-count-one"].Code)
			for _, label := range []string{"update-zero-circuit-bounded-one", "update-zero-circuit-unbounded-hundred", "update-zero-circuit-count-zero", "update-zero-circuit-bounded-over-hundred", "update-zero-circuit-unknown-threshold"} {
				t.Run(label, func(t *testing.T) {
					before := describe(t, clusterARN, *circuit.ServiceName)
					input := ecsReplicaInput[api.UpdateServiceInput](t, rows, label)
					ecsReplicaRequest(t, clients.server, "UpdateService", &input, rows[label].Code)
					if rows[label].Code != "Success" {
						after := describe(t, clusterARN, *circuit.ServiceName)
						if !reflect.DeepEqual(after["deploymentConfiguration"], before["deploymentConfiguration"]) || deploymentID(t, after) != deploymentID(t, before) {
							t.Fatalf("invalid threshold changed deployment state: before=%v after=%v", before, after)
						}
					}
				})
			}
			// A same-named service in another cluster must survive deletion and
			// name-based lookup of the first, before exercising its real runtime.
			otherCluster := api.String("replica-other")
			call("CreateCluster", &api.CreateClusterInput{ClusterName: &otherCluster}, "Success")
			other := base
			other.Cluster = &otherCluster
			otherService := call("CreateService", &other, "Success")["service"].(map[string]any)
			deleted := call("DeleteService", &api.DeleteServiceInput{Cluster: &clusterARN, Service: &serviceName}, rows["delete-zero-service"].Code)["service"].(map[string]any)
			var nativeDeleted struct{ Service struct{ Status string } }
			if err := json.Unmarshal(rows["delete-zero-service"].Output, &nativeDeleted); err != nil {
				t.Fatal(err)
			}
			if deleted["status"] != nativeDeleted.Service.Status {
				t.Fatalf("zero-count deletion: status=%v want %s", deleted["status"], nativeDeleted.Service.Status)
			}
			clients = reopen()
			call("UpdateService", &api.UpdateServiceInput{Cluster: &clusterARN, Service: &serviceName, DesiredCount: new(api.BoxedInteger(0))}, rows["update-deleted-service"].Code)
			listed := call("ListServices", &api.ListServicesInput{Cluster: &clusterARN}, "Success")
			for _, arn := range listed["serviceArns"].([]any) {
				if arn == created["serviceArn"] {
					t.Fatalf("deleted service still listed: %v", listed)
				}
			}
			survivor := describe(t, otherCluster, serviceName)
			if survivor["status"] != "ACTIVE" || survivor["serviceArn"] != otherService["serviceArn"] {
				t.Fatalf("deletion escaped its cluster: %v", survivor)
			}
			// A mutable local alias must not retarget a deployment's replacement
			// tasks, even when the alias now points at a different installed image.
			imageRepository := fmt.Sprintf("stackd-ecs-replica-%d-%d", os.Getpid(), index)
			imageReference := imageRepository + ":stable"
			tagImage := func(image string) {
				t.Helper()
				if err := engine.JSON(t.Context(), http.MethodPost, "/images/"+url.PathEscape(image)+"/tag?repo="+imageRepository+"&tag=stable", nil, nil); err != nil {
					t.Fatal(err)
				}
			}
			tagImage(string(*definition.ContainerDefinitions[0].Image))
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := engine.JSON(ctx, http.MethodDelete, "/images/"+url.PathEscape(imageReference)+"?force=true", nil, nil); err != nil {
					t.Errorf("remove owned mutable image alias: %v", err)
				}
			})
			mutable := ecsReplicaInput[api.RegisterTaskDefinitionInput](t, rows, "register-definition-v2")
			mutable.Family = new(api.String(imageRepository))
			mutable.ContainerDefinitions[0].Image = new(api.String(imageReference))
			registered := call("RegisterTaskDefinition", &mutable, "Success")["taskDefinition"].(map[string]any)
			other.TaskDefinition = new(api.String(registered["taskDefinitionArn"].(string)))
			call("UpdateService", &api.UpdateServiceInput{Cluster: other.Cluster, Service: other.ServiceName, TaskDefinition: other.TaskDefinition}, "Success")
			ecsReplicaRuntimeTransitions(t, clients.server, source, metered, rows, other, aws.ToString(vpc.Vpc.VpcId), aws.ToString(subnet.Subnet.SubnetId), owned, func() {
				tagImage(docker.ToolkitImage)
			}, func() {
				tagImage(string(*definition.ContainerDefinitions[0].Image))
			})
		})
	}
}

func ecsReplicaRuntimeTransitions(t *testing.T, server *httptest.Server, source *clock.Manual, executor *ecsMetricExecutor, rows map[string]ecsReplicaCapture, service api.CreateServiceInput, vpcID, subnetID string, owned map[string]computeecs.Specification, retagImage, restoreImage func()) {
	t.Helper()
	client := ecs.New(ecs.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	network := ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	cluster, name := string(*service.Cluster), string(*service.ServiceName)
	remember := func(arn string) {
		owned[arn] = computeecs.Specification{TaskARN: arn, Network: computenetwork.Specification{NetworkID: "arn:aws:ec2:us-east-1:000000000000:vpc/" + vpcID}}
	}
	// Include desired STOPPED tasks: actual shutdown and ENI release, rather
	// than a desired-state list alone, are part of each transition's result.
	tasks := func(ctx context.Context) ([]ecstypes.Task, error) {
		arns := []string{}
		seen := map[string]bool{}
		for _, desired := range []ecstypes.DesiredStatus{ecstypes.DesiredStatusRunning, ecstypes.DesiredStatusStopped} {
			out, err := client.ListTasks(ctx, &ecs.ListTasksInput{Cluster: &cluster, ServiceName: &name, DesiredStatus: desired})
			if err != nil {
				return nil, err
			}
			for _, arn := range out.TaskArns {
				remember(arn)
				if !seen[arn] {
					seen[arn] = true
					arns = append(arns, arn)
				}
			}
		}
		if len(arns) == 0 {
			return nil, nil
		}
		out, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: &cluster, Tasks: arns})
		if err != nil {
			return nil, err
		}
		if len(out.Failures) != 0 || len(out.Tasks) != len(arns) {
			return nil, fmt.Errorf("DescribeTasks: tasks=%v failures=%v", out.Tasks, out.Failures)
		}
		return out.Tasks, nil
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if _, err := client.DeleteService(ctx, &ecs.DeleteServiceInput{Cluster: &cluster, Service: &name, Force: aws.Bool(true)}); err != nil {
			t.Errorf("force-delete service cleanup: %v", err)
		}
		current, err := tasks(ctx)
		if err != nil {
			t.Errorf("enumerate service task cleanup: %v", err)
			return
		}
		for _, task := range current {
			if _, err := waitECSRuntimeStopped(ctx, client, &cluster, aws.ToString(task.TaskArn)); err != nil {
				t.Errorf("wait service task cleanup: %v", err)
			}
		}
	})
	primary := func(data ecstypes.Service) ecstypes.Deployment {
		for _, deployment := range data.Deployments {
			if aws.ToString(deployment.Status) == "PRIMARY" {
				return deployment
			}
		}
		t.Fatalf("service has no primary deployment: %v", data)
		return ecstypes.Deployment{}
	}
	wait := func(count int, excluded string) (ecstypes.Service, []ecstypes.Task) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		defer cancel()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		var observed ecstypes.Service
		var current []ecstypes.Task
		for {
			var err error
			current, err = tasks(ctx)
			if err != nil {
				t.Fatal(err)
			}
			out, err := client.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: &cluster, Services: []string{name}})
			if err != nil || out == nil || len(out.Services) != 1 || len(out.Failures) != 0 {
				t.Fatalf("DescribeServices: %v error=%v", out, err)
			}
			observed = out.Services[0]
			running := []ecstypes.Task{}
			settled := true
			readyAt := source.Now()
			for _, task := range current {
				switch aws.ToString(task.LastStatus) {
				case "RUNNING":
					running = append(running, task)
					if aws.ToString(task.DesiredStatus) != "RUNNING" || aws.ToString(task.TaskArn) == excluded || task.StartedAt == nil {
						settled = false
					} else if deadline := task.StartedAt.Add(41 * time.Second); deadline.After(readyAt) {
						readyAt = deadline
					}
				case "STOPPED":
					if task.StopCode == ecstypes.TaskStopCodeTaskFailedToStart || task.StopCode == ecstypes.TaskStopCodeEssentialContainerExited {
						t.Fatalf("service workload failed instead of converging: %v", task)
					}
				default:
					settled = false
				}
			}
			if settled && len(running) == count {
				// Only advance readiness after actual Docker processes have
				// reached RUNNING; never manufacture a running observation.
				if count > 0 && readyAt.After(source.Now()) {
					if err := source.Advance(readyAt.Sub(source.Now())); err != nil {
						t.Fatal(err)
					}
				} else if observed.RunningCount == int32(count) && observed.PendingCount == 0 && observed.DesiredCount == int32(count) && (aws.ToString(observed.Status) != "ACTIVE" || primary(observed).RolloutState == ecstypes.DeploymentRolloutStateCompleted) {
					return observed, running
				} else if count > 0 {
					// A controller can arm its next timer after the first
					// advance. Continue its clock only while tasks run.
					if err := source.Advance(time.Second); err != nil {
						t.Fatal(err)
					}
				}
			}
			select {
			case <-ctx.Done():
				t.Fatalf("service did not converge to %d running tasks: service=%v tasks=%v", count, observed, current)
			case <-ticker.C:
			}
		}
	}
	update := func(label string) {
		input := ecsReplicaInput[api.UpdateServiceInput](t, rows, label)
		input.Cluster, input.Service = service.Cluster, service.ServiceName
		ecsReplicaRequest(t, server, "UpdateService", &input, rows[label].Code)
	}
	initial, _ := wait(0, "")
	deploymentID := aws.ToString(primary(initial).Id)
	update("scale-one")
	one, running := wait(1, "")
	if aws.ToString(primary(one).Id) != deploymentID {
		t.Fatalf("scaling created a deployment instead of reconciling the existing one: %v", one.Deployments)
	}
	ecsReplicaMetricClockBoundary(t, server, source, executor, cluster, name)
	first := aws.ToString(running[0].TaskArn)
	retagImage()
	stop := ecsReplicaInput[api.StopTaskInput](t, rows, "stop-service-task-for-replacement")
	stop.Cluster, stop.Task = service.Cluster, new(api.String(first))
	ecsReplicaRequest(t, server, "StopTask", &stop, rows["stop-service-task-for-replacement"].Code)
	replaced, running := wait(1, first)
	if aws.ToString(primary(replaced).Id) != deploymentID || aws.ToString(running[0].StartedBy) != deploymentID {
		t.Fatalf("replacement lost its deployment identity: service=%v tasks=%v", replaced, running)
	}
	update("scale-two")
	two, running := wait(2, "")
	if aws.ToString(primary(two).Id) != deploymentID {
		t.Fatalf("scale-out replaced the deployment: %v", two.Deployments)
	}
	for _, task := range running {
		if aws.ToString(task.StartedBy) != deploymentID || aws.ToString(task.Group) != "service:"+name {
			t.Fatalf("scale-out task lost its service owner: %v", task)
		}
	}
	update("scale-zero")
	wait(0, "")
	restoreImage()
	update("force-new-deployment-zero")
	forced, _ := wait(0, "")
	nextDeployment := aws.ToString(primary(forced).Id)
	if nextDeployment == deploymentID {
		t.Fatalf("forced deployment reused the previous deployment: %v", forced.Deployments)
	}
	update("scale-one-for-force-delete")
	_, running = wait(1, "")
	if aws.ToString(running[0].StartedBy) != nextDeployment {
		t.Fatalf("forced deployment did not own the next real task: %v", running)
	}
	drain := ecsReplicaInput[api.DeleteServiceInput](t, rows, "force-delete-running-service")
	drain.Cluster, drain.Service = service.Cluster, service.ServiceName
	deleted := ecsReplicaRequest(t, server, "DeleteService", &drain, rows["force-delete-running-service"].Code)["service"].(map[string]any)
	if deleted["status"] != "DRAINING" || deleted["desiredCount"] != float64(0) {
		t.Fatalf("force deletion failed to initiate draining: %v", deleted)
	}
	wait(0, "")
	listed, err := client.ListServices(t.Context(), &ecs.ListServicesInput{Cluster: &cluster})
	if err != nil || listed == nil {
		t.Fatalf("ListServices after force drain: %v", err)
	}
	for _, arn := range listed.ServiceArns {
		if arn == aws.ToString(forced.ServiceArn) {
			t.Fatalf("force-drained service remains discoverable: %v", listed.ServiceArns)
		}
	}
	interfaces, err := network.DescribeNetworkInterfaces(t.Context(), &ec2.DescribeNetworkInterfacesInput{Filters: []ec2types.Filter{{Name: aws.String("subnet-id"), Values: []string{subnetID}}}})
	if err != nil || interfaces == nil || len(interfaces.NetworkInterfaces) != 0 {
		t.Fatalf("force drain retained task ENIs: output=%v error=%v", interfaces, err)
	}
}

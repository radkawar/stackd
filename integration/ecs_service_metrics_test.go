package stackd_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"stackd"
	"stackd/clock"
	computeecs "stackd/compute/ecs"
	api "stackd/internal/awsapi/ecs"
)

func ecsReplicaMonitoring(t *testing.T, server *httptest.Server, base api.CreateServiceInput, rows map[string]ecsReplicaCapture) {
	t.Helper()
	var creates, updates []ecsReplicaCapture
	for _, row := range rows {
		if strings.HasPrefix(row.Label, "create-monitoring-") {
			creates = append(creates, row)
		} else if strings.HasPrefix(row.Label, "update-isolated-") {
			updates = append(updates, row)
		}
	}
	order := func(a, b ecsReplicaCapture) int { return a.StartedAt.Compare(b.StartedAt) }
	slices.SortFunc(creates, order)
	slices.SortFunc(updates, order)
	primary := func(t *testing.T, service map[string]any) string {
		t.Helper()
		for _, deployment := range service["deployments"].([]any) {
			data := deployment.(map[string]any)
			if data["status"] == "PRIMARY" {
				return data["id"].(string)
			}
		}
		t.Fatalf("service has no primary deployment: %v", service)
		return ""
	}
	nativeIDs, localIDs := map[string]string{}, map[string]string{}
	for _, row := range creates {
		t.Run(row.Label, func(t *testing.T) {
			var input, native map[string]any
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			name := "metrics-" + input["serviceName"].(string)
			input["cluster"], input["taskDefinition"], input["networkConfiguration"], input["serviceName"] = base.Cluster, base.TaskDefinition, base.NetworkConfiguration, name
			out := ecsReplicaRequest(t, server, "CreateService", input, row.Code)
			if row.Code == "Success" {
				if err := json.Unmarshal(row.Output, &native); err != nil {
					t.Fatal(err)
				}
				nativeIDs[name] = primary(t, native["service"].(map[string]any))
				localIDs[name] = primary(t, out["service"].(map[string]any))
				return
			}
			absent := ecsReplicaRequest(t, server, "DescribeServices", map[string]any{"cluster": base.Cluster, "services": []string{name}}, "Success")
			if len(absent["services"].([]any)) != 0 || len(absent["failures"].([]any)) != 1 {
				t.Fatalf("rejected monitoring created a service: %v", absent)
			}
		})
	}
	for _, row := range updates {
		t.Run(row.Label, func(t *testing.T) {
			var input, native map[string]any
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			name := "metrics-" + input["service"].(string)
			input["cluster"], input["service"] = base.Cluster, name
			out := ecsReplicaRequest(t, server, "UpdateService", input, row.Code)
			changed := false
			var actual string
			if row.Code == "Success" {
				if err := json.Unmarshal(row.Output, &native); err != nil {
					t.Fatal(err)
				}
				nativeID := primary(t, native["service"].(map[string]any))
				changed = nativeID != nativeIDs[name]
				nativeIDs[name] = nativeID
				actual = primary(t, out["service"].(map[string]any))
			} else {
				retained := ecsReplicaRequest(t, server, "DescribeServices", map[string]any{"cluster": base.Cluster, "services": []string{name}}, "Success")
				actual = primary(t, retained["services"].([]any)[0].(map[string]any))
			}
			if (actual != localIDs[name]) != changed {
				t.Fatalf("monitoring deployment transition changed=%v, native changed=%v", actual != localIDs[name], changed)
			}
			localIDs[name] = actual
		})
	}
}

// Delay an actual Engine observation, never substitute counters or processes.
// All other execution and metadata operations retain the real implementation.
type ecsMetricExecutor struct {
	computeecs.Executor
	gate atomic.Pointer[ecsMetricGate]
}

type ecsMetricGate struct{ entered, resume chan struct{} }

type ecsMetricEnvironment struct {
	computeecs.Environment
	owner *ecsMetricExecutor
}

func (e *ecsMetricExecutor) Prepare(ctx context.Context, spec computeecs.Specification) (computeecs.Environment, error) {
	environment, err := e.Executor.Prepare(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &ecsMetricEnvironment{Environment: environment, owner: e}, nil
}

func (e *ecsMetricEnvironment) Usage(ctx context.Context, name string) (computeecs.ContainerUsage, error) {
	usage, err := e.Environment.Usage(ctx, name)
	if err != nil {
		return usage, err
	}
	if gate := e.owner.gate.Swap(nil); gate != nil {
		close(gate.entered)
		select {
		case <-gate.resume:
		case <-ctx.Done():
			return computeecs.ContainerUsage{}, ctx.Err()
		}
	}
	return usage, nil
}

func ecsReplicaMetricClockBoundary(t *testing.T, server *httptest.Server, source *clock.Manual, executor *ecsMetricExecutor, cluster, service string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	client := cloudwatch.New(cloudwatch.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	start := source.Now().Add(-time.Hour)
	query := func(end time.Time) (map[time.Time]float64, float64) {
		t.Helper()
		out, err := client.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
			Namespace: aws.String("AWS/ECS"), MetricName: aws.String("MemoryUtilization"),
			Dimensions: []metrictypes.Dimension{{Name: aws.String("ClusterName"), Value: &cluster}, {Name: aws.String("ServiceName"), Value: &service}},
			StartTime:  &start, EndTime: &end, Period: aws.Int32(60), Statistics: []metrictypes.Statistic{metrictypes.StatisticSampleCount},
		})
		if err != nil {
			t.Fatal(err)
		}
		points := make(map[time.Time]float64, len(out.Datapoints))
		total := 0.0
		for _, point := range out.Datapoints {
			count := aws.ToFloat64(point.SampleCount)
			points[point.Timestamp.UTC()] = count
			total += count
		}
		return points, total
	}
	advance := func(amount time.Duration) {
		t.Helper()
		if err := source.Advance(amount); err != nil {
			t.Fatal(err)
		}
	}
	gate := &ecsMetricGate{entered: make(chan struct{}), resume: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.resume) })
	defer release()
	executor.gate.Store(gate)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	advance(20 * time.Second)
waiting:
	for {
		select {
		case <-gate.entered:
			break waiting
		case <-ticker.C:
			advance(20 * time.Second)
		case <-ctx.Done():
			t.Fatal("real task did not supply a usage observation")
		}
	}
	boundary := source.Now().Truncate(time.Minute).Add(time.Minute)
	advance(boundary.Sub(source.Now()))
	cloud := server.Config.Handler.(*stackd.Stack)
	trailNativeDrain(t, cloud)
	before, beforeTotal := query(boundary)
	release()
	for {
		advance(time.Minute)
		trailNativeDrain(t, cloud)
		after, total := query(source.Now())
		if total > beforeTotal {
			for at := range after {
				if !at.Before(boundary) {
					delete(after, at)
				}
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("late real observation reopened a completed window: before=%v after=%v", before, after)
			}
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("released real usage observation was not published")
		}
	}
}

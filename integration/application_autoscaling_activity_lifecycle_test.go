package stackd_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ecs"

	"stackd"
	"stackd/clock"
	computeecs "stackd/compute/ecs"
	"stackd/internal/awstest"
)

// Hold placement at the real execution seam, rather than inventing successful
// task observations. Cancellation remains live during restart and scale-in.
type aasLifecycleExecutor struct {
	computeecs.Executor
	resume chan struct{}
}

func (e *aasLifecycleExecutor) Prepare(ctx context.Context, spec computeecs.Specification) (computeecs.Environment, error) {
	select {
	case <-e.resume:
		return e.Executor.Prepare(ctx, spec)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestApplicationAutoScalingNativeActivityLifecycle(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/applicationautoscaling/activity_lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		aasControlFixture
		PaginationSupplement aasControlFixture
		StablePagination     aasControlFixture
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	row := func(sequence int) aasControlRow {
		t.Helper()
		for _, r := range fixture.Calls {
			if r.Sequence == sequence {
				return r
			}
		}
		t.Fatalf("native lifecycle sequence %d missing", sequence)
		return aasControlRow{}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Calls[0].StartedAt)
			executor := &aasLifecycleExecutor{Executor: aasExecutor(t), resume: make(chan struct{})}
			release := sync.OnceFunc(func() { close(executor.resume) })
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source, ECSExecutor: executor, ComputeEndpoint: "http://stackd.invalid"})
			bindings, times := map[string]string{}, map[float64]float64{}
			advance := func(at time.Time) {
				t.Helper()
				if at.After(source.Now()) {
					if err := source.Advance(at.Sub(source.Now())); err != nil {
						t.Fatal(err)
					}
				}
			}
			drain := func(ctx context.Context) {
				t.Helper()
				if result, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil || result.More {
					t.Fatalf("activity jobs did not drain: %+v, %v", result, err)
				}
			}
			replay := func(r aasControlRow) {
				t.Helper()
				advance(r.StartedAt)
				aasFixtureRow(t, clients, r, bindings, times)
			}
			capacity := func(sequence int) {
				t.Helper()
				r := row(sequence)
				client := ecs.New(ecs.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				result, err := awstest.CallSDK(ctx, client, r.Operation, aasInput(t, r, bindings))
				if err != nil {
					t.Fatal(err)
				}
				services := result.(*ecs.DescribeServicesOutput).Services
				native := ecsControlBody(t, r.Output)["services"].([]any)[0].(map[string]any)
				if len(services) != 1 || services[0].DesiredCount != int32(native["desiredCount"].(float64)) || services[0].RunningCount != int32(native["runningCount"].(float64)) {
					t.Fatalf("%s: native desired/running %v/%v; got %+v", r.Label, native["desiredCount"], native["runningCount"], services)
				}
				// Fargate tasks held in Prepare are pending; native empty EC2
				// placement had no pending tasks. Neither has running capacity.
			}
			query := func(ctx context.Context, input map[string]any) map[string]any {
				t.Helper()
				body, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				wire := &awstest.WireClient{Client: clients.server.Client()}
				_, err = awstest.CallSDK(ctx, aasClient(clients, fixture.Region, "test", "test", wire), "DescribeScalingActivities", body)
				if err != nil {
					t.Fatal(err)
				}
				return ecsControlBody(t, wire.Body)
			}
			// Await the selected native states, then compare every wire field,
			// including absent fields and already-bound activity IDs/timestamps.
			observe := func(r aasControlRow) {
				t.Helper()
				advance(r.StartedAt)
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				want := ecsControlBody(t, r.Output)
				states := func(body map[string]any) []any {
					var result []any
					for _, activity := range body["ScalingActivities"].([]any) {
						result = append(result, activity.(map[string]any)["StatusCode"])
					}
					return result
				}
				for {
					drain(ctx)
					got := query(ctx, ecsControlBody(t, aasInput(t, r, bindings)))
					if reflect.DeepEqual(states(want), states(got)) {
						aasCompare(t, r.Label, want, got, bindings, times)
						return
					}
					select {
					case <-ctx.Done():
						t.Fatalf("%s: native states %v; actual %v", r.Label, states(want), states(got))
					case <-ticker.C:
						advance(source.Now().Add(time.Second))
					}
				}
			}
			// Stack.Close intentionally detaches retained tasks. Explicitly destroy
			// this test's service first, even if an assertion fails with placement held.
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				client := ecs.New(ecs.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				input := ecsControlBody(t, row(7).Input)
				cluster, service := input["cluster"].(string), input["serviceName"].(string)
				_, updateErr := client.UpdateService(ctx, &ecs.UpdateServiceInput{Cluster: &cluster, Service: &service, DesiredCount: aws.Int32(0)})
				_, deleteErr := client.DeleteService(ctx, &ecs.DeleteServiceInput{Cluster: &cluster, Service: &service, Force: aws.Bool(true)})
				release()
				if updateErr != nil || deleteErr != nil {
					t.Errorf("local ECS cleanup: update=%v delete=%v", updateErr, deleteErr)
					return
				}
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					out, err := client.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: &cluster, Services: []string{service}})
					if err != nil {
						t.Error(err)
						return
					}
					if len(out.Services) == 1 && aws.ToString(out.Services[0].Status) == "INACTIVE" {
						return
					}
					select {
					case <-ctx.Done():
						t.Error("local ECS service cleanup did not complete")
						return
					case <-ticker.C:
						_ = source.Advance(time.Second)
						_, _ = clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000)
					}
				}
			}()
			for _, sequence := range []int{4, 6, 7, 8, 9, 10, 14} {
				replay(row(sequence))
			}
			observe(row(17))
			capacity(18)
			clients = reopen()
			observe(row(53)) // Accepted capacity remains unfinished after recovery.
			capacity(54)
			replay(row(55))
			observe(row(62)) // External desired changes update the original activity.
			capacity(63)
			replay(row(64))
			observe(row(71)) // Zero capacity is the observed ECS fulfillment case.
			capacity(72)
			for _, sequence := range []int{73, 74, 75} {
				replay(row(sequence))
			}
			clients = reopen() // Recover the scheduled deadline before it fires.
			observe(row(92))   // Separate bounds-success and resource-InProgress rows.
			capacity(93)
			replay(row(128))
			observe(row(133))
			capacity(134)
			for _, sequence := range []int{135, 136, 137, 138, 139} {
				replay(row(sequence))
			}
			observe(row(140))
			capacity(141)
			replay(row(178))
			replay(row(179))
			observe(row(184))
			capacity(185)
			for _, sequence := range []int{186, 187, 188, 189} {
				replay(row(sequence))
			}
			for _, label := range []string{"external-set-desired-three", "enable-owned-policy-alarm", "before-equal-exact-trigger", "equal-exact-three-trigger-reset", "equal-exact-three-trigger"} {
				replay(fixture.PaginationSupplement.row(t, label))
			}
			observe(fixture.PaginationSupplement.row(t, "equal-exact-first"))
			replay(fixture.PaginationSupplement.row(t, "disable-owned-policy-alarm"))
			replay(fixture.PaginationSupplement.row(t, "restore-owned-service-zero"))

			// Native concurrent attempts include retried/failed duplicate actions.
			// Admit each captured schedule once through the serial local kernel;
			// derive inventory size from those commands, never native retry counts.
			base := ecsControlBody(t, row(186).Input)
			base["IncludeNotScaledActivities"] = true
			before := query(t.Context(), base)["ScalingActivities"].([]any)
			var schedules []aasControlRow
			for _, r := range fixture.PaginationSupplement.Calls {
				if r.Operation == "put-scheduled-action" {
					schedules = append(schedules, r)
					replay(r)
				}
			}
			advance(fixture.StablePagination.Calls[0].StartedAt)
			drain(t.Context())
			collect := func(input map[string]any) []any {
				t.Helper()
				var result []any
				seen := map[string]bool{}
				delete(input, "NextToken")
				for page := 0; page <= len(schedules)+len(before); page++ {
					out := query(t.Context(), input)
					for _, item := range out["ScalingActivities"].([]any) {
						id := item.(map[string]any)["ActivityId"].(string)
						if seen[id] {
							t.Fatalf("activity repeated across pages: %s", id)
						}
						seen[id] = true
						result = append(result, item)
					}
					token, more := out["NextToken"]
					if !more {
						delete(input, "NextToken")
						return result
					}
					input["NextToken"] = token
				}
				t.Fatal("activity pagination did not terminate")
				return nil
			}
			all := collect(base)
			if len(all) != len(before)+len(schedules) {
				t.Fatalf("serial commands yielded %d activities, want %d", len(all), len(before)+len(schedules))
			}
			byCause := map[string]map[string]any{}
			byID := map[string]map[string]any{}
			for _, item := range all {
				activity := item.(map[string]any)
				byCause[activity["Cause"].(string)] = activity
				byID[activity["ActivityId"].(string)] = activity
			}
			// Where native contention prevented a successful sample for a named
			// schedule, compare its input-independent success fields, not a made-up
			// native ID or execution time. Every ID/time is checked across reopen.
			nativeSuccess := map[string]map[string]any{}
			for _, r := range fixture.StablePagination.Calls[:2] {
				for _, item := range ecsControlBody(t, r.Output)["ScalingActivities"].([]any) {
					activity := item.(map[string]any)
					if activity["StatusCode"] == "Successful" && strings.Contains(activity["Cause"].(string), "-page-") {
						nativeSuccess[activity["Cause"].(string)] = activity
					}
				}
			}
			var template map[string]any
			for _, activity := range nativeSuccess {
				template = activity
				break
			}
			for _, r := range schedules {
				name := ecsControlBody(t, r.Input)["ScheduledActionName"].(string)
				cause := "scheduled action name " + name + " was triggered"
				actual, ok := byCause[cause]
				if !ok {
					t.Fatalf("missing scheduled bounds activity: %s", name)
				}
				if native, ok := nativeSuccess[cause]; ok {
					aasCompare(t, name, native, actual, bindings, times)
				} else {
					for _, field := range []string{"ServiceNamespace", "ResourceId", "ScalableDimension", "Description", "StatusCode", "StatusMessage"} {
						aasCompare(t, name+"."+field, template[field], actual[field], bindings, times)
					}
					if actual["EndTime"] == nil || actual["StartTime"] == nil {
						t.Fatalf("completed bounds activity lacks timestamps: %v", actual)
					}
				}
			}
			for _, prior := range before {
				activity := prior.(map[string]any)
				if !reflect.DeepEqual(activity, byID[activity["ActivityId"].(string)]) {
					t.Fatalf("later schedules rewrote retained history: %v", activity)
				}
			}
			for _, included := range []bool{false, true} {
				base["IncludeNotScaledActivities"] = included
				delete(base, "MaxResults")
				first := query(t.Context(), base)
				// Native stable-normal/mixed-first and max-51 both stop at 50.
				if len(first["ScalingActivities"].([]any)) != len(ecsControlBody(t, fixture.StablePagination.Calls[0].Output)["ScalingActivities"].([]any)) || first["NextToken"] == nil {
					t.Fatalf("default native page boundary changed: %v", first)
				}
				for _, size := range []int{50, 51} {
					base["MaxResults"] = size
					out := query(t.Context(), base)
					if !reflect.DeepEqual(first["ScalingActivities"], out["ScalingActivities"]) {
						t.Fatalf("explicit %d changed the native first page", size)
					}
					if (out["NextToken"] != nil) != (size > 50) {
						t.Fatalf("explicit %d changed native continuation presence", size)
					}
				}
				delete(base, "MaxResults")
				base["NextToken"] = first["NextToken"]
				second := query(t.Context(), base)
				clients = reopen()
				if got := query(t.Context(), base); !reflect.DeepEqual(second, got) {
					t.Fatalf("reusable token changed after reopen: %v / %v", second, got)
				}
				base["IncludeNotScaledActivities"] = !included
				flipped := query(t.Context(), base)
				if len(flipped["ScalingActivities"].([]any))-len(second["ScalingActivities"].([]any)) != map[bool]int{false: 1, true: -1}[included] {
					t.Fatal("continuation did not reapply IncludeNotScaledActivities")
				}
				base["ScalableDimension"] = "dynamodb:table:ReadCapacityUnits"
				other := query(t.Context(), base)
				if len(other["ScalingActivities"].([]any)) != 0 || other["NextToken"] != nil {
					t.Fatalf("continuation escaped the requested dimension: %v", other)
				}
				base["ScalableDimension"] = "ecs:service:DesiredCount"
				delete(base, "NextToken")
			}
			base["IncludeNotScaledActivities"] = true
			base["MaxResults"] = 51
			if got := collect(base); !reflect.DeepEqual(all, got) {
				t.Fatal("explicit pagination lost, reordered, or changed activity history")
			}
			// Native post-deregistration rows retain the same history. Local serial
			// inventory differs only because it does not fabricate AWS contention.
			for _, sequence := range []int{228, 229, 230, 231} {
				replay(row(sequence))
			}
			clients = reopen()
			if got := collect(base); !reflect.DeepEqual(all, got) {
				t.Fatal("deregistration/recovery discarded or rewrote scaling history")
			}
			client := aasClient(clients, fixture.Region, "test", "test", clients.server.Client())
			out, err := client.DescribeScalableTargets(t.Context(), &applicationautoscaling.DescribeScalableTargetsInput{ServiceNamespace: "ecs"})
			if err != nil || len(out.ScalableTargets) != 0 {
				t.Fatalf("target survived deregistration: %+v, %v", out, err)
			}
		})
	}
}

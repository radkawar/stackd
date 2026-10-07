package logs_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/logs"
	"stackd/storage/sqlite"
	sqllogs "stackd/storage/sqlite/logs"
)

// Exercise retained native effects, not adapter request echoes: recovery must
// keep ingested events, native retargeting must keep ownership, and native
// deletion/recreation must invalidate an old CFN incarnation.
func TestCloudFormationLogChildIncarnationRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
			var repository logs.Repository = logs.NewMemoryRepository(nil)
			reopen := func() {}
			if backend == "sqlite" {
				path := filepath.Join(t.TempDir(), "logs.sqlite")
				db, err := sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repository = sqllogs.New(db)
				reopen = func() {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repository = sqllogs.New(db)
				}
			}
			service := logs.New(logs.Config{Repository: repository})
			t.Cleanup(func() { _ = service.Close() })
			call := func(ctx context.Context, operation string, input any) (any, *awswire.Error) {
				t.Helper()
				model, _ := awscatalog.LookupService("logs")
				op, _ := model.Operation(operation)
				return service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
			}
			success := func(ctx context.Context, operation string, input any) any {
				t.Helper()
				out, wire := call(ctx, operation, input)
				if wire != nil {
					t.Fatalf("%s: %v", operation, wire)
				}
				return out
			}
			denied := func(ctx context.Context, operation string, input any) {
				t.Helper()
				_, wire := call(ctx, operation, input)
				if wire == nil || wire.Code != "AccessDeniedException" {
					t.Fatalf("%s: want incarnation refusal, got %v", operation, wire)
				}
			}
			group := new(api.LogGroupName("owned-group"))
			stream := new(api.LogStreamName("events"))
			success(ctx, "CreateLogGroup", &api.CreateLogGroupRequest{LogGroupName: group})
			create := logs.WithCloudFormationOwner(ctx, "first-incarnation", true)
			mutate := logs.WithCloudFormationOwner(ctx, "first-incarnation", false)
			streamInput := &api.CreateLogStreamRequest{LogGroupName: group, LogStreamName: stream}
			success(create, "CreateLogStream", streamInput)
			success(ctx, "PutLogEvents", &api.PutLogEventsRequest{LogGroupName: group, LogStreamName: stream, LogEvents: api.InputLogEvents{{Timestamp: new(api.Timestamp(time.Now().UnixMilli())), Message: new(api.EventMessage("retained-event"))}}})
			filter := &api.PutMetricFilterRequest{LogGroupName: group, FilterName: new(api.FilterName("counter")), FilterPattern: new(api.FilterPattern("")), MetricTransformations: api.MetricTransformations{{MetricName: new(api.MetricName("Count")), MetricNamespace: new(api.MetricNamespace("CFN/Owner")), MetricValue: new(api.MetricValue("1"))}}}
			success(create, "PutMetricFilter", filter)
			filter.MetricTransformations[0].MetricValue = new(api.MetricValue("2"))
			success(ctx, "PutMetricFilter", filter)
			_ = service.Close()
			reopen()
			service = logs.New(logs.Config{Repository: repository})
			success(create, "CreateLogStream", streamInput)
			events := success(ctx, "GetLogEvents", &api.GetLogEventsRequest{LogGroupName: group, LogStreamName: stream}).(*api.GetLogEventsResponse)
			if len(events.Events) != 1 || events.Events[0].Message == nil || string(*events.Events[0].Message) != "retained-event" {
				t.Fatalf("recovery lost admitted events: %+v", events.Events)
			}
			filters := success(ctx, "DescribeMetricFilters", &api.DescribeMetricFiltersRequest{LogGroupName: group}).(*api.DescribeMetricFiltersResponse)
			if len(filters.MetricFilters) != 1 || string(*filters.MetricFilters[0].MetricTransformations[0].MetricValue) != "2" {
				t.Fatalf("native update lost metric configuration: %+v", filters.MetricFilters)
			}
			other := logs.WithCloudFormationOwner(ctx, "other-incarnation", false)
			denied(other, "PutMetricFilter", filter)
			success(mutate, "PutMetricFilter", filter)
			deleteStream := &api.DeleteLogStreamRequest{LogGroupName: group, LogStreamName: stream}
			success(ctx, "DeleteLogStream", deleteStream)
			success(ctx, "CreateLogStream", streamInput)
			denied(mutate, "DeleteLogStream", deleteStream)
			live := success(ctx, "DescribeLogStreams", &api.DescribeLogStreamsRequest{LogGroupName: group}).(*api.DescribeLogStreamsResponse)
			if len(live.LogStreams) != 1 {
				t.Fatal("stale CFN delete removed a native recreation")
			}
			denied(mutate, "CreateLogStream", streamInput)
		})
	}
}

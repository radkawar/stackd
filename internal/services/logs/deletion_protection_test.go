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

func TestLogGroupDeletionProtection(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			metadata := awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"}
			ctx := awsctx.WithMetadata(t.Context(), metadata)
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
			success := func(operation string, input any) any {
				t.Helper()
				out, wire := call(ctx, operation, input)
				if wire != nil {
					t.Fatalf("%s: %v", operation, wire)
				}
				return out
			}
			group := new(api.LogGroupName("protected"))
			stream := new(api.LogStreamName("consumer"))
			success("CreateLogGroup", &api.CreateLogGroupRequest{LogGroupName: group, DeletionProtectionEnabled: new(api.DeletionProtectionEnabled(true))})
			success("CreateLogStream", &api.CreateLogStreamRequest{LogGroupName: group, LogStreamName: stream})
			success("PutLogEvents", &api.PutLogEventsRequest{LogGroupName: group, LogStreamName: stream, LogEvents: api.InputLogEvents{{Timestamp: new(api.Timestamp(time.Now().UnixMilli())), Message: new(api.EventMessage("live-bytes"))}}})
			success("PutMetricFilter", &api.PutMetricFilterRequest{LogGroupName: group, FilterName: new(api.FilterName("counter")), FilterPattern: new(api.FilterPattern("")), MetricTransformations: api.MetricTransformations{{MetricName: new(api.MetricName("Count")), MetricNamespace: new(api.MetricNamespace("Protection")), MetricValue: new(api.MetricValue("1"))}}})
			checkProtected := func() {
				t.Helper()
				groups := success("DescribeLogGroups", &api.DescribeLogGroupsRequest{}).(*api.DescribeLogGroupsResponse).LogGroups
				if len(groups) != 1 || groups[0].DeletionProtectionEnabled == nil || !bool(*groups[0].DeletionProtectionEnabled) {
					t.Fatalf("protection is not retained: %+v", groups)
				}
				if groups[0].MetricFilterCount == nil || int64(*groups[0].MetricFilterCount) != 1 {
					t.Fatalf("group projection lost actual filter count: %+v", groups)
				}
				_, wire := call(ctx, "DeleteLogGroup", &api.DeleteLogGroupRequest{LogGroupName: group})
				if wire == nil || wire.Code != "ValidationException" {
					t.Fatalf("protected delete: %v", wire)
				}
				events := success("GetLogEvents", &api.GetLogEventsRequest{LogGroupName: group, LogStreamName: stream}).(*api.GetLogEventsResponse).Events
				if len(events) != 1 || string(*events[0].Message) != "live-bytes" {
					t.Fatalf("protected deletion changed consumer bytes: %+v", events)
				}
			}
			checkProtected()
			_ = service.Close()
			reopen()
			service = logs.New(logs.Config{Repository: repository})
			checkProtected()
			input := &api.PutLogGroupDeletionProtectionRequest{LogGroupIdentifier: new(api.LogGroupIdentifier("arn:aws:logs:us-east-1:111111111111:log-group:protected")), DeletionProtectionEnabled: new(api.DeletionProtectionEnabled(false))}
			metadata.PrincipalARN = "arn:aws:iam::111111111111:user/no-permission"
			metadata.PrincipalID = "no-permission"
			if _, wire := call(awsctx.WithMetadata(t.Context(), metadata), "PutLogGroupDeletionProtection", input); wire == nil || wire.Code != "AccessDeniedException" {
				t.Fatalf("unauthorized protection update: %v", wire)
			}
			checkProtected()
			if _, wire := call(ctx, "PutLogGroupDeletionProtection", &api.PutLogGroupDeletionProtectionRequest{LogGroupIdentifier: input.LogGroupIdentifier}); wire == nil || wire.Code != "InvalidParameterException" {
				t.Fatalf("missing protection flag: %v", wire)
			}
			success("PutLogGroupDeletionProtection", input)
			success("DeleteLogGroup", &api.DeleteLogGroupRequest{LogGroupName: group})
			success("CreateLogGroup", &api.CreateLogGroupRequest{LogGroupName: group})
			groups := success("DescribeLogGroups", &api.DescribeLogGroupsRequest{}).(*api.DescribeLogGroupsResponse).LogGroups
			if len(groups) != 1 || groups[0].DeletionProtectionEnabled == nil || bool(*groups[0].DeletionProtectionEnabled) {
				t.Fatalf("native recreation inherited protection: %+v", groups)
			}
			if groups[0].MetricFilterCount == nil || *groups[0].MetricFilterCount != 0 {
				t.Fatalf("native recreation inherited metric filters: %+v", groups)
			}
			success("DeleteLogGroup", &api.DeleteLogGroupRequest{LogGroupName: group})
		})
	}
}

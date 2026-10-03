package integrations

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"stackd/clock"
	native "stackd/compute/eks"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/eks"
	"stackd/internal/services/iam"
	"stackd/internal/services/logs"
)

func TestEKSNativeAuditDeliveryPreservesOutOfOrderSourceEvents(t *testing.T) {
	body, err := os.ReadFile("../../testdata/integration/eks_out_of_order_audit.json")
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		Items []json.RawMessage `json:"items"`
	}
	if err = json.Unmarshal(body, &frame); err != nil {
		t.Fatal(err)
	}
	const stream = "kube-apiserver-audit-native-regression"
	records := make([]native.LogRecord, 0, len(frame.Items))
	remaining := make(map[string]int, len(frame.Items))
	timestamps := make(map[string]int64, len(frame.Items))
	var latest time.Time
	for _, raw := range frame.Items {
		var event struct {
			StageTimestamp           time.Time `json:"stageTimestamp"`
			RequestReceivedTimestamp time.Time `json:"requestReceivedTimestamp"`
		}
		if err = json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		at := event.StageTimestamp
		if at.IsZero() {
			at = event.RequestReceivedTimestamp
		}
		if at.After(latest) {
			latest = at
		}
		message := string(raw)
		records = append(records, native.LogRecord{Category: "audit", Stream: stream, Message: message, Timestamp: at})
		remaining[message]++
		timestamps[message] = at.UnixMilli()
	}

	// Replay at the source's time, rather than rewriting old captured timestamps.
	ctx, owner, adapter, cluster := eksLogDeliveryFixture(t, latest.Add(time.Second))
	if err = adapter.WriteControlPlaneLogs(ctx, cluster, records); err != nil {
		t.Fatal(err)
	}

	model, _ := awscatalog.LookupService("logs")
	operation, _ := model.Operation("GetLogEvents")
	result, wire := owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: &api.GetLogEventsRequest{LogGroupName: new(api.LogGroupName("/aws/eks/eks-owned-workflow/cluster")), LogStreamName: new(api.LogStreamName(stream)), StartFromHead: new(api.StartFromHead(true))}})
	if wire != nil {
		t.Fatal(wire)
	}
	events := result.(*api.GetLogEventsResponse).Events
	if len(events) != len(records) {
		t.Fatalf("native events lost or duplicated: delivered %d, source %d", len(events), len(records))
	}
	var previous int64
	for _, event := range events {
		if event.Message == nil || event.Timestamp == nil {
			t.Fatal("delivered event omitted its original message or timestamp")
		}
		message, at := string(*event.Message), int64(*event.Timestamp)
		if remaining[message] == 0 || timestamps[message] != at {
			t.Fatal("native event bytes or provider timestamp changed")
		}
		if at < previous {
			t.Fatal("delivered native timestamps are not chronological")
		}
		remaining[message]--
		previous = at
	}
}

func eksLogDeliveryFixture(t *testing.T, now time.Time) (context.Context, *logs.Service, EKSLogs, eks.Cluster) {
	t.Helper()
	c := clock.NewManual(now)
	scope := iam.Scope{Partition: "aws", AccountID: "314159265358"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: "us-east-1", PrincipalARN: "arn:aws:iam::314159265358:root", PrincipalID: scope.AccountID})
	repository := iam.NewMemoryRepository(nil)
	role := iam.Role{
		Arn:      "arn:aws:iam::314159265358:role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS",
		RoleName: "AWSServiceRoleForAmazonEKS", RoleId: "AROAEKSLOGSREGRESSION", MaxSessionDuration: 3600,
		AssumeRolePolicyDocument: EKSClusterRoleTemplate().TrustPolicy,
		IdentityPolicies:         iam.IdentityPolicies{Inline: map[string]string{"logs": `{"Statement":{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:us-east-1:314159265358:log-group:/aws/eks/eks-owned-workflow/cluster*"}}`}},
	}
	if err := repository.Update(ctx, func(tx iam.WriteTx) error { return tx.PutRole(scope, role) }); err != nil {
		t.Fatal(err)
	}
	credentials := identity.NewWithConfig(identity.Config{AccountID: scope.AccountID, Repository: iam.NewCredentialRepository(repository, nil), Clock: c})
	roles := iam.NewWithConfig(iam.Config{Repository: repository, Credentials: credentials, Clock: c})
	authorizer := authorization.NewWithClock(roles, nil, c)
	owner := logs.New(logs.Config{Clock: c, Authorizer: authorizer})
	t.Cleanup(func() { owner.Close() })
	adapter := EKSLogs{Roles: ServiceRoles{IAM: roles, Credentials: credentials, Authorizer: authorizer}, Logs: owner}
	cluster := eks.Cluster{Key: eks.Key{Scope: eks.Scope{Partition: scope.Partition, AccountID: scope.AccountID, Region: "us-east-1"}, Name: "eks-owned-workflow"}}
	return ctx, owner, adapter, cluster
}

func TestEKSPartialLogRejectionAdvancesEveryStreamWithoutReplay(t *testing.T) {
	body, err := os.ReadFile("../../testdata/integration/eks_log_rejection.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Clock   time.Time
		Batches [][]struct {
			Category, Stream, Offset, Message string
			Accepted                          bool
		}
	}
	if err = json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	ctx, owner, adapter, cluster := eksLogDeliveryFixture(t, fixture.Clock)
	expected := map[string]map[string]int64{}
	for _, batch := range fixture.Batches {
		records := make([]native.LogRecord, 0, len(batch))
		for _, source := range batch {
			offset, err := time.ParseDuration(source.Offset)
			if err != nil {
				t.Fatal(err)
			}
			at := fixture.Clock.Add(offset)
			records = append(records, native.LogRecord{Category: source.Category, Stream: source.Stream, Message: source.Message, Timestamp: at})
			if source.Accepted {
				if expected[source.Stream] == nil {
					expected[source.Stream] = map[string]int64{}
				}
				expected[source.Stream][source.Message] = at.UnixMilli()
			}
		}
		if err := adapter.WriteControlPlaneLogs(ctx, cluster, records); err != nil {
			t.Fatalf("partially acknowledged batch prevented source advancement: %v", err)
		}
	}
	model, _ := awscatalog.LookupService("logs")
	operation, _ := model.Operation("GetLogEvents")
	for stream, remaining := range expected {
		result, wire := owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: &api.GetLogEventsRequest{LogGroupName: new(api.LogGroupName("/aws/eks/eks-owned-workflow/cluster")), LogStreamName: new(api.LogStreamName(stream)), StartFromHead: new(api.StartFromHead(true))}})
		if wire != nil {
			t.Fatal(wire)
		}
		events := result.(*api.GetLogEventsResponse).Events
		if len(events) != len(remaining) {
			t.Fatalf("%s accepted events duplicated, rejected events stored, or delivery blocked: got %d, want %d", stream, len(events), len(remaining))
		}
		for _, event := range events {
			if event.Message == nil || event.Timestamp == nil {
				t.Fatal("accepted event lost its source bytes or timestamp")
			}
			at, exists := remaining[string(*event.Message)]
			if !exists || at != int64(*event.Timestamp) {
				t.Fatalf("%s received a duplicate, rejected or modified event", stream)
			}
			delete(remaining, string(*event.Message))
		}
	}
}

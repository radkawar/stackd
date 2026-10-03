package integrations

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/logs"
	"stackd/internal/services/mq"
)

type mqLogsFixture struct {
	root, caller context.Context
	owner        *logs.Service
	adapter      MQLogs
	broker       mq.BrokerRecord
	now          time.Time
	clock        *clock.Manual
	iam          iam.Repository
	user         iam.User
}

func newMQLogsFixture(t *testing.T) *mqLogsFixture {
	t.Helper()
	return newMQLogsFixtureWithRepository(t, nil)
}

func newMQLogsFixtureWithRepository(t *testing.T, repository logs.Repository) *mqLogsFixture {
	t.Helper()
	f := &mqLogsFixture{
		now:    time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC),
		broker: mq.BrokerRecord{Scope: mq.Scope{Partition: "aws", AccountID: "314159265358", Region: "us-east-1"}, ID: "b-native-logs", ARN: "arn:aws:mq:us-east-1:314159265358:broker:orders:b-native-logs", Engine: "ACTIVEMQ"},
		iam:    iam.NewMemoryRepository(nil),
		user:   iam.User{Arn: "arn:aws:iam::314159265358:user/deployer", UserName: "deployer", UserId: "AIDAMQLOGSDEPLOYER"},
	}
	f.root = mqLogsRootContext(t.Context(), f.broker.Scope)
	f.caller = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: f.broker.Partition, AccountID: f.broker.AccountID, Region: f.broker.Region, PrincipalARN: f.user.Arn, PrincipalID: f.user.UserId, UserName: f.user.UserName})
	f.setCallerPolicy(t, "")
	c := clock.NewManual(f.now)
	f.clock = c
	credentials := identity.NewWithConfig(identity.Config{AccountID: f.broker.AccountID, Repository: iam.NewCredentialRepository(f.iam, nil), Clock: c})
	roles := iam.NewWithConfig(iam.Config{Repository: f.iam, Credentials: credentials, Clock: c})
	authorizer := authorization.NewWithClock(roles, nil, c)
	f.owner = logs.New(logs.Config{Repository: repository, Clock: c, Authorizer: authorizer})
	t.Cleanup(func() { f.owner.Close(); roles.Close() })
	f.adapter = MQLogs{Logs: f.owner, Roles: ServiceRoles{IAM: roles, Credentials: credentials, Authorizer: authorizer}}
	return f
}

func mqLogsRootContext(ctx context.Context, scope mq.Scope) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID})
}

func (f *mqLogsFixture) setCallerPolicy(t *testing.T, document string) {
	t.Helper()
	f.user.IdentityPolicies.Inline = map[string]string{}
	if document != "" {
		f.user.IdentityPolicies.Inline["logs"] = document
	}
	if err := f.iam.Update(f.root, func(tx iam.WriteTx) error {
		return tx.PutUser(iam.Scope{Partition: f.broker.Partition, AccountID: f.broker.AccountID}, f.user)
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *mqLogsFixture) command(t *testing.T, ctx context.Context, operation string, input any) any {
	t.Helper()
	model, _ := awscatalog.LookupService("logs")
	op, _ := model.Operation(operation)
	out, wire := f.owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: input})
	if wire != nil {
		t.Fatalf("%s: %v", operation, wire)
	}
	return out
}

func (f *mqLogsFixture) policy() string {
	return `{"Statement":{"Effect":"Allow","Principal":{"Service":"mq.amazonaws.com"},"Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:us-east-1:314159265358:log-group:/aws/amazonmq/broker/b-native-logs/*:log-stream:activemq-b-native-logs-1.log","Condition":{"ArnEquals":{"aws:SourceArn":"` + f.broker.ARN + `"},"StringEquals":{"aws:SourceAccount":"314159265358","aws:PrincipalType":"AWSService"},"Bool":{"aws:PrincipalIsAWSService":"true"}}}}`
}

func (f *mqLogsFixture) putPolicy(t *testing.T, name, document string) {
	t.Helper()
	f.command(t, f.root, "PutResourcePolicy", &api.PutResourcePolicyRequest{PolicyName: new(api.PolicyName(name)), PolicyDocument: new(api.PolicyDocument(document))})
}

func (f *mqLogsFixture) assertEvents(t *testing.T, expected ...mq.LogRecord) {
	t.Helper()
	out := f.command(t, f.root, "GetLogEvents", &api.GetLogEventsRequest{
		LogGroupName:  new(api.LogGroupName("/aws/amazonmq/broker/b-native-logs/general")),
		LogStreamName: new(api.LogStreamName("activemq-b-native-logs-1.log")), StartFromHead: new(api.StartFromHead(true)),
	}).(*api.GetLogEventsResponse)
	if len(out.Events) != len(expected) {
		t.Fatalf("delivered events = %d, want %d", len(out.Events), len(expected))
	}
	for i, record := range expected {
		event := out.Events[i]
		if event.Message == nil || string(*event.Message) != record.Message || event.Timestamp == nil || int64(*event.Timestamp) != record.Timestamp.UnixMilli() {
			t.Fatalf("event %d changed native bytes/time or published a denied record: %+v", i, event)
		}
	}
}

func requireMQLogError(t *testing.T, err error, code string) {
	t.Helper()
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire == nil || wire.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func TestMQLogsCallerCreationIsSeparateFromServiceDelivery(t *testing.T) {
	f := newMQLogsFixture(t)
	f.putPolicy(t, "mq", f.policy())
	record := mq.LogRecord{Timestamp: f.now, Message: "native general output\n"}
	requireMQLogError(t, f.adapter.Prepare(f.caller, f.broker, mq.LogSettings{General: true}), "AccessDeniedException")
	// Resource-policy permission cannot create a group, even with root as the
	// incoming delivery context. No administrative credentials reach Write.
	requireMQLogError(t, f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{record}), "ResourceNotFoundException")
	groups := f.command(t, f.root, "DescribeLogGroups", &api.DescribeLogGroupsRequest{}).(*api.DescribeLogGroupsResponse)
	if len(groups.LogGroups) != 0 {
		t.Fatal("denied caller or MQ delivery fabricated a log group")
	}
	f.setCallerPolicy(t, `{"Statement":{"Effect":"Allow","Action":"logs:CreateLogGroup","Resource":"arn:aws:logs:us-east-1:314159265358:log-group:/aws/amazonmq/broker/b-native-logs/general:*"}}`)
	if wire := f.adapter.Prepare(f.caller, f.broker, mq.LogSettings{General: true}); wire != nil {
		t.Fatal(wire)
	}
	if wire := f.adapter.Prepare(f.caller, f.broker, mq.LogSettings{General: true}); wire != nil {
		t.Fatalf("authorized existing group: %v", wire)
	}
	requireMQLogError(t, f.adapter.Prepare(f.caller, f.broker, mq.LogSettings{Audit: true}), "AccessDeniedException")
	f.setCallerPolicy(t, `{"Statement":{"Effect":"Deny","Action":"logs:*","Resource":"*"}}`)
	requireMQLogError(t, f.adapter.Prepare(f.caller, f.broker, mq.LogSettings{General: true}), "AccessDeniedException")
	if err := f.adapter.Write(f.caller, f.broker, mq.GeneralLog, []mq.LogRecord{record}); err != nil {
		t.Fatalf("MQ delivery inherited caller denial rather than service authority: %v", err)
	}
	f.assertEvents(t, record)
}

func TestMQLogsDeliveryUsesCurrentResourceAuthority(t *testing.T) {
	f := newMQLogsFixture(t)
	if wire := f.adapter.Prepare(f.root, f.broker, mq.LogSettings{General: true, Audit: true}); wire != nil {
		t.Fatal(wire)
	}
	first := mq.LogRecord{Timestamp: f.now.Add(-time.Second), Message: "native line one\n  continuation\n"}
	second := mq.LogRecord{Timestamp: f.now, Message: "native line two\n"}
	rejected := mq.LogRecord{Timestamp: f.now, Message: "must not publish"}
	requireMQLogError(t, f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{rejected}), "AccessDeniedException")
	f.putPolicy(t, "mq", f.policy())
	if err := f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{second, first}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, old, replacement string }{
		{"source broker", f.broker.ARN, f.broker.ARN + "-other"},
		{"source account", `"aws:SourceAccount":"314159265358"`, `"aws:SourceAccount":"999999999999"`},
		{"principal", `"Service":"mq.amazonaws.com"`, `"Service":"eks.amazonaws.com"`},
		{"principal type", `"aws:PrincipalType":"AWSService"`, `"aws:PrincipalType":"AssumedRole"`},
		{"stream resource", "activemq-b-native-logs-1.log", "activemq-other-1.log"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f.putPolicy(t, "mq", strings.ReplaceAll(f.policy(), test.old, test.replacement))
			requireMQLogError(t, f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{rejected}), "AccessDeniedException")
			f.assertEvents(t, first, second)
		})
	}
	f.putPolicy(t, "mq", f.policy())
	f.putPolicy(t, "deny", `{"Statement":{"Effect":"Deny","Principal":{"Service":"mq.amazonaws.com"},"Action":["logs:PutLogEvents","logs:CreateLogStream"],"Resource":"*"}}`)
	requireMQLogError(t, f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{rejected}), "AccessDeniedException")
	requireMQLogError(t, f.adapter.Write(f.root, f.broker, mq.AuditLog, []mq.LogRecord{rejected}), "AccessDeniedException")
	f.assertEvents(t, first, second)
	streams := f.command(t, f.root, "DescribeLogStreams", &api.DescribeLogStreamsRequest{LogGroupName: new(api.LogGroupName("/aws/amazonmq/broker/b-native-logs/audit"))}).(*api.DescribeLogStreamsResponse)
	if len(streams.LogStreams) != 0 {
		t.Fatal("explicit denial created an audit stream")
	}
	f.command(t, f.root, "DeleteResourcePolicy", &api.DeleteResourcePolicyRequest{PolicyName: new(api.PolicyName("deny"))})
	f.command(t, f.root, "DeleteResourcePolicy", &api.DeleteResourcePolicyRequest{PolicyName: new(api.PolicyName("mq"))})
	requireMQLogError(t, f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{rejected}), "AccessDeniedException")
	f.assertEvents(t, first, second)
	f.putPolicy(t, "mq", f.policy())
	third := mq.LogRecord{Timestamp: f.now.Add(time.Second), Message: "delivery restored\n"}
	if err := f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{third}); err != nil {
		t.Fatal(err)
	}
	f.assertEvents(t, first, second, third)
}

func TestMQLogsDeliveryCannotBorrowAnotherScopePolicy(t *testing.T) {
	f := newMQLogsFixture(t)
	if wire := f.adapter.Prepare(f.root, f.broker, mq.LogSettings{General: true}); wire != nil {
		t.Fatal(wire)
	}
	f.putPolicy(t, "mq", f.policy())
	otherScopes := []mq.Scope{
		{Partition: "aws", AccountID: "999999999999", Region: "us-east-1"},
		{Partition: "aws", AccountID: f.broker.AccountID, Region: "us-west-2"},
		{Partition: "aws-cn", AccountID: f.broker.AccountID, Region: "cn-north-1"},
	}
	record := mq.LogRecord{Timestamp: f.now, Message: "broker-scoped delivery\n"}
	// The incoming scheduler context is not the destination or source scope.
	if err := f.adapter.Write(mqLogsRootContext(t.Context(), otherScopes[0]), f.broker, mq.GeneralLog, []mq.LogRecord{record}); err != nil {
		t.Fatal(err)
	}
	for _, scope := range otherScopes {
		other := f.broker
		other.Scope = scope
		other.ARN = "arn:" + scope.Partition + ":mq:" + scope.Region + ":" + scope.AccountID + ":broker:orders:" + other.ID
		root := mqLogsRootContext(t.Context(), scope)
		if wire := f.adapter.Prepare(root, other, mq.LogSettings{General: true}); wire != nil {
			t.Fatal(wire)
		}
		requireMQLogError(t, f.adapter.Write(f.root, other, mq.GeneralLog, []mq.LogRecord{record}), "AccessDeniedException")
		streams := f.command(t, root, "DescribeLogStreams", &api.DescribeLogStreamsRequest{LogGroupName: new(api.LogGroupName("/aws/amazonmq/broker/b-native-logs/general"))}).(*api.DescribeLogStreamsResponse)
		if len(streams.LogStreams) != 0 {
			t.Fatalf("scope %+v borrowed another scope's policy", scope)
		}
	}
	f.assertEvents(t, record)
}

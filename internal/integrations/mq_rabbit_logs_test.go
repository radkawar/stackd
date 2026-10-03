package integrations

import (
	"context"
	"testing"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/services/iam"
	"stackd/internal/services/mq"
)

func TestRabbitMQLogsUseCurrentLinkedRole(t *testing.T) {
	f := newMQLogsFixture(t)
	f.broker.Engine = "RABBITMQ"
	settings := mq.LogSettings{General: true}
	record := mq.LogRecord{Timestamp: f.now, Message: "real source frame supplied to transactional delivery"}
	requireMQLogError(t, f.adapter.Prepare(f.root, f.broker, settings), "AccessDenied")
	service := f.adapter.Roles.IAM.(*iam.Service)
	if err := service.RegisterServiceLinkedRole(MQRoleTemplate(), MQRoleUsage{}); err != nil {
		t.Fatal(err)
	}
	scope := iam.Scope{Partition: f.broker.Partition, AccountID: f.broker.AccountID}
	if err := service.ProvisionServiceLinkedRole(f.root, scope, "mq.amazonaws.com"); err != nil {
		t.Fatal(err)
	}
	// Caller denial must not suppress the service-linked role's own permission.
	// No CloudWatch resource policy exists in this fixture.
	f.setCallerPolicy(t, `{"Statement":{"Effect":"Deny","Action":"logs:*","Resource":"*"}}`)
	if wire := f.adapter.Prepare(f.caller, f.broker, settings); wire != nil {
		t.Fatal(wire)
	}
	if err := f.adapter.Write(context.Background(), f.broker, mq.GeneralLog, []mq.LogRecord{record}); err != nil {
		t.Fatal(err)
	}
	group := new(api.LogGroupName("/aws/amazonmq/broker/b-native-logs/general"))
	stream := new(api.LogStreamName("rabbitmq-b-native-logs-1.log"))
	read := func() *api.GetLogEventsResponse {
		return f.command(t, f.root, "GetLogEvents", &api.GetLogEventsRequest{LogGroupName: group, LogStreamName: stream, StartFromHead: new(api.StartFromHead(true))}).(*api.GetLogEventsResponse)
	}
	out := read()
	if len(out.Events) != 1 || out.Events[0].Message == nil || string(*out.Events[0].Message) != record.Message || int64(*out.Events[0].Timestamp) != record.Timestamp.UnixMilli() {
		t.Fatalf("delivered record changed: %+v", out.Events)
	}
	var original iam.Role
	if err := f.iam.View(f.root, func(tx iam.ReadTx) error {
		var err error
		original, err = tx.Role(scope, "AWSServiceRoleForAmazonMQ")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Internal mutation models current authority loss; public IAM APIs correctly
	// prohibit customers from editing protected service-linked role policies.
	changed := original
	changed.Inline = map[string]string{"deny": `{"Statement":{"Effect":"Deny","Action":"logs:PutLogEvents","Resource":"*"}}`}
	if err := f.iam.Update(f.root, func(tx iam.WriteTx) error { return tx.PutRole(scope, changed) }); err != nil {
		t.Fatal(err)
	}
	requireMQLogError(t, f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{record}), "AccessDeniedException")
	if len(read().Events) != 1 {
		t.Fatal("denied batch changed log events")
	}
	changed = original
	changed.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	if err := f.iam.Update(f.root, func(tx iam.WriteTx) error { return tx.PutRole(scope, changed) }); err != nil {
		t.Fatal(err)
	}
	requireMQLogError(t, f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{record}), "AccessDenied")
	if err := f.iam.Update(f.root, func(tx iam.WriteTx) error { return tx.PutRole(scope, original) }); err != nil {
		t.Fatal(err)
	}
	// RabbitMQ's role may recreate a deleted group, unlike ActiveMQ delivery.
	f.command(t, f.root, "DeleteLogGroup", &api.DeleteLogGroupRequest{LogGroupName: group})
	record.Message = "after group deletion and authority restoration"
	if err := f.adapter.Write(f.root, f.broker, mq.GeneralLog, []mq.LogRecord{record}); err != nil {
		t.Fatal(err)
	}
	out = read()
	if len(out.Events) != 1 || string(*out.Events[0].Message) != record.Message {
		t.Fatalf("restored delivery: %+v", out.Events)
	}
	foreign := f.broker
	foreign.AccountID = "999999999999"
	foreign.ARN = "arn:aws:mq:us-east-1:999999999999:broker:orders:b-native-logs"
	requireMQLogError(t, f.adapter.Write(f.root, foreign, mq.GeneralLog, []mq.LogRecord{record}), "AccessDenied")
	requireMQLogError(t, f.adapter.Write(f.root, f.broker, mq.AuditLog, []mq.LogRecord{record}), "InvalidParameterException")
}

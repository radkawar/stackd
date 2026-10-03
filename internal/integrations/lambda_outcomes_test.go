package integrations

import (
	"reflect"
	"testing"

	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
	"stackd/internal/services/lambda"
	"stackd/internal/services/sqs"
)

// Native deleted-alias and deleted-target captures establish original event bytes
// and qualified resource errors, including explicit $LATEST for unqualified work.
func TestLambdaDeletedTargetDeadLetter(t *testing.T) {
	for _, qualifier := range []string{":deleted", ":7", "", ":$LATEST"} {
		t.Run(qualifier, func(t *testing.T) {
			f := newLambdaRoleFixture(t)
			const queueARN = "arn:aws:sqs:us-east-1:123456789012:dead"
			f.role.IdentityPolicies.Inline = map[string]string{"send": `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"` + queueARN + `"}}`}
			f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
			queues := sqs.NewWithConfig(sqs.Config{Authorizer: f.adapter.Authorizer, Clock: f.clock})
			t.Cleanup(func() { queues.Close() })
			root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{
				Partition: "aws", AccountID: f.scope.AccountID, Region: "us-east-1",
				PrincipalARN: "arn:aws:iam::123456789012:root",
			})
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sqs": queues})
			if _, rejected := commands.Call(root, "sqs", "CreateQueue", []byte(`{"QueueName":"dead"}`)); rejected != nil {
				t.Fatal(rejected)
			}
			adapter := LambdaOutcomes{Roles: f.adapter.ServiceRoles, SQS: queues}
			invocation := lambda.InvocationRecord{
				ID: "accepted-event", RequestID: "accepted-request",
				Key:         lambda.FunctionKey{Scope: lambda.Scope{Partition: "aws", Account: f.scope.AccountID, Region: "us-east-1"}, Name: "f"},
				FunctionARN: lambdaTestFunction + qualifier, RoleARN: f.role.Arn,
				Payload: []byte("{\"original\": [17, \"payload-λ\"], \"spacing\": true }"),
				State:   "completed", Completion: "RetriesExhausted", InvokeCount: 1, ResponseStatus: 404,
			}
			delivery := lambda.OutcomeDeliveryRecord{ID: "legacy-delivery", InvocationID: invocation.ID, DestinationARN: queueARN, DeadLetter: true}
			if rejected := adapter.Send(root, invocation, delivery); rejected != nil {
				t.Fatalf("deleted target DLQ rejected: %v", rejected)
			}
			out, rejected := queues.ReceiveFromQueue(root, queueARN, &sqsapi.ReceiveMessageInput{MessageAttributeNames: sqsapi.MessageAttributeNameList{"All"}})
			if rejected != nil {
				t.Fatal(rejected)
			}
			if len(out.Messages) != 1 {
				t.Fatalf("missing deleted-target event: %+v", out)
			}
			message := out.Messages[0]
			if message.Body == nil || string(*message.Body) != string(invocation.Payload) {
				t.Fatalf("DLQ changed original payload bytes: %+v", message)
			}
			resource := invocation.FunctionARN
			if qualifier == "" {
				resource += ":$LATEST"
			}
			want := sqsapi.MessageBodyAttributeMap{
				"RequestID":    {DataType: new(sqsapi.String("String")), StringValue: new(sqsapi.String(invocation.RequestID))},
				"ErrorCode":    {DataType: new(sqsapi.String("Number")), StringValue: new(sqsapi.String("404"))},
				"ErrorMessage": {DataType: new(sqsapi.String("String")), StringValue: new(sqsapi.String("Function not found: " + resource))},
			}
			if !reflect.DeepEqual(message.MessageAttributes, want) {
				t.Fatalf("deleted-target DLQ attributes=%+v, want %+v", message.MessageAttributes, want)
			}
			// The pre-execution error projection must not bypass current delivery authority.
			f.role.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"` + queueARN + `"}}`
			f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
			if rejected := adapter.Send(root, invocation, delivery); rejected == nil || rejected.Code != "AccessDenied" {
				t.Fatalf("current DLQ denial ignored: %v", rejected)
			}
			out, rejected = queues.ReceiveFromQueue(root, queueARN, &sqsapi.ReceiveMessageInput{})
			if rejected != nil || len(out.Messages) != 0 {
				t.Fatalf("denied DLQ added a message: %+v, %v", out, rejected)
			}
		})
	}
}

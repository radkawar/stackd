package stackd_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// Empty-target completion is a real service transition, not an injected agent
// result. Official-agent invocation transitions are exercised by the guest smoke.
func TestSSMNotificationsAuthorityFiltersAndRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "123456789012"
			ctx := t.Context()
			cloud, clients, source, reopen := snsFeedbackCloud(t, backend)
			topics := clients.snsRegion("us-east-1", account, "test", "")
			commands := clients.ssm("us-east-1", account, "test")
			roles := clients.iam(account, "test", "")
			topic, err := topics.CreateTopic(ctx, &sns.CreateTopicInput{Name: new("ssm-notifications")})
			if err != nil {
				t.Fatal(err)
			}
			queues, queueURL, queueARN := snsControlQueue(t, clients, account, "ssm-notifications", *topic.TopicArn)
			snsControlSubscribe(t, topics, *topic.TopicArn, queueARN)
			trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ssm.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
			role, err := roles.CreateRole(ctx, &iam.CreateRoleInput{RoleName: new("ssm-notifications"), AssumeRolePolicyDocument: &trust})
			if err != nil {
				t.Fatal(err)
			}
			policy := func(effect string) {
				t.Helper()
				document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":%q,"Action":"sns:Publish","Resource":%q}]}`, effect, *topic.TopicArn)
				if _, e := roles.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: new("publish"), PolicyDocument: &document}); e != nil {
					t.Fatal(e)
				}
			}
			policy("Allow")
			input := func(kind ssmtypes.NotificationType, events ...ssmtypes.NotificationEvent) *ssm.SendCommandInput {
				return &ssm.SendCommandInput{DocumentName: new("AWS-RunShellScript"), Targets: []ssmtypes.Target{{Key: new("tag:no-such-node"), Values: []string{"none"}}}, Parameters: map[string][]string{"commands": {"true"}}, ServiceRoleArn: role.Role.Arn, NotificationConfig: &ssmtypes.NotificationConfig{NotificationArn: topic.TopicArn, NotificationType: kind, NotificationEvents: events}}
			}
			drain := func() {
				t.Helper()
				if _, e := cloud.RunDueJobs(ctx, 1000); e != nil {
					t.Fatal(e)
				}
			}
			receive := func() []map[string]any {
				t.Helper()
				drain()
				out, e := queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10})
				if e != nil {
					t.Fatal(e)
				}
				var values []map[string]any
				for _, message := range out.Messages {
					var envelope struct{ Message, Subject string }
					if e = json.Unmarshal([]byte(*message.Body), &envelope); e != nil {
						t.Fatal(e)
					}
					if envelope.Subject != "EC2 Run Command Notification us-east-1" {
						t.Fatalf("subject: %q", envelope.Subject)
					}
					var payload map[string]any
					if e = json.Unmarshal([]byte(envelope.Message), &payload); e != nil {
						t.Fatal(e)
					}
					values = append(values, payload)
					if _, e = queues.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: queueURL, ReceiptHandle: message.ReceiptHandle}); e != nil {
						t.Fatal(e)
					}
				}
				return values
			}
			_, key, secret := clients.user(t, account, "ssm-notification-caller")
			putUserPolicy(t, roles, "ssm-notification-caller", `{"Statement":[{"Effect":"Allow","Action":"ssm:SendCommand","Resource":"*"}]}`)
			caller := clients.ssm("us-east-1", key, secret)
			_, err = caller.SendCommand(ctx, input(ssmtypes.NotificationTypeCommand, ssmtypes.NotificationEventAll))
			assertAPIError(t, err, "AccessDeniedException")
			putUserPolicy(t, roles, "ssm-notification-caller", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"ssm:SendCommand","Resource":"*"},{"Effect":"Allow","Action":"iam:PassRole","Resource":%q,"Condition":{"StringEquals":{"iam:PassedToService":"ssm.amazonaws.com"}}}]}`, *role.Role.Arn))
			// Admission uses trust even when no instance resolves.
			badTrust := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
			if _, err = roles.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: role.Role.RoleName, PolicyDocument: &badTrust}); err != nil {
				t.Fatal(err)
			}
			_, err = caller.SendCommand(ctx, input(ssmtypes.NotificationTypeCommand, ssmtypes.NotificationEventAll))
			assertAPIError(t, err, "InvalidRole")
			if _, err = roles.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: role.Role.RoleName, PolicyDocument: &trust}); err != nil {
				t.Fatal(err)
			}
			// Current role denial retains the completion intent over a repository reopen.
			policy("Deny")
			admitted, err := caller.SendCommand(ctx, input(ssmtypes.NotificationTypeCommand))
			if err != nil {
				t.Fatal(err)
			}
			if got := receive(); len(got) != 0 {
				t.Fatalf("denied publish: %+v", got)
			}
			cloud = reopen()
			policy("Allow")
			if err = source.Advance(31 * time.Second); err != nil {
				t.Fatal(err)
			}
			got := receive()
			if len(got) != 1 || got[0]["commandId"] != aws.ToString(admitted.Command.CommandId) || got[0]["status"] != "Success" || got[0]["documentName"] != "AWS-RunShellScript" {
				t.Fatalf("recovered transition: %+v", got)
			}
			if ids, ok := got[0]["instanceIds"].([]any); !ok || len(ids) != 0 {
				t.Fatalf("tag target instance IDs: %+v", got)
			}
			// Pending and fabricated Invocation events must never be synthesized from a
			// command that targeted no nodes; a Failed-only filter suppresses Success.
			for _, request := range []*ssm.SendCommandInput{input(ssmtypes.NotificationTypeInvocation, ssmtypes.NotificationEventAll), input(ssmtypes.NotificationTypeCommand, ssmtypes.NotificationEventFailed)} {
				if _, err = commands.SendCommand(ctx, request); err != nil {
					t.Fatal(err)
				}
			}
			if got = receive(); len(got) != 0 {
				t.Fatalf("unobserved/filtered transitions: %+v", got)
			}
			// A current topic denial is independent of the role's identity grant.
			snsControlPolicy(t, topics, *topic.TopicArn, fmt.Sprintf(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sns:Publish","Resource":%q}]}`, *topic.TopicArn))
			admitted, err = commands.SendCommand(ctx, input(ssmtypes.NotificationTypeCommand, ssmtypes.NotificationEventSuccess))
			if err != nil {
				t.Fatal(err)
			}
			if got = receive(); len(got) != 0 {
				t.Fatalf("topic-denied publish: %+v", got)
			}
			snsControlPolicy(t, topics, *topic.TopicArn, fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sns:Publish","Resource":%q}]}`, account, *topic.TopicArn))
			if err = source.Advance(31 * time.Second); err != nil {
				t.Fatal(err)
			}
			got = receive()
			if len(got) != 1 || got[0]["commandId"] != aws.ToString(admitted.Command.CommandId) || got[0]["status"] != "Success" {
				t.Fatalf("topic recovery: %+v", got)
			}
			// Recreating an ARN cannot grant the old command the new role's authority.
			policy("Deny")
			if _, err = commands.SendCommand(ctx, input(ssmtypes.NotificationTypeCommand, ssmtypes.NotificationEventSuccess)); err != nil {
				t.Fatal(err)
			}
			if got = receive(); len(got) != 0 {
				t.Fatalf("pre-replacement denial: %+v", got)
			}
			if _, err = roles.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: new("publish")}); err != nil {
				t.Fatal(err)
			}
			if _, err = roles.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: role.Role.RoleName}); err != nil {
				t.Fatal(err)
			}
			replacement, err := roles.CreateRole(ctx, &iam.CreateRoleInput{RoleName: role.Role.RoleName, AssumeRolePolicyDocument: &trust})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(replacement.Role.RoleId) == aws.ToString(role.Role.RoleId) {
				t.Fatal("role incarnation did not change")
			}
			policy("Allow")
			if err = source.Advance(31 * time.Second); err != nil {
				t.Fatal(err)
			}
			if got = receive(); len(got) != 0 {
				t.Fatalf("old intent used a replacement role: %+v", got)
			}
		})
	}
}

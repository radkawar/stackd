package integrations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	schedulerapi "stackd/internal/awsapi/scheduler"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/iam"
	scheduler "stackd/internal/services/scheduler"
	"stackd/internal/services/sqs"
	"stackd/storage/memory"
)

func TestSchedulerCurrentExecutionRoleAndPassRole(t *testing.T) {
	domain := memory.NewDomain()
	now := time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC)
	c := clock.NewManual(now)
	repository := iam.NewMemoryRepository(domain)
	scope := iam.Scope{
		Partition: "aws",
		AccountID: "123456789012",
	}
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{
		Partition:    "aws",
		AccountID:    scope.AccountID,
		Region:       "us-east-1",
		PrincipalARN: "arn:aws:iam::123456789012:root",
	})
	role := iam.Role{
		Arn:                      "arn:aws:iam::123456789012:role/scheduler",
		RoleName:                 "scheduler",
		RoleId:                   "AROASCHEDULERTEST",
		MaxSessionDuration:       3600,
		AssumeRolePolicyDocument: `{"Statement":{"Effect":"Allow","Principal":{"Service":"scheduler.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:SourceArn":"arn:aws:scheduler:us-east-1:123456789012:schedule-group/default"},"StringEquals":{"aws:SourceAccount":"123456789012"}}}}`,
		IdentityPolicies:         iam.IdentityPolicies{Inline: map[string]string{"send": `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}}`}},
	}
	user := iam.User{
		Arn:              "arn:aws:iam::123456789012:user/deployer",
		UserName:         "deployer",
		UserId:           "AIDASCHEDULERTEST",
		IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"scheduler": `{"Statement":{"Effect":"Allow","Action":"scheduler:*","Resource":"*"}}`}},
	}
	update := func() {
		t.Helper()
		if err := repository.Update(root, func(tx iam.WriteTx) error {
			if err := tx.PutRole(scope, role); err != nil {
				return err
			}
			return tx.PutUser(scope, user)
		}); err != nil {
			t.Fatal(err)
		}
	}
	update()
	credentials := identity.NewWithConfig(identity.Config{
		AccountID:  scope.AccountID,
		Repository: iam.NewCredentialRepository(repository, nil),
		Clock:      c,
	})
	iamService := iam.NewWithConfig(iam.Config{
		Repository:  repository,
		Credentials: credentials,
		Clock:       c,
	})
	authorizer := authorization.NewWithClock(iamService, nil, c)
	roles := ServiceRoles{
		IAM:         iamService,
		Credentials: credentials,
		Authorizer:  authorizer,
	}
	queueService := sqs.NewWithConfig(sqs.Config{
		Repository: sqs.NewMemoryRepository(domain),
		Authorizer: authorizer,
		Clock:      c,
	})
	defer queueService.Close()
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sqs": queueService})
	adapter := &SchedulerTargets{
		Commands: commands,
		Roles:    roles,
	}
	schedules := scheduler.NewWithConfig(scheduler.Config{
		Repository: scheduler.NewMemoryRepository(domain),
		Authorizer: authorizer,
		Clock:      c,
		Delivery:   adapter,
		Roles:      adapter,
	})
	defer schedules.Close()
	commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{
		"sqs":       queueService,
		"scheduler": schedules,
	})
	call := func(ctx context.Context, service, operation string, input any) StepFunctionsCommandResult {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		out, rejected := commands.Call(ctx, service, operation, raw)
		if rejected != nil {
			t.Fatalf("%s:%s: %v (cause: %v)", service, operation, rejected, rejected.Cause)
		}
		return out
	}
	targetScope := awsctx.FromContext(root)
	targetScope.Region = "us-west-2"
	targetRoot := awsctx.WithMetadata(root, targetScope)
	queue := call(targetRoot, "sqs", "CreateQueue", map[string]any{"QueueName": "orders"}).Output.(*sqsapi.CreateQueueOutput)
	dlq := call(root, "sqs", "CreateQueue", map[string]any{"QueueName": "dead"}).Output.(*sqsapi.CreateQueueOutput)
	deployer := awsctx.WithMetadata(t.Context(), awsctx.Metadata{
		Partition:    "aws",
		AccountID:    scope.AccountID,
		Region:       "us-east-1",
		PrincipalARN: user.Arn,
		PrincipalID:  user.UserId,
		UserName:     user.UserName,
	})
	input := map[string]any{
		"Name":               "one",
		"ScheduleExpression": "at(2031-01-02T03:05:00)",
		"FlexibleTimeWindow": map[string]string{"Mode": "OFF"},
		"Target": map[string]any{
			"Arn":              "arn:aws:sqs:us-west-2:123456789012:orders",
			"RoleArn":          role.Arn,
			"Input":            "scheduled",
			"DeadLetterConfig": map[string]string{"Arn": "arn:aws:sqs:us-east-1:123456789012:dead"},
		},
	}
	raw, _ := json.Marshal(input)
	if _, rejected := commands.Call(deployer, "scheduler", "CreateSchedule", raw); rejected == nil || rejected.Code != "AccessDeniedException" {
		t.Fatalf("missing PassRole was not denied: %v", rejected)
	}
	user.IdentityPolicies.Inline["pass"] = `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/scheduler","Condition":{"StringEquals":{"iam:PassedToService":"scheduler.amazonaws.com"}}}}`
	update()
	call(deployer, "scheduler", "CreateSchedule", input)
	c.Advance(time.Minute)
	if _, err := schedules.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	received := call(targetRoot, "sqs", "ReceiveMessage", map[string]any{"QueueUrl": *queue.QueueUrl}).Output.(*sqsapi.ReceiveMessageOutput)
	if len(received.Messages) != 1 || string(*received.Messages[0].Body) != "scheduled" {
		t.Fatalf("real target effect missing: %#v", received.Messages)
	}
	input["Name"], input["ScheduleExpression"] = "two", "at(2031-01-02T03:06:00)"
	call(deployer, "scheduler", "CreateSchedule", input)
	role.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-west-2:123456789012:orders"}}`
	update()
	c.Advance(time.Minute)
	if _, err := schedules.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	dead := call(root, "sqs", "ReceiveMessage", map[string]any{
		"QueueUrl":              *dlq.QueueUrl,
		"MessageAttributeNames": []string{"All"},
	}).Output.(*sqsapi.ReceiveMessageOutput)
	if len(dead.Messages) != 1 || string(*dead.Messages[0].Body) != "scheduled" {
		t.Fatalf("current IAM denial did not route to real DLQ: %#v", dead.Messages)
	}
	if attr, ok := dead.Messages[0].MessageAttributes["ERROR_CODE"]; !ok || attr.StringValue == nil || string(*attr.StringValue) != "AccessDenied" {
		t.Fatalf("DLQ did not preserve target rejection: %#v", dead.Messages[0].MessageAttributes)
	}
	t.Run("ExcludedUppercaseOperation", func(t *testing.T) {
		receiveInput, err := json.Marshal(map[string]any{"QueueUrl": *queue.QueueUrl})
		if err != nil {
			t.Fatal(err)
		}
		input["Name"] = "bad-read"
		input["Target"] = map[string]string{
			"Arn":     "arn:aws:scheduler:::aws-sdk:sqs:ReceiveMessage",
			"RoleArn": role.Arn,
			"Input":   string(receiveInput),
		}
		raw, _ = json.Marshal(input)
		if _, rejected := commands.Call(deployer, "scheduler", "CreateSchedule", raw); rejected == nil || rejected.Code != "ValidationException" {
			t.Fatalf("universal receive must fail admission: %v", rejected)
		}
	})
	got := call(deployer, "scheduler", "GetSchedule", map[string]string{"Name": "two"}).Output.(*schedulerapi.GetScheduleOutput)
	if got.State == nil || string(*got.State) != "ENABLED" {
		t.Fatal("target failure changed the public schedule state")
	}
	t.Run("CodeBuildNullOverrides", func(t *testing.T) {
		call(root, "sqs", "DeleteMessage", map[string]any{"QueueUrl": *dlq.QueueUrl, "ReceiptHandle": *dead.Messages[0].ReceiptHandle})
		builds := codebuild.New(codebuild.Config{Repository: codebuild.NewMemoryRepository(domain), Authorizer: authorizer, Clock: c})
		defer builds.Close()
		adapter.Commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sqs": queueService, "codebuild": builds})
		call(deployer, "scheduler", "CreateSchedule", map[string]any{
			"Name":               "null-build",
			"ScheduleExpression": "at(2031-01-02T03:07:00)",
			"FlexibleTimeWindow": map[string]string{"Mode": "OFF"},
			"Target": map[string]any{
				"Arn":              "arn:aws:codebuild:us-east-1:123456789012:project/unconfigured",
				"RoleArn":          role.Arn,
				"Input":            "null",
				"DeadLetterConfig": map[string]string{"Arn": "arn:aws:sqs:us-east-1:123456789012:dead"},
			},
		})
		c.Advance(time.Minute)
		if _, err := schedules.JobDriver().RunDue(t.Context(), 100); err != nil {
			t.Fatal(err)
		}
		rejected := call(root, "sqs", "ReceiveMessage", map[string]any{
			"QueueUrl":              *dlq.QueueUrl,
			"MessageAttributeNames": []string{"All"},
		}).Output.(*sqsapi.ReceiveMessageOutput)
		if len(rejected.Messages) != 1 || string(*rejected.Messages[0].Body) != "null" {
			t.Fatalf("invalid CodeBuild overrides did not reach actual DLQ: %#v", rejected.Messages)
		}
		code := rejected.Messages[0].MessageAttributes["ERROR_CODE"].StringValue
		if code == nil || string(*code) != "ValidationException" {
			t.Fatalf("invalid CodeBuild overrides did not retain validation failure: %v", code)
		}
	})
}

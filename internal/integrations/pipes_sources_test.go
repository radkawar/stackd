package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/pipes"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/pipes"
	"stackd/internal/services/sqs"
	"stackd/storage/sqlite"
	sqliam "stackd/storage/sqlite/iam"
	sqlpipes "stackd/storage/sqlite/pipes"
	sqlsqs "stackd/storage/sqlite/sqs"
)

// All effects below go through real IAM and SQS owners. No source consumer,
// receipt, target response or checkpoint is substituted by a test double.
func TestPipesQueueFilteringCurrentRoleAndSQLiteRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipes.sqlite")
	sourceClock := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
	var db *sql.DB
	var iamRepository *sqliam.Repository
	var pipeRepository *sqlpipes.Repository
	var queueService *sqs.Service
	var pipeService *pipes.Service
	var commands StepFunctionsCommands
	var targetGate *pipesCompletionGate
	open := func() {
		t.Helper()
		var err error
		db, err = sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		iamRepository = sqliam.New(db)
		pipeRepository = sqlpipes.New(db)
		credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(iamRepository, nil), Clock: sourceClock})
		iamService := iam.NewWithConfig(iam.Config{Repository: iamRepository, Credentials: credentials, Clock: sourceClock})
		authorizer := authorization.NewWithClock(iamService, nil, sourceClock)
		roles := ServiceRoles{IAM: iamService, Credentials: credentials, Authorizer: authorizer}
		queueService = sqs.NewWithConfig(sqs.Config{Repository: sqlsqs.New(db), Authorizer: authorizer, Clock: sourceClock})
		target := &PipesTargets{Roles: roles}
		targetGate = &pipesCompletionGate{Targets: target}
		pipeService = pipes.NewWithConfig(pipes.Config{
			Repository: pipeRepository,
			Authorizer: authorizer,
			Clock:      sourceClock,
			Sources:    &PipesSources{Roles: roles, Queues: queueService},
			Targets:    targetGate,
		})
		commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sqs": queueService, "pipes": pipeService})
		target.Commands = commands
	}
	closeCloud := func() {
		t.Helper()
		if err := pipeService.Close(); err != nil {
			t.Fatal(err)
		}
		queueService.Close()
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	open()
	defer func() {
		closeCloud()
	}()
	role := iam.Role{
		Arn:                      "arn:aws:iam::123456789012:role/pipes",
		RoleName:                 "pipes",
		RoleId:                   "AROAPIPESINTEGRATION",
		MaxSessionDuration:       3600,
		AssumeRolePolicyDocument: `{"Statement":{"Effect":"Allow","Principal":{"Service":"pipes.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:SourceArn":"arn:aws:pipes:us-east-1:123456789012:pipe/orders"},"StringEquals":{"aws:SourceAccount":"123456789012"}}}}`,
		IdentityPolicies:         iam.IdentityPolicies{Inline: map[string]string{"queue": `{"Statement":{"Effect":"Allow","Action":["sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes","sqs:SendMessage"],"Resource":"*"}}`}},
	}
	updateRole := func() {
		t.Helper()
		if err := iamRepository.Update(root, func(tx iam.WriteTx) error {
			return tx.PutRole(iam.Scope{Partition: "aws", AccountID: "123456789012"}, role)
		}); err != nil {
			t.Fatal(err)
		}
	}
	updateRole()
	call := func(service, operation string, input any) StepFunctionsCommandResult {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		out, rejected := commands.Call(root, service, operation, raw)
		if rejected != nil {
			t.Fatalf("%s.%s: %v", service, operation, rejected)
		}
		return out
	}
	source := call("sqs", "CreateQueue", map[string]any{"QueueName": "source", "Attributes": map[string]string{"VisibilityTimeout": "2"}}).Output.(*sqsapi.CreateQueueOutput)
	destination := call("sqs", "CreateQueue", map[string]any{"QueueName": "target"}).Output.(*sqsapi.CreateQueueOutput)
	call("pipes", "CreatePipe", map[string]any{
		"Name":         "orders",
		"RoleArn":      role.Arn,
		"Source":       "arn:aws:sqs:us-east-1:123456789012:source",
		"Target":       "arn:aws:sqs:us-east-1:123456789012:target",
		"DesiredState": "STOPPED",
		"SourceParameters": map[string]any{
			"SqsQueueParameters": map[string]any{"BatchSize": 1},
			"FilterCriteria":     map[string]any{"Filters": []any{map[string]any{"Pattern": `{"body":{"keep":[true]}}`}}},
		},
		"TargetParameters": map[string]any{"InputTemplate": `{"value":<$.body.value>}`},
	})
	eventually := func(check func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := pipeService.JobDriver().RunDue(t.Context(), 64); err != nil {
				t.Fatal(err)
			}
			if check() {
				return
			}
			time.Sleep(time.Millisecond)
		}
		pipeRepository.View(context.Background(), func(r pipes.Reader) error {
			all, err := r.Pipes()
			if err != nil {
				return err
			}
			for _, p := range all {
				work, err := r.Work(p.ID)
				t.Logf("pipe state=%s due=%s now=%s reason=%s work=%+v error=%v", p.State, p.Due, sourceClock.Now(), p.Reason, work, err)
			}
			return nil
		})
		t.Fatal("Pipes state did not converge")
	}
	state := func(expected string) bool {
		out := call("pipes", "DescribePipe", map[string]string{"Name": "orders"}).Output.(*api.DescribePipeOutput)
		return pipesValue(out.CurrentState) == expected
	}
	eventually(func() bool {
		return state("STOPPED")
	})
	send := func(body string) {
		call("sqs", "SendMessage", map[string]any{"QueueUrl": *source.QueueUrl, "MessageBody": body})
	}
	attributes := func(url *sqsapi.String) map[sqsapi.QueueAttributeName]sqsapi.String {
		return call("sqs", "GetQueueAttributes", map[string]any{"QueueUrl": *url, "AttributeNames": []string{"ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"}}).Output.(*sqsapi.GetQueueAttributesOutput).Attributes
	}
	send(`{"keep":true,"value":7}`)
	send(`{"keep":false,"value":9}`)
	sourceClock.Advance(time.Second)
	if _, err := pipeService.JobDriver().RunDue(t.Context(), 64); err != nil {
		t.Fatal(err)
	}
	if got := attributes(source.QueueUrl); got["ApproximateNumberOfMessages"] != "2" || got["ApproximateNumberOfMessagesNotVisible"] != "0" {
		t.Fatalf("stopped pipe acquired source messages: %#v", got)
	}
	call("pipes", "StartPipe", map[string]string{"Name": "orders"})
	eventually(func() bool {
		return attributes(source.QueueUrl)["ApproximateNumberOfMessages"] == "0" && attributes(source.QueueUrl)["ApproximateNumberOfMessagesNotVisible"] == "0"
	})
	received := call("sqs", "ReceiveMessage", map[string]any{"QueueUrl": *destination.QueueUrl}).Output.(*sqsapi.ReceiveMessageOutput)
	if len(received.Messages) != 1 || pipesValue(received.Messages[0].Body) != `{"value":7}` {
		t.Fatalf("real filtered transformation missing: %#v", received.Messages)
	}
	role.IdentityPolicies.Inline["deny-target"] = `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123456789012:target"}}`
	updateRole()
	send(`{"keep":true,"value":11}`)
	sourceClock.Advance(time.Second)
	eventually(func() bool {
		waiting := false
		err := pipeRepository.View(context.Background(), func(r pipes.Reader) error {
			all, err := r.Pipes()
			if err != nil {
				return err
			}
			rows, err := r.Work(all[0].ID)
			if err != nil {
				return err
			}
			for _, w := range rows {
				waiting = waiting || w.Phase == "waiting"
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return waiting
	})
	call("pipes", "StopPipe", map[string]string{"Name": "orders"})
	eventually(func() bool {
		return state("STOPPED")
	})
	closeCloud()
	open()
	sourceClock.Advance(3 * time.Second)
	if _, err := pipeService.JobDriver().RunDue(t.Context(), 64); err != nil {
		t.Fatal(err)
	}
	if got := attributes(source.QueueUrl); got["ApproximateNumberOfMessages"] != "1" {
		t.Fatalf("restart consumed stopped work: %#v", got)
	}
	delete(role.IdentityPolicies.Inline, "deny-target")
	updateRole()
	call("pipes", "StartPipe", map[string]string{"Name": "orders"})
	eventually(func() bool {
		return attributes(source.QueueUrl)["ApproximateNumberOfMessages"] == "0" && attributes(source.QueueUrl)["ApproximateNumberOfMessagesNotVisible"] == "0"
	})
	received = call("sqs", "ReceiveMessage", map[string]any{"QueueUrl": *destination.QueueUrl, "MaxNumberOfMessages": 10}).Output.(*sqsapi.ReceiveMessageOutput)
	found := false
	for _, message := range received.Messages {
		found = found || pipesValue(message.Body) == `{"value":11}`
	}
	if !found {
		t.Fatalf("retained denied work was not retried after restart: %#v", received.Messages)
	}

	// Hold a real successful target result across StopPipe's transition. This
	// controls timing only: both the receipt and target response are genuine.
	reached, release := targetGate.hold()
	defer release()
	send(`{"keep":true,"value":13}`)
	sourceClock.Advance(time.Second)
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("real target did not reach its completion gate")
	}
	call("pipes", "StopPipe", map[string]string{"Name": "orders"})
	if !state("STOPPING") {
		t.Fatal("pipe stopped while its target result was still in flight")
	}
	// Join any acquisition that was already in progress when StopPipe won.
	if _, err := pipeService.JobDriver().RunDue(t.Context(), 64); err != nil {
		t.Fatal(err)
	}
	send(`{"keep":true,"value":17}`)
	release()
	sourceClock.Advance(time.Second)
	eventually(func() bool { return state("STOPPED") })
	if got := attributes(source.QueueUrl); got["ApproximateNumberOfMessages"] != "1" || got["ApproximateNumberOfMessagesNotVisible"] != "0" {
		t.Fatalf("stopping failed to acknowledge success or acquired fresh work: %#v", got)
	}
	received = call("sqs", "ReceiveMessage", map[string]any{"QueueUrl": *destination.QueueUrl, "MaxNumberOfMessages": 10}).Output.(*sqsapi.ReceiveMessageOutput)
	if len(received.Messages) != 1 || pipesValue(received.Messages[0].Body) != `{"value":13}` {
		t.Fatalf("stopping replayed success or delivered fresh work: %#v", received.Messages)
	}
}

// pipesCompletionGate delays only the return of a genuine target operation;
// it neither fabricates responses nor replaces destination authorization.
type pipesCompletionGate struct {
	pipes.Targets
	mu      sync.Mutex
	reached chan struct{}
	release chan struct{}
}

func (g *pipesCompletionGate) hold() (<-chan struct{}, func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reached, g.release = make(chan struct{}), make(chan struct{})
	release := g.release
	return g.reached, sync.OnceFunc(func() { close(release) })
}

func (g *pipesCompletionGate) Deliver(ctx context.Context, p pipes.PipeRecord, work []pipes.Work, events []pipes.TargetEvent, dlq bool) (pipes.DeliveryResult, *awswire.Error) {
	result, rejected := g.Targets.Deliver(ctx, p, work, events, dlq)
	g.mu.Lock()
	reached, release := g.reached, g.release
	g.reached, g.release = nil, nil
	g.mu.Unlock()
	if reached != nil {
		close(reached)
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	return result, rejected
}

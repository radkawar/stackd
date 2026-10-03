package ssmcommands_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	commands "stackd/internal/services/ssmcommands"
	"stackd/internal/services/ssmdocuments"
	"stackd/internal/services/ssmmessages"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	commanddb "stackd/storage/sqlite/ssmcommands"
	documentdb "stackd/storage/sqlite/ssmdocuments"
)

// This fixture exercises the state machine, not the external agent. The separate
// CLI/guest workflow executes actual plugins; current IAM is exercised there and
// by signed integration tests. No test adapter executes customer programs.
type allowStateMachine struct{}

func (allowStateMachine) Authorize(context.Context, authorization.Request) *awswire.Error { return nil }

type instances map[string]commands.Instance

func (i instances) Instance(_ context.Context, id string) (commands.Instance, error) {
	v, ok := i[id]
	if !ok {
		return v, commands.ErrNotFound
	}
	return v, nil
}

type fixture struct {
	s         *commands.Service
	repo      commands.Repository
	docs      *ssmdocuments.Service
	clock     *clock.Manual
	root      context.Context
	agents    map[string]context.Context
	instances instances
	reopen    func()
}

func fixtures(t *testing.T, run func(*testing.T, *fixture)) {
	t.Helper()
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := &fixture{clock: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)), agents: map[string]context.Context{}, instances: instances{}}
			f.root = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111122223333", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalID: "111122223333", AccessKeyID: "111122223333"})
			creds := identity.NewWithConfig(identity.Config{AccountID: "111122223333", Repository: identity.NewMemoryRepository(), Clock: f.clock})
			var db *sql.DB
			var documentRepo ssmdocuments.Repository
			domain := memory.NewDomain()
			path := filepath.Join(t.TempDir(), "commands.db")
			f.reopen = func() {
				if f.s != nil {
					_ = f.s.Close()
				}
				if backend == "sqlite" {
					if db != nil {
						_ = db.Close()
					}
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					f.repo = commanddb.New(db)
					documentRepo = documentdb.New(db)
				} else if f.repo == nil {
					f.repo = commands.NewMemoryRepository(domain)
					documentRepo = ssmdocuments.NewMemoryRepository(domain)
				}
				f.docs = ssmdocuments.New(ssmdocuments.Config{Repository: documentRepo, Clock: f.clock, Authorizer: allowStateMachine{}})
				f.s = commands.New(commands.Config{Repository: f.repo, Documents: f.docs, Clock: f.clock, Authorizer: allowStateMachine{}, Instances: f.instances, Credentials: creds})
			}
			f.reopen()
			t.Cleanup(func() {
				_ = f.s.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			for n := 1; n <= 3; n++ {
				id := fmt.Sprintf("i-%017x", n)
				f.instances[id] = commands.Instance{ID: id, State: "running", Tags: map[string]string{"team": "compute"}}
				c, err := creds.IssueServiceRoleSession(t.Context(), identity.RoleSessionSpec{
					Role:        identity.Principal{AccountID: "111122223333", ARN: "arn:aws:iam::111122223333:role/agent", ID: "AROAAGENT"},
					SessionName: id, Duration: time.Hour,
					InScopeOf: journal.APIIdentityScope{IssuerType: "AWS::EC2::Instance", CredentialsIssuedTo: "arn:aws:ec2:us-east-1:111122223333:instance/" + id},
				})
				if err != nil {
					t.Fatal(err)
				}
				m, err := identity.RequestMetadata(c, c.AccessKeyID, "us-east-1", "agent-request")
				if err != nil {
					t.Fatal(err)
				}
				f.agents[id] = awsctx.WithMetadata(t.Context(), m)
				if err = f.repo.Update(f.root, func(tx commands.Transaction) error {
					return tx.PutNode(commands.Node{Key: commands.Key{Scope: commands.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, ID: id}, RegisteredAt: f.clock.Now(), LastPing: f.clock.Now(), PlatformType: "Linux"})
				}); err != nil {
					t.Fatal(err)
				}
			}
			run(t, f)
		})
	}
}
func call(t *testing.T, f *fixture, action string, input any) any {
	t.Helper()
	model, _ := awscatalog.LookupService("ssm")
	op, _ := model.Operation(action)
	out, err := f.s.ExecuteCommand(f.root, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func send(t *testing.T, f *fixture, limit, errors string, ids ...string) string {
	t.Helper()
	in := &api.SendCommandRequest{DocumentName: new(api.DocumentARN("AWS-RunShellScript")), Parameters: api.Parameters{"commands": {"echo actual-agent-only"}, "executionTimeout": {"5"}}, MaxConcurrency: new(api.MaxConcurrency(limit)), MaxErrors: new(api.MaxErrors(errors)), TimeoutSeconds: new(api.TimeoutSeconds(30))}
	for _, id := range ids {
		in.InstanceIds = append(in.InstanceIds, api.InstanceId(id))
	}
	return string(*call(t, f, "SendCommand", in).(*api.SendCommandResult).Command.CommandId)
}
func pending(t *testing.T, f *fixture, node string) []ssmmessages.Message {
	t.Helper()
	out, err := f.s.PendingMessages(f.agents[node], node)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func receive(t *testing.T, f *fixture, node string, message ssmmessages.Message) {
	t.Helper()
	if err := f.s.ReceiveMessage(f.agents[node], node, message); err != nil {
		t.Fatal(err)
	}
}
func reply(t *testing.T, command, node, status string, code int32, stdout, stderr string) ssmmessages.Message {
	t.Helper()
	result := map[string]any{"documentStatus": status, "runtimeStatus": map[string]any{"aws:runShellScript": map[string]any{"status": status, "code": code, "name": "aws:runShellScript", "output": stdout + stderr, "standardOutput": stdout, "standardError": stderr, "startDateTime": "2031-01-02T03:04:05.000Z", "endDateTime": "2031-01-02T03:04:06.000Z"}}}
	content, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"schemaVersion": 1, "jobId": "aws.ssm." + command + "." + node, "topic": "aws.ssm.sendCommand", "content": string(content)})
	if err != nil {
		t.Fatal(err)
	}
	return ssmmessages.Message{ID: uuid.New(), Type: "agent_job_reply", Payload: payload}
}
func invocation(t *testing.T, f *fixture, command, node string) *api.GetCommandInvocationResult {
	t.Helper()
	return call(t, f, "GetCommandInvocation", &api.GetCommandInvocationRequest{CommandId: new(api.CommandId(command)), InstanceId: new(api.InstanceId(node))}).(*api.GetCommandInvocationResult)
}
func TestConcurrentDeliveryHonorsErrorBudgetAndNeverExecutesTerminatedTargets(t *testing.T) {
	fixtures(t, func(t *testing.T, f *fixture) {
		ids := []string{"i-00000000000000001", "i-00000000000000002", "i-00000000000000003"}
		command := send(t, f, "1", "0", ids...)
		var wg sync.WaitGroup
		var mu sync.Mutex
		delivered := map[string][]ssmmessages.Message{}
		failures := make(chan error, len(ids))
		for _, id := range ids {
			wg.Go(func() {
				out, err := f.s.PendingMessages(f.agents[id], id)
				if err != nil {
					failures <- err
					return
				}
				mu.Lock()
				delivered[id] = out
				mu.Unlock()
			})
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
		winner := ""
		count := 0
		for id, msgs := range delivered {
			count += len(msgs)
			if len(msgs) > 0 {
				winner = id
			}
		}
		if count != 1 {
			t.Fatalf("concurrency1 delivered %d distinct node jobs", count)
		}
		receive(t, f, winner, reply(t, command, winner, "Failed", 7, "customer-out\n", "exit status 7"))
		for _, id := range ids {
			if msgs := pending(t, f, id); len(msgs) != 0 {
				t.Fatalf("error budget exceeded but %s received a job", id)
			}
			got := invocation(t, f, command, id)
			if id == winner {
				if string(*got.Status) != "Failed" || *got.ResponseCode != 7 || string(*got.StandardErrorContent) != "exit status 7" {
					t.Fatalf("lost real failure: %+v", got)
				}
			} else if string(*got.Status) != "Cancelled" || string(*got.StatusDetails) != "Terminated" {
				t.Fatalf("undelivered node not terminated: %+v", got)
			}
		}
		parent := call(t, f, "ListCommands", &api.ListCommandsRequest{CommandId: new(api.CommandId(command))}).(*api.ListCommandsResult).Commands[0]
		if string(*parent.Status) != "Failed" || *parent.ErrorCount != 1 || *parent.CompletedCount != 3 {
			t.Fatalf("wrong aggregate: %+v", parent)
		}
	})
}
func TestReconnectDuplicateReplyAndCompletedSideEffectFence(t *testing.T) {
	fixtures(t, func(t *testing.T, f *fixture) {
		node := "i-00000000000000001"
		command := send(t, f, "1", "0", node)
		first := pending(t, f, node)
		if len(first) != 1 {
			t.Fatal(first)
		}
		f.clock.Advance(10 * time.Second)
		again := pending(t, f, node)
		if len(again) != 1 || again[0].ID != first[0].ID || !reflect.DeepEqual(again[0].Payload, first[0].Payload) {
			t.Fatal("retry changed durable delivery identity")
		}
		terminal := reply(t, command, node, "Success", 0, "one side effect\n", "")
		receive(t, f, node, terminal)
		f.reopen()
		receive(t, f, node, terminal)
		late := reply(t, command, node, "InProgress", 0, "stale", "")
		receive(t, f, node, late)
		f.clock.Advance(10 * time.Second)
		if out := pending(t, f, node); len(out) != 0 {
			t.Fatal("completed command was redelivered")
		}
		got := invocation(t, f, command, node)
		if string(*got.Status) != "Success" || string(*got.StandardOutputContent) != "one side effect\n" {
			t.Fatalf("late duplicate rewrote terminal result: %+v", got)
		}
		if err := f.s.ReceiveMessage(f.agents["i-00000000000000002"], node, terminal); err == nil {
			t.Fatal("foreign credential origin can commit node result")
		}
	})
}
func TestAcknowledgedWorkExpiresOnlyWithoutTerminalAgentReply(t *testing.T) {
	fixtures(t, func(t *testing.T, f *fixture) {
		node := "i-00000000000000001"
		command := send(t, f, "1", "0", node)
		msg := pending(t, f, node)[0]
		payload, _ := json.Marshal(map[string]string{"jobId": "aws.ssm." + command + "." + node, "acknowledgedMessageId": msg.ID.String(), "statusCode": "200"})
		receive(t, f, node, ssmmessages.Message{ID: uuid.New(), Type: "agent_job_ack", Payload: payload})
		f.reopen()
		if msgs := pending(t, f, node); len(msgs) != 0 {
			t.Fatal("acknowledged work redelivered")
		}
		f.clock.Advance(35 * time.Second)
		if _, err := f.s.JobDriver().RunDue(t.Context(), 20); err != nil {
			t.Fatal(err)
		}
		got := invocation(t, f, command, node)
		if string(*got.Status) != "TimedOut" || string(*got.StatusDetails) != "DeliveryTimedOut" || *got.ResponseCode != -1 {
			t.Fatalf("missing reply did not delivery-timeout: %+v", got)
		}
		// A terminal execution-timeout signal has a distinct failure budget outcome.
		command = send(t, f, "1", "0", node)
		pending(t, f, node)
		receive(t, f, node, reply(t, command, node, "TimedOut", 137, "before-timeout\n", ""))
		parent := call(t, f, "ListCommands", &api.ListCommandsRequest{CommandId: new(api.CommandId(command))}).(*api.ListCommandsResult).Commands[0]
		if string(*parent.Status) != "Failed" || *parent.ErrorCount != 1 || *parent.DeliveryTimedOutCount != 0 {
			t.Fatalf("execution timeout aggregate differs from native fixture: %+v", parent)
		}
	})
}
func TestCancellationDistinguishesQueuedFromAgentExecutingWork(t *testing.T) {
	fixtures(t, func(t *testing.T, f *fixture) {
		node := "i-00000000000000001"
		command := send(t, f, "1", "0", node)
		call(t, f, "CancelCommand", &api.CancelCommandRequest{CommandId: new(api.CommandId(command))})
		if got := invocation(t, f, command, node); string(*got.Status) != "Cancelled" || *got.ResponseCode != -1 {
			t.Fatal(got)
		}
		if len(pending(t, f, node)) != 0 {
			t.Fatal("cancelled queued work delivered")
		}
		command = send(t, f, "1", "0", node)
		first := pending(t, f, node)[0]
		call(t, f, "CancelCommand", &api.CancelCommandRequest{CommandId: new(api.CommandId(command))})
		cancel := pending(t, f, node)
		if len(cancel) != 1 || cancel[0].ID == first.ID {
			t.Fatal("cancellation did not get separate durable message identity")
		}
		var job struct{ Content, Topic string }
		if err := json.Unmarshal(cancel[0].Payload, &job); err != nil {
			t.Fatal(err)
		}
		var payload struct {
			CancelMessageID string `json:"CancelMessageId"`
		}
		if err := json.Unmarshal([]byte(job.Content), &payload); err != nil {
			t.Fatal(err)
		}
		if job.Topic != "aws.ssm.cancelCommand" || payload.CancelMessageID != "aws.ssm."+command+"."+node {
			t.Fatal("cancellation targets wrong job")
		}
		receive(t, f, node, reply(t, command, node, "Cancelled", 137, "before-cancel\n", ""))
		got := invocation(t, f, command, node)
		if string(*got.Status) != "Cancelled" || *got.ResponseCode != 137 || string(*got.StandardOutputContent) != "before-cancel\n" {
			t.Fatal(got)
		}
	})
}

func TestAgentAuthorityIsBoundToIssuedInstanceAndCurrentLifetime(t *testing.T) {
	fixtures(t, func(t *testing.T, f *fixture) {
		first, second := "i-00000000000000001", "i-00000000000000002"
		ctx := f.agents[first]
		action := "ssmmessages:OpenControlChannel"
		if err := f.s.AuthorizeAgent(ctx, first, action); err != nil {
			t.Fatal(err)
		}
		rejected := func(node, code string) {
			t.Helper()
			err := f.s.AuthorizeAgent(ctx, node, action)
			wire, ok := err.(*awswire.Error)
			if !ok || wire.Code != code {
				t.Fatalf("node %s: %v; want %s", node, err, code)
			}
		}
		rejected(second, "AccessDeniedException")
		node := f.instances[first]
		node.State = "stopped"
		f.instances[first] = node
		rejected(first, "InvalidInstanceId")
		node.State = "running"
		f.instances[first] = node
		if err := f.clock.Advance(time.Hour); err != nil {
			t.Fatal(err)
		}
		rejected(first, "AccessDeniedException")
	})
}

func TestTerminalDocumentReplyDoesNotDiscardLaterPluginResult(t *testing.T) {
	fixtures(t, func(t *testing.T, f *fixture) {
		node := "i-00000000000000001"
		command := send(t, f, "1", "0", node)
		pending(t, f, node)
		// Observed with official agent 3.3.5226.0: an empty Failed document
		// reply overtakes its InProgress envelope carrying a Failed plugin.
		completion := reply(t, command, node, "Failed", 9, "", "")
		alter := func(message ssmmessages.Message, empty bool) ssmmessages.Message {
			t.Helper()
			var envelope map[string]any
			if err := json.Unmarshal(message.Payload, &envelope); err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			if err := json.Unmarshal([]byte(envelope["content"].(string)), &result); err != nil {
				t.Fatal(err)
			}
			if empty {
				result["runtimeStatus"] = map[string]any{}
			} else {
				result["documentStatus"] = "InProgress"
			}
			content, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			envelope["content"] = string(content)
			message.Payload, err = json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			return message
		}
		receive(t, f, node, alter(completion, true))
		f.reopen()
		receive(t, f, node, alter(reply(t, command, node, "Failed", 9, "retained-out\n", "retained-error\n"), false))
		out := invocation(t, f, command, node)
		if string(*out.Status) != "Failed" || *out.ResponseCode != 9 || string(*out.StandardOutputContent) != "retained-out\n" || string(*out.StandardErrorContent) != "retained-error\n" {
			t.Fatalf("late plugin outcome was lost: %#v", out)
		}
		commandsOut := call(t, f, "ListCommands", &api.ListCommandsRequest{CommandId: new(api.CommandId(command))}).(*api.ListCommandsResult)
		if string(*commandsOut.Commands[0].Status) != "Failed" || *commandsOut.Commands[0].ErrorCount != 1 {
			t.Fatalf("late InProgress envelope reopened terminal command: %#v", commandsOut.Commands[0])
		}
	})
}

func TestEmptyTargetCommandLifecycleSurvivesRestartAndCancellation(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancel), func(t *testing.T) {
			fixtures(t, func(t *testing.T, f *fixture) {
				// Stop automatic draining so admission and pre-job cancellation are
				// deterministic. Reopening recovers the same persisted job.
				f.s.JobDriver().Close()
				admittedAt := f.clock.Now()
				out := call(t, f, "SendCommand", &api.SendCommandRequest{
					DocumentName: new(api.DocumentARN("AWS-RunShellScript")),
					Parameters:   api.Parameters{"commands": {"printf must-not-execute"}},
					Targets:      []api.Target{{Key: new(api.TargetKey("tag:absent")), Values: []api.TargetValue{"owned"}}},
				}).(*api.SendCommandResult).Command
				id := string(*out.CommandId)
				if string(*out.Status) != "Pending" || string(*out.StatusDetails) != "Pending" || *out.TargetCount != 0 {
					t.Fatalf("empty-target admission differs from native Pending: %+v", out)
				}
				key := commands.Key{Scope: commands.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, ID: id}
				if err := f.repo.View(f.root, func(r commands.Reader) error {
					stored, err := r.Command(key)
					if err != nil {
						return err
					}
					if stored.Status != "Pending" || stored.StatusDetails != "Pending" || !stored.EmptyTargetReadyAt.Equal(admittedAt) || !stored.DeliveryDeadline.Equal(*out.ExpiresAfter) {
						t.Fatalf("admission state or independent expiry lost: %+v", stored)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if cancel {
					call(t, f, "CancelCommand", &api.CancelCommandRequest{CommandId: out.CommandId})
				}
				f.reopen()
				drained, err := f.s.JobDriver().RunDue(t.Context(), 2)
				if err != nil {
					t.Fatal(err)
				}
				wantProcessed := 1
				wantStatus, wantDetails := "Success", "NoInstancesInTag"
				if cancel {
					wantProcessed, wantStatus, wantDetails = 0, "Cancelled", "Cancelled"
				}
				if drained.Processed != wantProcessed || drained.More || drained.Next != nil || !f.clock.Now().Equal(admittedAt) {
					t.Fatalf("recovered job did not consume exactly once at service time: %+v", drained)
				}
				got := call(t, f, "ListCommands", &api.ListCommandsRequest{CommandId: out.CommandId}).(*api.ListCommandsResult).Commands[0]
				if string(*got.Status) != wantStatus || string(*got.StatusDetails) != wantDetails || *got.TargetCount != 0 || *got.CompletedCount != 0 || *got.ErrorCount != 0 || *got.DeliveryTimedOutCount != 0 || !got.ExpiresAfter.Equal(*out.ExpiresAfter) {
					t.Fatalf("wrong empty-target terminal outcome: %+v", got)
				}
				invs := call(t, f, "ListCommandInvocations", &api.ListCommandInvocationsRequest{CommandId: out.CommandId}).(*api.ListCommandInvocationsResult)
				if len(invs.CommandInvocations) != 0 {
					t.Fatal("empty-target command manufactured an invocation")
				}
				for node := range f.agents {
					if msgs := pending(t, f, node); len(msgs) != 0 {
						t.Fatalf("empty-target command delivered work to %s: %+v", node, msgs)
					}
				}
				// Repeated cancellation and expiry cannot reopen a terminal job.
				call(t, f, "CancelCommand", &api.CancelCommandRequest{CommandId: out.CommandId})
				if err := f.clock.Advance(out.ExpiresAfter.Sub(f.clock.Now()) + time.Second); err != nil {
					t.Fatal(err)
				}
				if drained, err := f.s.JobDriver().RunDue(t.Context(), 2); err != nil || drained.Processed != 0 || drained.More || drained.Next != nil {
					t.Fatalf("terminal empty command kept scheduling: %+v %v", drained, err)
				}
				if err := f.repo.View(f.root, func(r commands.Reader) error {
					stored, err := r.Command(key)
					if err != nil {
						return err
					}
					if stored.Status != wantStatus || stored.StatusDetails != wantDetails || !stored.EmptyTargetReadyAt.IsZero() {
						t.Fatalf("terminal empty-target command resurrected: %+v", stored)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

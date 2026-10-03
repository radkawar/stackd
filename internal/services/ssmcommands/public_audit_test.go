package ssmcommands_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ssm"
	commands "stackd/internal/services/ssmcommands"
	"stackd/internal/services/ssmdocuments"
	"stackd/internal/services/ssmfrontend"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	journaldb "stackd/storage/sqlite/journal"
	commanddb "stackd/storage/sqlite/ssmcommands"
)

func TestPublicCommandAuditPreservesAPIData(t *testing.T) {
	type nativeCall struct {
		Label, Operation, Code string
		Input, Output          json.RawMessage
	}
	var source struct {
		Account, Region string
		Calls           []nativeCall
	}
	var control struct{ Calls []nativeCall }
	var audit struct {
		History struct {
			Events []struct {
				Label string `json:"call_label"`
				Event json.RawMessage
			}
		}
	}
	for name, target := range map[string]any{"managed_execution_current.json": &source, "managed_execution_control_edges.json": &control, "managed_execution_audit.json": &audit} {
		raw, err := os.ReadFile("../../../testdata/aws/ssm/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatal(err)
		}
	}
	calls := map[string]nativeCall{}
	for _, row := range source.Calls {
		calls[row.Label] = row
	}
	for _, row := range control.Calls {
		calls["control:"+row.Label] = row
	}
	expected := map[string]json.RawMessage{}
	for _, row := range audit.History.Events {
		label := strings.TrimPrefix(row.Label, "managed_execution_current.json:")
		label = strings.Replace(label, "managed_execution_control_edges.json:", "control:", 1)
		expected[label] = row.Event
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			domain := memory.NewDomain()
			var repo commands.Repository = commands.NewMemoryRepository(domain)
			var history journal.Storage = journal.NewMemory(domain)
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "public-audit.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo, history = commanddb.New(db), journaldb.New(db)
			}
			var nativeSend api.SendCommandRequest
			if err := json.Unmarshal(calls["command-success-output"].Input, &nativeSend); err != nil {
				t.Fatal(err)
			}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: source.Account, Region: source.Region, PrincipalARN: "arn:aws:iam::" + source.Account + ":root"})
			var firstSend api.SendCommandResult
			if err := json.Unmarshal(calls["command-success-output"].Output, &firstSend); err != nil {
				t.Fatal(err)
			}
			manual := clock.NewManual(*firstSend.Command.RequestedDateTime)
			nodeID := string(nativeSend.InstanceIds[0])
			if err := repo.Update(ctx, func(tx commands.Transaction) error {
				return tx.PutNode(commands.Node{Key: commands.Key{Scope: commands.Scope{Partition: "aws", AccountID: source.Account, Region: source.Region}, ID: nodeID}, LastPing: manual.Now(), PlatformType: "Linux"})
			}); err != nil {
				t.Fatal(err)
			}
			docs := ssmdocuments.New(ssmdocuments.Config{Clock: manual, Authorizer: allowStateMachine{}})
			service := commands.New(commands.Config{Repository: repo, Recorder: apievents.New(history), Documents: docs, Clock: manual, Authorizer: allowStateMachine{}, Instances: instances{nodeID: {ID: nodeID, State: "running"}}})
			frontend := ssmfrontend.New(ssm.New(ssm.Config{}), docs, service)
			t.Cleanup(func() { _ = service.Close() })
			nativeID, actualID := "", ""
			var cursor int64
			for _, label := range []string{
				"command-success-output", "success-commands", "success-plugins", "success-invocation-4",
				"invocation-wrong-plugin", "invocation-missing-command", "send-missing-document",
				"send-missing-version", "send-missing-instance", "send-unknown-parameter", "send-missing-tag",
				"send-timeout-too-small", "send-concurrency-zero", "send-errors-negative",
				"control:cancel-missing-command", "control:cancel-malformed-command", "control:invocation-invalid-id",
				"control:fleet-missing-id", "control:fleet-invalid-key", "control:fleet-invalid-next-token",
				"control:fleet-mixed-filters", "control:fleet-tag-and-id",
			} {
				row := calls[label]
				input := row.Input
				wantRaw := expected[label]
				if nativeID != "" {
					input = []byte(strings.ReplaceAll(string(input), nativeID, actualID))
					wantRaw = []byte(strings.ReplaceAll(string(wantRaw), nativeID, actualID))
				}
				var sendResult api.SendCommandResult
				if row.Operation == "SendCommand" && row.Code == "Success" {
					if err := json.Unmarshal(row.Output, &sendResult); err != nil {
						t.Fatal(err)
					}
					if err := manual.Advance(sendResult.Command.RequestedDateTime.Sub(manual.Now())); err != nil {
						t.Fatal(err)
					}
				}
				request, err := api.DecodeRequest(row.Operation, awsapi.Request{JSON: input})
				var out any
				var rejected *awswire.Error
				if err != nil {
					rejected = frontend.RequestError(row.Operation, err)
					request.Input = frontend.RequestErrorInput(request.Operation, awsapi.Request{JSON: input})
					if err := frontend.RecordRequestError(ctx, request, rejected); err != nil {
						t.Fatalf("%s rejected audit: %v", label, err)
					}
				} else {
					out, rejected = frontend.ExecuteCommand(ctx, request)
				}
				if row.Code == "Success" && rejected != nil || row.Code != "Success" && (rejected == nil || rejected.Code != row.Code) {
					t.Fatalf("%s API outcome: %v, want %s", label, rejected, row.Code)
				}
				if row.Operation == "SendCommand" && rejected == nil {
					result := out.(*api.SendCommandResult)
					if !reflect.DeepEqual(result.Command.Parameters, request.Input.(*api.SendCommandRequest).Parameters) {
						t.Fatalf("%s API command parameters were changed by audit", label)
					}
					wantRaw = []byte(strings.ReplaceAll(string(wantRaw), string(*sendResult.Command.CommandId), string(*result.Command.CommandId)))
					if label == "command-success-output" {
						nativeID, actualID = string(*sendResult.Command.CommandId), string(*result.Command.CommandId)
					}
				}
				events, err := history.Read(ctx, cursor, 2)
				if err != nil || len(events) != 1 {
					t.Fatalf("%s journal: %v %v", label, events, err)
				}
				cursor = events[0].Sequence
				gotRaw, err := apievents.CloudTrailRecord(events[0])
				if err != nil {
					t.Fatal(err)
				}
				var got, want map[string]any
				if err := json.Unmarshal(gotRaw, &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(wantRaw, &want); err != nil {
					t.Fatal(err)
				}
				if row.Operation == "SendCommand" && rejected == nil {
					result := out.(*api.SendCommandResult).Command
					recorded := got["responseElements"].(map[string]any)["command"].(map[string]any)
					if recorded["status"] != string(*result.Status) || recorded["statusDetails"] != string(*result.StatusDetails) {
						t.Fatal("journal invented a command lifecycle snapshot different from the API response")
					}
				}
				for _, field := range []string{"eventName", "eventSource", "eventCategory", "readOnly", "requestParameters", "responseElements", "resources", "errorCode", "errorMessage"} {
					if !reflect.DeepEqual(got[field], want[field]) {
						t.Errorf("%s CloudTrail %s: got %#v want %#v", label, field, got[field], want[field])
					}
				}
				if label == "send-missing-tag" {
					if _, err := service.JobDriver().RunDue(ctx, 20); err != nil {
						t.Fatal(err)
					}
					var terminal api.ListCommandsResult
					if err := json.Unmarshal(calls["missing-tag-terminal-1"].Output, &terminal); err != nil {
						t.Fatal(err)
					}
					id := string(*out.(*api.SendCommandResult).Command.CommandId)
					if err := repo.View(ctx, func(r commands.Reader) error {
						cmd, err := r.Command(commands.Key{Scope: commands.Scope{Partition: "aws", AccountID: source.Account, Region: source.Region}, ID: id})
						if err != nil {
							return err
						}
						if cmd.Status != string(*terminal.Commands[0].Status) || cmd.StatusDetails != string(*terminal.Commands[0].StatusDetails) {
							t.Fatalf("empty-target settled state differs from native capture: %+v", cmd)
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					retained, err := history.Read(ctx, cursor-1, 1)
					if err != nil || !reflect.DeepEqual(retained, events) {
						t.Fatalf("settling command changed admission journal snapshot: %+v %v", retained, err)
					}
				}
			}
		})
	}
}

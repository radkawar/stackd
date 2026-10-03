package ssmcommands

import (
	"context"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/services/ssmdocuments"
	"stackd/storage/memory"
)

type alarmObservationFunc func(context.Context, Command) (string, error)

func (f alarmObservationFunc) Prepare(context.Context, Command) (string, error) { return "role", nil }
func (f alarmObservationFunc) State(ctx context.Context, cmd Command) (string, error) {
	return f(ctx, cmd)
}

func TestAlarmObservationCannotOverwriteConcurrentCancellation(t *testing.T) {
	scope := Scope{"aws", "123456789012", "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.AccountID})
	now := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	source := clock.NewManual(now)
	repo := NewMemoryRepository(nil)
	cmd := Command{Key: Key{Scope: scope, ID: "11111111-1111-4111-8111-111111111111"}, Status: "InProgress", DeliveryDeadline: now.Add(time.Hour), Alarm: &AlarmConfiguration{Name: "guard"}, AlarmPoll: AlarmPoll{RoleID: "role", Due: now, Revision: 1, Checked: true}}
	inv := Invocation{Key: InvocationKey{Command: cmd.Key, NodeID: "i-00000000000000001"}, Status: "InProgress", DeliveredAt: now, Plugins: []Plugin{{Name: "shell", Status: "InProgress", Code: -1}}}
	if err := repo.Update(ctx, func(tx Transaction) error {
		if err := tx.PutCommand(cmd); err != nil {
			return err
		}
		return tx.PutInvocation(inv)
	}); err != nil {
		t.Fatal(err)
	}
	var service *Service
	service = New(Config{Repository: repo, Clock: source, Alarms: alarmObservationFunc(func(context.Context, Command) (string, error) {
		// Entering this write during the observation also guards against moving
		// CloudWatch polling under the owner's external-effects transaction.
		err := repo.Update(ctx, func(tx Transaction) error {
			_, err := service.cancelCommand(tx, &api.CancelCommandRequest{CommandId: new(api.CommandId(cmd.Key.ID))})
			return err
		})
		return "ALARM", err
	})})
	defer service.Close()
	jobs := alarmJobs{service}
	job, found, err := jobs.Next(ctx)
	if err != nil || !found {
		t.Fatalf("alarm selection: %+v %v", job, err)
	}
	if err = jobs.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err = repo.View(ctx, func(r Reader) error {
		current, err := r.Command(cmd.Key)
		if err != nil {
			return err
		}
		if current.Status != "Cancelling" || current.AlarmPoll.TriggeredState != "" {
			t.Fatalf("observation overwrote cancellation: %+v", current)
		}
		currentInv, err := r.Invocation(inv.Key)
		if err != nil {
			return err
		}
		if currentInv.Status != "Cancelling" || currentInv.CancelID == "" || currentInv.CancelJobID == "" {
			t.Fatalf("cancellation fence lost: %+v", currentInv)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type alarmNoInstances struct{}

func (alarmNoInstances) Instance(context.Context, string) (Instance, error) {
	return Instance{}, ErrNotFound
}

func TestAlarmAdmissionRechecksDocumentAfterExternalObservation(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "deleted"
		if replacement {
			name = "replaced"
		}
		t.Run(name, func(t *testing.T) {
			scope := Scope{"aws", "123456789012", "us-east-1"}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.AccountID})
			source := clock.NewManual(time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC))
			domain := memory.NewDomain()
			repo := NewMemoryRepository(domain)
			documents := ssmdocuments.New(ssmdocuments.Config{Repository: ssmdocuments.NewMemoryRepository(domain), Clock: source})
			defer documents.Close()
			model, _ := awscatalog.LookupService("ssm")
			documentCall := func(action string, input any) any {
				t.Helper()
				op, _ := model.Operation(action)
				out, err := documents.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			content := `{"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript","name":"shell","inputs":{"runCommand":["printf original"],"timeoutSeconds":"5"}}]}`
			create := func(content string) *api.CreateDocumentResult {
				result := documentCall("CreateDocument", &api.CreateDocumentRequest{Name: new(api.DocumentName("alarm-document")), Content: new(api.DocumentContent(content)), DocumentType: new(api.DocumentType("Command")), DocumentFormat: new(api.DocumentFormat("JSON"))}).(*api.CreateDocumentResult)
				if _, err := documents.JobDriver().RunDue(ctx, 10); err != nil {
					t.Fatal(err)
				}
				return result
			}
			original := create(content)
			service := New(Config{Repository: repo, Clock: source, Documents: documents, Instances: alarmNoInstances{}, Alarms: alarmObservationFunc(func(context.Context, Command) (string, error) {
				documentCall("DeleteDocument", &api.DeleteDocumentRequest{Name: new(api.DocumentName("alarm-document"))})
				if replacement {
					create(`{"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript","name":"shell","inputs":{"runCommand":["printf replacement"],"timeoutSeconds":"5"}}]}`)
				}
				return "OK", nil
			})})
			defer service.Close()
			op, _ := model.Operation("SendCommand")
			input := &api.SendCommandRequest{DocumentName: new(api.DocumentARN("alarm-document")), DocumentHash: original.DocumentDescription.Hash, DocumentHashType: new(api.DocumentHashType("Sha256")), Targets: api.Targets{{Key: new(api.TargetKey("tag:absent")), Values: api.TargetValues{"none"}}}, AlarmConfiguration: &api.AlarmConfiguration{Alarms: api.AlarmList{{Name: new(api.AlarmName("guard"))}}}}
			_, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
			if rejected == nil || rejected.Code != "InvalidDocument" {
				t.Fatalf("document changed during alarm observation was admitted: %v", rejected)
			}
			if err := repo.View(ctx, func(r Reader) error {
				commands, err := r.Commands(scope)
				if err == nil && len(commands) != 0 {
					t.Fatalf("rejected document retained command work: %+v", commands)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

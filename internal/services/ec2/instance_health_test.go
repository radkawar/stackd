package ec2

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func TestInstanceContinuousFailure(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/ec2/instance_health.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Steps []struct {
			Name            string
			At              time.Time
			Reachable       bool
			Status, Summary string
			ImpairedSince   time.Time `json:"impaired_since"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var check InstanceStatusCheck
	for _, step := range fixture.Steps {
		t.Run(step.Name, func(t *testing.T) {
			check = observeInstanceCheck(check, step.Reachable, step.At)
			if string(check.Status) != step.Status || !check.ImpairedSince.Equal(step.ImpairedSince) {
				t.Fatalf("observation %+v, want status %s impaired since %s", check, step.Status, step.ImpairedSince)
			}
			view := instanceCheckSummary(check)
			if str(view.Status) != step.Summary || len(view.Details) != 1 || str(view.Details[0].Name) != "reachability" || str(view.Details[0].Status) != step.Status {
				t.Fatalf("consumer status %+v", view)
			}
			var since time.Time
			if view.Details[0].ImpairedSince != nil {
				since = time.Time(*view.Details[0].ImpairedSince)
			}
			if !since.Equal(step.ImpairedSince) {
				t.Fatalf("consumer failure origin %s, want %s", since, step.ImpairedSince)
			}
		})
	}
}

// Replay short-ID lexical admission and status request boundaries, not AWS's
// opaque long-ID encoding (retained separately as an implementation gap).
func TestNativeInstanceReadAdmission(t *testing.T) {
	service := New(Config{Clock: clock.NewManual(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
	own := key(ctx, "i-0ffffffffffffffff")
	foreign := ResourceKey{Scope: Scope{"aws", "111111111111", "us-east-1"}, ID: "i-00000000000000001"}
	if err := service.repository.Update(ctx, func(tx Transaction) error {
		for _, k := range []ResourceKey{own, foreign} {
			if err := tx.PutInstance(InstanceRecord{Key: k, Data: api.Instance{InstanceId: new(api.String(k.ID)), State: instanceStateValue("running"), Placement: &api.Placement{AvailabilityZone: new(api.String("us-east-1a"))}}}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"instance_status_inputs", "instance_status_id_boundaries", "instance_status_controls"} {
		data, err := os.ReadFile("../../../testdata/aws/ec2/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Calls []struct {
				Label, Operation, Code string
				Input                  json.RawMessage
			}
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		for _, call := range fixture.Calls {
			if call.Operation != "DescribeInstanceStatus" && call.Operation != "DescribeInstances" {
				continue
			}
			var input api.DescribeInstanceStatusRequest
			if err := json.Unmarshal(call.Input, &input); err != nil {
				t.Fatal(err)
			}
			if len(input.InstanceIds) == 1 && len(input.InstanceIds[0]) >= 19 && input.MaxResults == nil && input.NextToken == nil && !boolValue(input.DryRun) {
				continue
			}
			t.Run(name+"/"+call.Label, func(t *testing.T) {
				var result *api.DescribeInstanceStatusResult
				var callErr error
				if err := service.repository.Update(ctx, func(tx Transaction) error {
					if call.Operation == "DescribeInstanceStatus" {
						result, callErr = service.describeInstanceStatus(tx.Context(), tx, &input)
					} else {
						_, callErr = service.describeInstances(tx.Context(), tx, &api.DescribeInstancesRequest{InstanceIds: input.InstanceIds})
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if call.Code != "Success" {
					var modeled *awswire.Error
					if !errors.As(callErr, &modeled) || modeled.Code != call.Code {
						t.Fatalf("error %v, native code %s", callErr, call.Code)
					}
					return
				}
				if callErr != nil || result == nil || len(result.InstanceStatuses) != 1 || str(result.InstanceStatuses[0].InstanceId) != own.ID || result.NextToken != nil {
					t.Fatalf("valid page must retain the matching owned instance and exclude the foreign account: result=%+v error=%v", result, callErr)
				}
			})
		}
	}
}

func TestHibernateAdmissionRequiresCurrentGuestReadiness(t *testing.T) {
	service := New(Config{Clock: clock.NewManual(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))})
	t.Cleanup(func() { service.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
	k := key(ctx, "i-0123456789abcdef0")
	for _, test := range []struct {
		name, state, code string
		configured, ready bool
	}{
		{name: "not-enabled", state: "running", ready: true, code: "UnsupportedHibernationConfiguration"},
		{name: "guest-not-ready", state: "running", configured: true, code: "UnsupportedOperation"},
		{name: "guest-ready", state: "running", configured: true, ready: true},
		{name: "already-stopped", state: "stopped", configured: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := InstanceRecord{Key: k, Data: api.Instance{InstanceId: new(api.String(k.ID)), State: instanceStateValue(test.state), HibernationOptions: &api.HibernationOptions{Configured: new(api.Boolean(test.configured))}}, Health: InstanceHealthRecord{HibernationReady: test.ready}}
			if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutInstance(record) }); err != nil {
				t.Fatal(err)
			}
			var result *api.StopInstancesResult
			callErr := service.repository.Update(ctx, func(tx Transaction) error {
				var err error
				result, err = service.stopInstances(tx.Context(), tx, &api.StopInstancesRequest{InstanceIds: api.InstanceIdStringList{api.InstanceId(k.ID)}, Hibernate: new(api.Boolean(true))})
				return err
			})
			if test.code != "" {
				var modeled *awswire.Error
				if !errors.As(callErr, &modeled) || modeled.Code != test.code {
					t.Fatalf("StopInstances: got %v, want %s", callErr, test.code)
				}
				if test.code == "UnsupportedOperation" && !errors.Is(callErr, ErrInstanceHibernationNotReady) {
					t.Fatalf("readiness error lost its typed transient cause: %v", callErr)
				}
			} else if callErr != nil || result == nil {
				t.Fatalf("StopInstances: result=%+v error=%v", result, callErr)
			}
			if err := service.repository.View(ctx, func(tx Reader) error {
				current, err := tx.Instance(k)
				if err != nil {
					return err
				}
				wantState := test.state
				if test.code == "" && test.state == "running" {
					wantState = "stopping"
					if current.Intent != InstanceIntentHibernate {
						t.Errorf("accepted hibernate lost its lifecycle intent: %s", current.Intent)
					}
				}
				if instanceState(current) != wantState {
					t.Errorf("state = %s, want %s", instanceState(current), wantState)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("new-running-incarnation-forgets-old-readiness", func(t *testing.T) {
		if err := service.repository.Update(ctx, func(tx Transaction) error {
			record := InstanceRecord{Key: k, Data: api.Instance{InstanceId: new(api.String(k.ID)), State: instanceStateValue("pending"), HibernationOptions: &api.HibernationOptions{Configured: new(api.Boolean(true))}}, Health: InstanceHealthRecord{HibernationReady: true}}
			if err := service.changeInstanceState(tx.Context(), tx, &record, "running"); err != nil {
				return err
			}
			_, err := service.stopInstances(tx.Context(), tx, &api.StopInstancesRequest{InstanceIds: api.InstanceIdStringList{api.InstanceId(k.ID)}, Hibernate: new(api.Boolean(true))})
			if !errors.Is(err, ErrInstanceHibernationNotReady) {
				t.Fatalf("new running incarnation must wait for its own observed guest readiness: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestHibernatedResizeRequiresOrdinaryStop(t *testing.T) {
	service := New(Config{Clock: clock.NewManual(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))})
	t.Cleanup(func() { service.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
	k := key(ctx, "i-0123456789abcdef0")
	for _, reason := range []string{"Client.UserInitiatedHibernate", "Client.UserInitiatedShutdown"} {
		t.Run(reason, func(t *testing.T) {
			record := InstanceRecord{Key: k, Data: api.Instance{
				InstanceId: new(api.String(k.ID)), InstanceType: new(api.InstanceType("t3.nano")), Architecture: new(api.ArchitectureValues("x86_64")),
				State: instanceStateValue("stopped"), StateReason: &api.StateReason{Code: new(api.String(reason))},
				HibernationOptions: &api.HibernationOptions{Configured: new(api.Boolean(true))},
			}}
			if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutInstance(record) }); err != nil {
				t.Fatal(err)
			}
			err := service.repository.Update(ctx, func(tx Transaction) error {
				_, err := service.modifyInstanceAttribute(tx.Context(), tx, &api.ModifyInstanceAttributeRequest{InstanceId: new(api.InstanceId(k.ID)), InstanceType: &api.AttributeValue{Value: new(api.String("t3.micro"))}})
				return err
			})
			wantType := "t3.micro"
			if reason == "Client.UserInitiatedHibernate" {
				wantType = "t3.nano"
				var rejected *awswire.Error
				if !errors.As(err, &rejected) || rejected.Code != "IncorrectInstanceState" {
					t.Fatalf("hibernated resize: %v", err)
				}
			} else if err != nil {
				t.Fatalf("configured but normally stopped resize: %v", err)
			}
			if err := service.repository.View(ctx, func(tx Reader) error {
				current, err := tx.Instance(k)
				if err == nil && str(current.Data.InstanceType) != wantType {
					t.Errorf("instance type = %s, want %s", str(current.Data.InstanceType), wantType)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

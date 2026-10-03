package ec2

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

type instanceMonitoringPolicies string

func (p instanceMonitoringPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []policy.Policy{{Document: string(p)}}}, nil
}

func TestNativeInstanceMonitoringTransitions(t *testing.T) {
	service := New(Config{Authorizer: authorization.New(instanceMonitoringPolicies(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}}`), nil)})
	t.Cleanup(func() { service.Close() })
	model, _ := awscatalog.LookupService("ec2")
	for _, name := range []string{"instance_monitoring_owned.json", "instance_monitoring_edges.json"} {
		data, err := os.ReadFile("../../../testdata/aws/ec2/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Account, Region string
			Calls           []struct {
				Label, Operation, Code, Caller string
				Input, Output                  json.RawMessage
			}
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		metadata := awsctx.Metadata{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region, PrincipalARN: "arn:aws:iam::" + fixture.Account + ":root", PrincipalID: fixture.Account}
		root := awsctx.WithMetadata(t.Context(), metadata)
		for _, call := range fixture.Calls {
			switch call.Operation {
			case "RunInstances":
				if call.Code != "Success" {
					continue
				}
				var out api.Reservation
				if err := json.Unmarshal(call.Output, &out); err != nil {
					t.Fatal(err)
				}
				if err := service.repository.Update(root, func(tx Transaction) error {
					for _, data := range out.Instances {
						data.Monitoring.State = new(api.MonitoringState(effectiveMonitoringState(str(data.Monitoring.State))))
						if err := tx.PutInstance(InstanceRecord{Key: key(root, str(data.InstanceId)), Data: data}); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case "StopInstances", "TerminateInstances":
				if call.Code != "Success" {
					continue
				}
				var changes struct {
					StoppingInstances, TerminatingInstances api.InstanceStateChangeList
				}
				if err := json.Unmarshal(call.Output, &changes); err != nil {
					t.Fatal(err)
				}
				for _, change := range append(changes.StoppingInstances, changes.TerminatingInstances...) {
					if err := service.repository.Update(root, func(tx Transaction) error {
						record, err := tx.Instance(key(root, str(change.InstanceId)))
						if err != nil {
							return err
						}
						record.Data.State = change.CurrentState
						// Native TerminateInstances reports its target as terminated
						// before the following DescribeInstances observations still
						// show shutting-down. Replay the accepted transition here;
						// only an observed read completes retirement below.
						if call.Operation == "TerminateInstances" && str(change.PreviousState.Name) != "terminated" {
							record.Data.State = instanceStateValue("shutting-down")
						}
						return tx.PutInstance(record)
					}); err != nil {
						t.Fatal(err)
					}
				}
			case "DescribeInstances":
				if call.Code != "Success" {
					continue
				}
				var out api.DescribeInstancesResult
				if err := json.Unmarshal(call.Output, &out); err != nil {
					t.Fatal(err)
				}
				for _, reservation := range out.Reservations {
					for _, data := range reservation.Instances {
						if err := service.repository.Update(root, func(tx Transaction) error {
							record, err := tx.Instance(key(root, str(data.InstanceId)))
							if err != nil {
								return err
							}
							if got, want := str(record.Data.Monitoring.State), effectiveMonitoringState(str(data.Monitoring.State)); got != want {
								t.Fatalf("%s: retained monitoring %s, native effective mode %s", call.Label, got, want)
							}
							record.Data.State = data.State
							return tx.PutInstance(record)
						}); err != nil {
							t.Fatal(err)
						}
					}
				}
			case "MonitorInstances", "UnmonitorInstances":
				t.Run(name+"/"+call.Label, func(t *testing.T) {
					ctx := root
					if call.Caller == "read-only" {
						caller := metadata
						caller.PrincipalARN = "arn:aws:iam::" + fixture.Account + ":user/read-only"
						caller.PrincipalID = "monitoring-read-only"
						ctx = awsctx.WithMetadata(t.Context(), caller)
					}
					var input any
					if call.Operation == "MonitorInstances" {
						input = new(api.MonitorInstancesRequest)
					} else {
						input = new(api.UnmonitorInstancesRequest)
					}
					if err := json.Unmarshal(call.Input, input); err != nil {
						t.Fatal(err)
					}
					before := monitoringRecords(t, service, root)
					op, _ := model.Operation(call.Operation)
					out, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
					if call.Code != "Success" {
						if rejected == nil || rejected.Code != call.Code {
							t.Fatalf("error %v, native code %s", rejected, call.Code)
						}
						if after := monitoringRecords(t, service, root); !reflect.DeepEqual(before, after) {
							t.Fatalf("rejected command changed instance state: before %+v, after %+v", before, after)
						}
						return
					}
					if rejected != nil {
						t.Fatal(rejected)
					}
					var expected struct{ InstanceMonitorings api.InstanceMonitoringList }
					if err := json.Unmarshal(call.Output, &expected); err != nil {
						t.Fatal(err)
					}
					var actual api.InstanceMonitoringList
					if result, ok := out.(*api.MonitorInstancesResult); ok {
						actual = result.InstanceMonitorings
					} else {
						actual = out.(*api.UnmonitorInstancesResult).InstanceMonitorings
					}
					for i := range expected.InstanceMonitorings {
						item := &expected.InstanceMonitorings[i]
						item.Monitoring.State = new(api.MonitoringState(effectiveMonitoringState(str(item.Monitoring.State))))
					}
					if !reflect.DeepEqual(actual, expected.InstanceMonitorings) {
						t.Fatalf("monitoring selection %+v, native %+v", actual, expected.InstanceMonitorings)
					}
				})
			}
		}
	}
}

// Native pending/disabling are eventual transitions. Local monitoring changes
// directly configure the retained publisher, so replay compares effective mode,
// not AWS's external subscription propagation latency.
func effectiveMonitoringState(state string) string {
	switch state {
	case "pending":
		return "enabled"
	case "disabling":
		return "disabled"
	default:
		return state
	}
}

func monitoringRecords(t *testing.T, service *Service, ctx context.Context) []InstanceRecord {
	t.Helper()
	var records []InstanceRecord
	if err := service.repository.View(ctx, func(tx Reader) error {
		var err error
		records, err = tx.Instances(scopeFor(ctx))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return records
}

func TestInstanceMonitoringSelectionAtomicity(t *testing.T) {
	for _, action := range []string{"MonitorInstances", "UnmonitorInstances"} {
		t.Run(action, func(t *testing.T) {
			service := New(Config{Authorizer: authorization.New(instanceMonitoringPolicies(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:MonitorInstances","ec2:UnmonitorInstances"],"Resource":"*","Condition":{"StringEquals":{"ec2:ResourceTag/team":"allowed"}}}}`), nil)})
			t.Cleanup(func() { service.Close() })
			metadata := awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}
			root := awsctx.WithMetadata(t.Context(), metadata)
			caller := metadata
			caller.PrincipalARN, caller.PrincipalID = "arn:aws:iam::123456789012:user/monitor", "monitor-user"
			user := awsctx.WithMetadata(t.Context(), caller)
			initial := "disabled"
			if action == "UnmonitorInstances" {
				initial = "enabled"
			}
			if err := service.repository.Update(root, func(tx Transaction) error {
				for i, id := range []string{"i-11111111", "i-22222222", "i-33333333"} {
					state, team := "running", "allowed"
					if i == 1 {
						team = "denied"
					}
					if i == 2 {
						state = "terminated"
					}
					if err := tx.PutInstance(InstanceRecord{Key: key(root, id), Data: api.Instance{InstanceId: new(api.String(id)), State: instanceStateValue(state), Monitoring: &api.Monitoring{State: new(api.MonitoringState(initial))}, Tags: api.TagList{{Key: new(api.String("team")), Value: new(api.String(team))}}}}); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			model, _ := awscatalog.LookupService("ec2")
			op, _ := model.Operation(action)
			for _, check := range []struct {
				name, other, code string
				ctx               context.Context
				dry               bool
			}{
				{"denied-selection", "i-22222222", "UnauthorizedOperation", user, false},
				{"denied-dry-selection", "i-22222222", "UnauthorizedOperation", user, true},
				{"terminal-selection", "i-33333333", "InvalidState", root, false},
				{"missing-selection", "i-44444444", "InvalidInstanceID.NotFound", root, false},
			} {
				t.Run(check.name, func(t *testing.T) {
					before := monitoringRecords(t, service, root)
					ids := api.InstanceIdStringList{"i-11111111", api.InstanceId(check.other)}
					var input any = &api.MonitorInstancesRequest{InstanceIds: ids, DryRun: new(api.Boolean(check.dry))}
					if action == "UnmonitorInstances" {
						input = &api.UnmonitorInstancesRequest{InstanceIds: ids, DryRun: new(api.Boolean(check.dry))}
					}
					_, rejected := service.ExecuteCommand(check.ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
					if rejected == nil || rejected.Code != check.code {
						t.Fatalf("error %v, want %s", rejected, check.code)
					}
					if after := monitoringRecords(t, service, root); !reflect.DeepEqual(before, after) {
						t.Fatalf("selection rejection changed state: before %+v, after %+v", before, after)
					}
				})
			}
		})
	}
}

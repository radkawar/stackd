package integrations

import (
	"context"
	"errors"
	"strings"
	"testing"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	ec2api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
)

func TestAutoScalingTerminationProtection(t *testing.T) {
	for _, test := range []struct {
		name        string
		public      bool
		deny        bool
		unprotected bool
		sourceFrom  string
		sourceTo    string
		group       string
		wantCode    string
	}{
		{name: "protected-public", public: true, group: "workers", wantCode: "OperationNotPermitted"},
		{name: "protected-owned", group: "workers"},
		{name: "wrong-group", group: "other", wantCode: "IncorrectState"},
		{name: "unprotected-wrong-group", unprotected: true, group: "other", wantCode: "IncorrectState"},
		{name: "unowned", wantCode: "IncorrectState"},
		{name: "wrong-account", group: "workers", sourceFrom: "123456789012", sourceTo: "999999999999", wantCode: "InvalidParameterValue"},
		{name: "wrong-region", group: "workers", sourceFrom: "us-east-1", sourceTo: "us-west-2", wantCode: "InvalidParameterValue"},
		{name: "wrong-service", group: "workers", sourceFrom: ":autoscaling:", sourceTo: ":ec2:", wantCode: "InvalidParameterValue"},
		{name: "current-iam-deny", group: "workers", deny: true, wantCode: "UnauthorizedOperation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAutoScalingFixture(t)
			f.role.IdentityPolicies.Inline["terminate"] = `{"Statement":{"Effect":"Allow","Action":"ec2:TerminateInstances","Resource":"arn:aws:ec2:us-east-1:123456789012:instance/i-12345678"}}`
			f.update(t)
			ctx, err := f.adapter.Context(f.caller, f.group)
			if err != nil {
				t.Fatal(err)
			}
			if test.deny {
				// Reuse the issued session: authorization must consult current IAM.
				f.role.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"ec2:TerminateInstances","Resource":"*"}}`
				f.update(t)
			}
			if test.sourceFrom != "" {
				source := ctx.Value(autoScalingSourceKey{}).(awsctx.ServicePrincipal)
				source.SourceARN = strings.Replace(source.SourceARN, test.sourceFrom, test.sourceTo, 1)
				ctx = context.WithValue(ctx, autoScalingSourceKey{}, source)
			}
			repository := ec2.NewMemoryRepository(f.domain)
			compute := ec2.New(ec2.Config{Repository: repository, Authorizer: f.roles.Authorizer, Clock: f.clock, Recorder: apievents.New(f.events)})
			t.Cleanup(func() { compute.Close() })
			f.adapter.EC2 = compute
			key := ec2.ResourceKey{Scope: ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: "i-12345678"}
			record := ec2.InstanceRecord{Key: key, DisableAPITermination: !test.unprotected, Data: ec2api.Instance{
				InstanceId: new(ec2api.String(key.ID)),
				State:      &ec2api.InstanceState{Code: new(ec2api.Integer(16)), Name: new(ec2api.InstanceStateName("running"))},
			}}
			if test.group != "" {
				record.Data.Tags = ec2api.TagList{{Key: new(ec2api.String("aws:autoscaling:groupName")), Value: new(ec2api.String(test.group))}}
			}
			if err := repository.Update(f.root, func(tx ec2.Transaction) error { return tx.PutInstance(record) }); err != nil {
				t.Fatal(err)
			}
			if test.public {
				model, _ := awscatalog.LookupService("ec2")
				op, _ := model.Operation("TerminateInstances")
				_, rejected := compute.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: &ec2api.TerminateInstancesRequest{InstanceIds: ec2api.InstanceIdStringList{ec2api.InstanceId(key.ID)}}})
				if rejected != nil {
					err = rejected
				}
			} else {
				err = f.adapter.Terminate(ctx, key.ID)
			}
			if test.wantCode == "" {
				if err != nil {
					t.Errorf("Auto Scaling cannot terminate its protected instance: %v", err)
				}
			} else {
				var rejected *awswire.Error
				if !errors.As(err, &rejected) || rejected.Code != test.wantCode {
					t.Errorf("termination error = %v, want %s", err, test.wantCode)
				}
			}
			if err := repository.View(f.root, func(tx ec2.Reader) error {
				current, err := tx.Instance(key)
				if err != nil {
					return err
				}
				if current.DisableAPITermination != record.DisableAPITermination {
					t.Error("termination changed the customer's API termination protection setting")
				}
				if test.wantCode == "" {
					if string(*current.Data.State.Name) != "shutting-down" || current.Intent != ec2.InstanceIntentTerminate || current.Generation != record.Generation+1 {
						t.Errorf("termination did not commit the native transition: state=%s intent=%s generation=%d", *current.Data.State.Name, current.Intent, current.Generation)
					}
				} else if string(*current.Data.State.Name) != "running" || current.Generation != record.Generation || current.Intent != record.Intent {
					t.Errorf("rejected termination mutated the instance: state=%s intent=%s generation=%d", *current.Data.State.Name, current.Intent, current.Generation)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			events, err := f.events.Read(f.root, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			wantAuditCode := ""
			if test.wantCode != "" {
				wantAuditCode = "Client." + test.wantCode
			}
			count := 0
			for _, event := range events {
				if call := event.APICallCompleted; call != nil && call.EventName == "TerminateInstances" {
					count++
					if call.ErrorCode != wantAuditCode {
						t.Errorf("native termination audit error = %q, want %q", call.ErrorCode, wantAuditCode)
					}
				}
			}
			if count != 1 {
				t.Errorf("native termination audit count = %d, want one outcome", count)
			}
		})
	}
}

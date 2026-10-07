package eventbridge_test

import (
	"encoding/json"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/eventbridge"
)

func cfnEventCommand(t *testing.T, s *service.Service, kind, owner, sid, action string, input any) (any, *awswire.Error) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := api.DecodeRequest(action, awsapi.Request{JSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", RequestID: action})
	return s.ExecuteCommand(service.WithCloudFormationOwner(ctx, kind, owner, sid), decoded)
}

func TestCloudFormationArchiveOwnershipSurvivesReopen(t *testing.T) {
	backends(t, func(t *testing.T, b *backend) {
		source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
		s := newService(t, b, source, &sender{})
		if _, err := cfnEventCommand(t, s, "Archive", "owner-one", "", "CreateArchive", map[string]any{"ArchiveName": "archive", "EventSourceArn": "arn:aws:events:us-east-1:123456789012:event-bus/default"}); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		b.reopen()
		s = newService(t, b, source, &sender{})
		for _, action := range []string{"UpdateArchive", "DeleteArchive"} {
			input := map[string]any{"ArchiveName": "archive"}
			if action == "UpdateArchive" {
				input["Description"] = "hijacked"
			}
			if _, err := cfnEventCommand(t, s, "Archive", "owner-two", "", action, input); err == nil {
				t.Fatalf("%s adopted another resource incarnation", action)
			}
		}
		if _, err := cfnEventCommand(t, s, "Archive", "owner-one", "", "UpdateArchive", map[string]any{"ArchiveName": "archive", "Description": "owned"}); err != nil {
			t.Fatal(err)
		}
		if _, err := cfnEventCommand(t, s, "Archive", "owner-one", "", "DeleteArchive", map[string]any{"ArchiveName": "archive"}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCloudFormationEventBusPolicyStatementOwnership(t *testing.T) {
	backends(t, func(t *testing.T, b *backend) {
		source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
		s := newService(t, b, source, &sender{})
		permission := func(owner, sid, principal string) {
			t.Helper()
			if _, err := cfnEventCommand(t, s, "EventBusPolicy", owner, sid, "PutPermission", map[string]any{"StatementId": sid, "Action": "events:PutEvents", "Principal": principal}); err != nil {
				t.Fatal(err)
			}
		}
		permission("owner-one", "first", "*")
		permission("owner-two", "second", "*")
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		b.reopen()
		s = newService(t, b, source, &sender{})
		ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
		if err := s.CloudFormationEventBusPolicyOwned(ctx, "default", "first", "owner-one"); err != nil {
			t.Fatalf("private statement recovery returned a non-nil error after reopen: %v", err)
		}
		if _, err := cfnEventCommand(t, s, "EventBusPolicy", "intruder", "first", "RemovePermission", map[string]any{"StatementId": "first"}); err == nil {
			t.Fatal("unowned permission removed")
		}
		permission("owner-one", "first", "111122223333")
		if _, err := cfnEventCommand(t, s, "EventBusPolicy", "owner-one", "first", "RemovePermission", map[string]any{"StatementId": "first"}); err != nil {
			t.Fatal(err)
		}
		out := success(t, s, "DescribeEventBus", map[string]any{"Name": "default"})
		var text string
		if err := json.Unmarshal(out["Policy"], &text); err != nil {
			t.Fatal(err)
		}
		var policy struct{ Statement []struct{ Sid string } }
		if err := json.Unmarshal([]byte(text), &policy); err != nil {
			t.Fatal(err)
		}
		if len(policy.Statement) != 1 || policy.Statement[0].Sid != "second" {
			t.Fatalf("neighboring statement changed: %s", text)
		}
	})
}

func TestCloudFormationPrivateRuleOwnerRejectsRecreation(t *testing.T) {
	backends(t, func(t *testing.T, b *backend) {
		source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
		s := newService(t, b, source, &sender{})
		input := map[string]any{"Name": "owned-rule", "Description": "first", "EventPattern": `{"source":["test"]}`}
		if _, err := cfnEventCommand(t, s, "Rule", "first-incarnation", "", "PutRule", input); err != nil {
			t.Fatal(err)
		}
		success(t, s, "PutRule", map[string]any{"Name": "owned-rule", "Description": "native", "EventPattern": `{"source":["test"]}`})
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		b.reopen()
		s = newService(t, b, source, &sender{})
		ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
		if err := s.CloudFormationRuleOwned(ctx, "default", "owned-rule", "first-incarnation"); err != nil {
			t.Fatalf("private rule recovery returned a non-nil error after native update and reopen: %v", err)
		}
		if _, err := cfnEventCommand(t, s, "Rule", "intruder", "", "PutRule", input); err == nil {
			t.Fatal("foreign incarnation adopted claimed rule")
		}
		if _, err := cfnEventCommand(t, s, "Rule", "first-incarnation", "", "DeleteRule", map[string]any{"Name": "owned-rule"}); err != nil {
			t.Fatalf("native update or reopen lost private rule claim: %v", err)
		}
		// Same-name recreation, even carrying the old public marker tags, is unclaimed.
		success(t, s, "PutRule", map[string]any{"Name": "owned-rule", "Description": "replacement", "EventPattern": `{"source":["test"]}`, "Tags": []map[string]string{{"Key": "stackd:cloudformation:incarnation", "Value": "first-incarnation"}}})
		for _, action := range []string{"PutRule", "DisableRule", "DeleteRule"} {
			in := map[string]any{"Name": "owned-rule"}
			if action == "PutRule" {
				in["Description"], in["EventPattern"] = "hijacked", `{"source":["changed"]}`
			}
			if _, err := cfnEventCommand(t, s, "Rule", "first-incarnation", "", action, in); err == nil {
				t.Fatalf("%s adopted a recreated rule", action)
			}
		}
		out := success(t, s, "DescribeRule", map[string]any{"Name": "owned-rule"})
		var description, state string
		if err := json.Unmarshal(out["Description"], &description); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(out["State"], &state); err != nil {
			t.Fatal(err)
		}
		if description != "replacement" || state != "ENABLED" {
			t.Fatalf("replacement changed: %s %s", description, state)
		}
	})
}

func TestCloudFormationPrivateBusOwnerRejectsRecreation(t *testing.T) {
	backends(t, func(t *testing.T, b *backend) {
		source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
		s := newService(t, b, source, &sender{})
		if _, err := cfnEventCommand(t, s, "EventBus", "first-incarnation", "", "CreateEventBus", map[string]any{"Name": "owned-bus"}); err != nil {
			t.Fatal(err)
		}
		if _, err := cfnEventCommand(t, s, "EventBus", "first-incarnation", "", "DeleteEventBus", map[string]any{"Name": "owned-bus"}); err != nil {
			t.Fatal(err)
		}
		success(t, s, "CreateEventBus", map[string]any{"Name": "owned-bus", "Description": "replacement", "Tags": []map[string]string{{"Key": "stackd:cloudformation:incarnation", "Value": "first-incarnation"}}})
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		b.reopen()
		s = newService(t, b, source, &sender{})
		for _, action := range []string{"UpdateEventBus", "DeleteEventBus"} {
			input := map[string]any{"Name": "owned-bus"}
			if action == "UpdateEventBus" {
				input["Description"] = "hijacked"
			}
			if _, err := cfnEventCommand(t, s, "EventBus", "first-incarnation", "", action, input); err == nil {
				t.Fatalf("%s adopted a recreated bus", action)
			}
		}
		out := success(t, s, "DescribeEventBus", map[string]any{"Name": "owned-bus"})
		var description string
		if err := json.Unmarshal(out["Description"], &description); err != nil {
			t.Fatal(err)
		}
		if description != "replacement" {
			t.Fatalf("replacement changed: %s", description)
		}
	})
}

func TestCloudFormationEventBusFullPolicyChangesCannotEraseStatementClaims(t *testing.T) {
	backends(t, func(t *testing.T, b *backend) {
		source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
		s := newService(t, b, source, &sender{})
		const owner = "bus-incarnation"
		if _, err := cfnEventCommand(t, s, "EventBus", owner, "", "CreateEventBus", map[string]any{"Name": "mixed-bus"}); err != nil {
			t.Fatal(err)
		}
		policy := `{"Version":"2012-10-17","Statement":[{"Sid":"managed","Effect":"Allow","Principal":"*","Action":"events:PutEvents","Resource":"*"}]}`
		if _, err := cfnEventCommand(t, s, "EventBus", owner, "", "PutPermission", map[string]any{"EventBusName": "mixed-bus", "Policy": policy}); err != nil {
			t.Fatal(err)
		}
		if _, err := cfnEventCommand(t, s, "EventBusPolicy", "independent-owner", "independent", "PutPermission", map[string]any{"EventBusName": "mixed-bus", "StatementId": "independent", "Action": "events:PutEvents", "Principal": "*"}); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		b.reopen()
		s = newService(t, b, source, &sender{})
		for _, action := range []string{"PutPermission", "RemovePermission"} {
			input := map[string]any{"EventBusName": "mixed-bus"}
			if action == "PutPermission" {
				input["Policy"] = policy
			} else {
				input["RemoveAllPermissions"] = true
			}
			if _, err := cfnEventCommand(t, s, "EventBus", owner, "", action, input); err == nil || err.Code != "ValidationException" {
				t.Fatalf("%s failed to atomically protect independent claims: %v", action, err)
			}
			out := success(t, s, "DescribeEventBus", map[string]any{"Name": "mixed-bus"})
			var text string
			if err := json.Unmarshal(out["Policy"], &text); err != nil {
				t.Fatal(err)
			}
			var document struct{ Statement []struct{ Sid string } }
			if err := json.Unmarshal([]byte(text), &document); err != nil {
				t.Fatal(err)
			}
			if len(document.Statement) != 2 || document.Statement[0].Sid != "managed" || document.Statement[1].Sid != "independent" {
				t.Fatalf("rejected %s erased a statement: %s", action, text)
			}
		}
		// The failed whole-policy changes must preserve the independent claim,
		// not merely retain the statement and make it adoptable by another owner.
		if _, err := cfnEventCommand(t, s, "EventBusPolicy", "intruder", "independent", "RemovePermission", map[string]any{"EventBusName": "mixed-bus", "StatementId": "independent"}); err == nil {
			t.Fatal("independent claim was erased")
		}
		if _, err := cfnEventCommand(t, s, "EventBusPolicy", "independent-owner", "independent", "RemovePermission", map[string]any{"EventBusName": "mixed-bus", "StatementId": "independent"}); err != nil {
			t.Fatal(err)
		}
		if _, err := cfnEventCommand(t, s, "EventBus", owner, "", "RemovePermission", map[string]any{"EventBusName": "mixed-bus", "RemoveAllPermissions": true}); err != nil {
			t.Fatal(err)
		}
	})
}

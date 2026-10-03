package ec2

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

type screenshotPolicies string

func (p screenshotPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []policy.Policy{{Document: string(p)}}}, nil
}

type screenshotAudit struct{ call journal.APICallCompleted }

func (a *screenshotAudit) Record(_ context.Context, _ journal.Envelope, call journal.APICallCompleted) error {
	a.call = call
	return nil
}

func TestNativeConsoleScreenshotAdmissionAndAudit(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/ec2/console_screenshot_boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Account, Region string
		LauncherRole    string `json:"launcher_role"`
		Sessions        map[string]json.RawMessage
		Calls           []struct {
			Label, Operation, Code, Caller string
			Input, Output                  json.RawMessage
		}
		CloudTrail struct {
			Events []struct {
				Label string `json:"call_label"`
				Event struct {
					RequestParameters, ResponseElements any
					ReadOnly                            bool
					ErrorCode                           string
				}
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var instance api.Instance
	var basePolicy string
	for _, call := range fixture.Calls {
		if call.Operation == "RunInstances" && call.Code == "Success" {
			var output struct{ Instances []api.Instance }
			if err := json.Unmarshal(call.Output, &output); err != nil {
				t.Fatal(err)
			}
			instance = output.Instances[0]
		}
		if call.Label == "owned-screenshot-policy" {
			var input struct{ PolicyDocument string }
			if err := json.Unmarshal(call.Input, &input); err != nil {
				t.Fatal(err)
			}
			basePolicy = input.PolicyDocument
		}
	}
	if instance.InstanceId == nil || basePolicy == "" {
		t.Fatal("native fixture has no owned guest or bounded IAM policy")
	}
	for _, call := range fixture.Calls {
		if call.Operation != "GetConsoleScreenshot" {
			continue
		}
		t.Run(call.Label, func(t *testing.T) {
			var input api.GetConsoleScreenshotRequest
			if err := json.Unmarshal(call.Input, &input); err != nil {
				t.Fatal(err)
			}
			// The shared instance-ID validator explicitly does not implement
			// AWS's opaque long-ID encoding. Do not special-case a zero ID here.
			if call.Code == "InvalidInstanceID.Malformed" && len(str(input.InstanceId)) == 19 {
				t.Skip("shared opaque long-ID admission remains outside screenshot semantics")
			}
			audit := &screenshotAudit{}
			service := New(Config{Authorizer: authorization.New(screenshotPolicies(basePolicy), nil), Recorder: audit})
			t.Cleanup(func() {
				if err := service.Close(); err != nil {
					t.Error(err)
				}
			})
			metadata := awsctx.Metadata{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region,
				PrincipalARN: "arn:aws:iam::" + fixture.Account + ":root", PrincipalID: fixture.Account}
			if document, ok := fixture.Sessions[call.Caller]; ok {
				metadata.PrincipalARN = "arn:aws:sts::" + fixture.Account + ":assumed-role/" + fixture.LauncherRole + "/" + call.Caller
				metadata.PrincipalID = "screenshot-role:" + call.Caller
				metadata.IssuerARN = "arn:aws:iam::" + fixture.Account + ":role/" + fixture.LauncherRole
				metadata.IssuerID = "screenshot-role"
				metadata.SessionType = "AssumeRole"
				metadata.HasSessionPolicy = true
				metadata.SessionPolicies = []string{string(document)}
			}
			ctx := awsctx.WithMetadata(t.Context(), metadata)
			record := InstanceRecord{Key: key(ctx, str(instance.InstanceId)), Data: instance}
			state := "running"
			switch {
			case call.Label == "pending":
				state = "pending"
			case call.Label == "stopping":
				state = "stopping"
			case strings.HasPrefix(call.Label, "stopped"):
				state = "stopped"
			case strings.HasPrefix(call.Label, "terminated"):
				state = "terminated"
			}
			record.Data.State = instanceStateValue(state)
			if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutInstance(record) }); err != nil {
				t.Fatal(err)
			}
			if call.Label == "other-region" {
				metadata.Region = "us-west-2"
				ctx = awsctx.WithMetadata(t.Context(), metadata)
			}
			var admitted InstanceRecord
			callErr := service.repository.View(ctx, func(tx Reader) error {
				var err error
				admitted, err = service.admitConsoleScreenshot(ctx, tx, &input)
				return err
			})
			var rejected *awswire.Error
			if callErr != nil {
				rejected = wireError(callErr)
			}
			if call.Code == "Success" {
				if callErr != nil || admitted.Key != record.Key {
					t.Fatalf("native screenshot target not admitted: record=%+v error=%v", admitted.Key, callErr)
				}
			} else if rejected == nil || rejected.Code != call.Code {
				t.Fatalf("screenshot error=%v, native code=%s", callErr, call.Code)
			}
			var output api.GetConsoleScreenshotResult
			if len(call.Output) != 0 {
				if err := json.Unmarshal(call.Output, &output); err != nil {
					t.Fatal(err)
				}
			}
			if err := service.recordCall(ctx, "GetConsoleScreenshot", &input, &output, rejected); err != nil {
				t.Fatal(err)
			}
			for _, native := range fixture.CloudTrail.Events {
				if native.Label != call.Label {
					continue
				}
				var request, response any
				if len(audit.call.RequestParameters) != 0 {
					if err := json.Unmarshal(audit.call.RequestParameters, &request); err != nil {
						t.Fatal(err)
					}
				}
				if len(audit.call.ResponseElements) != 0 {
					if err := json.Unmarshal(audit.call.ResponseElements, &response); err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(request, native.Event.RequestParameters) || !reflect.DeepEqual(response, native.Event.ResponseElements) || audit.call.ReadOnly != native.Event.ReadOnly || audit.call.ErrorCode != native.Event.ErrorCode {
					t.Fatalf("native screenshot audit mismatch: request=%v response=%v readonly=%v error=%s; native=%+v", request, response, audit.call.ReadOnly, audit.call.ErrorCode, native.Event)
				}
				return
			}
			if call.Label != "other-region" {
				t.Fatal("missing regional native audit fixture")
			}
		})
	}
}

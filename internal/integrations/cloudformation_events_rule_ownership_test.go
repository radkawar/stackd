package integrations

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/eventbridge"
)

const cfnRuleQueue = "arn:aws:sqs:us-east-1:123456789012:rule-queue"

func cfnRuleRequest(token string) cloudformation.ResourceRequest {
	r := cfnWorkflowOwnerRequest("AWS::Events::Rule", "OwnedRule", cloudformation.Properties{
		"Name": "owned-rule", "Description": "initial", "EventPattern": map[string]any{"source": []any{"test"}},
		"Targets": []any{map[string]any{"Id": "queue", "Arn": cfnRuleQueue}},
	})
	if token != "" {
		r.Token = token
	}
	return r
}

type cfnRuleState struct {
	Rule    eventbridge.RuleRecord
	Targets []eventbridge.TargetRecord
}

func (f *cfnEventPolicyFixture) rule(t *testing.T, name string) (cfnRuleState, bool) {
	t.Helper()
	key := eventbridge.RuleKey{Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: "default"}, Name: name}
	var state cfnRuleState
	found := true
	if err := f.repository.View(f.ctx, func(reader eventbridge.Reader) error {
		var err error
		state.Rule, err = reader.Rule(key)
		if errors.Is(err, eventbridge.ErrNotFound) {
			found = false
			return nil
		}
		if err != nil {
			return err
		}
		state.Targets, err = reader.Targets(key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return state, found
}

func cfnRuleCreate(t *testing.T, f *cfnEventPolicyFixture, r cloudformation.ResourceRequest) cloudformation.ResourceRequest {
	t.Helper()
	created, err := (cfnEventRule{f.commands}).Create(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = created.PhysicalID
	return r
}

type cfnRuleLostReply struct {
	*eventbridge.Service
	lose bool
}

func (e *cfnRuleLostReply) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.Service.ExecuteCommand(ctx, request)
	if err == nil && e.lose && string(request.Operation.Name) == "PutRule" {
		e.lose = false
		return nil, &awswire.Error{Code: "ValidationException", Message: "lost admitted rule reply", StatusCode: 400}
	}
	return out, err
}

func TestCFNEventRuleLostReplyRecoversExactPrivateIncarnation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, cc := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cc=%t", backend, cc), func(t *testing.T) {
				f := newCFNEventPolicyFixture(t, backend)
				lossy := cfnEventRule{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"eventbridge": &cfnRuleLostReply{Service: f.owner, lose: true}})}
				r := cfnRuleRequest("")
				r.CloudControl = cc
				admitted, err := lossy.Create(f.ctx, r)
				if err == nil || admitted.PhysicalID != "owned-rule" {
					t.Fatalf("lost native reply discarded admitted rule: %+v %v", admitted, err)
				}
				f.reopen(t)
				h := cfnEventRule{f.commands}
				state, found := f.rule(t, "owned-rule")
				if !found || state.Rule.CFNOwner != cfnMessagingMarker(r) || len(state.Targets) != 0 {
					t.Fatalf("native admission did not atomically store exact private claim: %+v", state)
				}
				if out, err := h.RecoverCreation(f.ctx, r); err != nil || out.PhysicalID != admitted.PhysicalID {
					t.Fatalf("private rule recovery failed: %+v %v", out, err)
				}
				if out, err := h.Create(f.ctx, r); err != nil || out.PhysicalID != admitted.PhysicalID {
					t.Fatalf("same-token replay failed to converge: %+v %v", out, err)
				}
				state, _ = f.rule(t, "owned-rule")
				if state.Rule.CFNOwner != cfnMessagingMarker(r) || len(state.Targets) != 1 {
					t.Fatalf("replay changed claim or skipped targets: %+v", state)
				}
				foreign := r
				foreign.Token = "foreign-incarnation"
				if out, err := h.Create(f.ctx, foreign); err == nil || out.PhysicalID != "" {
					t.Fatalf("foreign create adopted admitted rule: %+v %v", out, err)
				}
				if out, err := h.RecoverCreation(f.ctx, foreign); err == nil || out.PhysicalID != "" {
					t.Fatalf("foreign recovery adopted admitted rule: %+v %v", out, err)
				}
				if after, _ := f.rule(t, "owned-rule"); !reflect.DeepEqual(state, after) {
					t.Fatal("foreign create changed native rule")
				}
				r.PhysicalID, r.CloudControl = admitted.PhysicalID, false
				if err := h.Delete(f.ctx, r); err != nil {
					t.Fatal(err)
				}
				if _, err := h.RecoverCreation(f.ctx, r); !cfnComputeMissing(err) {
					t.Fatalf("exact cleanup left rule: %v", err)
				}
			})
		}
	}
}

func TestCFNEventRuleCreateCannotAdoptUnclaimedOrCopiedTagRule(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, cc := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cc=%t", backend, cc), func(t *testing.T) {
				f := newCFNEventPolicyFixture(t, backend)
				r := cfnRuleRequest("")
				r.CloudControl = cc
				f.native(t, "PutRule", map[string]any{"Name": "owned-rule", "EventPattern": `{"source":["native"]}`, "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))})
				f.reopen(t)
				before, _ := f.rule(t, "owned-rule")
				h := cfnEventRule{f.commands}
				if out, err := h.Create(f.ctx, r); err == nil || out.PhysicalID != "" {
					t.Fatalf("copied public tags adopted unclaimed native rule: %+v %v", out, err)
				}
				if out, err := h.RecoverCreation(f.ctx, r); err == nil || out.PhysicalID != "" {
					t.Fatalf("copied public tags recovered unclaimed native rule: %+v %v", out, err)
				}
				r.PhysicalID = "owned-rule"
				if err := h.Delete(f.ctx, r); !cc && err == nil {
					t.Fatal("copied public tags let controller delete unclaimed rule")
				}
				if !cc {
					if after, _ := f.rule(t, "owned-rule"); !reflect.DeepEqual(before, after) || after.Rule.CFNOwner != "" {
						t.Fatal("rejected controller mutation changed or claimed native rule")
					}
				}
			})
		}
	}
}

func TestCFNEventRuleNativeUpdatesPreserveButRecreationClearsClaim(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			r := cfnRuleCreate(t, f, cfnRuleRequest(""))
			arn := "arn:aws:events:us-east-1:123456789012:rule/owned-rule"
			if tags, err := cfnEventTags(f.ctx, f.commands, arn); err != nil || len(tags) != 0 {
				t.Fatalf("private admission emitted public markers: %#v %v", tags, err)
			}
			claim := cfnMessagingMarker(r)
			f.native(t, "PutRule", map[string]any{"Name": "owned-rule", "Description": "native", "EventPattern": `{"source":["native"]}`})
			f.native(t, "DisableRule", map[string]any{"Name": "owned-rule"})
			f.native(t, "EnableRule", map[string]any{"Name": "owned-rule"})
			f.native(t, "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(map[string]string{"team": "native"})})
			f.native(t, "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": []string{"team"}})
			f.native(t, "PutTargets", map[string]any{"Rule": "owned-rule", "Targets": []any{map[string]any{"Id": "native", "Arn": cfnRuleQueue}}})
			f.native(t, "RemoveTargets", map[string]any{"Rule": "owned-rule", "Ids": []string{"native"}})
			f.reopen(t)
			if state, _ := f.rule(t, "owned-rule"); state.Rule.CFNOwner != claim {
				t.Fatal("ordinary native mutation replaced private rule claim")
			}
			h := cfnEventRule{f.commands}
			// An unchanged update is a no-op that still rechecks the private claim.
			r.Previous = r.Properties
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if state, _ := f.rule(t, "owned-rule"); state.Rule.CFNOwner != claim || state.Rule.Description != "initial" || len(state.Targets) != 1 {
				t.Fatalf("authentic update did not converge under retained claim: %+v", state)
			}
			f.native(t, "RemoveTargets", map[string]any{"Rule": "owned-rule", "Ids": []string{"queue"}})
			f.native(t, "DeleteRule", map[string]any{"Name": "owned-rule"})
			f.native(t, "PutRule", map[string]any{"Name": "owned-rule", "Description": "replacement", "EventPattern": `{"source":["replacement"]}`})
			f.native(t, "PutTargets", map[string]any{"Rule": "owned-rule", "Targets": []any{map[string]any{"Id": "replacement", "Arn": cfnRuleQueue}}})
			f.native(t, "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))})
			f.reopen(t)
			h = cfnEventRule{f.commands}
			replacement, _ := f.rule(t, "owned-rule")
			if replacement.Rule.CFNOwner != "" {
				t.Fatal("same-name native recreation inherited private claim")
			}
			if _, err := h.Update(f.ctx, r); err == nil {
				t.Fatal("stale stack updated native replacement")
			}
			if err := h.Delete(f.ctx, r); err == nil {
				t.Fatal("stale stack deleted native replacement")
			}
			if _, err := h.RecoverCreation(f.ctx, r); err == nil {
				t.Fatal("stale stack recovered native replacement")
			}
			// The stale parent's target and tag transactions are fenced by the
			// native owner itself, not only by the controller's earlier read.
			stale := eventbridge.WithCloudFormationOwner(f.ctx, "Rule", claim, "")
			for _, action := range []struct {
				name  string
				input map[string]any
			}{
				{"PutTargets", map[string]any{"Rule": "owned-rule", "Targets": []any{map[string]any{"Id": "stale", "Arn": cfnRuleQueue}}}},
				{"RemoveTargets", map[string]any{"Rule": "owned-rule", "Ids": []string{"replacement"}}},
				{"TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(map[string]string{"stale": "parent"})}},
				{"UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": []string{"stackd:cloudformation:incarnation"}}},
				{"DisableRule", map[string]any{"Name": "owned-rule"}},
				{"PutRule", map[string]any{"Name": "owned-rule", "EventPattern": `{"source":["stale"]}`}},
				{"DeleteRule", map[string]any{"Name": "owned-rule"}},
			} {
				var wire *awswire.Error
				if err := cfnComputeRun(stale, f.commands, "eventbridge", action.name, action.input); !errors.As(err, &wire) || wire.Code != "ResourceAlreadyExistsException" {
					t.Fatalf("%s from stale parent incarnation was not fenced natively: %v", action.name, err)
				}
			}
			if after, _ := f.rule(t, "owned-rule"); !reflect.DeepEqual(replacement, after) {
				t.Fatal("stale parent changed native replacement rule or targets")
			}
		})
	}
}

func TestCFNEventRuleRemovedAndForgedTagsDoNotAffectPrivateClaim(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			r := cfnRuleCreate(t, f, cfnRuleRequest(""))
			arn := "arn:aws:events:us-east-1:123456789012:rule/owned-rule"
			forged := r
			forged.Token = "counterfeit-incarnation"
			f.native(t, "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(cfnComputeOwnedTags(forged))})
			f.reopen(t)
			h := cfnEventRule{f.commands}
			if out, err := h.RecoverCreation(f.ctx, forged); err == nil || out.PhysicalID != "" {
				t.Fatalf("forged public tags granted rule recovery: %+v %v", out, err)
			}
			if err := h.Delete(f.ctx, forged); err == nil {
				t.Fatal("forged public tags deleted privately owned rule")
			}
			r.Previous, r.Properties = r.Properties, cloudformation.Properties{"Name": "owned-rule", "Description": "authentic", "EventPattern": r.Properties["EventPattern"], "Targets": r.Properties["Targets"], "Tags": []any{map[string]any{"Key": "team", "Value": "rules"}}}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatalf("forged public tags revoked authentic update: %v", err)
			}
			tags, err := cfnEventTags(f.ctx, f.commands, arn)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tags, map[string]string{"team": "rules"}) {
				t.Fatalf("rule tags did not converge to customer metadata: %#v", tags)
			}
			f.native(t, "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": []string{"team"}})
			f.reopen(t)
			h = cfnEventRule{f.commands}
			if out, err := h.RecoverCreation(f.ctx, r); err != nil || out.PhysicalID != "owned-rule" {
				t.Fatalf("tag removal revoked private recovery: %+v %v", out, err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatalf("tag removal revoked private cleanup: %v", err)
			}
			if _, found := f.rule(t, "owned-rule"); found {
				t.Fatal("private cleanup left rule")
			}
		})
	}
}

func TestCFNEventRuleRecoveryAndNoOpRecheckCurrentIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			out, err := cfnComputeCall[iamapi.CreateUserOutput](f.ctx, f.commands, "iam", "CreateUser", map[string]any{"UserName": "event-rule-owner"})
			if err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(f.ctx, f.commands, "iam", "PutUserPolicy", map[string]any{"UserName": "event-rule-owner", "PolicyName": "events", "PolicyDocument": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"events:*","Resource":"*"}}`}); err != nil {
				t.Fatal(err)
			}
			metadata := awsctx.FromContext(f.ctx)
			metadata.PrincipalARN, metadata.PrincipalID = cfnComputeValue(out.User.Arn), cfnComputeValue(out.User.UserId)
			user := awsctx.WithMetadata(f.ctx, metadata)
			h := cfnEventRule{f.commands}
			r := cfnRuleRequest("")
			created, err := h.Create(user, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			if err := cfnComputeRun(f.ctx, f.commands, "iam", "DeleteUserPolicy", map[string]any{"UserName": "event-rule-owner", "PolicyName": "events"}); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			h = cfnEventRule{f.commands}
			before, _ := f.rule(t, "owned-rule")
			r.Previous = r.Properties
			foreign := r
			foreign.Token = "foreign"
			for _, action := range []string{"create", "recover", "update", "delete", "foreign-delete"} {
				var rejected error
				switch action {
				case "create":
					_, rejected = h.Create(user, r)
				case "recover":
					_, rejected = h.RecoverCreation(user, r)
				case "update":
					_, rejected = h.Update(user, r)
				case "delete":
					rejected = h.Delete(user, r)
				case "foreign-delete":
					rejected = h.Delete(user, foreign)
				}
				var wire *awswire.Error
				if !errors.As(rejected, &wire) || wire.Code != "AccessDeniedException" {
					t.Fatalf("%s used private incarnation instead of current IAM: %v", action, rejected)
				}
			}
			if after, _ := f.rule(t, "owned-rule"); !reflect.DeepEqual(before, after) {
				t.Fatal("revoked IAM changed private/native rule state")
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNEventRulePrivateClaimRequiresExactCurrentScope(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			r := cfnRuleCreate(t, f, cfnRuleRequest(""))
			before, _ := f.rule(t, "owned-rule")
			r.Properties["EventBusName"] = "arn:aws:events:us-east-1:123456789012:event-bus/default"
			metadata := awsctx.FromContext(f.ctx)
			metadata.AccountID, metadata.PrincipalARN, metadata.PrincipalID = "999999999999", "arn:aws:iam::999999999999:root", "999999999999"
			ctx := awsctx.WithMetadata(f.ctx, metadata)
			r.Scope.Account = "999999999999"
			h := cfnEventRule{f.commands}
			if _, err := h.Create(ctx, r); err == nil {
				t.Fatal("private rule claim crossed current account")
			}
			if _, err := h.RecoverCreation(ctx, r); err == nil {
				t.Fatal("private rule recovery crossed current account")
			}
			if err := h.Delete(ctx, r); err == nil || strings.Contains(err.Error(), "ResourceNotFound") {
				t.Fatalf("private rule deletion crossed current account: %v", err)
			}
			if after, _ := f.rule(t, "owned-rule"); !reflect.DeepEqual(before, after) {
				t.Fatal("out-of-scope controller changed native rule")
			}
		})
	}
}

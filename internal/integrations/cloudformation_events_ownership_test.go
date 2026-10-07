package integrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	eventsapi "stackd/internal/awsapi/eventbridge"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	eventstore "stackd/storage/sqlite/eventbridge"
)

func cfnWorkflowOwnerContext(t *testing.T) context.Context {
	t.Helper()
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
}
func cfnWorkflowOwnerRequest(kind, name string, properties cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{Type: kind, StackID: "workflow-stack", StackName: "workflow", LogicalID: name, Token: name + "-incarnation", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Properties: properties}
}
func cfnWorkflowBusPolicy(sid string) map[string]any {
	return map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Sid": sid, "Effect": "Allow", "Principal": "*", "Action": "events:PutEvents", "Resource": "*"}}}
}
func cfnWorkflowBusSIDs(t *testing.T, h cfnEventBus, ctx context.Context, r cloudformation.ResourceRequest) []string {
	t.Helper()
	out, err := cfnComputeCall[eventsapi.DescribeEventBusOutput](ctx, h.commands, "eventbridge", "DescribeEventBus", map[string]any{"Name": r.PhysicalID})
	if err != nil {
		t.Fatal(err)
	}
	if cfnComputeValue(out.Policy) == "" {
		return nil
	}
	var document struct{ Statement []struct{ Sid string } }
	if err := json.Unmarshal([]byte(cfnComputeValue(out.Policy)), &document); err != nil {
		t.Fatal(err)
	}
	var sids []string
	for _, statement := range document.Statement {
		sids = append(sids, statement.Sid)
	}
	return sids
}

func TestCFNEventBusUnrelatedUpdatesPreserveIndependentPolicies(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			ctx, commands := f.ctx, f.commands
			h := cfnEventBus{commands}
			initial := cloudformation.Properties{"Name": "owned-bus", "Description": "initial", "Policy": cfnWorkflowBusPolicy("managed")}
			r := cfnWorkflowOwnerRequest("AWS::Events::EventBus", "Bus", initial)
			created, err := h.Create(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			independent := cfnWorkflowOwnerRequest("AWS::Events::EventBusPolicy", "Independent", cloudformation.Properties{"EventBusName": r.PhysicalID, "StatementId": "independent", "Action": "events:PutEvents", "Principal": "*"})
			p := cfnEventBusPolicy{commands}
			admitted, err := p.Create(ctx, independent)
			if err != nil {
				t.Fatal(err)
			}
			independent.PhysicalID = admitted.PhysicalID
			f.reopen(t)
			commands = f.commands
			h, p = cfnEventBus{commands}, cfnEventBusPolicy{commands}
			privateBefore := f.row(t, "owned-bus")
			if privateBefore.CFNOwner != cfnMessagingMarker(r) || privateBefore.PolicyStatementOwners["independent"].CFNOwner != cfnMessagingMarker(independent) {
				t.Fatal("mixed native ownership did not survive reopen")
			}
			arn := created.Attributes["Arn"].(string)
			before, err := cfnEventTags(ctx, commands, arn)
			if err != nil {
				t.Fatal(err)
			}
			r.Previous = initial
			r.Properties = cloudformation.Properties{"Name": "owned-bus", "Description": "unrelated", "Policy": initial["Policy"], "Tags": []any{map[string]any{"Key": "team", "Value": "workflow"}}}
			if _, err := h.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			if got := cfnWorkflowBusSIDs(t, h, ctx, r); !reflect.DeepEqual(got, []string{"managed", "independent"}) {
				t.Fatalf("unrelated update rewrote policies: %v", got)
			}
			after, err := cfnEventTags(ctx, commands, arn)
			if err != nil {
				t.Fatal(err)
			}
			if len(before) != 0 {
				t.Fatalf("private bus/policy admission emitted public owner markers: %#v", before)
			}
			privateAfter := f.row(t, "owned-bus")
			if privateAfter.CFNOwner != privateBefore.CFNOwner || !reflect.DeepEqual(privateAfter.PolicyStatementOwners, privateBefore.PolicyStatementOwners) {
				t.Fatal("unrelated update changed private incarnation metadata")
			}
			if after["team"] != "workflow" {
				t.Fatal("unrelated tags did not converge")
			}
			// Both mixed-owner replacement and removal are rejected before changing the
			// bus configuration, tags, policy, or independently held statement claims.
			current := r.Properties
			changedIndependent := map[string]any{"Version": "2012-10-17", "Statement": []any{cfnWorkflowBusPolicy("managed")["Statement"].([]any)[0], map[string]any{"Sid": "independent", "Effect": "Deny", "Principal": "*", "Action": "events:PutEvents", "Resource": "*"}}}
			for _, policy := range []any{cfnWorkflowBusPolicy("replacement"), changedIndependent, nil} {
				r.Previous = current
				r.Properties = cloudformation.Properties{"Name": "owned-bus", "Description": "must-not-change"}
				if policy != nil {
					r.Properties["Policy"] = policy
				}
				if _, err := h.Update(ctx, r); err == nil {
					t.Fatal("mixed-owner full-policy change accepted")
				}
				live, err := h.Read(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				if live["Description"] != "unrelated" {
					t.Fatalf("rejected update changed bus configuration: %#v", live)
				}
				tags, err := cfnEventTags(ctx, commands, arn)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(tags, after) {
					t.Fatalf("rejected update changed claims/tags: %#v", tags)
				}
				if got := cfnWorkflowBusSIDs(t, h, ctx, r); !reflect.DeepEqual(got, []string{"managed", "independent"}) {
					t.Fatalf("rejected update changed policies: %v", got)
				}
			}
			replay := r
			replay.Properties = initial
			replay.Previous = nil
			recovered, err := h.Create(ctx, replay)
			if err == nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("same-token replay lost admitted bus on policy rejection: %+v %v", recovered, err)
			}
			if err := p.Delete(ctx, independent); err != nil {
				t.Fatal(err)
			}
			f.native(t, "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(map[string]string{cfnEventPolicyForgedTag("unclaimed"): "counterfeit-owner"})})
			r.Previous = current
			r.Properties = cloudformation.Properties{"Name": "owned-bus", "Description": "replacement", "Policy": cfnWorkflowBusPolicy("replacement")}
			if _, err := h.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			if got := cfnWorkflowBusSIDs(t, h, ctx, r); !reflect.DeepEqual(got, []string{"replacement"}) {
				t.Fatalf("policy replacement did not converge: %v", got)
			}
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"Name": "owned-bus"}
			if _, err := h.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			if got := cfnWorkflowBusSIDs(t, h, ctx, r); len(got) != 0 {
				t.Fatalf("policy removal did not converge: %v", got)
			}
			r.Previous = r.Properties
			r.Properties = initial
			if _, err := h.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			if got := cfnWorkflowBusSIDs(t, h, ctx, r); !reflect.DeepEqual(got, []string{"managed"}) {
				t.Fatalf("policy rollback did not converge: %v", got)
			}
		})
	}
}

type cfnWorkflowLostEventReply struct {
	*eventbridge.Service
	lose bool
}

func (e *cfnWorkflowLostEventReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.Service.ExecuteCommand(ctx, r)
	if err == nil && e.lose && string(r.Operation.Name) == "CreateEventBus" {
		e.lose = false
		return nil, &awswire.Error{Code: "ValidationException", Message: "lost admitted create reply", StatusCode: 400}
	}
	return out, err
}
func TestCFNEventBusAdmittedErrorRetainsPrivateIncarnation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := cfnWorkflowOwnerContext(t)
			source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
			var repository eventbridge.Repository = eventbridge.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "workflow.sqlite")
			open := func() {
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repository = eventstore.New(db)
			}
			if backend == "sqlite" {
				open()
			}
			owner := eventbridge.NewWithConfig(eventbridge.Config{Repository: repository, Clock: source})
			t.Cleanup(func() {
				_ = owner.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			executor := &cfnWorkflowLostEventReply{Service: owner, lose: true}
			h := cfnEventBus{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"eventbridge": executor})}
			r := cfnWorkflowOwnerRequest("AWS::Events::EventBus", "CCBus", cloudformation.Properties{"Name": "cc-bus"})
			r.CloudControl = true
			created, err := h.Create(ctx, r)
			if err == nil || created.PhysicalID != "cc-bus" {
				t.Fatalf("lost modeled reply discarded admitted ID: %+v %v", created, err)
			}
			if backend == "sqlite" {
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				open()
				owner = eventbridge.NewWithConfig(eventbridge.Config{Repository: repository, Clock: source})
				h = cfnEventBus{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"eventbridge": owner})}
			}
			recovered, err := h.RecoverCreation(ctx, r)
			if err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("private create claim did not survive recovery: %+v %v", recovered, err)
			}
			replayed, err := h.Create(ctx, r)
			if err != nil || replayed.PhysicalID != created.PhysicalID {
				t.Fatalf("same-token CC create replay changed ownership: %+v %v", replayed, err)
			}
			foreign := r
			foreign.Token = "foreign-incarnation"
			// Public tags cannot manufacture the private native incarnation authority.
			if err := cfnComputeRun(ctx, h.commands, "eventbridge", "TagResource", map[string]any{"ResourceARN": created.Attributes["Arn"], "Tags": cfnComputeTagList(cfnComputeOwnedTags(foreign))}); err != nil {
				t.Fatal(err)
			}
			rejected, err := h.Create(ctx, foreign)
			if err == nil || rejected.PhysicalID != "" {
				t.Fatalf("foreign CC create adopted existing bus: %+v %v", rejected, err)
			}
			rejected, err = h.RecoverCreation(ctx, foreign)
			if err == nil || rejected.PhysicalID != "" {
				t.Fatalf("public tags forged native recovery claim: %+v %v", rejected, err)
			}
			r.PhysicalID = created.PhysicalID
			if err := h.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := h.RecoverCreation(ctx, r); !cfnComputeMissing(err) {
				t.Fatalf("rollback failed to delete exact admitted bus: %v", err)
			}
		})
	}
}

type cfnEventPolicyFixture struct {
	ctx        context.Context
	path       string
	db         *sql.DB
	repository eventbridge.Repository
	source     *clock.Manual
	identities *iam.Service
	authorizer authorization.Authorizer
	owner      *eventbridge.Service
	commands   StepFunctionsCommands
	policy     cfnEventBusPolicy
}

func newCFNEventPolicyFixture(t *testing.T, backend string) *cfnEventPolicyFixture {
	t.Helper()
	domain := memory.NewDomain()
	f := &cfnEventPolicyFixture{ctx: cfnWorkflowOwnerContext(t), source: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC)), repository: eventbridge.NewMemoryRepository(domain)}
	identities := iam.NewMemoryRepository(domain)
	credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(identities, nil), Clock: f.source})
	f.identities = iam.NewWithConfig(iam.Config{Repository: identities, Credentials: credentials, Clock: f.source})
	f.authorizer = authorization.NewWithClock(f.identities, nil, f.source)
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "event-policy.sqlite")
		f.open(t)
	}
	f.start()
	t.Cleanup(func() {
		_ = f.owner.Close()
		_ = f.identities.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}

func (f *cfnEventPolicyFixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.db, err = sqlite.Open(f.ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.repository = eventstore.New(f.db)
}

func (f *cfnEventPolicyFixture) start() {
	f.owner = eventbridge.NewWithConfig(eventbridge.Config{Repository: f.repository, Clock: f.source, Authorizer: f.authorizer})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"eventbridge": f.owner, "iam": f.identities})
	f.policy = cfnEventBusPolicy{f.commands}
}

func (f *cfnEventPolicyFixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			t.Fatal(err)
		}
		f.open(t)
	}
	f.start()
}

func (f *cfnEventPolicyFixture) native(t *testing.T, action string, input map[string]any) {
	t.Helper()
	if err := cfnComputeRun(f.ctx, f.commands, "eventbridge", action, input); err != nil {
		t.Fatal(err)
	}
}

func (f *cfnEventPolicyFixture) row(t *testing.T, name string) eventbridge.BusRecord {
	t.Helper()
	var bus eventbridge.BusRecord
	if err := f.repository.View(f.ctx, func(reader eventbridge.Reader) error {
		var err error
		bus, err = reader.Bus(eventbridge.BusKey{Scope: eventbridge.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: name})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return bus
}

func cfnEventPolicyRequest(sid string, full bool) cloudformation.ResourceRequest {
	properties := cloudformation.Properties{"EventBusName": "private-policy-bus", "StatementId": sid, "Action": "events:PutEvents", "Principal": "*"}
	if full {
		delete(properties, "Action")
		delete(properties, "Principal")
		properties["Statement"] = map[string]any{"Effect": "Allow", "Principal": "*", "Action": "events:PutEvents", "Resource": "*"}
	}
	return cfnWorkflowOwnerRequest("AWS::Events::EventBusPolicy", sid, properties)
}

// This is the obsolete public marker format, reproduced only to attack it.
func cfnEventPolicyForgedTag(sid string) string {
	sum := sha256.Sum256([]byte(sid))
	return fmt.Sprintf("stackd:cloudformation:policy-%x", sum[:16])
}

func TestCFNEventBusPolicyPrivateClaimsIgnorePublicMarkers(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			f.native(t, "CreateEventBus", map[string]any{"Name": "private-policy-bus"})
			arn := "arn:aws:events:us-east-1:123456789012:event-bus/private-policy-bus"
			foreign := cfnEventPolicyRequest("foreign", false)
			f.native(t, "PutPermission", map[string]any{"EventBusName": "private-policy-bus", "StatementId": "foreign", "Action": "events:PutEvents", "Principal": "111122223333"})
			tags := cfnComputeOwnedTags(foreign)
			tags[cfnEventPolicyForgedTag("foreign")] = cfnMessagingMarker(foreign)
			f.native(t, "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(tags)})
			f.reopen(t)
			before := f.row(t, "private-policy-bus")
			if len(before.PolicyStatementOwners) != 0 {
				t.Fatal("public marker was backfilled into private authority")
			}
			for _, full := range []bool{false, true} {
				attack := cfnEventPolicyRequest("foreign", full)
				out, err := f.policy.Create(f.ctx, attack)
				if err == nil || out.PhysicalID != "" {
					t.Fatalf("public marker adopted foreign same-Sid statement: %+v %v", out, err)
				}
			}
			if out, err := f.policy.RecoverCreation(f.ctx, foreign); err == nil || out.PhysicalID != "" {
				t.Fatalf("public marker recovered foreign statement: %+v %v", out, err)
			}
			if err := f.policy.Delete(f.ctx, foreign); err == nil {
				t.Fatal("public marker deleted foreign statement")
			}
			if !reflect.DeepEqual(before, f.row(t, "private-policy-bus")) {
				t.Fatal("forged-owner mutation changed native policy or tags")
			}
			owned := cfnEventPolicyRequest("owned", false)
			admitted, err := f.policy.Create(f.ctx, owned)
			if err != nil {
				t.Fatal(err)
			}
			owned.PhysicalID = admitted.PhysicalID
			current, err := cfnEventTags(f.ctx, f.commands, arn)
			if err != nil {
				t.Fatal(err)
			}
			if current[cfnEventPolicyForgedTag("owned")] != "" {
				t.Fatal("private admission emitted a public statement-owner marker")
			}
			keys := []string{}
			for key := range current {
				keys = append(keys, key)
			}
			f.native(t, "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": keys})
			f.reopen(t)
			if _, err := f.policy.RecoverCreation(f.ctx, owned); err != nil {
				t.Fatalf("public marker removal revoked private recovery: %v", err)
			}
			forged := owned
			forged.Token = "counterfeit-incarnation"
			f.native(t, "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(map[string]string{cfnEventPolicyForgedTag("owned"): cfnMessagingMarker(forged)})})
			owned.Properties["Principal"] = "222233334444"
			if _, err := f.policy.Update(f.ctx, owned); err != nil {
				t.Fatalf("forged marker revoked authentic update: %v", err)
			}
			if err := f.policy.Delete(f.ctx, forged); err == nil {
				t.Fatal("forged marker deleted privately owned statement")
			}
			if err := f.policy.Delete(f.ctx, owned); err != nil {
				t.Fatalf("public marker mutation revoked private cleanup: %v", err)
			}
			if got := f.row(t, "private-policy-bus"); len(got.PolicyStatementOwners) != 0 || !strings.Contains(got.Policy.Document, `"foreign"`) {
				t.Fatal("cleanup erased foreign neighboring policy or retained stale private claim")
			}
		})
	}
}

func TestCFNEventBusPolicyNativeUpdatesPreserveButRecreationClearsClaims(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			f.native(t, "CreateEventBus", map[string]any{"Name": "private-policy-bus"})
			r := cfnEventPolicyRequest("owned", true)
			admitted, err := f.policy.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = admitted.PhysicalID
			claim := f.row(t, "private-policy-bus").PolicyStatementOwners["owned"]
			if claim.CFNOwner != cfnMessagingMarker(r) {
				t.Fatal("native statement did not store exact private claim")
			}
			f.native(t, "PutPermission", map[string]any{"EventBusName": "private-policy-bus", "StatementId": "owned", "Action": "events:PutEvents", "Principal": "111122223333"})
			document, err := cfnComputeDocument(cfnWorkflowBusPolicy("owned"))
			if err != nil {
				t.Fatal(err)
			}
			f.native(t, "PutPermission", map[string]any{"EventBusName": "private-policy-bus", "Policy": document})
			f.reopen(t)
			if got := f.row(t, "private-policy-bus").PolicyStatementOwners["owned"]; got != claim {
				t.Fatal("authorized in-place native policy update replaced exact private claim")
			}
			if _, err := f.policy.RecoverCreation(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			for _, removal := range []string{"single", "all", "full"} {
				input := map[string]any{"EventBusName": "private-policy-bus", "StatementId": "owned"}
				if removal == "all" {
					delete(input, "StatementId")
					input["RemoveAllPermissions"] = true
				}
				if removal == "full" {
					document, err := cfnComputeDocument(cfnWorkflowBusPolicy("neighbor"))
					if err != nil {
						t.Fatal(err)
					}
					f.native(t, "PutPermission", map[string]any{"EventBusName": "private-policy-bus", "Policy": document})
				} else {
					f.native(t, "RemovePermission", input)
				}
				if len(f.row(t, "private-policy-bus").PolicyStatementOwners) != 0 {
					t.Fatal("native deletion retained old statement incarnation")
				}
				f.native(t, "PutPermission", map[string]any{"EventBusName": "private-policy-bus", "StatementId": "owned", "Action": "events:PutEvents", "Principal": "222233334444"})
				f.native(t, "TagResource", map[string]any{"ResourceARN": "arn:aws:events:us-east-1:123456789012:event-bus/private-policy-bus", "Tags": cfnComputeTagList(map[string]string{cfnEventPolicyForgedTag("owned"): cfnMessagingMarker(r)})})
				f.reopen(t)
				replacement := f.row(t, "private-policy-bus")
				if len(replacement.PolicyStatementOwners) != 0 {
					t.Fatal("same-Sid native recreation inherited private incarnation")
				}
				if err := f.policy.Delete(f.ctx, r); err == nil {
					t.Fatal("stale stack removed native same-Sid replacement")
				}
				if _, err := f.policy.Create(f.ctx, r); err == nil {
					t.Fatal("stale stack adopted native same-Sid replacement")
				}
				if _, err := f.policy.RecoverCreation(f.ctx, r); err == nil {
					t.Fatal("stale stack recovered native same-Sid replacement")
				}
				if !reflect.DeepEqual(replacement, f.row(t, "private-policy-bus")) {
					t.Fatal("stale stack changed native replacement")
				}
				if _, err := f.policy.Read(f.ctx, r); err != nil {
					t.Fatal(err)
				}
				listed, err := f.policy.List(f.ctx, r)
				expected := 1
				if removal == "full" {
					expected = 2
				}
				if err != nil || len(listed) != expected {
					t.Fatalf("ordinary public policy listing failed: %+v %v", listed, err)
				}
				if removal != "full" {
					f.native(t, "RemovePermission", map[string]any{"EventBusName": "private-policy-bus", "StatementId": "owned"})
					if _, err := f.policy.Create(f.ctx, r); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

type cfnEventPolicyLostReply struct {
	*eventbridge.Service
	lose bool
}

func (e *cfnEventPolicyLostReply) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.Service.ExecuteCommand(ctx, request)
	if err == nil && e.lose && string(request.Operation.Name) == "PutPermission" {
		e.lose = false
		return nil, &awswire.Error{Code: "ValidationException", Message: "lost admitted permission reply", StatusCode: 400}
	}
	return out, err
}

func TestCFNEventBusPolicyAdmittedLostReplyRecoversPrivateIncarnation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, full := range []bool{false, true} {
			for _, cc := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/full=%t/cc=%t", backend, full, cc), func(t *testing.T) {
					f := newCFNEventPolicyFixture(t, backend)
					f.native(t, "CreateEventBus", map[string]any{"Name": "private-policy-bus"})
					executor := &cfnEventPolicyLostReply{Service: f.owner, lose: true}
					handler := cfnEventBusPolicy{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"eventbridge": executor})}
					r := cfnEventPolicyRequest("owned", full)
					r.CloudControl = cc
					admitted, err := handler.Create(f.ctx, r)
					if err == nil || admitted.PhysicalID != "private-policy-bus|owned" {
						t.Fatalf("lost native reply discarded admitted private ID: %+v %v", admitted, err)
					}
					before := f.row(t, "private-policy-bus")
					f.reopen(t)
					recovered, err := f.policy.RecoverCreation(f.ctx, r)
					if err != nil || recovered.PhysicalID != admitted.PhysicalID {
						t.Fatalf("lostreply private recovery failed: %+v %v", recovered, err)
					}
					replayed, err := f.policy.Create(f.ctx, r)
					if err != nil || replayed.PhysicalID != admitted.PhysicalID {
						t.Fatalf("same-token replay changed native incarnation: %+v %v", replayed, err)
					}
					if got := f.row(t, "private-policy-bus"); !reflect.DeepEqual(before.PolicyStatementOwners, got.PolicyStatementOwners) || before.Policy.Document != got.Policy.Document || !before.Modified.Equal(got.Modified) {
						t.Fatal("same-token replay rewrote native policy incarnation")
					}
					foreign := r
					foreign.Token = "different-native-incarnation"
					if out, err := f.policy.Create(f.ctx, foreign); err == nil || out.PhysicalID != "" {
						t.Fatalf("foreign token adopted admitted policy: %+v %v", out, err)
					}
					r.PhysicalID, r.CloudControl = admitted.PhysicalID, false
					if err := f.policy.Delete(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					if out, err := f.policy.RecoverCreation(f.ctx, r); !cfnComputeMissing(err) || out.PhysicalID != "" {
						t.Fatalf("exact private cleanup not absent: %+v %v", out, err)
					}
				})
			}
		}
	}
}

func TestCFNEventBusPolicyRecoveryAndNoOpRecheckRealIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			f.native(t, "CreateEventBus", map[string]any{"Name": "private-policy-bus"})
			out, err := cfnComputeCall[iamapi.CreateUserOutput](f.ctx, f.commands, "iam", "CreateUser", map[string]any{"UserName": "event-policy-owner"})
			if err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(f.ctx, f.commands, "iam", "PutUserPolicy", map[string]any{"UserName": "event-policy-owner", "PolicyName": "events", "PolicyDocument": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"events:*","Resource":"*"}}`}); err != nil {
				t.Fatal(err)
			}
			metadata := awsctx.FromContext(f.ctx)
			metadata.PrincipalARN, metadata.PrincipalID = cfnComputeValue(out.User.Arn), cfnComputeValue(out.User.UserId)
			user := awsctx.WithMetadata(f.ctx, metadata)
			r := cfnEventPolicyRequest("owned", false)
			admitted, err := f.policy.Create(user, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = admitted.PhysicalID
			if err := cfnComputeRun(f.ctx, f.commands, "iam", "DeleteUserPolicy", map[string]any{"UserName": "event-policy-owner", "PolicyName": "events"}); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			before := f.row(t, "private-policy-bus")
			for _, action := range []string{"create", "recover", "update", "delete"} {
				var rejected error
				switch action {
				case "create":
					_, rejected = f.policy.Create(user, r)
				case "recover":
					_, rejected = f.policy.RecoverCreation(user, r)
				case "update":
					_, rejected = f.policy.Update(user, r)
				case "delete":
					rejected = f.policy.Delete(user, r)
				}
				var wire *awswire.Error
				if !errors.As(rejected, &wire) || wire.Code != "AccessDeniedException" {
					t.Fatalf("%s used private incarnation instead of current IAM: %v", action, rejected)
				}
			}
			foreign := r
			foreign.Token = "foreign"
			var wire *awswire.Error
			if err := f.policy.Delete(user, foreign); !errors.As(err, &wire) || wire.Code != "AccessDeniedException" {
				t.Fatalf("private fence ran before current IAM: %v", err)
			}
			if !reflect.DeepEqual(before, f.row(t, "private-policy-bus")) {
				t.Fatal("revoked IAM changed private/native policy state")
			}
			if err := f.policy.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNEventBusPrivateOwnerSurvivesTagRemovalAndFencing(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			h := cfnEventBus{f.commands}
			r := cfnWorkflowOwnerRequest("AWS::Events::EventBus", "PrivateBus", cloudformation.Properties{"Name": "private-policy-bus", "Description": "initial"})
			admitted, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = admitted.PhysicalID
			arn := admitted.Attributes["Arn"].(string)
			forged := r
			forged.Token = "counterfeit-incarnation"
			f.native(t, "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(cfnComputeOwnedTags(forged))})
			f.reopen(t)
			h = cfnEventBus{f.commands}
			r.Previous, r.Properties = r.Properties, cloudformation.Properties{"Name": "private-policy-bus", "Description": "authentic"}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatalf("public tags revoked private native bus update: %v", err)
			}
			if out, err := h.RecoverCreation(f.ctx, forged); err == nil || out.PhysicalID != "" {
				t.Fatalf("public tags granted private bus recovery: %+v %v", out, err)
			}
			tags, err := cfnEventTags(f.ctx, f.commands, arn)
			if err != nil {
				t.Fatal(err)
			}
			if len(tags) != 0 {
				t.Fatalf("native bus update backfilled public owner markers: %#v", tags)
			}
			if out, err := h.RecoverCreation(f.ctx, r); err != nil || out.PhysicalID != admitted.PhysicalID {
				t.Fatalf("marker removal revoked private bus recovery: %+v %v", out, err)
			}
			independent := cfnEventPolicyRequest("independent", false)
			if _, err := f.policy.Create(f.ctx, independent); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatalf("private EventBus deletion changed native policy lifetime semantics: %v", err)
			}
			if _, err := f.policy.RecoverCreation(f.ctx, independent); !cfnComputeMissing(err) {
				t.Fatalf("bus deletion retained independent policy metadata: %v", err)
			}
			f.native(t, "CreateEventBus", map[string]any{"Name": "private-policy-bus", "Description": "replacement", "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))})
			f.reopen(t)
			h = cfnEventBus{f.commands}
			before := f.row(t, "private-policy-bus")
			if err := h.Delete(f.ctx, r); err == nil {
				t.Fatal("public bus markers let stale stack delete native replacement")
			}
			if _, err := h.Update(f.ctx, r); err == nil {
				t.Fatal("public bus markers let stale stack mutate native replacement")
			}
			if !reflect.DeepEqual(before, f.row(t, "private-policy-bus")) {
				t.Fatal("stale stack changed recreated native bus")
			}
		})
	}
}

func TestCFNEventBusInlinePolicyPermissionCheckedBeforeConfigurationWrites(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			h := cfnEventBus{f.commands}
			r := cfnWorkflowOwnerRequest("AWS::Events::EventBus", "PrivateBus", cloudformation.Properties{"Name": "private-policy-bus", "Description": "initial", "Policy": cfnWorkflowBusPolicy("managed")})
			admitted, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = admitted.PhysicalID
			out, err := cfnComputeCall[iamapi.CreateUserOutput](f.ctx, f.commands, "iam", "CreateUser", map[string]any{"UserName": "inline-owner"})
			if err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(f.ctx, f.commands, "iam", "PutUserPolicy", map[string]any{"UserName": "inline-owner", "PolicyName": "events", "PolicyDocument": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"events:*","Resource":"*"},{"Effect":"Deny","Action":["events:PutPermission","events:RemovePermission"],"Resource":"*"}]}`}); err != nil {
				t.Fatal(err)
			}
			metadata := awsctx.FromContext(f.ctx)
			metadata.PrincipalARN, metadata.PrincipalID = cfnComputeValue(out.User.Arn), cfnComputeValue(out.User.UserId)
			user := awsctx.WithMetadata(f.ctx, metadata)
			before := f.row(t, "private-policy-bus")
			initial := r.Properties
			for _, incoming := range []any{cfnWorkflowBusPolicy("replacement"), nil} {
				r.Previous = initial
				r.Properties = cloudformation.Properties{"Name": "private-policy-bus", "Description": "must-not-change", "Tags": []any{map[string]any{"Key": "team", "Value": "must-not-change"}}}
				if incoming != nil {
					r.Properties["Policy"] = incoming
				}
				var wire *awswire.Error
				if _, err := h.Update(user, r); !errors.As(err, &wire) || wire.Code != "AccessDeniedException" {
					t.Fatalf("inline policy mutation cached or bypassed current IAM: %v", err)
				}
				if !reflect.DeepEqual(before, f.row(t, "private-policy-bus")) {
					t.Fatal("permission denial occurred after native bus configuration/tag write")
				}
			}
		})
	}
}

func TestCFNEventBusPolicyPrivateClaimRequiresExactCurrentScope(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			f.native(t, "CreateEventBus", map[string]any{"Name": "private-policy-bus"})
			r := cfnEventPolicyRequest("owned", false)
			if _, err := f.policy.Create(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			r.Properties["EventBusName"] = "arn:aws:events:us-east-1:123456789012:event-bus/private-policy-bus"
			before := f.row(t, "private-policy-bus")
			for _, scope := range []cloudformation.Scope{{Partition: "aws", Account: "999999999999", Region: "us-east-1"}, {Partition: "aws", Account: "123456789012", Region: "us-west-2"}, {Partition: "aws-cn", Account: "123456789012", Region: "cn-north-1"}} {
				metadata := awsctx.FromContext(f.ctx)
				metadata.Partition, metadata.AccountID, metadata.Region = scope.Partition, scope.Account, scope.Region
				metadata.PrincipalARN, metadata.PrincipalID = "arn:"+scope.Partition+":iam::"+scope.Account+":root", scope.Account
				ctx := awsctx.WithMetadata(f.ctx, metadata)
				r.Scope = scope
				if _, err := f.policy.Create(ctx, r); err == nil {
					t.Fatal("private statement claim crossed current account/Region/partition")
				}
				if _, err := f.policy.RecoverCreation(ctx, r); err == nil {
					t.Fatal("private statement recovery crossed current account/Region/partition")
				}
				if err := f.policy.Delete(ctx, r); err == nil {
					t.Fatal("private statement removal crossed current account/Region/partition")
				}
				if !reflect.DeepEqual(before, f.row(t, "private-policy-bus")) {
					t.Fatal("out-of-scope ownership changed native policy")
				}
			}
		})
	}
}

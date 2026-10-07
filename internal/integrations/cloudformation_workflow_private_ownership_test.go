package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	pipeapi "stackd/internal/awsapi/pipes"
	sqsapi "stackd/internal/awsapi/sqs"
	sfnapi "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/iam"
	"stackd/internal/services/pipes"
	"stackd/internal/services/scheduler"
	"stackd/internal/services/sqs"
	"stackd/internal/services/stepfunctions"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	pipestore "stackd/storage/sqlite/pipes"
	schedstore "stackd/storage/sqlite/scheduler"
	sfnstore "stackd/storage/sqlite/stepfunctions"
)

type cfnPrivateWorkflowFixture struct {
	ctx, user            context.Context
	clock                *clock.Manual
	db                   *sql.DB
	path                 string
	identities           *iam.MemoryRepository
	iam                  *iam.Service
	auth                 authorization.Authorizer
	credentials          *identity.Store
	queues               *sqs.Service
	schedulerRepository  scheduler.Repository
	workflowRepository   stepfunctions.Repository
	pipeRepository       pipes.Repository
	schedules            *scheduler.Service
	workflows            *stepfunctions.Service
	pipes                *pipes.Service
	commands             StepFunctionsCommands
	sourceURL, targetURL string
}

const cfnPrivateWorkflowRole = "arn:aws:iam::123456789012:role/private-workflow"
const cfnPrivateWorkflowDefinition = `{"StartAt":"Hold","States":{"Hold":{"Type":"Wait","Seconds":1,"Next":"Result"},"Result":{"Type":"Pass","Result":"original","End":true}}}`

func newCFNPrivateWorkflowFixture(t *testing.T, backend string) *cfnPrivateWorkflowFixture {
	t.Helper()
	domain := memory.NewDomain()
	f := &cfnPrivateWorkflowFixture{ctx: cfnWorkflowOwnerContext(t), clock: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC)), identities: iam.NewMemoryRepository(domain), schedulerRepository: scheduler.NewMemoryRepository(domain), workflowRepository: stepfunctions.NewMemoryRepository(domain), pipeRepository: pipes.NewMemoryRepository(domain)}
	f.credentials = identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(f.identities, nil), Clock: f.clock})
	f.iam = iam.NewWithConfig(iam.Config{Repository: f.identities, Credentials: f.credentials, Clock: f.clock})
	f.auth = authorization.NewWithClock(f.iam, nil, f.clock)
	role := iam.Role{Arn: cfnPrivateWorkflowRole, RoleName: "private-workflow", RoleId: "AROAPRIVATEWORKFLOW", MaxSessionDuration: 3600, AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":["scheduler.amazonaws.com","pipes.amazonaws.com","states.amazonaws.com"]},"Action":"sts:AssumeRole"}}`, IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"queues": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*"}}`}}}
	if err := f.identities.Update(f.ctx, func(tx iam.WriteTx) error {
		return tx.PutRole(iam.Scope{Partition: "aws", AccountID: "123456789012"}, role)
	}); err != nil {
		t.Fatal(err)
	}
	f.user = awsctx.WithMetadata(f.ctx, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:user/workflow-deployer", PrincipalID: "AIDAPRIVATEWORKFLOW", UserName: "workflow-deployer"})
	f.policy(t, "Allow")
	f.queues = sqs.NewWithConfig(sqs.Config{Repository: sqs.NewMemoryRepository(domain), Authorizer: f.auth, Clock: f.clock})
	queueCommands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sqs": f.queues})
	for _, name := range []string{"private-workflow-source", "private-workflow-target"} {
		out, err := cfnComputeCall[sqsapi.CreateQueueOutput](f.ctx, queueCommands, "sqs", "CreateQueue", map[string]any{"QueueName": name})
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(name, "source") {
			f.sourceURL = cfnComputeValue(out.QueueUrl)
		} else {
			f.targetURL = cfnComputeValue(out.QueueUrl)
		}
	}
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "workflow.sqlite")
		f.open(t)
	}
	f.start()
	t.Cleanup(func() {
		f.close()
		_ = f.queues.Close()
		_ = f.iam.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}
func (f *cfnPrivateWorkflowFixture) policy(t *testing.T, effect string) {
	t.Helper()
	user := iam.User{Arn: "arn:aws:iam::123456789012:user/workflow-deployer", UserName: "workflow-deployer", UserId: "AIDAPRIVATEWORKFLOW", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"workflow": `{"Version":"2012-10-17","Statement":{"Effect":"` + effect + `","Action":["scheduler:*","states:*","pipes:*","iam:PassRole"],"Resource":"*"}}`}}}
	if err := f.identities.Update(f.ctx, func(tx iam.WriteTx) error {
		return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
	}); err != nil {
		t.Fatal(err)
	}
}
func (f *cfnPrivateWorkflowFixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.db, err = sqlite.Open(f.ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.schedulerRepository = schedstore.New(f.db)
	f.workflowRepository, err = sfnstore.New(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	f.pipeRepository = pipestore.New(f.db)
}
func (f *cfnPrivateWorkflowFixture) start() {
	roles := ServiceRoles{IAM: f.iam, Credentials: f.credentials, Authorizer: f.auth}
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sqs": f.queues})
	schedulerTargets := &SchedulerTargets{Commands: commands, Roles: roles}
	f.schedules = scheduler.NewWithConfig(scheduler.Config{Repository: f.schedulerRepository, Authorizer: f.auth, Clock: f.clock, Delivery: schedulerTargets, Roles: schedulerTargets})
	f.workflows = stepfunctions.New(stepfunctions.Config{Repository: f.workflowRepository, Authorizer: f.auth, Clock: f.clock})
	f.pipes = pipes.NewWithConfig(pipes.Config{Repository: f.pipeRepository, Authorizer: f.auth, Clock: f.clock, Sources: &PipesSources{Roles: roles, Queues: f.queues}, Targets: &PipesTargets{Roles: roles, Commands: commands}})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"scheduler": f.schedules, "stepfunctions": f.workflows, "pipes": f.pipes, "sqs": f.queues, "iam": f.iam})
}
func (f *cfnPrivateWorkflowFixture) close() {
	_ = f.schedules.Close()
	_ = f.workflows.Close()
	_ = f.pipes.Close()
}
func (f *cfnPrivateWorkflowFixture) reopen(t *testing.T) {
	t.Helper()
	f.close()
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			t.Fatal(err)
		}
		f.open(t)
	}
	f.start()
}
func (f *cfnPrivateWorkflowFixture) request(kind string) cloudformation.ResourceRequest {
	p := cloudformation.Properties{}
	switch kind {
	case "ScheduleGroup":
		p = cloudformation.Properties{"Name": "private-workflow-group"}
	case "Schedule":
		p = cloudformation.Properties{"Name": "private-workflow-schedule", "GroupName": "default", "State": "DISABLED", "ScheduleExpression": "rate(1 day)", "FlexibleTimeWindow": map[string]any{"Mode": "OFF"}, "Target": map[string]any{"Arn": "arn:aws:sqs:us-east-1:123456789012:private-workflow-target", "RoleArn": cfnPrivateWorkflowRole, "Input": "scheduler-payload"}}
	case "StateMachine":
		p = cloudformation.Properties{"StateMachineName": "private-workflow-machine", "RoleArn": cfnPrivateWorkflowRole, "DefinitionString": cfnPrivateWorkflowDefinition}
	case "Activity":
		p = cloudformation.Properties{"Name": "private-workflow-activity"}
	case "Pipe":
		p = cloudformation.Properties{"Name": "private-workflow-pipe", "RoleArn": cfnPrivateWorkflowRole, "Source": "arn:aws:sqs:us-east-1:123456789012:private-workflow-source", "Target": "arn:aws:sqs:us-east-1:123456789012:private-workflow-target", "DesiredState": "STOPPED"}
	}
	if kind == "Pipe" {
		p["Tags"] = map[string]any{"team": "workflow-owner"}
	} else if kind != "Schedule" {
		p["Tags"] = []any{map[string]any{"Key": "team", "Value": "workflow-owner"}}
	}
	service := "StepFunctions"
	if kind == "Schedule" || kind == "ScheduleGroup" {
		service = "Scheduler"
	}
	if kind == "Pipe" {
		service = "Pipes"
	}
	return cfnWorkflowOwnerRequest("AWS::"+service+"::"+kind, kind, p)
}
func cfnPrivateWorkflowHandler(c StepFunctionsCommands, r cloudformation.ResourceRequest) cloudformation.ResourceHandler {
	return CloudFormationWorkflowHandlers(c)[r.Type]
}
func cfnPrivateWorkflowKind(r cloudformation.ResourceRequest) string {
	at := strings.LastIndex(r.Type, "::")
	return r.Type[at+2:]
}
func cfnPrivateWorkflowPhysical(r cloudformation.ResourceRequest) string {
	switch cfnPrivateWorkflowKind(r) {
	case "StateMachine":
		return "arn:aws:states:us-east-1:123456789012:stateMachine:" + cfnComputeString(r.Properties, "StateMachineName")
	case "Activity":
		return "arn:aws:states:us-east-1:123456789012:activity:" + cfnComputeString(r.Properties, "Name")
	case "Schedule":
		group, name := cfnScheduleIdentity(r)
		return cfnScheduleResult(r, group, name).PhysicalID
	default:
		return cfnComputeString(r.Properties, "Name")
	}
}
func cfnPrivateWorkflowForgery(r cloudformation.ResourceRequest) map[string]string {
	tags := cfnComputeOwnedTags(r)
	tags[cfnMessagingOwnerTag] = cfnMessagingOwner(r)
	tags[cfnMessagingTokenTag] = cfnMessagingHash(r.Token)
	return tags
}
func (f *cfnPrivateWorkflowFixture) native(t *testing.T, service, operation string, input map[string]any) {
	t.Helper()
	if err := cfnComputeRun(f.ctx, f.commands, service, operation, input); err != nil {
		t.Fatal(err)
	}
}
func (f *cfnPrivateWorkflowFixture) nativeCreate(t *testing.T, r cloudformation.ResourceRequest) {
	t.Helper()
	kind := cfnPrivateWorkflowKind(r)
	input := map[string]any{}
	for k, v := range r.Properties {
		input[k] = v
	}
	input["Tags"] = cfnComputeTagList(cfnPrivateWorkflowForgery(r))
	service := "stepfunctions"
	operation := "Create" + kind
	switch kind {
	case "StateMachine":
		input["Name"] = input["StateMachineName"]
		input["Definition"] = input["DefinitionString"]
		delete(input, "StateMachineName")
		delete(input, "DefinitionString")
	case "ScheduleGroup":
		service = "scheduler"
		input["ClientToken"] = cfnScheduleToken(r)
	case "Schedule":
		service = "scheduler"
		delete(input, "Tags")
		input["ClientToken"] = cfnScheduleToken(r)
	case "Pipe":
		service = "pipes"
		input["Tags"] = cfnPrivateWorkflowForgery(r)
	}
	f.native(t, service, operation, input)
}
func (f *cfnPrivateWorkflowFixture) drain(t *testing.T) {
	t.Helper()
	for range 2 {
		if err := f.clock.Advance(5 * time.Second); err != nil {
			t.Fatal(err)
		}
		if _, err := f.workflows.JobDriver().RunDue(f.ctx, 100); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pipes.JobDriver().RunDue(f.ctx, 100); err != nil {
			t.Fatal(err)
		}
	}
}
func (f *cfnPrivateWorkflowFixture) nativeDelete(t *testing.T, r cloudformation.ResourceRequest) {
	t.Helper()
	kind := cfnPrivateWorkflowKind(r)
	input := map[string]any{"Name": cfnComputeString(r.Properties, "Name")}
	service := "stepfunctions"
	switch kind {
	case "StateMachine":
		input = map[string]any{"StateMachineArn": cfnPrivateWorkflowPhysical(r)}
	case "Activity":
		input = map[string]any{"ActivityArn": cfnPrivateWorkflowPhysical(r)}
	case "ScheduleGroup":
		service = "scheduler"
	case "Schedule":
		service = "scheduler"
		group, name := cfnScheduleIdentity(r)
		input = map[string]any{"Name": name, "GroupName": group}
	case "Pipe":
		service = "pipes"
	}
	f.native(t, service, "Delete"+kind, input)
	f.drain(t)
}

type cfnPrivateWorkflowRow struct {
	ID, Owner, Parent string
	Native            any
}

func (f *cfnPrivateWorkflowFixture) row(t *testing.T, r cloudformation.ResourceRequest) cfnPrivateWorkflowRow {
	t.Helper()
	var row cfnPrivateWorkflowRow
	var err error
	switch cfnPrivateWorkflowKind(r) {
	case "ScheduleGroup":
		err = f.schedulerRepository.View(f.ctx, func(reader scheduler.Reader) error {
			v, e := reader.Group(scheduler.GroupKey{Scope: scheduler.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: cfnComputeString(r.Properties, "Name")})
			row = cfnPrivateWorkflowRow{ID: v.ID, Owner: v.CFNOwner, Native: v}
			return e
		})
	case "Schedule":
		group, name := cfnScheduleIdentity(r)
		err = f.schedulerRepository.View(f.ctx, func(reader scheduler.Reader) error {
			v, e := reader.Schedule(scheduler.ScheduleKey{Group: scheduler.GroupKey{Scope: scheduler.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: group}, Name: name})
			row = cfnPrivateWorkflowRow{Owner: v.CFNOwner, Parent: v.ParentID, Native: v}
			return e
		})
	case "StateMachine":
		err = f.workflowRepository.View(f.ctx, func(reader stepfunctions.Reader) error {
			v, e := reader.Machine(stepfunctions.MachineKey{Scope: stepfunctions.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: cfnComputeString(r.Properties, "StateMachineName")})
			row = cfnPrivateWorkflowRow{ID: v.ID, Owner: v.CFNOwner, Native: v}
			return e
		})
	case "Activity":
		err = f.workflowRepository.View(f.ctx, func(reader stepfunctions.Reader) error {
			v, e := reader.Activity(stepfunctions.ActivityKey{Scope: stepfunctions.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: cfnComputeString(r.Properties, "Name")})
			row = cfnPrivateWorkflowRow{ID: v.ID, Owner: v.CFNOwner, Native: v}
			return e
		})
	case "Pipe":
		err = f.pipeRepository.View(f.ctx, func(reader pipes.Reader) error {
			v, e := reader.Pipe(pipes.Key{Scope: pipes.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: cfnComputeString(r.Properties, "Name")})
			row = cfnPrivateWorkflowRow{ID: v.ID, Owner: v.CFNOwner, Native: v}
			return e
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	if cfnPrivateWorkflowKind(r) == "Pipe" {
		out, err := cfnComputeCall[pipeapi.DescribePipeOutput](f.ctx, f.commands, "pipes", "DescribePipe", map[string]any{"Name": cfnComputeString(r.Properties, "Name")})
		if err != nil {
			t.Fatal(err)
		}
		// Native reconciliation may advance lifecycle state and normalize stored
		// representations without changing the admitted, consumer-visible config.
		out.CurrentState, out.StateReason = nil, nil
		out.CreationTime, out.LastModifiedTime = nil, nil
		config, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		row.Native = string(config)
	}
	return row
}
func (f *cfnPrivateWorkflowFixture) tags(t *testing.T, r cloudformation.ResourceRequest, tags map[string]string) {
	t.Helper()
	kind := cfnPrivateWorkflowKind(r)
	if kind == "Schedule" {
		return
	}
	arn := r.PhysicalID
	service := "stepfunctions"
	var input any = cfnComputeTagList(tags)
	if kind == "ScheduleGroup" {
		service = "scheduler"
		arn = cfnScheduleGroupResult(r, r.PhysicalID).Attributes["Arn"].(string)
	}
	if kind == "Pipe" {
		service = "pipes"
		arn = cfnPipeResult(r, r.PhysicalID).Attributes["Arn"].(string)
		input = tags
	}
	f.native(t, service, "TagResource", map[string]any{"ResourceArn": arn, "Tags": input})
}
func (f *cfnPrivateWorkflowFixture) removeTags(t *testing.T, r cloudformation.ResourceRequest, keys []string) {
	t.Helper()
	kind := cfnPrivateWorkflowKind(r)
	if kind == "Schedule" {
		return
	}
	arn := r.PhysicalID
	service := "stepfunctions"
	if kind == "ScheduleGroup" {
		service = "scheduler"
		arn = cfnScheduleGroupResult(r, r.PhysicalID).Attributes["Arn"].(string)
	}
	if kind == "Pipe" {
		service = "pipes"
		arn = cfnPipeResult(r, r.PhysicalID).Attributes["Arn"].(string)
	}
	f.native(t, service, "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": keys})
}

// Fault injection occurs after the real owner has committed its admission. No
// resource result or workflow/target execution is mocked.
type cfnPrivateWorkflowLostReply struct {
	owner  awscommands.CommandExecutor
	action string
	lost   bool
}

func (e *cfnPrivateWorkflowLostReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.owner.ExecuteCommand(ctx, r)
	if err == nil && !e.lost && string(r.Operation.Name) == e.action {
		e.lost = true
		return nil, &awswire.Error{Code: "InternalException", Message: "lost reply after real native admission", StatusCode: 500}
	}
	return out, err
}

type cfnPrivateWorkflowMutationRace struct {
	owner  awscommands.CommandExecutor
	action string
	before func()
}

func (e *cfnPrivateWorkflowMutationRace) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	if string(r.Operation.Name) == e.action && e.before != nil {
		before := e.before
		e.before = nil
		before()
	}
	return e.owner.ExecuteCommand(ctx, r)
}

func TestCFNWorkflowPrivateClaimsIgnorePublicMetadata(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"ScheduleGroup", "Schedule", "StateMachine", "Activity", "Pipe"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newCFNPrivateWorkflowFixture(t, backend)
				r := f.request(kind)
				if kind != "Schedule" {
					r.Tags = map[string]string{"customer": "stack-tag"}
				}
				h := cfnPrivateWorkflowHandler(f.commands, r)
				f.nativeCreate(t, r)
				unclaimed := f.row(t, r)
				if unclaimed.Owner != "" {
					t.Fatal("public create tokens or tags admitted a private claim")
				}
				if out, err := h.Create(f.ctx, r); err == nil || out.PhysicalID != "" {
					t.Fatalf("forged public metadata adopted native row: %+v %v", out, err)
				}
				if out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil || out.PhysicalID != "" {
					t.Fatalf("public metadata recovered unclaimed row: %+v %v", out, err)
				}
				r.PhysicalID = cfnPrivateWorkflowPhysical(r)
				r.Previous = r.Properties
				if _, err := h.Update(f.ctx, r); err == nil {
					t.Fatal("CFN no-op update adopted unclaimed row")
				}
				if err := h.Delete(f.ctx, r); err == nil {
					t.Fatal("CFN deletion adopted unclaimed row")
				}
				if !reflect.DeepEqual(unclaimed, f.row(t, r)) {
					t.Fatal("rejected CFN operation mutated native row")
				}
				if _, err := h.(cloudformation.ResourceReader).Read(f.user, r); err != nil {
					t.Fatalf("authorized native import observation failed: %v", err)
				}
				if f.row(t, r).Owner != "" {
					t.Fatal("import observation adopted public metadata")
				}
				cc := r
				cc.CloudControl = true
				if kind == "Pipe" {
					cc.Properties = cfnComputeCopy(r.Properties, "Name", "RoleArn", "Source", "Target", "DesiredState", "Tags")
					cc.Properties["Description"] = "cloudcontrol-updated"
					cc.Properties["Target"] = r.Properties["Source"]
					cc.Properties["TargetParameters"] = map[string]any{"InputTemplate": `"cloudcontrol-payload"`}
				}
				if _, err := h.Update(f.ctx, cc); err != nil {
					t.Fatalf("ordinary CloudControl update required ownership: %v", err)
				}
				if kind == "Pipe" {
					out, err := cfnComputeCall[pipeapi.DescribePipeOutput](f.ctx, f.commands, "pipes", "DescribePipe", map[string]any{"Name": r.PhysicalID})
					if err != nil || cfnComputeValue(out.Description) != "cloudcontrol-updated" || cfnComputeValue(out.Target) != r.Properties["Source"] || out.TargetParameters == nil || cfnComputeValue(out.TargetParameters.InputTemplate) != `"cloudcontrol-payload"` || out.EnrichmentParameters != nil {
						t.Fatalf("CloudControl did not replace actual Pipe configuration: %+v %v", out, err)
					}
				}
				if f.row(t, r).Owner != "" {
					t.Fatal("CloudControl mutation adopted private ownership")
				}
				if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, cc); err != nil {
					t.Fatal(err)
				}
				if _, err := h.(cloudformation.ResourceReader).List(f.ctx, cc); err != nil {
					t.Fatal(err)
				}
				f.nativeDelete(t, r)
				r.PhysicalID = ""
				service := "stepfunctions"
				var owner awscommands.CommandExecutor = f.workflows
				if kind == "Schedule" || kind == "ScheduleGroup" {
					service = "scheduler"
					owner = f.schedules
				}
				if kind == "Pipe" {
					service = "pipes"
					owner = f.pipes
				}
				lost := &cfnPrivateWorkflowLostReply{owner: owner, action: "Create" + kind}
				h = cfnPrivateWorkflowHandler(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{service: lost}), r)
				r.CloudControl = true
				admitted, err := h.Create(f.user, r)
				if err == nil || admitted.PhysicalID == "" || !lost.lost {
					t.Fatalf("lost reply did not retain actual native admission: %+v %v", admitted, err)
				}
				r.PhysicalID = admitted.PhysicalID
				before := f.row(t, r)
				if before.Owner != cfnMessagingMarker(r) {
					t.Fatal("real native row lacks exact private claim")
				}
				f.reopen(t)
				h = cfnPrivateWorkflowHandler(f.commands, r)
				out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, r)
				if err != nil || out.PhysicalID != r.PhysicalID {
					t.Fatalf("reopened private recovery: %+v %v", out, err)
				}
				if out, err := h.Create(f.user, r); err != nil || out.PhysicalID != r.PhysicalID {
					t.Fatalf("CC same-token replay failed: %+v %v", out, err)
				}
				if _, err := h.Update(f.user, r); err != nil {
					t.Fatalf("ordinary CloudControl update of claimed row failed: %v", err)
				}
				if f.row(t, r).Owner != before.Owner {
					t.Fatal("ordinary CloudControl update transferred a surviving claim")
				}
				projected, err := h.(cloudformation.ResourceReader).Read(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				tagBytes, _ := json.Marshal(projected["Tags"])
				if strings.Contains(string(tagBytes), cfnComputeTagPrefix) {
					t.Fatalf("trusted create emitted public owner markers: %s", tagBytes)
				}
				if kind != "Schedule" && !strings.Contains(string(tagBytes), "stack-tag") {
					t.Fatalf("trusted create dropped ordinary customer tags: %s", tagBytes)
				}
				r.CloudControl = false
				foreign := r
				foreign.Token = "foreign-incarnation"
				if kind == "Pipe" {
					foreign.Properties = cfnComputeCopy(r.Properties, "Name", "RoleArn", "Source", "Target", "DesiredState", "Tags")
					foreign.Properties["Description"] = "must-not-apply"
					foreign.Properties["Target"] = r.Properties["Source"]
				}
				f.tags(t, foreign, cfnPrivateWorkflowForgery(foreign))
				f.removeTags(t, r, cfnMessagingKeys(cfnPrivateWorkflowForgery(r)))
				beforeForeign := f.row(t, r)
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, foreign); err == nil {
					t.Fatal("copied tags authorized foreign recovery")
				}
				if _, err := h.Update(f.ctx, foreign); err == nil {
					t.Fatal("copied tags authorized foreign no-op update")
				}
				if err := h.Delete(f.ctx, foreign); err == nil {
					t.Fatal("copied tags authorized foreign delete")
				}
				if !reflect.DeepEqual(beforeForeign, f.row(t, r)) {
					t.Fatal("foreign private claim changed native configuration or ownership")
				}
				if _, err := h.Update(f.user, r); err != nil {
					t.Fatalf("marker removal revoked authentic no-op update: %v", err)
				}
				if f.row(t, r).Owner != before.Owner {
					t.Fatal("native/tag/CC mutations replaced private owner")
				}
				f.policy(t, "Deny")
				for _, operation := range []string{"create", "recover", "update", "delete", "read", "list"} {
					var err error
					switch operation {
					case "create":
						_, err = h.Create(f.user, r)
					case "recover":
						_, err = h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, r)
					case "update":
						_, err = h.Update(f.user, r)
					case "delete":
						err = h.Delete(f.user, r)
					case "read":
						_, err = h.(cloudformation.ResourceReader).Read(f.user, r)
					case "list":
						_, err = h.(cloudformation.ResourceReader).List(f.user, r)
					}
					if err == nil || cfnSFNMissing(err) || cfnPipeMissing(err) {
						t.Fatalf("%s bypassed current IAM or falsely certified absence: %v", operation, err)
					}
				}
				f.policy(t, "Allow")
				for _, scope := range []awsctx.Metadata{{Partition: "aws-cn", AccountID: "123456789012", Region: "us-east-1"}, {Partition: "aws", AccountID: "999999999999", Region: "us-east-1"}, {Partition: "aws", AccountID: "123456789012", Region: "us-west-2"}} {
					scope.PrincipalARN = "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":root"
					ctx := awsctx.WithMetadata(f.ctx, scope)
					if _, err := h.Create(ctx, r); err == nil {
						t.Fatal("create claim crossed current caller scope")
					}
					if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, r); err == nil {
						t.Fatal("recovery crossed current caller scope")
					}
					if _, err := h.Update(ctx, r); err == nil {
						t.Fatal("update crossed current caller scope")
					}
					if err := h.Delete(ctx, r); err == nil {
						t.Fatal("delete crossed current caller scope")
					}
				}
				if kind == "StateMachine" || kind == "Activity" {
					cfnPrivateWorkflowRejectsForeignARN(t, f.ctx, h, r)
				}
				f.nativeDelete(t, r)
				f.nativeCreate(t, r)
				f.reopen(t)
				h = cfnPrivateWorkflowHandler(f.commands, r)
				recreated := f.row(t, r)
				if recreated.Owner != "" || kind != "Schedule" && recreated.ID == before.ID {
					t.Fatal("native recreation retained previous private lifetime")
				}
				if out, err := h.Create(f.ctx, r); err == nil || out.PhysicalID != "" {
					t.Fatalf("copied metadata recreated old private claim: %+v %v", out, err)
				}
				if out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil || out.PhysicalID != "" {
					t.Fatalf("stale recovery adopted same-identity recreation: %+v %v", out, err)
				}
				if _, err := h.Update(f.ctx, r); err == nil {
					t.Fatal("stale no-op changed recreation")
				}
				if err := h.Delete(f.ctx, r); err == nil {
					t.Fatal("stale deletion destroyed recreation")
				}
				if !reflect.DeepEqual(recreated, f.row(t, r)) {
					t.Fatal("stale controller changed recreated native row")
				}
			})
		}
	}
}

func TestCFNSchedulerPrivateParentAndChildrenLifetime(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNPrivateWorkflowFixture(t, backend)
			group := f.request("ScheduleGroup")
			child := f.request("Schedule")
			child.Properties["GroupName"] = group.Properties["Name"]
			gh, ch := cfnScheduleGroup{f.commands}, cfnSchedule{f.commands}
			g, err := gh.Create(f.ctx, group)
			if err != nil {
				t.Fatal(err)
			}
			group.PhysicalID = g.PhysicalID
			s, err := ch.Create(f.ctx, child)
			if err != nil {
				t.Fatal(err)
			}
			child.PhysicalID = s.PhysicalID
			oldParent, oldChild := f.row(t, group), f.row(t, child)
			if oldParent.ID == "" || oldChild.Parent != oldParent.ID {
				t.Fatal("schedule claim lacks exact parent incarnation")
			}
			f.nativeDelete(t, group)
			f.nativeCreate(t, group)
			f.nativeCreate(t, child)
			f.reopen(t)
			parent, next := f.row(t, group), f.row(t, child)
			if parent.ID == oldParent.ID || next.Parent != parent.ID || parent.Owner != "" || next.Owner != "" {
				t.Fatal("group delete/recreate carried old parent/child claims")
			}
			for _, request := range []cloudformation.ResourceRequest{group, child} {
				h := cfnPrivateWorkflowHandler(f.commands, request)
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, request); err == nil {
					t.Fatal("stale parent/child recovered recreated native lifetime")
				}
				if _, err := h.Update(f.ctx, request); err == nil {
					t.Fatal("stale parent/child update crossed recreation")
				}
				if err := h.Delete(f.ctx, request); err == nil {
					t.Fatal("stale parent/child delete crossed recreation")
				}
			}
			if !reflect.DeepEqual(parent, f.row(t, group)) || !reflect.DeepEqual(next, f.row(t, child)) {
				t.Fatal("stale group deletion damaged surviving children")
			}
		})
	}
}

func TestCFNWorkflowQualifiedPrivateClaimsAndRealExecutions(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNPrivateWorkflowFixture(t, backend)
			machine := f.request("StateMachine")
			mh := cfnStateMachine{f.commands}
			created, err := mh.Create(f.ctx, machine)
			if err != nil {
				t.Fatal(err)
			}
			machine.PhysicalID = created.PhysicalID
			version := cfnWorkflowOwnerRequest("AWS::StepFunctions::StateMachineVersion", "Version", cloudformation.Properties{"StateMachineArn": machine.PhysicalID})
			version.CloudControl = true
			versionLoss := &cfnPrivateWorkflowLostReply{owner: f.workflows, action: "PublishStateMachineVersion"}
			versionCommands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"stepfunctions": versionLoss})
			v, err := (cfnStateMachineVersion{versionCommands}).Create(f.ctx, version)
			if err == nil || !versionLoss.lost || v.PhysicalID == "" {
				t.Fatalf("lost qualified version admission was not recovered: %+v %v", v, err)
			}
			version.PhysicalID = v.PhysicalID
			vh := cfnStateMachineVersion{f.commands}
			if replay, err := vh.Create(f.user, version); err != nil || replay.PhysicalID != version.PhysicalID {
				t.Fatalf("qualified version replay: %+v %v", replay, err)
			}
			alias := cfnWorkflowOwnerRequest("AWS::StepFunctions::StateMachineAlias", "Alias", cloudformation.Properties{"Name": "private-alias", "RoutingConfiguration": []any{map[string]any{"StateMachineVersionArn": v.PhysicalID, "Weight": 100}}})
			alias.CloudControl = true
			aliasLoss := &cfnPrivateWorkflowLostReply{owner: f.workflows, action: "CreateStateMachineAlias"}
			aliasCommands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"stepfunctions": aliasLoss})
			a, err := (cfnStateMachineAlias{aliasCommands}).Create(f.ctx, alias)
			if err == nil || !aliasLoss.lost || a.PhysicalID == "" {
				t.Fatalf("lost qualified alias admission was not recovered: %+v %v", a, err)
			}
			alias.PhysicalID = a.PhysicalID
			ah := cfnStateMachineAlias{f.commands}
			if replay, err := ah.Create(f.user, alias); err != nil || replay.PhysicalID != alias.PhysicalID {
				t.Fatalf("qualified alias replay: %+v %v", replay, err)
			}
			old, err := cfnComputeCall[sfnapi.StartExecutionOutput](f.ctx, f.commands, "stepfunctions", "StartExecution", map[string]any{"StateMachineArn": a.PhysicalID, "Name": "pinned-qualified", "Input": "{}"})
			if err != nil {
				t.Fatal(err)
			}
			machine.Previous = machine.Properties
			machine.Properties = cloudformation.Properties{"StateMachineName": "private-workflow-machine", "RoleArn": cfnPrivateWorkflowRole, "DefinitionString": strings.ReplaceAll(cfnPrivateWorkflowDefinition, "original", "updated")}
			if _, err := mh.Update(f.ctx, machine); err != nil {
				t.Fatal(err)
			}
			current, err := cfnComputeCall[sfnapi.StartExecutionOutput](f.ctx, f.commands, "stepfunctions", "StartExecution", map[string]any{"StateMachineArn": machine.PhysicalID, "Name": "current-unqualified", "Input": "{}"})
			if err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			f.drain(t)
			for _, check := range []struct{ id, want string }{{cfnComputeValue(old.ExecutionArn), `"original"`}, {cfnComputeValue(current.ExecutionArn), `"updated"`}} {
				out, err := cfnComputeCall[sfnapi.DescribeExecutionOutput](f.ctx, f.commands, "stepfunctions", "DescribeExecution", map[string]any{"ExecutionArn": check.id})
				if err != nil || cfnComputeValue(out.Status) != "SUCCEEDED" || cfnComputeValue(out.Output) != check.want {
					t.Fatalf("actual execution lost immutable/current revision semantics: %+v %v", out, err)
				}
			}
			vh, ah = cfnStateMachineVersion{f.commands}, cfnStateMachineAlias{f.commands}
			for _, r := range []cloudformation.ResourceRequest{version, alias} {
				h := cfnPrivateWorkflowHandler(f.commands, r)
				r.CloudControl = false
				r.Previous = r.Properties
				if _, err := h.Update(f.user, r); err != nil {
					t.Fatal(err)
				}
				if out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, r); err != nil || out.PhysicalID != r.PhysicalID {
					t.Fatalf("qualified private recovery: %+v %v", out, err)
				}
				foreign := r
				foreign.Token = "foreign-qualified"
				if _, err := h.Update(f.ctx, foreign); err == nil {
					t.Fatal("qualified no-op adopted foreign private owner")
				}
				if err := h.Delete(f.ctx, foreign); err == nil {
					t.Fatal("qualified deletion adopted foreign private owner")
				}
				f.policy(t, "Deny")
				if _, err := h.Update(f.user, r); err == nil {
					t.Fatal("qualified no-op bypassed current IAM")
				}
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, r); err == nil {
					t.Fatal("qualified recovery bypassed current IAM")
				}
				f.policy(t, "Allow")
			}
			for _, r := range []cloudformation.ResourceRequest{version, alias} {
				r.CloudControl = false
				r.Previous = r.Properties
				cfnPrivateWorkflowRejectsForeignARN(t, f.ctx, cfnPrivateWorkflowHandler(f.commands, r), r)
			}
			if err := ah.Delete(f.ctx, cloudformation.ResourceRequest{Type: alias.Type, Scope: alias.Scope, StackID: alias.StackID, LogicalID: alias.LogicalID, Token: alias.Token, PhysicalID: alias.PhysicalID, Properties: alias.Properties}); err != nil {
				t.Fatal(err)
			}
			version.CloudControl = false
			if err := vh.Delete(f.ctx, version); err != nil {
				t.Fatal(err)
			}
			// Deleting and recreating the parent must not bind old versions or aliases to
			// a numerically identical qualified ARN in the new machine lifetime.
			f.nativeDelete(t, machine)
			f.nativeCreate(t, machine)
			f.native(t, "stepfunctions", "PublishStateMachineVersion", map[string]any{"StateMachineArn": machine.PhysicalID})
			f.native(t, "stepfunctions", "CreateStateMachineAlias", map[string]any{"Name": "private-alias", "RoutingConfiguration": alias.Properties["RoutingConfiguration"]})
			f.reopen(t)
			for _, r := range []cloudformation.ResourceRequest{version, alias} {
				r.CloudControl = false
				h := cfnPrivateWorkflowHandler(f.commands, r)
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil {
					t.Fatal("qualified private claim crossed recreated parent")
				}
				if err := h.Delete(f.ctx, r); err == nil {
					t.Fatal("stale qualified claim deleted recreated child")
				}
			}
		})
	}
}

func TestCFNWorkflowNativeSchedulerAndPipeEffectsRemainReal(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNPrivateWorkflowFixture(t, backend)
			schedule := f.request("Schedule")
			schedule.Properties["State"] = "ENABLED"
			schedule.Properties["ScheduleExpression"] = "at(2031-01-02T03:04:01)"
			if _, err := (cfnSchedule{f.commands}).Create(f.ctx, schedule); err != nil {
				t.Fatal(err)
			}
			pipe := f.request("Pipe")
			pipe.Properties["DesiredState"] = "RUNNING"
			if _, err := (cfnPipe{f.commands}).Create(f.ctx, pipe); err != nil {
				t.Fatal(err)
			}
			f.native(t, "sqs", "SendMessage", map[string]any{"QueueUrl": f.sourceURL, "MessageBody": "pipe-payload"})
			if err := f.clock.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			bodies := map[string]bool{}
			for attempt := 0; attempt < 100 && (!bodies["scheduler-payload"] || !bodies["pipe-payload"]); attempt++ {
				if _, err := f.schedules.JobDriver().RunDue(f.ctx, 100); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pipes.JobDriver().RunDue(f.ctx, 100); err != nil {
					t.Fatal(err)
				}
				out, err := cfnComputeCall[sqsapi.ReceiveMessageOutput](f.ctx, f.commands, "sqs", "ReceiveMessage", map[string]any{"QueueUrl": f.targetURL, "MaxNumberOfMessages": 10})
				if err != nil {
					t.Fatal(err)
				}
				for _, message := range out.Messages {
					body := cfnComputeValue(message.Body)
					bodies[body] = true
					if strings.Contains(body, "pipe-payload") {
						bodies["pipe-payload"] = true
					}
				}
				if err := f.clock.Advance(time.Second); err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Millisecond)
			}
			if !bodies["scheduler-payload"] || !bodies["pipe-payload"] {
				raw, _ := json.Marshal(bodies)
				t.Fatalf("real source-owner/target effects missing: %s", raw)
			}
		})
	}
}

func TestCFNWorkflowNativeMutationFencesSameNameRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"ScheduleGroup", "Schedule", "StateMachine", "Activity", "Pipe"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newCFNPrivateWorkflowFixture(t, backend)
				r := f.request(kind)
				h := cfnPrivateWorkflowHandler(f.commands, r)
				admitted, err := h.Create(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				r.PhysicalID = admitted.PhysicalID
				r.Previous = r.Properties
				service, action := "stepfunctions", "Update"+kind
				var owner awscommands.CommandExecutor = f.workflows
				if kind == "Schedule" || kind == "ScheduleGroup" {
					service = "scheduler"
					owner = f.schedules
				}
				if kind == "Pipe" {
					service = "pipes"
					owner = f.pipes
				}
				recreate := r
				if kind == "Pipe" {
					r.Properties = cfnComputeCopy(r.Properties, "Name", "RoleArn", "Source", "Target", "DesiredState", "Tags")
					r.Properties["Description"] = "must-not-apply"
					r.Properties["Target"] = recreate.Properties["Source"]
				}
				if kind == "ScheduleGroup" || kind == "Activity" {
					action = "TagResource"
					r.Properties = cloudformation.Properties{"Name": r.Properties["Name"], "Tags": []any{map[string]any{"Key": "team", "Value": "must-not-apply"}}}
				}
				var replacement cfnPrivateWorkflowRow
				race := &cfnPrivateWorkflowMutationRace{owner: owner, action: action, before: func() { f.nativeDelete(t, r); f.nativeCreate(t, recreate); replacement = f.row(t, r) }}
				h = cfnPrivateWorkflowHandler(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{service: race}), r)
				if _, err := h.Update(f.ctx, r); err == nil {
					t.Fatal("native transaction adopted recreation after private adapter observation")
				}
				if race.before != nil {
					t.Fatal("test did not enter the actual native mutation boundary")
				}
				if !reflect.DeepEqual(replacement, f.row(t, r)) {
					t.Fatal("failed stale mutation changed replacement native state")
				}
			})
		}
	}
}

func cfnPrivateWorkflowRejectsForeignARN(t *testing.T, ctx context.Context, h cloudformation.ResourceHandler, r cloudformation.ResourceRequest) {
	t.Helper()
	for _, replacement := range []struct{ from, to string }{{"arn:aws:", "arn:aws-cn:"}, {"123456789012", "999999999999"}, {"us-east-1", "us-west-2"}} {
		foreign := r
		foreign.PhysicalID = strings.ReplaceAll(r.PhysicalID, replacement.from, replacement.to)
		if _, err := h.Create(ctx, foreign); err == nil {
			t.Fatal("create accepted a foreign native ARN")
		}
		if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, foreign); err == nil {
			t.Fatal("recovery accepted a foreign native ARN")
		}
		if _, err := h.Update(ctx, foreign); err == nil {
			t.Fatal("update accepted a foreign native ARN")
		}
		if err := h.Delete(ctx, foreign); err == nil {
			t.Fatal("delete certified a foreign native ARN as absent")
		}
	}
}

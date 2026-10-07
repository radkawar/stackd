package integrations

import (
	"context"
	"database/sql"
	"maps"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cloudwatch"
	"stackd/internal/services/iam"
	"stackd/internal/services/logs"
	"stackd/storage/sqlite"
	cwstore "stackd/storage/sqlite/cloudwatch"
	logsstore "stackd/storage/sqlite/logs"
)

type cfnObservabilityLostAdmissionReply struct {
	owner     awscommands.CommandExecutor
	operation string
	armed     bool
	after     func()
}

func (e *cfnObservabilityLostAdmissionReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, wire := e.owner.ExecuteCommand(ctx, r)
	if wire == nil && e.armed && string(r.Operation.Name) == e.operation {
		e.armed = false
		if e.after != nil {
			e.after()
		}
		return nil, &awswire.Error{Code: "RequestTimeout", Message: "native admission reply lost", StatusCode: 504}
	}
	return out, wire
}

type cfnObservabilityPrivateFixture struct {
	ctx            context.Context
	commands       StepFunctionsCommands
	cw             *cloudwatch.Service
	logs           *logs.Service
	logsRepository logs.Repository
	reopen         func()
	policy         func(string)
	lostReply      *cfnObservabilityLostAdmissionReply
}

func newCFNObservabilityPrivateFixture(t *testing.T, backend, service, lostOperation string) *cfnObservabilityPrivateFixture {
	t.Helper()
	f := &cfnObservabilityPrivateFixture{ctx: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})}
	source := clock.NewManual(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
	admin := f.ctx
	identities := iam.NewMemoryRepository(nil)
	identityOwner := iam.NewWithConfig(iam.Config{Repository: identities, Clock: source})
	t.Cleanup(func() { _ = identityOwner.Close() })
	authorizer := authorization.NewWithClock(identityOwner, nil, source)
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:user/observability-owner", PrincipalID: "AIDAOBSERVABILITYOWNER"})
	f.policy = func(document string) {
		t.Helper()
		user := iam.User{UserName: "observability-owner", UserId: "AIDAOBSERVABILITYOWNER", Arn: "arn:aws:iam::123456789012:user/observability-owner", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"native": document}}}
		if err := identities.Update(admin, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
		}); err != nil {
			t.Fatal(err)
		}
	}
	f.policy(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["cloudwatch:*","logs:*"],"Resource":"*"}}`)
	var cwrepo cloudwatch.Repository = cloudwatch.NewMemoryRepository(nil)
	var logsrepo logs.Repository = logs.NewMemoryRepository(nil)
	var db *sql.DB
	path := filepath.Join(t.TempDir(), "observability.sqlite")
	open := func() {
		if backend == "sqlite" {
			var err error
			db, err = sqlite.Open(f.ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			cwrepo, logsrepo = cwstore.New(db), logsstore.New(db)
		}
	}
	open()
	assemble := func(lose bool) {
		f.cw = cloudwatch.New(cloudwatch.Config{Repository: cwrepo, Clock: source, Authorizer: authorizer})
		f.logs = logs.New(logs.Config{Repository: logsrepo, Clock: source, Authorizer: authorizer})
		f.logsRepository = logsrepo
		owners := map[string]awscommands.CommandExecutor{"cloudwatch": f.cw, "logs": f.logs}
		if lose {
			f.lostReply = &cfnObservabilityLostAdmissionReply{owner: owners[service], operation: lostOperation, armed: true}
			owners[service] = f.lostReply
		}
		f.commands = NewStepFunctionsCommands(owners)
	}
	assemble(lostOperation != "")
	f.reopen = func() {
		_ = f.cw.Close()
		_ = f.logs.Close()
		if db != nil {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			open()
		}
		assemble(false)
	}
	t.Cleanup(func() {
		_ = f.cw.Close()
		_ = f.logs.Close()
		if db != nil {
			_ = db.Close()
		}
	})
	return f
}
func cfnObservabilityPrivateHandler(commands StepFunctionsCommands, kind string) cloudformation.ResourceHandler {
	if kind == "AWS::Logs::LogGroup" {
		return cfnLogGroup{commands}
	}
	return CloudFormationObservabilityHandlers(commands)[kind]
}

func TestCFNObservabilityPrivateIncarnationsAndNativeRecovery(t *testing.T) {
	rows := []struct {
		kind, service, create, remove, nameProperty string
		properties                                  cloudformation.Properties
	}{
		{"AWS::CloudWatch::Alarm", "cloudwatch", "PutMetricAlarm", "DeleteAlarms", "AlarmName", cloudformation.Properties{"AlarmName": "private-alarm", "Namespace": "Owner/Test", "MetricName": "Count", "Statistic": "Sum", "Period": 60, "EvaluationPeriods": 1, "Threshold": 1, "ComparisonOperator": "GreaterThanThreshold"}},
		{"AWS::CloudWatch::CompositeAlarm", "cloudwatch", "PutCompositeAlarm", "DeleteAlarms", "AlarmName", cloudformation.Properties{"AlarmName": "private-composite", "AlarmRule": "FALSE"}},
		{"AWS::CloudWatch::Dashboard", "cloudwatch", "PutDashboard", "DeleteDashboards", "DashboardName", cloudformation.Properties{"DashboardName": "private-dashboard", "DashboardBody": `{"widgets":[]}`}},
		{"AWS::Logs::LogGroup", "logs", "CreateLogGroup", "DeleteLogGroup", "LogGroupName", cloudformation.Properties{"LogGroupName": "private-group", "RetentionInDays": 7}},
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, row := range rows {
			for _, cc := range []bool{false, true} {
				label := "cfn"
				if cc {
					label = "cc"
				}
				t.Run(backend+"/"+row.kind+"/"+label, func(t *testing.T) {
					f := newCFNObservabilityPrivateFixture(t, backend, row.service, row.create)
					f.lostReply.after = func() {
						f.policy(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":["cloudwatch:*","logs:*"],"Resource":"*"}}`)
					}
					r := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Resource", Token: "creation-token", Type: row.kind, Properties: maps.Clone(row.properties), CloudControl: cc}
					r.Scope = cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
					r.Properties["Tags"] = []any{map[string]any{"Key": "customer", "Value": "retained"}}
					h := cfnObservabilityPrivateHandler(f.commands, row.kind)
					admitted, err := h.Create(f.ctx, r)
					if err == nil || admitted.PhysicalID == "" {
						t.Fatalf("lost actual admission reply discarded private identity: %+v %v", admitted, err)
					}
					if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil {
						t.Fatal("exact-token recovery ignored IAM revoked after actual admission")
					}
					f.policy(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["cloudwatch:*","logs:*"],"Resource":"*"}}`)
					r.PhysicalID = admitted.PhysicalID
					f.reopen()
					h = cfnObservabilityPrivateHandler(f.commands, row.kind)
					recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
					if err != nil || recovered.PhysicalID != admitted.PhysicalID {
						t.Fatalf("native private recovery failed after reopen: %+v %v", recovered, err)
					}
					if replay, err := h.Create(f.ctx, r); err != nil || replay.PhysicalID != admitted.PhysicalID {
						t.Fatalf("same-token creation did not retain native incarnation: %+v %v", replay, err)
					}
					model, err := h.(cloudformation.ResourceReader).Read(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					tags, err := cfnComputeTags(model)
					if err != nil {
						t.Fatal(err)
					}
					if len(tags) != 1 || tags["customer"] != "retained" {
						t.Fatalf("response exposed claim tags or lost customer tags: %+v", tags)
					}
					f.policy(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":["cloudwatch:*","logs:*"],"Resource":"*"}}`)
					if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil {
						t.Fatal("private recovery bypassed current native IAM")
					}
					if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err == nil {
						t.Fatal("native read bypassed current IAM")
					}
					if _, err := h.Update(f.ctx, r); err == nil {
						t.Fatal("private update bypassed current native IAM")
					}
					if err := h.Delete(f.ctx, r); err == nil {
						t.Fatal("private delete bypassed current native IAM")
					}
					f.policy(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["cloudwatch:*","logs:*"],"Resource":"*"}}`)
					name := cfnComputeString(r.Properties, row.nameProperty)
					deleteInput := map[string]any{}
					switch row.remove {
					case "DeleteAlarms":
						deleteInput["AlarmNames"] = []string{name}
					case "DeleteDashboards":
						deleteInput["DashboardNames"] = []string{name}
					default:
						deleteInput["LogGroupName"] = name
					}
					if err := cfnComputeRun(f.ctx, f.commands, row.service, row.remove, deleteInput); err != nil {
						t.Fatal(err)
					}
					input := maps.Clone(row.properties)
					delete(input, "RetentionInDays")
					forged := cfnComputeOwnedTags(r)
					forged["stackd:cloudformation:owner"] = cfnLogsMarker(r)
					if row.service == "logs" {
						input["Tags"] = forged
					} else {
						input["Tags"] = cfnComputeTagList(forged)
					}
					if err := cfnComputeRun(f.ctx, f.commands, row.service, row.create, input); err != nil {
						t.Fatal(err)
					}
					if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err != nil {
						t.Fatalf("native replacement unreadable: %v", err)
					}
					if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil || recovered.PhysicalID != "" {
						t.Fatalf("counterfeit tags forged recovery: %+v %v", recovered, err)
					}
					if created, err := h.Create(f.ctx, r); err == nil || created.PhysicalID != "" {
						t.Fatalf("creation adopted native replacement: %+v %v", created, err)
					}
					stale := r
					stale.CloudControl = false
					stale.Previous = r.Properties
					if _, err := h.Update(f.ctx, stale); err == nil {
						t.Fatal("stale CFN update accepted counterfeit markers")
					}
					if err := h.Delete(f.ctx, stale); err == nil {
						t.Fatal("stale CFN delete accepted counterfeit markers")
					}
					if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err != nil {
						t.Fatalf("stale mutation damaged native replacement: %v", err)
					}
					direct := r
					direct.CloudControl = true
					direct.Previous = r.Properties
					if _, err := h.Update(f.ctx, direct); err != nil {
						t.Fatalf("ordinary IAM-permitted CC update was fenced: %v", err)
					}
					if err := h.Delete(f.ctx, direct); err != nil {
						t.Fatalf("ordinary IAM-permitted CC delete was fenced: %v", err)
					}
				})
			}
		}
	}
}

func TestCFNLogGroupPostAdmissionRetentionFailureRetainsIdentity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNObservabilityPrivateFixture(t, backend, "logs", "")
			r := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Group", Token: "retention-failure", Type: "AWS::Logs::LogGroup", Properties: cloudformation.Properties{"LogGroupName": "retention-failure", "RetentionInDays": 2}}
			r.Scope = cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
			h := cfnLogGroup{f.commands}
			result, err := h.Create(f.ctx, r)
			if err == nil || result.PhysicalID != "retention-failure" {
				t.Fatalf("postadmission failure lost authentic group: %+v %v", result, err)
			}
			f.reopen()
			h = cfnLogGroup{f.commands}
			recovered, err := h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != result.PhysicalID {
				t.Fatalf("postadmission native claim not retained: %+v %v", recovered, err)
			}
		})
	}
}

// This retained-row fixture isolates SQLite claim persistence and the native
// policy/tag/delete commands from the unrelated external Kinesis engine.
// Native destination admission/recheck itself is exercised in the Logs owner test.
func TestCFNLogDestinationRetainedPrivateClaimAndRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNObservabilityPrivateFixture(t, backend, "logs", "")
			r := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Destination", Token: "retained-creation", Type: "AWS::Logs::Destination", Properties: cloudformation.Properties{"DestinationName": "retained-destination", "TargetArn": "arn:aws:kinesis:us-east-1:123456789012:stream/target", "RoleArn": "arn:aws:iam::123456789012:role/logs"}}
			r.Scope = cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
			key := logs.DestinationKey{Scope: logs.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "retained-destination"}
			store := func(owner string) {
				t.Helper()
				if err := f.logsRepository.Update(f.ctx, func(tx logs.Transaction) error {
					return tx.PutDestination(logs.DestinationRecord{Key: key, CFNOwner: owner, TargetARN: cfnComputeString(r.Properties, "TargetArn"), RoleARN: cfnComputeString(r.Properties, "RoleArn"), Created: 1, Tags: map[string]string{"customer": "retained"}})
				}); err != nil {
					t.Fatal(err)
				}
			}
			store(cfnLogsMarker(r))
			f.reopen()
			h := cfnLogDestination{f.commands}
			recovered, err := h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != key.Name {
				t.Fatalf("private destination claim lost on reopen: %+v %v", recovered, err)
			}
			r.PhysicalID = recovered.PhysicalID
			// No engine is configured: a failed replay must still retain its actually
			// admitted identity rather than report an unclaimed generated name.
			replay, err := h.Create(f.ctx, r)
			if err == nil || replay.PhysicalID != key.Name {
				t.Fatalf("failed replay forgot authentic private admission: %+v %v", replay, err)
			}
			policy := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"logs:PutSubscriptionFilter","Resource":"*"}}`
			if err := cfnComputeRun(cfnLogsContext(f.ctx, r, false), f.commands, "logs", "PutDestinationPolicy", map[string]any{"DestinationName": key.Name, "AccessPolicy": policy}); err != nil {
				t.Fatal(err)
			}
			forged := cfnComputeOwnedTags(r)
			forged["stackd:cloudformation:owner"] = cfnLogsMarker(r)
			if err := cfnComputeRun(f.ctx, f.commands, "logs", "TagResource", map[string]any{"ResourceArn": key.ARN(), "Tags": forged}); err != nil {
				t.Fatal(err)
			}
			if recovered, err := h.RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != key.Name {
				t.Fatalf("public tags displaced private row authority: %+v %v", recovered, err)
			}
			f.policy(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"logs:*","Resource":"*"}}`)
			if _, err := h.RecoverCreation(f.ctx, r); err == nil {
				t.Fatal("destination recovery bypassed current IAM")
			}
			if err := h.Delete(f.ctx, r); err == nil {
				t.Fatal("destination delete bypassed current IAM")
			}
			f.policy(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["cloudwatch:*","logs:*"],"Resource":"*"}}`)
			if err := cfnComputeRun(f.ctx, f.commands, "logs", "DeleteDestination", map[string]any{"DestinationName": key.Name}); err != nil {
				t.Fatal(err)
			}
			store("")
			if err := cfnComputeRun(f.ctx, f.commands, "logs", "TagResource", map[string]any{"ResourceArn": key.ARN(), "Tags": forged}); err != nil {
				t.Fatal(err)
			}
			f.reopen()
			h = cfnLogDestination{f.commands}
			if _, err := h.Read(f.ctx, r); err != nil {
				t.Fatalf("native recreated destination unreadable: %v", err)
			}
			if recovered, err := h.RecoverCreation(f.ctx, r); err == nil || recovered.PhysicalID != "" {
				t.Fatalf("counterfeit public marker forged destination recovery: %+v %v", recovered, err)
			}
			if created, err := h.Create(f.ctx, r); err == nil || created.PhysicalID != "" {
				t.Fatalf("counterfeit destination adopted on create: %+v %v", created, err)
			}
			if _, err := h.Update(f.ctx, r); err == nil {
				t.Fatal("private update adopted foreign destination")
			}
			if err := h.Delete(f.ctx, r); err == nil {
				t.Fatal("private delete removed foreign destination")
			}
			for _, operation := range []string{"PutDestinationPolicy", "TagResource", "UntagResource"} {
				input := map[string]any{"DestinationName": key.Name, "AccessPolicy": policy}
				if operation == "TagResource" {
					input = map[string]any{"ResourceArn": key.ARN(), "Tags": map[string]string{"customer": "forged"}}
				}
				if operation == "UntagResource" {
					input = map[string]any{"ResourceArn": key.ARN(), "TagKeys": []string{"customer"}}
				}
				if err := cfnComputeRun(cfnLogsContext(f.ctx, r, false), f.commands, "logs", operation, input); err == nil {
					t.Fatalf("private destination fence bypassed by %s", operation)
				}
			}
			if _, err := h.Read(f.ctx, r); err != nil {
				t.Fatalf("stale commands damaged native destination: %v", err)
			}
			direct := r
			direct.CloudControl = true
			if err := h.Delete(f.ctx, direct); err != nil {
				t.Fatalf("CC ordinary destination delete was fenced: %v", err)
			}
		})
	}
}

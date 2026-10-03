package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

const (
	cfnMigrationRule             = "cfn-bus-migration-rule"
	cfnMigrationSource           = "cfn-bus-migration-source"
	cfnMigrationDestination      = "cfn-bus-migration-destination"
	cfnMigrationSourceQueue      = "cfn-bus-migration-before"
	cfnMigrationDestinationQueue = "cfn-bus-migration-after"
	cfnMigrationEventSource      = "stackd.cfn.rule-migration"
)

type cfnRuleMigration struct {
	clients cloudClients
	reopen  func() cloudClients
	clock   *clock.Manual
	stackID string
}

func newCFNRuleMigration(t *testing.T, backend string) *cfnRuleMigration {
	t.Helper()
	f := &cfnRuleMigration{clock: clock.NewManual(time.Now().UTC())}
	f.clients, f.reopen = retainedCloud(t, backend, stackd.Config{Clock: f.clock}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return startPublicCloud(t, config)
	})
	for _, bus := range []string{cfnMigrationSource, cfnMigrationDestination} {
		if _, err := f.events().CreateEventBus(t.Context(), &eventbridge.CreateEventBusInput{Name: aws.String(bus)}); err != nil {
			t.Fatal(err)
		}
	}
	queues := f.clients.sqs("test", "test", "")
	for _, name := range []string{cfnMigrationSourceQueue, cfnMigrationDestinationQueue} {
		queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(name)})
		if err != nil {
			t.Fatal(err)
		}
		policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":[%q,%q]}}}]}`,
			cfnMigrationQueueARN(name), cfnMigrationRuleARN(cfnMigrationSource), cfnMigrationRuleARN(cfnMigrationDestination))
		if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
			t.Fatal(err)
		}
	}
	created, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{
		StackName: aws.String("event-rule-migration"), TemplateBody: aws.String(cfnMigrationTemplate(t, cfnMigrationSource, cfnMigrationSourceQueue, "before")),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.stackID = aws.ToString(created.StackId)
	f.identity(t, f.wait(t, cfntypes.StackStatusCreateComplete), cfnMigrationSource)
	return f
}

func cfnMigrationQueueARN(name string) string {
	return "arn:aws:sqs:us-east-1:000000000000:" + name
}

func cfnMigrationRuleARN(bus string) string {
	return "arn:aws:events:us-east-1:000000000000:rule/" + bus + "/" + cfnMigrationRule
}

func cfnMigrationTransformer(version string) *eventtypes.InputTransformer {
	return &eventtypes.InputTransformer{
		InputPathsMap: map[string]string{"id": "$.id", "marker": "$.detail.marker"},
		InputTemplate: aws.String(fmt.Sprintf(`{"event":<id>,"marker":<marker>,"version":%q}`, version)),
	}
}

func cfnMigrationTemplate(t *testing.T, bus, queue, version string) string {
	t.Helper()
	transformer := cfnMigrationTransformer(version)
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{"Rule": map[string]any{
			"Type": "AWS::Events::Rule", "Properties": map[string]any{
				"Name": cfnMigrationRule, "EventBusName": bus, "State": "ENABLED",
				"EventPattern": map[string]any{"source": []string{cfnMigrationEventSource}},
				"Targets": []any{map[string]any{
					"Id": "queue", "Arn": cfnMigrationQueueARN(queue),
					"InputTransformer": map[string]any{"InputPathsMap": transformer.InputPathsMap, "InputTemplate": aws.ToString(transformer.InputTemplate)},
					"RetryPolicy":      map[string]int{"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
				}},
			},
		}},
		"Outputs": map[string]any{
			"RuleRef":  map[string]any{"Value": map[string]string{"Ref": "Rule"}},
			"RuleArn":  map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Rule", "Arn"}}},
			"RuleName": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Rule", "RuleName"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func (f *cfnRuleMigration) cfn() *cloudformation.Client {
	return cloudFormationClient(f.clients, "us-east-1", "test", "test")
}

func (f *cfnRuleMigration) events() *eventbridge.Client {
	return eventDeliveryClient(f.clients, "test")
}

func (f *cfnRuleMigration) wait(t *testing.T, status cfntypes.StackStatus) cfntypes.Stack {
	t.Helper()
	return cloudFormationWait(t, f.clients, f.clock, f.cfn(), f.stackID, status)
}

func (f *cfnRuleMigration) update(t *testing.T, client *cloudformation.Client, bus, queue, version string, status cfntypes.StackStatus) cfntypes.Stack {
	t.Helper()
	if _, err := client.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{
		StackName: aws.String(f.stackID), TemplateBody: aws.String(cfnMigrationTemplate(t, bus, queue, version)),
	}); err != nil {
		t.Fatal(err)
	}
	return f.wait(t, status)
}

func (f *cfnRuleMigration) identity(t *testing.T, stack cfntypes.Stack, bus string) {
	t.Helper()
	outputs := make(map[string]string, len(stack.Outputs))
	for _, output := range stack.Outputs {
		outputs[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
	}
	want := map[string]string{"RuleRef": bus + "|" + cfnMigrationRule, "RuleArn": cfnMigrationRuleARN(bus), "RuleName": cfnMigrationRule}
	if !reflect.DeepEqual(outputs, want) {
		t.Fatalf("rule identity changed incorrectly: got %v, want %v", outputs, want)
	}
	resource, err := f.cfn().DescribeStackResource(t.Context(), &cloudformation.DescribeStackResourceInput{
		StackName: aws.String(f.stackID), LogicalResourceId: aws.String("Rule"),
	})
	if err != nil || resource.StackResourceDetail == nil || aws.ToString(resource.StackResourceDetail.PhysicalResourceId) != want["RuleRef"] {
		t.Fatalf("physical resource identity does not identify the current bus and rule: %+v %v", resource, err)
	}
	rule, err := f.events().DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{Name: aws.String(cfnMigrationRule), EventBusName: aws.String(bus)})
	if err != nil || aws.ToString(rule.Arn) != want["RuleArn"] || aws.ToString(rule.Name) != cfnMigrationRule || rule.State != eventtypes.RuleStateEnabled {
		t.Fatalf("stack output does not identify the enabled real rule: %+v %v", rule, err)
	}
}

func (f *cfnRuleMigration) targets(t *testing.T, bus, queue, version string) {
	t.Helper()
	out, err := f.events().ListTargetsByRule(t.Context(), &eventbridge.ListTargetsByRuleInput{Rule: aws.String(cfnMigrationRule), EventBusName: aws.String(bus)})
	if err != nil || len(out.Targets) != 1 {
		t.Fatalf("expected one managed target on %s: %+v %v", bus, out, err)
	}
	target := out.Targets[0]
	if aws.ToString(target.Id) != "queue" || aws.ToString(target.Arn) != cfnMigrationQueueARN(queue) || !reflect.DeepEqual(target.InputTransformer, cfnMigrationTransformer(version)) ||
		target.RetryPolicy == nil || aws.ToInt32(target.RetryPolicy.MaximumRetryAttempts) != 0 || aws.ToInt32(target.RetryPolicy.MaximumEventAgeInSeconds) != 60 {
		t.Fatalf("target configuration was not retained on %s: %+v", bus, target)
	}
}

type cfnMigrationEvent struct {
	bus, marker, queue, version string
}

// Publish old-bus events before the current-route marker. Drive the actual
// scheduler and match every SQS payload against its accepted EventBridge ID;
// a quiet queue or a wall-clock delay alone is not evidence of migration.
func (f *cfnRuleMigration) delivery(t *testing.T, probes ...cfnMigrationEvent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	want := map[string]map[string]string{
		cfnMigrationSourceQueue: {}, cfnMigrationDestinationQueue: {},
	}
	for _, probe := range probes {
		out, err := f.events().PutEvents(ctx, &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{{
			EventBusName: aws.String(probe.bus), Source: aws.String(cfnMigrationEventSource), DetailType: aws.String("migration-marker"),
			Detail: aws.String(fmt.Sprintf(`{"marker":%q}`, probe.marker)), Time: aws.Time(f.clock.Now()),
		}}})
		if err != nil || out.FailedEntryCount != 0 || len(out.Entries) != 1 || aws.ToString(out.Entries[0].EventId) == "" {
			t.Fatalf("marker admission failed: %+v %v", out, err)
		}
		if probe.queue != "" {
			id := aws.ToString(out.Entries[0].EventId)
			want[probe.queue][id] = fmt.Sprintf(`{"event":%q,"marker":%q,"version":%q}`, id, probe.marker, probe.version)
		}
	}
	queues := f.clients.sqs("test", "test", "")
	urls := make(map[string]*string)
	for name := range want {
		out, err := queues.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: aws.String(name)})
		if err != nil {
			t.Fatal(err)
		}
		urls[name] = out.QueueUrl
	}
	for {
		drain, err := f.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for name, url := range urls {
			out, err := queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: url, MaxNumberOfMessages: 10})
			if err != nil {
				t.Fatal(err)
			}
			for _, message := range out.Messages {
				var body struct {
					Event string `json:"event"`
				}
				if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &body); err != nil {
					t.Fatal(err)
				}
				expected, ok := want[name][body.Event]
				if !ok {
					t.Fatalf("unexpected or duplicate delivery to %s: %s", name, aws.ToString(message.Body))
				}
				assertEventInputBody(t, aws.ToString(message.Body), expected)
				delete(want[name], body.Event)
				if _, err := queues.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: url, ReceiptHandle: message.ReceiptHandle}); err != nil {
					t.Fatal(err)
				}
			}
		}
		if !drain.More && len(want[cfnMigrationSourceQueue]) == 0 && len(want[cfnMigrationDestinationQueue]) == 0 {
			return
		}
		advanceClock(t, f.clock, time.Second)
		select {
		case <-ctx.Done():
			t.Fatalf("accepted events did not reach their expected targets: %v: %v", want, ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

// Native external outcomes are captured in
// testdata/aws/cloudformation/eventbridge_rule_migration.json: bus|name Ref and
// physical identity change, the rule Name stays fixed, and the old route is
// removed. The companion eventbridge_rule_migration_identity.json captures
// equivalent bus-ARN spelling. IAM revocation below is a local authorization
// regression, not an inferred AWS implementation step.
func TestCloudFormationEventBridgeRuleMigration(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRuleMigration(t, backend)
			f.delivery(t, cfnMigrationEvent{cfnMigrationSource, "before-failure", cfnMigrationSourceQueue, "before"})

			rolledBack := f.update(t, f.cfn(), "cfn-bus-migration-missing", cfnMigrationDestinationQueue, "missing",
				cfntypes.StackStatusUpdateRollbackComplete)
			f.identity(t, rolledBack, cfnMigrationSource)
			f.targets(t, cfnMigrationSource, cfnMigrationSourceQueue, "before")
			f.delivery(t, cfnMigrationEvent{cfnMigrationSource, "missing-bus-rollback", cfnMigrationSourceQueue, "before"})

			_, access, secret := f.clients.user(t, "test", "cfn-rule-migration-operator")
			allowed := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","events:*"],"Resource":"*"}]}`
			putUserPolicy(t, f.clients.iam("test", "test", ""), "cfn-rule-migration-operator", allowed)
			actor := cloudFormationClient(f.clients, "us-east-1", access, secret)
			if _, err := actor.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: aws.String(f.stackID)}); err != nil {
				t.Fatal(err)
			}
			// The existing signed key must see current destination authorization;
			// source-bus permissions remain available to the real rollback.
			denied := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","events:*"],"Resource":"*"},{"Effect":"Deny","Action":"events:PutRule","Resource":%q}]}`, cfnMigrationRuleARN(cfnMigrationDestination))
			putUserPolicy(t, f.clients.iam("test", "test", ""), "cfn-rule-migration-operator", denied)
			rolledBack = f.update(t, actor, cfnMigrationDestination, cfnMigrationDestinationQueue, "after",
				cfntypes.StackStatusUpdateRollbackComplete)
			f.identity(t, rolledBack, cfnMigrationSource)
			f.targets(t, cfnMigrationSource, cfnMigrationSourceQueue, "before")
			_, err := f.events().DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{
				Name: aws.String(cfnMigrationRule), EventBusName: aws.String(cfnMigrationDestination),
			})
			assertAPIError(t, err, "ResourceNotFoundException")
			f.delivery(t, cfnMigrationEvent{cfnMigrationDestination, "denied-destination", "", ""},
				cfnMigrationEvent{cfnMigrationSource, "denied-migration-rollback", cfnMigrationSourceQueue, "before"})

			f.clients = f.reopen()
			f.identity(t, f.wait(t, cfntypes.StackStatusUpdateRollbackComplete), cfnMigrationSource)
			f.targets(t, cfnMigrationSource, cfnMigrationSourceQueue, "before")
			f.delivery(t, cfnMigrationEvent{cfnMigrationSource, "rollback-reopened", cfnMigrationSourceQueue, "before"})

			// Exercise a partial-effect failure too: destination rule creation
			// is allowed but target admission is not. Rollback must remove
			// that owned replacement without disturbing the original route.
			deniedTargets := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","events:*"],"Resource":"*"},{"Effect":"Deny","Action":"events:PutTargets","Resource":%q}]}`, cfnMigrationRuleARN(cfnMigrationDestination))
			putUserPolicy(t, f.clients.iam("test", "test", ""), "cfn-rule-migration-operator", deniedTargets)
			actor = cloudFormationClient(f.clients, "us-east-1", access, secret)
			rolledBack = f.update(t, actor, cfnMigrationDestination, cfnMigrationDestinationQueue, "after",
				cfntypes.StackStatusUpdateRollbackComplete)
			f.identity(t, rolledBack, cfnMigrationSource)
			f.targets(t, cfnMigrationSource, cfnMigrationSourceQueue, "before")
			_, err = f.events().DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{
				Name: aws.String(cfnMigrationRule), EventBusName: aws.String(cfnMigrationDestination),
			})
			assertAPIError(t, err, "ResourceNotFoundException")
			f.delivery(t, cfnMigrationEvent{cfnMigrationDestination, "target-denied-destination", "", ""},
				cfnMigrationEvent{cfnMigrationSource, "target-denied-rollback", cfnMigrationSourceQueue, "before"})

			putUserPolicy(t, f.clients.iam("test", "test", ""), "cfn-rule-migration-operator", allowed)
			actor = cloudFormationClient(f.clients, "us-east-1", access, secret)
			migrated := f.update(t, actor, cfnMigrationDestination, cfnMigrationDestinationQueue, "after",
				cfntypes.StackStatusUpdateComplete)
			f.identity(t, migrated, cfnMigrationDestination)
			f.targets(t, cfnMigrationDestination, cfnMigrationDestinationQueue, "after")
			_, err = f.events().DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{
				Name: aws.String(cfnMigrationRule), EventBusName: aws.String(cfnMigrationSource),
			})
			assertAPIError(t, err, "ResourceNotFoundException")
			f.delivery(t, cfnMigrationEvent{cfnMigrationSource, "retired-source", "", ""},
				cfnMigrationEvent{cfnMigrationDestination, "restored-authority", cfnMigrationDestinationQueue, "after"})

			f.clients = f.reopen()
			f.identity(t, f.wait(t, cfntypes.StackStatusUpdateComplete), cfnMigrationDestination)
			f.targets(t, cfnMigrationDestination, cfnMigrationDestinationQueue, "after")
			f.delivery(t, cfnMigrationEvent{cfnMigrationSource, "retired-source-reopened", "", ""},
				cfnMigrationEvent{cfnMigrationDestination, "migrated-reopened", cfnMigrationDestinationQueue, "after"})
			// The native identity capture preserves canonical bus|name when
			// changing this bus's name to its equivalent ARN.
			destinationARN := "arn:aws:events:us-east-1:000000000000:event-bus/" + cfnMigrationDestination
			updated := f.update(t, f.cfn(), destinationARN, cfnMigrationDestinationQueue, "updated",
				cfntypes.StackStatusUpdateComplete)
			f.identity(t, updated, cfnMigrationDestination)
			f.targets(t, cfnMigrationDestination, cfnMigrationDestinationQueue, "updated")
			f.delivery(t, cfnMigrationEvent{cfnMigrationDestination, "updated-target", cfnMigrationDestinationQueue, "updated"})
			if _, err := f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)}); err != nil {
				t.Fatal(err)
			}
			f.wait(t, cfntypes.StackStatusDeleteComplete)
			_, err = f.events().DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{
				Name: aws.String(cfnMigrationRule), EventBusName: aws.String(cfnMigrationDestination),
			})
			assertAPIError(t, err, "ResourceNotFoundException")
			// Buses and queues are external prerequisites, not stack resources:
			// both remain independently usable after managed-route deletion.
			for _, bus := range []string{cfnMigrationSource, cfnMigrationDestination} {
				if _, err := f.events().DescribeEventBus(t.Context(), &eventbridge.DescribeEventBusInput{Name: aws.String(bus)}); err != nil {
					t.Fatal(err)
				}
			}
			f.delivery(t, cfnMigrationEvent{cfnMigrationSource, "deleted-source", "", ""},
				cfnMigrationEvent{cfnMigrationDestination, "deleted-destination", "", ""})
		})
	}
}

// The private ownership guard is a stackd safety boundary, not an assertion
// about undocumented AWS provider calls or native same-name adoption.
func TestCloudFormationEventBridgeRuleMigrationForeignDestination(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRuleMigration(t, backend)
			_, err := f.events().PutRule(t.Context(), &eventbridge.PutRuleInput{
				Name: aws.String(cfnMigrationRule), EventBusName: aws.String(cfnMigrationDestination),
				EventPattern: aws.String(fmt.Sprintf(`{"source":[%q]}`, cfnMigrationEventSource)),
				Description:  aws.String("independently-owned destination"),
			})
			if err != nil {
				t.Fatal(err)
			}
			foreignTarget := eventtypes.Target{
				Id: aws.String("foreign"), Arn: aws.String(cfnMigrationQueueARN(cfnMigrationDestinationQueue)),
				InputTransformer: cfnMigrationTransformer("foreign"),
			}
			targets, err := f.events().PutTargets(t.Context(), &eventbridge.PutTargetsInput{
				Rule: aws.String(cfnMigrationRule), EventBusName: aws.String(cfnMigrationDestination),
				Targets: []eventtypes.Target{foreignTarget},
			})
			if err != nil || targets.FailedEntryCount != 0 {
				t.Fatalf("foreign target setup failed: %+v %v", targets, err)
			}
			f.clients = f.reopen()
			rolledBack := f.update(t, f.cfn(), cfnMigrationDestination, cfnMigrationSourceQueue, "must-not-adopt",
				cfntypes.StackStatusUpdateRollbackComplete)
			f.identity(t, rolledBack, cfnMigrationSource)
			f.targets(t, cfnMigrationSource, cfnMigrationSourceQueue, "before")
			f.delivery(t, cfnMigrationEvent{cfnMigrationDestination, "foreign-after-rejected-move", cfnMigrationDestinationQueue, "foreign"},
				cfnMigrationEvent{cfnMigrationSource, "owned-after-rejected-move", cfnMigrationSourceQueue, "before"})
			f.clients = f.reopen()
			foreign, err := f.events().DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{
				Name: aws.String(cfnMigrationRule), EventBusName: aws.String(cfnMigrationDestination),
			})
			if err != nil || aws.ToString(foreign.Description) != "independently-owned destination" {
				t.Fatalf("failed migration changed foreign rule: %+v %v", foreign, err)
			}
			listed, err := f.events().ListTargetsByRule(t.Context(), &eventbridge.ListTargetsByRuleInput{
				Rule: aws.String(cfnMigrationRule), EventBusName: aws.String(cfnMigrationDestination),
			})
			if err != nil || len(listed.Targets) != 1 || aws.ToString(listed.Targets[0].Id) != "foreign" ||
				aws.ToString(listed.Targets[0].Arn) != cfnMigrationQueueARN(cfnMigrationDestinationQueue) ||
				!reflect.DeepEqual(listed.Targets[0].InputTransformer, foreignTarget.InputTransformer) {
				t.Fatalf("failed migration changed foreign target: %+v %v", listed, err)
			}
			if _, err := f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)}); err != nil {
				t.Fatal(err)
			}
			f.wait(t, cfntypes.StackStatusDeleteComplete)
			_, err = f.events().DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{
				Name: aws.String(cfnMigrationRule), EventBusName: aws.String(cfnMigrationSource),
			})
			assertAPIError(t, err, "ResourceNotFoundException")
			f.delivery(t, cfnMigrationEvent{cfnMigrationSource, "deleted-owned-route", "", ""},
				cfnMigrationEvent{cfnMigrationDestination, "foreign-after-stack-delete", cfnMigrationDestinationQueue, "foreign"})
		})
	}
}

// Native eventbridge_rule_migration_changesets.json reports Conditional plans
// for both equivalent spelling and a changed bus. Execution must distinguish
// them; the cross-account failure below additionally fences local identity.
func TestCloudFormationEventBridgeRuleMigrationChangeSetIdentity(t *testing.T) {
	f := newCFNRuleMigration(t, "memory")
	for _, tc := range []struct {
		name, bus, resultBus string
		status               cfntypes.StackStatus
	}{
		{"same-owner-arn", "arn:aws:events:us-east-1:000000000000:event-bus/" + cfnMigrationSource, cfnMigrationSource, cfntypes.StackStatusUpdateComplete},
		{"different-owner", "arn:aws:events:us-east-1:111111111111:event-bus/" + cfnMigrationSource, cfnMigrationSource, cfntypes.StackStatusUpdateRollbackComplete},
		{"different-bus", cfnMigrationDestination, cfnMigrationDestination, cfntypes.StackStatusUpdateComplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created, err := f.cfn().CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{
				StackName: aws.String(f.stackID), ChangeSetName: aws.String(tc.name),
				ChangeSetType: cfntypes.ChangeSetTypeUpdate,
				TemplateBody:  aws.String(cfnMigrationTemplate(t, tc.bus, cfnMigrationSourceQueue, "before")),
			})
			if err != nil {
				t.Fatal(err)
			}
			described, err := f.cfn().DescribeChangeSet(t.Context(), &cloudformation.DescribeChangeSetInput{
				ChangeSetName: created.Id, IncludePropertyValues: aws.Bool(true),
			})
			if err != nil || len(described.Changes) != 1 {
				t.Fatalf("change-set description: %+v %v", described, err)
			}
			change := described.Changes[0].ResourceChange
			if change == nil || change.Replacement != cfntypes.ReplacementConditional {
				t.Fatalf("incorrect scoped replacement: %+v", change)
			}
			found := false
			for _, detail := range change.Details {
				if detail.Target != nil && aws.ToString(detail.Target.Name) == "EventBusName" {
					found = true
					if detail.Target.RequiresRecreation != cfntypes.RequiresRecreationConditionally {
						t.Fatalf("bus property disagrees with scoped replacement: %+v", detail.Target)
					}
				}
			}
			if !found {
				t.Fatal("change-set omitted bus property details")
			}
			if _, err := f.cfn().ExecuteChangeSet(t.Context(), &cloudformation.ExecuteChangeSetInput{ChangeSetName: created.Id}); err != nil {
				t.Fatal(err)
			}
			f.identity(t, f.wait(t, tc.status), tc.resultBus)
			f.delivery(t, cfnMigrationEvent{tc.resultBus, tc.name, cfnMigrationSourceQueue, "before"})
		})
	}
}

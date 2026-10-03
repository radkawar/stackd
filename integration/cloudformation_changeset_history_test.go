package stackd_test

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"

	"stackd"
	"stackd/clock"
)

// Native evidence: testdata/aws/cloudformation/changeset_name_reuse.json.
// Execution preserves ARN-addressed history without reserving the active name.
func TestCloudFormationExecutedChangeSetNameReuse(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			body := func(delay int) *string {
				return aws.String(fmt.Sprintf(`{"Resources":{"Queue":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"cfn-change-name","DelaySeconds":%d}}},"Outputs":{"Queue":{"Value":{"Ref":"Queue"}}}}`, delay))
			}
			created, err := root.CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{StackName: aws.String("cfn-change-name"), ChangeSetName: aws.String("repeatable"), ChangeSetType: cfntypes.ChangeSetTypeCreate, TemplateBody: body(0)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := root.ExecuteChangeSet(t.Context(), &cloudformation.ExecuteChangeSetInput{ChangeSetName: created.Id}); err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			c = reopen()
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			_, err = root.DescribeChangeSet(t.Context(), &cloudformation.DescribeChangeSetInput{StackName: created.StackId, ChangeSetName: aws.String("repeatable")})
			assertAPIError(t, err, "ChangeSetNotFound")
			listed, err := root.ListChangeSets(t.Context(), &cloudformation.ListChangeSetsInput{StackName: created.StackId})
			if err != nil || len(listed.Summaries) != 0 {
				t.Fatalf("executed history leaked into active change sets: %v %v", listed, err)
			}
			if _, err := root.DeleteChangeSet(t.Context(), &cloudformation.DeleteChangeSetInput{StackName: created.StackId, ChangeSetName: aws.String("repeatable")}); err != nil {
				t.Fatal(err)
			}
			history, err := root.DescribeChangeSet(t.Context(), &cloudformation.DescribeChangeSetInput{ChangeSetName: created.Id})
			if err != nil || history.ExecutionStatus != cfntypes.ExecutionStatusExecuteComplete {
				t.Fatalf("name deletion removed immutable history: %v %v", history, err)
			}
			_, err = root.DeleteChangeSet(t.Context(), &cloudformation.DeleteChangeSetInput{ChangeSetName: created.Id})
			assertAPIError(t, err, "InvalidChangeSetStatus")
			update, err := root.CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{StackName: created.StackId, ChangeSetName: aws.String("repeatable"), ChangeSetType: cfntypes.ChangeSetTypeUpdate, TemplateBody: body(1)})
			if err != nil {
				t.Fatal("executed name cannot be reused", err)
			}
			active, err := root.DescribeChangeSet(t.Context(), &cloudformation.DescribeChangeSetInput{StackName: created.StackId, ChangeSetName: aws.String("repeatable")})
			if err != nil || aws.ToString(active.ChangeSetId) != aws.ToString(update.Id) || aws.ToString(update.Id) == aws.ToString(created.Id) {
				t.Fatalf("reused name did not identify new plan: %v %v", active, err)
			}
			if _, err := root.ExecuteChangeSet(t.Context(), &cloudformation.ExecuteChangeSetInput{StackName: created.StackId, ChangeSetName: aws.String("repeatable")}); err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			history, err = root.DescribeChangeSet(t.Context(), &cloudformation.DescribeChangeSetInput{ChangeSetName: created.Id})
			if err != nil || history.ExecutionStatus != cfntypes.ExecutionStatusExecuteComplete {
				t.Fatalf("name reuse lost old execution history: %v %v", history, err)
			}
			cloudFormationDeleteQueueStack(t, c, source, root, c.sqs("test", "test", ""), aws.ToString(created.StackId), cloudFormationQueueURL(t, stack))
		})
	}
}

// eventbridge_rule_migration_changesets.json retains native AVAILABLE plans by
// ARN after stack deletion; each can still be explicitly deleted.
func TestCloudFormationUnexecutedChangeSetAfterStackDeletion(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRuleMigration(t, backend)
			plan, err := f.cfn().CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{
				StackName: aws.String(f.stackID), ChangeSetName: aws.String("retained-plan"),
				ChangeSetType: cfntypes.ChangeSetTypeUpdate,
				TemplateBody:  aws.String(cfnMigrationTemplate(t, cfnMigrationDestination, cfnMigrationSourceQueue, "before")),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)}); err != nil {
				t.Fatal(err)
			}
			f.wait(t, cfntypes.StackStatusDeleteComplete)
			f.clients = f.reopen()
			retained, err := f.cfn().DescribeChangeSet(t.Context(), &cloudformation.DescribeChangeSetInput{ChangeSetName: plan.Id})
			if err != nil || retained.Status != cfntypes.ChangeSetStatusCreateComplete || retained.ExecutionStatus != cfntypes.ExecutionStatusAvailable || aws.ToString(retained.StackId) != f.stackID {
				t.Fatalf("stack deletion lost the unexecuted plan: %+v %v", retained, err)
			}
			if _, err := f.cfn().DeleteChangeSet(t.Context(), &cloudformation.DeleteChangeSetInput{ChangeSetName: plan.Id}); err != nil {
				t.Fatal(err)
			}
			_, err = f.cfn().DescribeChangeSet(t.Context(), &cloudformation.DescribeChangeSetInput{ChangeSetName: plan.Id})
			assertAPIError(t, err, "ChangeSetNotFound")
		})
	}
}

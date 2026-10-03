package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awsapi"
	"stackd/journal"
	cfnstore "stackd/storage/cloudformation"
	sqsstore "stackd/storage/sqs"
)

func cloudFormationClient(c cloudClients, region, key, secret string) *cloudformation.Client {
	return cloudformation.New(cloudformation.Options{Region: region, BaseEndpoint: aws.String(c.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func cloudFormationQueueTemplate(t *testing.T, name string, visibility int, exports int) string {
	t.Helper()
	outputs := map[string]any{"Queue": map[string]any{"Value": map[string]any{"Ref": "Queue"}}}
	for i := range exports {
		outputs[fmt.Sprintf("Export%03d", i)] = map[string]any{
			"Value":  map[string]any{"Fn::GetAtt": []string{"Queue", "Arn"}},
			"Export": map[string]any{"Name": fmt.Sprintf("%s-%03d", name, i)},
		}
	}
	body, err := json.Marshal(map[string]any{"Resources": map[string]any{"Queue": map[string]any{
		"Type": "AWS::SQS::Queue", "Properties": map[string]any{"QueueName": name, "VisibilityTimeout": visibility}}}, "Outputs": outputs})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func cloudFormationWait(t *testing.T, c cloudClients, source *clock.Manual, client *cloudformation.Client, id string, wanted cfntypes.StackStatus) cfntypes.Stack {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for {
		out, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(id)})
		if err != nil {
			t.Fatal(err)
		}
		stack := out.Stacks[0]
		if stack.StackStatus == wanted {
			return stack
		}
		if !cloudFormationTransient(map[string]any{"Stacks": []any{map[string]any{"StackStatus": string(stack.StackStatus)}}}) {
			t.Fatalf("expected %s, got %s: %s", wanted, stack.StackStatus, aws.ToString(stack.StackStatusReason))
		}
		advanceClock(t, source, time.Second)
		if _, err := c.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("stack did not settle", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func cloudFormationTemplateEqual(t *testing.T, want, got string) {
	t.Helper()
	var expected, actual any
	awsDecodeJSON(t, []byte(want), &expected)
	awsDecodeJSON(t, []byte(got), &actual)
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("committed template changed\nwant %#v\ngot %#v", expected, actual)
	}
}

func cloudFormationQueueURL(t *testing.T, stack cfntypes.Stack) string {
	t.Helper()
	for _, output := range stack.Outputs {
		if aws.ToString(output.OutputKey) == "Queue" {
			return aws.ToString(output.OutputValue)
		}
	}
	t.Fatal("settled stack did not publish its queue Ref")
	return ""
}

func cloudFormationQueueVisibility(t *testing.T, client *sqs.Client, url string, expected string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	out, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(url),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameVisibilityTimeout}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Attributes["VisibilityTimeout"] != expected {
		t.Fatalf("real SQS visibility: want %s, got %v", expected, out.Attributes)
	}
}

func cloudFormationCommittedVisibility(t *testing.T, repository sqsstore.Repository, name string, expected int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var queue sqsstore.QueueRecord
	err := repository.View(ctx, func(reader sqsstore.Reader) error {
		var err error
		queue, err = reader.Queue(sqsstore.QueueKey{Partition: "aws", Account: "000000000000", Region: "us-east-1", Name: name})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if queue.Configuration.VisibilitySeconds != expected {
		t.Fatalf("committed SQS visibility: want %d, got %d", expected, queue.Configuration.VisibilitySeconds)
	}
}

func cloudFormationDeleteQueueStack(t *testing.T, c cloudClients, source *clock.Manual, client *cloudformation.Client, queueClient *sqs.Client, id, url string) {
	t.Helper()
	if _, err := client.DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(id)}); err != nil {
		t.Fatal(err)
	}
	cloudFormationWait(t, c, source, client, id, cfntypes.StackStatusDeleteComplete)
	_, err := queueClient.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: aws.String(url),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
	assertAPIError(t, err, "AWS.SimpleQueueService.NonExistentQueue")
}

func TestCloudFormationCurrentAuthorityAndScope(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			body := cloudFormationQueueTemplate(t, "cfn-authority-queue", 10, 0)
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("authority"), TemplateBody: aws.String(body)})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			queue := cloudFormationQueueURL(t, stack)
			_, access, secret := c.user(t, "test", "cfn-operator")
			policy := allow(`["cloudformation:DescribeStacks","cloudformation:UpdateStack"]`, "*")
			putUserPolicy(t, c.iam("test", "test", ""), "cfn-operator", policy)
			actor := cloudFormationClient(c, "us-east-1", access, secret)
			allowed, err := actor.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: created.StackId})
			if err != nil || aws.ToString(allowed.Stacks[0].StackId) != aws.ToString(created.StackId) {
				t.Fatalf("existing key did not read its authorized stack: %v %v", allowed, err)
			}
			putUserPolicy(t, c.iam("test", "test", ""), "cfn-operator", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudformation:*","Resource":"*"},{"Effect":"Deny","Action":["cloudformation:DescribeStacks","cloudformation:UpdateStack"],"Resource":"*"}]}`)
			_, err = actor.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: created.StackId})
			assertAPIError(t, err, "AccessDenied")
			_, err = actor.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId,
				TemplateBody: aws.String(cloudFormationQueueTemplate(t, "cfn-authority-queue", 99, 0))})
			assertAPIError(t, err, "AccessDenied")
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), queue, "10")
			putUserPolicy(t, c.iam("test", "test", ""), "cfn-operator", policy)
			restored, err := actor.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: created.StackId})
			if err != nil || restored.Stacks[0].StackStatus != cfntypes.StackStatusCreateComplete {
				t.Fatalf("same key did not observe restored authority and unchanged stack: %v %v", restored, err)
			}
			for _, scope := range []struct{ account, region string }{{"111111111111", "us-east-1"}, {"000000000000", "us-west-2"}} {
				other := cloudFormationClient(c, scope.region, scope.account, "test")
				for _, name := range []string{"authority", aws.ToString(created.StackId)} {
					_, err := other.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: aws.String(name)})
					assertAPIError(t, err, "ValidationError")
				}
				separate, err := other.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("authority"), TemplateBody: aws.String(body)})
				if err != nil {
					t.Fatal(err)
				}
				isolated := cloudFormationWait(t, c, source, other, aws.ToString(separate.StackId), cfntypes.StackStatusCreateComplete)
				if aws.ToString(isolated.StackId) == aws.ToString(created.StackId) {
					t.Fatal("same-name stacks shared identity across scope")
				}
				queueClient := sqs.New(sqs.Options{Region: scope.region, BaseEndpoint: aws.String(c.server.URL),
					HTTPClient: c.server.Client(), Credentials: credentials.NewStaticCredentialsProvider(scope.account, "test", ""), RetryMaxAttempts: 1})
				isolatedURL := cloudFormationQueueURL(t, isolated)
				attributes, err := queueClient.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: aws.String(isolatedURL), AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
				want := "arn:aws:sqs:" + scope.region + ":" + scope.account + ":cfn-authority-queue"
				if err != nil || attributes.Attributes["QueueArn"] != want {
					t.Fatalf("cross-scope deployment used wrong resource owner: %v %v", attributes, err)
				}
				cloudFormationDeleteQueueStack(t, c, source, other, queueClient, aws.ToString(separate.StackId), isolatedURL)
				cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), queue, "10")
			}
			cloudFormationDeleteQueueStack(t, c, source, root, c.sqs("test", "test", ""), aws.ToString(created.StackId), queue)
		})
	}
}

func TestCloudFormationPaginationScopeAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("pagination"),
				TemplateBody: aws.String(cloudFormationQueueTemplate(t, "cfn-page", 10, 101))})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			first, err := root.ListExports(t.Context(), &cloudformation.ListExportsInput{})
			if err != nil || aws.ToString(first.NextToken) == "" {
				t.Fatalf("export boundary did not provide a continuation: %v %v", first, err)
			}
			_, err = root.ListExports(t.Context(), &cloudformation.ListExportsInput{NextToken: aws.String("not-a-valid-cursor")})
			assertAPIError(t, err, "ValidationError")
			_, err = root.ListStacks(t.Context(), &cloudformation.ListStacksInput{NextToken: first.NextToken})
			assertAPIError(t, err, "ValidationError")
			for _, scope := range []struct{ account, region string }{{"111111111111", "us-east-1"}, {"000000000000", "us-west-2"}} {
				_, err := cloudFormationClient(c, scope.region, scope.account, "test").ListExports(t.Context(), &cloudformation.ListExportsInput{NextToken: first.NextToken})
				assertAPIError(t, err, "ValidationError")
			}
			seen := map[string]string{}
			collect := func(rows []cfntypes.Export) {
				for _, row := range rows {
					name := aws.ToString(row.Name)
					if _, duplicate := seen[name]; duplicate {
						t.Fatal("pagination repeated export", name)
					}
					if aws.ToString(row.ExportingStackId) != aws.ToString(created.StackId) {
						t.Fatal("pagination changed export owner", row)
					}
					seen[name] = aws.ToString(row.Value)
				}
			}
			collect(first.Exports)
			c = reopen()
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			token := first.NextToken
			for token != nil {
				page, err := root.ListExports(t.Context(), &cloudformation.ListExportsInput{NextToken: token})
				if err != nil {
					t.Fatal("retained pagination cursor failed after restart", err)
				}
				collect(page.Exports)
				token = page.NextToken
			}
			want := map[string]string{}
			for i := range 101 {
				want[fmt.Sprintf("cfn-page-%03d", i)] = "arn:aws:sqs:us-east-1:000000000000:cfn-page"
			}
			if !reflect.DeepEqual(seen, want) {
				t.Fatalf("pagination lost, repeated, or changed exports\nwant %v\ngot %v", want, seen)
			}
			cloudFormationDeleteQueueStack(t, c, source, root, c.sqs("test", "test", ""), aws.ToString(created.StackId), cloudFormationQueueURL(t, stack))
			remaining, err := root.ListExports(t.Context(), &cloudformation.ListExportsInput{})
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range remaining.Exports {
				if aws.ToString(row.ExportingStackId) == aws.ToString(created.StackId) {
					t.Fatal("deleted stack retained a public export", row)
				}
			}
		})
	}
}

// Pause after the real owner commits its queue change but before CloudFormation
// records completion. No command output/state is replaced: the barrier selects a
// deterministic cancellation/crash boundary while retaining real SQS semantics.
type cloudFormationQueuePause struct {
	entered, release chan struct{}
	once             sync.Once
	operation        string
}

func (p *cloudFormationQueuePause) unblock() { p.once.Do(func() { close(p.release) }) }

type cloudFormationQueueRepository struct {
	sqsstore.Repository
	pause atomic.Pointer[cloudFormationQueuePause]
}

func (r *cloudFormationQueueRepository) Attempt(ctx context.Context, fn func(sqsstore.Transaction) error) error {
	var pause *cloudFormationQueuePause
	candidate := r.pause.Load()
	if request, ok := awsapi.FromContext(ctx); ok && candidate != nil && string(request.Operation.Name) == candidate.operation && r.pause.CompareAndSwap(candidate, nil) {
		pause = candidate
	}
	if err := r.Repository.Attempt(ctx, fn); err != nil {
		return err
	}
	if pause != nil {
		close(pause.entered)
		select {
		case <-pause.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (r *cloudFormationQueueRepository) arm(t *testing.T, operation string) *cloudFormationQueuePause {
	t.Helper()
	pause := &cloudFormationQueuePause{entered: make(chan struct{}), release: make(chan struct{}), operation: operation}
	t.Cleanup(pause.unblock)
	r.pause.Store(pause)
	return pause
}

func cloudFormationAwaitQueueCommit(t *testing.T, pause *cloudFormationQueuePause) {
	t.Helper()
	select {
	case <-pause.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("CloudFormation did not reach the actual SQS commit boundary")
	}
}

func TestCloudFormationCancelAndPendingRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			var repository *cloudFormationQueueRepository
			start := func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				base := config.Storage.SQS
				if previous, ok := base.(*cloudFormationQueueRepository); ok {
					base = previous.Repository
				}
				repository = &cloudFormationQueueRepository{Repository: base}
				config.Storage.SQS = repository
				return startPublicCloud(t, config)
			}
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, start)
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			original := cloudFormationQueueTemplate(t, "cfn-recovery-queue", 10, 0)
			created, err := root.CreateStack(ctx, &cloudformation.CreateStackInput{StackName: aws.String("recovery"), TemplateBody: aws.String(original)})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			queue := cloudFormationQueueURL(t, stack)
			pause := repository.arm(t, "SetQueueAttributes")
			if _, err := root.UpdateStack(ctx, &cloudformation.UpdateStackInput{StackName: created.StackId,
				TemplateBody: aws.String(cloudFormationQueueTemplate(t, "cfn-recovery-queue", 20, 0)), ClientRequestToken: aws.String("cancelled-update")}); err != nil {
				t.Fatal(err)
			}
			cloudFormationAwaitQueueCommit(t, pause)
			cloudFormationCommittedVisibility(t, repository, "cfn-recovery-queue", 20)
			pending, err := root.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: created.StackId})
			if err != nil || pending.Stacks[0].StackStatus != cfntypes.StackStatusUpdateInProgress {
				t.Fatalf("expected a genuinely pending update: %v %v", pending, err)
			}
			if _, err := root.CancelUpdateStack(ctx, &cloudformation.CancelUpdateStackInput{StackName: created.StackId}); err != nil {
				t.Fatal(err)
			}
			pause.unblock()
			rolledBack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateRollbackComplete)
			if cloudFormationQueueURL(t, rolledBack) != queue {
				t.Fatal("cancelled mutable update changed physical queue")
			}
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), queue, "10")
			stored, err := root.GetTemplate(ctx, &cloudformation.GetTemplateInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationTemplateEqual(t, original, aws.ToString(stored.TemplateBody))
			updated := cloudFormationQueueTemplate(t, "cfn-recovery-queue", 30, 0)
			pause = repository.arm(t, "SetQueueAttributes")
			if _, err := root.UpdateStack(ctx, &cloudformation.UpdateStackInput{StackName: created.StackId,
				TemplateBody: aws.String(updated), ClientRequestToken: aws.String("recovered-update")}); err != nil {
				t.Fatal(err)
			}
			cloudFormationAwaitQueueCommit(t, pause)
			cloudFormationCommittedVisibility(t, repository, "cfn-recovery-queue", 30)
			pending, err = root.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: created.StackId})
			if err != nil || pending.Stacks[0].StackStatus != cfntypes.StackStatusUpdateInProgress {
				t.Fatalf("restart boundary was not pending: %v %v", pending, err)
			}
			c = reopen() // Close cancels the gate's context; the committed queue effect survives.
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			recovered := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			if aws.ToString(recovered.StackId) != aws.ToString(created.StackId) || cloudFormationQueueURL(t, recovered) != queue {
				t.Fatal("pending recovery replaced stack or physical resource identity")
			}
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), queue, "30")
			stored, err = root.GetTemplate(ctx, &cloudformation.GetTemplateInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationTemplateEqual(t, updated, aws.ToString(stored.TemplateBody))
			cloudFormationDeleteQueueStack(t, c, source, root, c.sqs("test", "test", ""), aws.ToString(created.StackId), queue)
		})
	}
}

func TestCloudFormationEffectiveExecutionRoleCondition(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			iamClient := c.iam("test", "test", "")
			roles := map[string]string{}
			for _, name := range []string{"cfn-allowed", "cfn-other"} {
				role, err := iamClient.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name),
					AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudformation.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
				if err != nil {
					t.Fatal(err)
				}
				roles[name] = aws.ToString(role.Role.Arn)
				_, err = iamClient.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: aws.String(name), PolicyName: aws.String("owner"), PolicyDocument: aws.String(allow(`"sqs:*"`, "*"))})
				if err != nil {
					t.Fatal(err)
				}
			}
			_, access, secret := c.user(t, "test", "cfn-role-operator")
			putUserPolicy(t, iamClient, "cfn-role-operator", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"},{"Effect":"Allow","Action":"cloudformation:*","Resource":"*","Condition":{"StringEquals":{"cloudformation:RoleArn":%q}}}]}`, roles["cfn-allowed"]))
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			actor := cloudFormationClient(c, "us-east-1", access, secret)
			body := func(visibility int) *string {
				return aws.String(cloudFormationQueueTemplate(t, "cfn-role-condition", visibility, 0))
			}
			created, err := actor.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("role-condition"), TemplateBody: body(10), RoleARN: aws.String(roles["cfn-allowed"])})
			if err != nil {
				t.Fatal("requested allowed role was not used for CreateStack authorization", err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			queue := cloudFormationQueueURL(t, stack)
			_, err = actor.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: body(20), RoleARN: aws.String(roles["cfn-other"])})
			assertAPIError(t, err, "AccessDenied")
			_, err = actor.ContinueUpdateRollback(t.Context(), &cloudformation.ContinueUpdateRollbackInput{StackName: created.StackId, RoleARN: aws.String(roles["cfn-other"])})
			assertAPIError(t, err, "AccessDenied")
			_, err = actor.RollbackStack(t.Context(), &cloudformation.RollbackStackInput{StackName: created.StackId, RoleARN: aws.String(roles["cfn-other"])})
			assertAPIError(t, err, "AccessDenied")
			blocked, err := root.CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{StackName: created.StackId, ChangeSetName: aws.String("blocked-role"), TemplateBody: body(20), RoleARN: aws.String(roles["cfn-other"])})
			if err != nil {
				t.Fatal(err)
			}
			_, err = actor.ExecuteChangeSet(t.Context(), &cloudformation.ExecuteChangeSetInput{ChangeSetName: blocked.Id})
			assertAPIError(t, err, "AccessDenied")
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), queue, "10")
			_, err = root.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: body(30), RoleARN: aws.String(roles["cfn-other"])})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			_, err = root.DescribeChangeSet(t.Context(), &cloudformation.DescribeChangeSetInput{ChangeSetName: blocked.Id})
			assertAPIError(t, err, "ChangeSetNotFound")
			_, err = actor.ExecuteChangeSet(t.Context(), &cloudformation.ExecuteChangeSetInput{ChangeSetName: blocked.Id})
			assertAPIError(t, err, "ChangeSetNotFound")
			allowed, err := actor.CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{StackName: created.StackId, ChangeSetName: aws.String("allowed-role"), TemplateBody: body(40), RoleARN: aws.String(roles["cfn-allowed"])})
			if err != nil {
				t.Fatal("requested allowed role was not used for CreateChangeSet authorization", err)
			}
			if _, err = actor.ExecuteChangeSet(t.Context(), &cloudformation.ExecuteChangeSetInput{ChangeSetName: allowed.Id}); err != nil {
				t.Fatal("retained change-set role was not used for execution authorization", err)
			}
			stack = cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			if aws.ToString(stack.RoleARN) != roles["cfn-allowed"] {
				t.Fatal("change set did not select its retained role", stack.RoleARN)
			}
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), queue, "40")
			_, err = actor.DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId, RoleARN: aws.String(roles["cfn-other"])})
			assertAPIError(t, err, "AccessDenied")
			putUserPolicy(t, iamClient, "cfn-role-operator", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudformation:*","Resource":"*","Condition":{"StringEquals":{"cloudformation:RoleArn":%q}}}]}`, roles["cfn-allowed"]))
			cloudFormationDeleteQueueStack(t, c, source, actor, c.sqs("test", "test", ""), aws.ToString(created.StackId), queue)
			for name := range roles {
				if _, err = iamClient.DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: aws.String(name), PolicyName: aws.String("owner")}); err != nil {
					t.Fatal(err)
				}
				if _, err = iamClient.DeleteRole(t.Context(), &iam.DeleteRoleInput{RoleName: aws.String(name)}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCloudFormationCancelledCommittedCreateRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			var repository *cloudFormationQueueRepository
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				base := config.Storage.SQS
				if previous, ok := base.(*cloudFormationQueueRepository); ok {
					base = previous.Repository
				}
				repository = &cloudFormationQueueRepository{Repository: base}
				config.Storage.SQS = repository
				return startPublicCloud(t, config)
			})
			_, key, secret := c.user(t, "test", "cfn-recovery-actor")
			policy := allow(`["cloudformation:*","sqs:*"]`, "*")
			putUserPolicy(t, c.iam("test", "test", ""), "cfn-recovery-actor", policy)
			actor := cloudFormationClient(c, "us-east-1", key, secret)
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			body := cloudFormationQueueTemplate(t, "cfn-original", 10, 0)
			created, err := actor.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("create-recovery"), TemplateBody: aws.String(body)})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			var expanded map[string]any
			awsDecodeJSON(t, []byte(body), &expanded)
			expanded["Resources"].(map[string]any)["Added"] = map[string]any{"Type": "AWS::SQS::Queue", "Properties": map[string]any{"QueueName": "cfn-unrecorded", "VisibilityTimeout": 17}}
			updated, err := json.Marshal(expanded)
			if err != nil {
				t.Fatal(err)
			}
			pause := repository.arm(t, "CreateQueue")
			_, err = actor.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(string(updated))})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationAwaitQueueCommit(t, pause)
			cloudFormationCommittedVisibility(t, repository, "cfn-unrecorded", 17)
			if _, err = actor.CancelUpdateStack(t.Context(), &cloudformation.CancelUpdateStackInput{StackName: created.StackId}); err != nil {
				t.Fatal(err)
			}
			putUserPolicy(t, c.iam("test", "test", ""), "cfn-recovery-actor", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","sqs:*"],"Resource":"*"},{"Effect":"Deny","Action":"sqs:GetQueueUrl","Resource":"*"}]}`)
			c = reopen()
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			actor = cloudFormationClient(c, "us-east-1", key, secret)
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateRollbackFailed)
			actual, err := c.sqs("test", "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("cfn-unrecorded")})
			if err != nil {
				t.Fatal("committed owner effect was not present at the recovery failure", err)
			}
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), aws.ToString(actual.QueueUrl), "17")
			// Recovery can now identify the owned queue, but its attribute read
			// still fails. The returned physical identity must permit cleanup.
			putUserPolicy(t, c.iam("test", "test", ""), "cfn-recovery-actor", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","sqs:*"],"Resource":"*"},{"Effect":"Deny","Action":"sqs:GetQueueAttributes","Resource":"*"}]}`)
			if _, err = actor.ContinueUpdateRollback(t.Context(), &cloudformation.ContinueUpdateRollbackInput{StackName: created.StackId}); err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateRollbackComplete)
			_, err = c.sqs("test", "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("cfn-unrecorded")})
			assertAPIError(t, err, "AWS.SimpleQueueService.NonExistentQueue")
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), cloudFormationQueueURL(t, stack), "10")
			cloudFormationDeleteQueueStack(t, c, source, root, c.sqs("test", "test", ""), aws.ToString(created.StackId), cloudFormationQueueURL(t, stack))
		})
	}
}

func cloudFormationCleanupHistory(t *testing.T, client *cloudformation.Client, id, token, logicalID, physicalID string) {
	t.Helper()
	var cleanup, warning bool
	var attempts, failures int
	pages := cloudformation.NewDescribeStackEventsPaginator(client, &cloudformation.DescribeStackEventsInput{StackName: aws.String(id)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.StackEvents {
			if aws.ToString(event.ClientRequestToken) != token {
				continue
			}
			if strings.HasPrefix(string(event.ResourceStatus), "UPDATE_ROLLBACK") {
				t.Fatal("cleanup failure incorrectly started rollback", event)
			}
			if aws.ToString(event.ResourceType) == "AWS::CloudFormation::Stack" {
				switch event.ResourceStatus {
				case "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS":
					cleanup = true
				case cfntypes.ResourceStatusUpdateComplete:
					warning = aws.ToString(event.ResourceStatusReason) != ""
				}
			}
			if aws.ToString(event.LogicalResourceId) == logicalID && event.ResourceStatus == cfntypes.ResourceStatusDeleteFailed {
				if aws.ToString(event.PhysicalResourceId) != physicalID || aws.ToString(event.ResourceStatusReason) == "" {
					t.Fatal("cleanup failure lost the old physical identity or owner error", event)
				}
				failures++
			}
			if aws.ToString(event.LogicalResourceId) == logicalID && aws.ToString(event.PhysicalResourceId) == physicalID && event.ResourceStatus == cfntypes.ResourceStatusDeleteInProgress {
				attempts++
			}
		}
	}
	if !cleanup || !warning || attempts != 3 || failures != 3 {
		t.Fatalf("cleanup history: phase=%t completion warning=%t deletion starts=%d failures=%d", cleanup, warning, attempts, failures)
	}
}

func cloudFormationOwnerDeleteAttempts(t *testing.T, events journal.Storage, source *clock.Manual, access, operation, errorCode string, want int) {
	t.Helper()
	rows, err := events.LookupAPICalls(t.Context(), journal.APICallQuery{Partition: "aws", AccountID: "000000000000",
		Region: "us-east-1", End: source.Now(), AttributeKey: "EventName", AttributeValue: operation, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range rows.Events {
		call := row.APICallCompleted
		if call == nil || row.ActorService != "cloudformation.amazonaws.com" || call.Identity.AccessKeyID != access {
			continue
		}
		if call.ErrorCode != errorCode {
			t.Fatalf("unexpected real owner %s outcome: %+v", operation, call)
		}
		count++
	}
	if count != want {
		t.Fatalf("real owner %s attempts: want %d, got %d", operation, want, count)
	}
}

func TestCloudFormationPartialDeleteDetachesRule(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			var audit journal.Storage
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				audit = config.Storage.Journal
				return startPublicCloud(t, config)
			})
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			body := `{"Resources":{"Queue":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"cfn-rule-cleanup"}},"Rule":{"Type":"AWS::Events::Rule","Properties":{"Name":"cfn-delete-cleanup","EventPattern":{"source":["stackd.cfn.cleanup"]},"Targets":[{"Id":"queue","Arn":{"Fn::GetAtt":["Queue","Arn"]}}]}}},"Outputs":{"Queue":{"Value":{"Ref":"Queue"}}}}`
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("partial-delete"), TemplateBody: aws.String(body)})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			events := eventbridge.New(eventbridge.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client()})
			targets, err := events.ListTargetsByRule(t.Context(), &eventbridge.ListTargetsByRuleInput{Rule: aws.String("cfn-delete-cleanup")})
			if err != nil || len(targets.Targets) != 1 || aws.ToString(targets.Targets[0].Id) != "queue" {
				t.Fatalf("rule target was not provisioned: %+v %v", targets, err)
			}
			_, key, secret := c.user(t, "test", "cfn-rule-deleter")
			putUserPolicy(t, c.iam("test", "test", ""), "cfn-rule-deleter", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","events:*","sqs:*"],"Resource":"*"},{"Effect":"Deny","Action":"events:DeleteRule","Resource":"*"}]}`)
			desired := cloudFormationQueueTemplate(t, "cfn-rule-cleanup", 42, 0)
			actor := cloudFormationClient(c, "us-east-1", key, secret)
			if _, err = actor.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(desired), ClientRequestToken: aws.String("remove-rule")}); err != nil {
				t.Fatal(err)
			}
			updated := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			if cloudFormationQueueURL(t, updated) != cloudFormationQueueURL(t, stack) || aws.ToString(updated.StackStatusReason) == "" {
				t.Fatal("cleanup failure lost committed state or warning", updated)
			}
			cloudFormationCleanupHistory(t, root, aws.ToString(created.StackId), "remove-rule", "Rule", "cfn-delete-cleanup")
			cloudFormationOwnerDeleteAttempts(t, audit, source, key, "DeleteRule", "AccessDeniedException", 3)
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), cloudFormationQueueURL(t, updated), "42")
			stored, err := root.GetTemplate(t.Context(), &cloudformation.GetTemplateInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationTemplateEqual(t, desired, aws.ToString(stored.TemplateBody))
			_, err = root.DescribeStackResource(t.Context(), &cloudformation.DescribeStackResourceInput{StackName: created.StackId, LogicalResourceId: aws.String("Rule")})
			assertAPIError(t, err, "ValidationError")
			rule, err := events.DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{Name: aws.String("cfn-delete-cleanup")})
			if err != nil || aws.ToString(rule.Name) != "cfn-delete-cleanup" {
				t.Fatalf("failed deletion did not leave the physical rule: %+v %v", rule, err)
			}
			targets, err = events.ListTargetsByRule(t.Context(), &eventbridge.ListTargetsByRuleInput{Rule: aws.String("cfn-delete-cleanup")})
			if err != nil || len(targets.Targets) != 0 {
				t.Fatalf("cleanup incorrectly replayed removed targets: %+v %v", targets, err)
			}
			cloudFormationDeleteQueueStack(t, c, source, root, c.sqs("test", "test", ""), aws.ToString(created.StackId), cloudFormationQueueURL(t, stack))
			if _, err = events.DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{Name: aws.String("cfn-delete-cleanup")}); err != nil {
				t.Fatal("stack deletion should not manage the detached rule", err)
			}
			if _, err = events.DeleteRule(t.Context(), &eventbridge.DeleteRuleInput{Name: aws.String("cfn-delete-cleanup")}); err != nil {
				t.Fatal(err)
			}
			_, err = events.DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{Name: aws.String("cfn-delete-cleanup")})
			assertAPIError(t, err, "ResourceNotFoundException")
		})
	}
}

func TestCloudFormationCleanupFailureDetachesOldQueue(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, change := range []string{"removal", "replacement"} {
			t.Run(backend+"/"+change, func(t *testing.T) {
				source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
				var audit journal.Storage
				var deployments cfnstore.Repository
				c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					audit = config.Storage.Journal
					deployments = config.Storage.CloudFormation
					return startPublicCloud(t, config)
				})
				root := cloudFormationClient(c, "us-east-1", "test", "test")
				original := cloudFormationQueueTemplate(t, "cfn-cleanup-old", 10, 0)
				created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("cleanup-failure"), TemplateBody: aws.String(original)})
				if err != nil {
					t.Fatal(err)
				}
				stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
				oldURL := cloudFormationQueueURL(t, stack)
				desired := cloudFormationQueueTemplate(t, "cfn-cleanup-new", 42, 0)
				logicalID := "Queue"
				if change == "removal" {
					logicalID = "Kept"
					var body map[string]any
					awsDecodeJSON(t, []byte(desired), &body)
					resources := body["Resources"].(map[string]any)
					resources[logicalID] = resources["Queue"]
					delete(resources, "Queue")
					body["Outputs"].(map[string]any)["Queue"] = map[string]any{"Value": map[string]any{"Ref": logicalID}}
					encoded, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					desired = string(encoded)
				}
				_, key, secret := c.user(t, "test", "cfn-cleanup-actor")
				putUserPolicy(t, c.iam("test", "test", ""), "cfn-cleanup-actor", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","sqs:*"],"Resource":"*"},{"Effect":"Deny","Action":"sqs:DeleteQueue","Resource":"arn:aws:sqs:us-east-1:000000000000:cfn-cleanup-old"}]}`)
				actor := cloudFormationClient(c, "us-east-1", key, secret)
				if _, err = actor.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(desired), ClientRequestToken: aws.String("cleanup-update")}); err != nil {
					t.Fatal(err)
				}
				// Freeze manual time until the first owner failure is checkpointed.
				// Waiting on storage only selects the crash boundary; attempts are
				// measured from actual owner API outcomes, not the retry counter.
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				for {
					checkpointed := false
					err = deployments.View(ctx, func(reader cfnstore.Reader) error {
						current, err := reader.Stack(aws.ToString(created.StackId))
						if err != nil {
							return err
						}
						operation, err := reader.Operation(current.OperationID)
						if err != nil {
							return err
						}
						for _, step := range operation.Steps {
							if step.Before.PhysicalID == oldURL && step.DeleteFailures > 0 {
								checkpointed = true
							}
						}
						return nil
					})
					if err != nil {
						t.Fatal(err)
					}
					if checkpointed {
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("cleanup did not checkpoint the first owner failure", ctx.Err())
					case <-time.After(time.Millisecond):
					}
				}
				cloudFormationOwnerDeleteAttempts(t, audit, source, key, "DeleteQueue", "AccessDenied", 1)
				pending, err := root.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: created.StackId})
				if err != nil || pending.Stacks[0].StackStatus != cfntypes.StackStatusUpdateCompleteCleanupInProgress {
					t.Fatalf("retry boundary was not cleanup: %+v %v", pending, err)
				}
				newURL := cloudFormationQueueURL(t, pending.Stacks[0])
				if newURL == oldURL {
					t.Fatal("cleanup did not commit the new desired output")
				}
				c = reopen()
				root = cloudFormationClient(c, "us-east-1", "test", "test")
				updated := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
				if cloudFormationQueueURL(t, updated) != newURL || aws.ToString(updated.StackStatusReason) == "" {
					t.Fatal("restart changed committed cleanup outcome or lost the warning", updated)
				}
				cloudFormationCleanupHistory(t, root, aws.ToString(created.StackId), "cleanup-update", "Queue", oldURL)
				cloudFormationOwnerDeleteAttempts(t, audit, source, key, "DeleteQueue", "AccessDenied", 3)
				resources, err := root.DescribeStackResources(t.Context(), &cloudformation.DescribeStackResourcesInput{StackName: created.StackId})
				if err != nil || len(resources.StackResources) != 1 || aws.ToString(resources.StackResources[0].LogicalResourceId) != logicalID ||
					aws.ToString(resources.StackResources[0].PhysicalResourceId) != newURL {
					t.Fatalf("stack did not detach the old incarnation: %+v %v", resources, err)
				}
				if change == "removal" {
					_, err = root.DescribeStackResource(t.Context(), &cloudformation.DescribeStackResourceInput{StackName: created.StackId, LogicalResourceId: aws.String("Queue")})
					assertAPIError(t, err, "ValidationError")
				}
				stored, err := root.GetTemplate(t.Context(), &cloudformation.GetTemplateInput{StackName: created.StackId})
				if err != nil {
					t.Fatal(err)
				}
				cloudFormationTemplateEqual(t, desired, aws.ToString(stored.TemplateBody))
				queues := c.sqs("test", "test", "")
				cloudFormationQueueVisibility(t, queues, newURL, "42")
				cloudFormationQueueVisibility(t, queues, oldURL, "10")
				cloudFormationDeleteQueueStack(t, c, source, root, queues, aws.ToString(created.StackId), newURL)
				// Deleting the stack must not adopt or retry its detached resource.
				cloudFormationQueueVisibility(t, queues, oldURL, "10")
				if _, err = queues.DeleteQueue(t.Context(), &sqs.DeleteQueueInput{QueueUrl: aws.String(oldURL)}); err != nil {
					t.Fatal(err)
				}
				_, err = queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("cfn-cleanup-old")})
				assertAPIError(t, err, "AWS.SimpleQueueService.NonExistentQueue")
			})
		}
	}
}

func TestCloudFormationCleanupUsesOriginalDependencyOrder(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, change := range []string{"replacement", "removal"} {
			t.Run(backend+"/"+change, func(t *testing.T) {
				source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
				c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					return startPublicCloud(t, config)
				})
				_, key, secret := c.user(t, "test", "cleanup-order-actor")
				putUserPolicy(t, c.iam("test", "test", ""), "cleanup-order-actor", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","s3:*"],"Resource":"*"}]}`)
				client := cloudFormationClient(c, "us-east-1", key, secret)
				template := func(logicalID, name string) string {
					body, err := json.Marshal(map[string]any{"Resources": map[string]any{
						logicalID: map[string]any{"Type": "AWS::S3::Bucket", "Properties": map[string]any{"BucketName": name}},
						"Policy": map[string]any{"Type": "AWS::S3::BucketPolicy", "Properties": map[string]any{
							"Bucket": map[string]any{"Ref": logicalID},
							"PolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": []any{
								map[string]any{"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteBucket", "Resource": map[string]any{"Fn::GetAtt": []string{logicalID, "Arn"}}},
							}},
						}},
					}})
					if err != nil {
						t.Fatal(err)
					}
					return string(body)
				}
				created, err := client.CreateStack(t.Context(), &cloudformation.CreateStackInput{
					StackName: aws.String("cleanup-order"), TemplateBody: aws.String(template("Bucket", "cfn-cleanup-order-old"))})
				if err != nil {
					t.Fatal(err)
				}
				cloudFormationWait(t, c, source, client, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
				logicalID := "Bucket"
				if change == "removal" {
					logicalID = "Next"
				}
				if _, err := client.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{
					StackName: created.StackId, TemplateBody: aws.String(template(logicalID, "cfn-cleanup-order-new"))}); err != nil {
					t.Fatal(err)
				}
				updated := cloudFormationWait(t, c, source, client, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
				if aws.ToString(updated.StackStatusReason) != "" {
					t.Fatal("cleanup orphaned a dependency instead of deleting its old dependent first", updated)
				}
				buckets := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL),
					Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), UsePathStyle: true, RetryMaxAttempts: 1})
				_, err = buckets.GetBucketLocation(t.Context(), &s3.GetBucketLocationInput{Bucket: aws.String("cfn-cleanup-order-old")})
				assertAPIError(t, err, "NoSuchBucket")
				if _, err := buckets.GetBucketLocation(t.Context(), &s3.GetBucketLocationInput{Bucket: aws.String("cfn-cleanup-order-new")}); err != nil {
					t.Fatal(err)
				}
				if _, err := client.DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId}); err != nil {
					t.Fatal(err)
				}
				cloudFormationWait(t, c, source, client, aws.ToString(created.StackId), cfntypes.StackStatusDeleteComplete)
				_, err = buckets.GetBucketLocation(t.Context(), &s3.GetBucketLocationInput{Bucket: aws.String("cfn-cleanup-order-new")})
				assertAPIError(t, err, "NoSuchBucket")
			})
		}
	}
}

func TestCloudFormationCancelRejectedDuringCleanup(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			var repository *cloudFormationQueueRepository
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				repository = &cloudFormationQueueRepository{Repository: config.Storage.SQS}
				config.Storage.SQS = repository
				return startPublicCloud(t, config)
			})
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("cleanup-cancel"),
				TemplateBody: aws.String(cloudFormationQueueTemplate(t, "cfn-cancel-old", 10, 0))})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			pause := repository.arm(t, "DeleteQueue")
			desired := cloudFormationQueueTemplate(t, "cfn-cancel-new", 42, 0)
			if _, err = root.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(desired)}); err != nil {
				t.Fatal(err)
			}
			cloudFormationAwaitQueueCommit(t, pause)
			pending, err := root.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: created.StackId})
			if err != nil || pending.Stacks[0].StackStatus != cfntypes.StackStatusUpdateCompleteCleanupInProgress {
				t.Fatalf("delete boundary was not cleanup: %+v %v", pending, err)
			}
			_, err = root.CancelUpdateStack(t.Context(), &cloudformation.CancelUpdateStackInput{StackName: created.StackId})
			assertAPIError(t, err, "ValidationError")
			pause.unblock()
			updated := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			if cloudFormationQueueURL(t, updated) == cloudFormationQueueURL(t, stack) {
				t.Fatal("rejected cleanup cancellation restored the old incarnation")
			}
			stored, err := root.GetTemplate(t.Context(), &cloudformation.GetTemplateInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationTemplateEqual(t, desired, aws.ToString(stored.TemplateBody))
			queues := c.sqs("test", "test", "")
			cloudFormationQueueVisibility(t, queues, cloudFormationQueueURL(t, updated), "42")
			_, err = queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("cfn-cancel-old")})
			assertAPIError(t, err, "AWS.SimpleQueueService.NonExistentQueue")
			cloudFormationDeleteQueueStack(t, c, source, root, queues, aws.ToString(created.StackId), cloudFormationQueueURL(t, updated))
		})
	}
}

func TestCloudFormationRemovesFailedResourceWithoutPhysicalIdentity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			var audit journal.Storage
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				audit = config.Storage.Journal
				return startPublicCloud(t, config)
			})
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			body := `{"Resources":{"Queue":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"cfn-empty-good","VisibilityTimeout":10}},"Bad":{"Type":"AWS::SQS::Queue","DependsOn":"Queue","Properties":{"QueueName":"cfn-empty-bad","RedrivePolicy":{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:000000000000:cfn-empty-missing","maxReceiveCount":3}}}},"Outputs":{"Queue":{"Value":{"Ref":"Queue"}}}}`
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("empty-physical-removal"), TemplateBody: aws.String(body), DisableRollback: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateFailed)
			failed, err := root.DescribeStackResource(t.Context(), &cloudformation.DescribeStackResourceInput{StackName: created.StackId, LogicalResourceId: aws.String("Bad")})
			if err != nil || failed.StackResourceDetail.ResourceStatus != cfntypes.ResourceStatusCreateFailed || aws.ToString(failed.StackResourceDetail.PhysicalResourceId) != "" {
				t.Fatalf("expected failed creation without an owner identity: %+v %v", failed, err)
			}
			queues := c.sqs("test", "test", "")
			unowned, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("cfn-empty-bad"), Attributes: map[string]string{"VisibilityTimeout": "55"}})
			if err != nil {
				t.Fatal(err)
			}
			_, key, secret := c.user(t, "test", "cfn-empty-actor")
			putUserPolicy(t, c.iam("test", "test", ""), "cfn-empty-actor", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","sqs:*"],"Resource":"*"},{"Effect":"Deny","Action":["sqs:CreateQueue","sqs:DeleteQueue"],"Resource":"*"}]}`)
			actor := cloudFormationClient(c, "us-east-1", key, secret)
			desired := cloudFormationQueueTemplate(t, "cfn-empty-good", 42, 0)
			if _, err = actor.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(desired)}); err != nil {
				t.Fatal(err)
			}
			updated := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			if aws.ToString(updated.StackStatusReason) != "" {
				t.Fatal("absent physical resource caused a cleanup warning", updated)
			}
			cloudFormationOwnerDeleteAttempts(t, audit, source, key, "DeleteQueue", "", 0)
			_, err = root.DescribeStackResource(t.Context(), &cloudformation.DescribeStackResourceInput{StackName: created.StackId, LogicalResourceId: aws.String("Bad")})
			assertAPIError(t, err, "ValidationError")
			stored, err := root.GetTemplate(t.Context(), &cloudformation.GetTemplateInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationTemplateEqual(t, desired, aws.ToString(stored.TemplateBody))
			cloudFormationQueueVisibility(t, queues, cloudFormationQueueURL(t, updated), "42")
			cloudFormationQueueVisibility(t, queues, aws.ToString(unowned.QueueUrl), "55")
			cloudFormationDeleteQueueStack(t, c, source, root, queues, aws.ToString(created.StackId), cloudFormationQueueURL(t, updated))
			cloudFormationQueueVisibility(t, queues, aws.ToString(unowned.QueueUrl), "55")
			if _, err = queues.DeleteQueue(t.Context(), &sqs.DeleteQueueInput{QueueUrl: unowned.QueueUrl}); err != nil {
				t.Fatal(err)
			}
			_, err = queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("cfn-empty-bad")})
			assertAPIError(t, err, "AWS.SimpleQueueService.NonExistentQueue")
		})
	}
}

func TestCloudFormationFailedCreateRollbackBaseline(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			body := `{"Parameters":{"Visibility":{"Type":"Number","Default":10}},"Resources":{"Good":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"cfn-baseline-good","VisibilityTimeout":{"Ref":"Visibility"}}},"Bad":{"Type":"AWS::SQS::Queue","DependsOn":"Good","Properties":{"QueueName":"cfn-baseline-bad","RedrivePolicy":{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:000000000000:cfn-baseline-missing","maxReceiveCount":3}}}},"Outputs":{"Queue":{"Value":{"Ref":"Good"}}}}`
			parameters := func(value string) []cfntypes.Parameter {
				return []cfntypes.Parameter{{ParameterKey: aws.String("Visibility"), ParameterValue: aws.String(value)}}
			}
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("failed-create-baseline"), TemplateBody: aws.String(body), Parameters: parameters("13"), DisableRollback: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			failed := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateFailed)
			if len(failed.Parameters) != 1 || aws.ToString(failed.Parameters[0].ParameterValue) != "13" {
				t.Fatal("failed create lost bound parameters", failed.Parameters)
			}
			actual, err := c.sqs("test", "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("cfn-baseline-good")})
			if err != nil {
				t.Fatal(err)
			}
			_, key, secret := c.user(t, "test", "cfn-baseline-actor")
			putUserPolicy(t, c.iam("test", "test", ""), "cfn-baseline-actor", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*","sqs:*"],"Resource":"*"},{"Effect":"Deny","Action":"sqs:CreateQueue","Resource":"*"}]}`)
			var changed map[string]any
			awsDecodeJSON(t, []byte(body), &changed)
			delete(changed["Resources"].(map[string]any)["Bad"].(map[string]any)["Properties"].(map[string]any), "RedrivePolicy")
			encoded, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			actor := cloudFormationClient(c, "us-east-1", key, secret)
			if _, err = actor.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(string(encoded)), Parameters: parameters("27")}); err != nil {
				t.Fatal(err)
			}
			restored := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateRollbackComplete)
			if aws.ToString(restored.Parameters[0].ParameterValue) != "13" {
				t.Fatal("rollback did not restore failed-create parameter baseline", restored.Parameters)
			}
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), aws.ToString(actual.QueueUrl), "13")
			stored, err := root.GetTemplate(t.Context(), &cloudformation.GetTemplateInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationTemplateEqual(t, body, aws.ToString(stored.TemplateBody))
			cloudFormationDeleteQueueStack(t, c, source, root, c.sqs("test", "test", ""), aws.ToString(created.StackId), aws.ToString(actual.QueueUrl))
		})
	}
}

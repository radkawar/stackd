package stackd_test

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"stackd"
	"stackd/clock"
)

// A change set must keep the SSM value it admitted, not fetch a different value
// at execution/restart. UsePreviousValue reuses the parameter key, not that old
// resolution, when the next change set is created.
func TestCloudFormationSSMChangeSetSnapshot(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			parameterClient := func() *ssm.Client {
				return ssm.New(ssm.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			}
			put := func(value string) {
				t.Helper()
				_, err := parameterClient().PutParameter(t.Context(), &ssm.PutParameterInput{Name: aws.String("/cfn-snapshot/queue"), Type: ssmtypes.ParameterTypeString, Value: aws.String(value), Overwrite: aws.Bool(true)})
				if err != nil {
					t.Fatal(err)
				}
			}
			put("cfn-snapshot-first")
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			body := `{"Parameters":{"QueueName":{"Type":"AWS::SSM::Parameter::Value<String>","Default":"/cfn-snapshot/queue"}},"Resources":{"Queue":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":{"Ref":"QueueName"}}}},"Outputs":{"Queue":{"Value":{"Ref":"Queue"}}}}`
			created, err := root.CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{StackName: aws.String("ssm-snapshot"), ChangeSetName: aws.String("create"), ChangeSetType: cfntypes.ChangeSetTypeCreate, TemplateBody: aws.String(body)})
			if err != nil {
				t.Fatal(err)
			}
			put("cfn-snapshot-second")
			c = reopen()
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			if _, err := root.ExecuteChangeSet(t.Context(), &cloudformation.ExecuteChangeSetInput{ChangeSetName: created.Id}); err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			if len(stack.Parameters) != 1 || aws.ToString(stack.Parameters[0].ParameterValue) != "/cfn-snapshot/queue" || aws.ToString(stack.Parameters[0].ResolvedValue) != "cfn-snapshot-first" {
				t.Fatalf("admitted parameter lost after execution/reopen: %#v", stack.Parameters)
			}
			firstURL := cloudFormationQueueURL(t, stack)
			first, err := c.sqs("test", "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("cfn-snapshot-first")})
			if err != nil {
				t.Fatal(err)
			}
			retainedURL, err := url.Parse(firstURL)
			if err != nil {
				t.Fatal(err)
			}
			ownerURL, err := url.Parse(aws.ToString(first.QueueUrl))
			if err != nil || ownerURL.Path != retainedURL.Path {
				t.Fatalf("queue did not consume admitted SSM value: retained %s, owner %s: %v", firstURL, aws.ToString(first.QueueUrl), err)
			}
			update, err := root.CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{StackName: created.StackId, ChangeSetName: aws.String("update"), ChangeSetType: cfntypes.ChangeSetTypeUpdate, TemplateBody: aws.String(body), Parameters: []cfntypes.Parameter{{ParameterKey: aws.String("QueueName"), UsePreviousValue: aws.Bool(true)}}})
			if err != nil {
				t.Fatal(err)
			}
			put("cfn-snapshot-third")
			c = reopen()
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			if _, err := root.ExecuteChangeSet(t.Context(), &cloudformation.ExecuteChangeSetInput{ChangeSetName: update.Id}); err != nil {
				t.Fatal(err)
			}
			stack = cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			if len(stack.Parameters) != 1 || aws.ToString(stack.Parameters[0].ResolvedValue) != "cfn-snapshot-second" {
				t.Fatalf("UsePreviousValue must resolve the current key at admission: %#v", stack.Parameters)
			}
			secondURL := cloudFormationQueueURL(t, stack)
			if secondURL == firstURL {
				t.Fatal("SSM create-only property change did not replace queue")
			}
			_, err = c.sqs("test", "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("cfn-snapshot-first")})
			assertAPIError(t, err, "AWS.SimpleQueueService.NonExistentQueue")
			cloudFormationDeleteQueueStack(t, c, source, root, c.sqs("test", "test", ""), aws.ToString(created.StackId), secondURL)
			if _, err := parameterClient().DeleteParameter(t.Context(), &ssm.DeleteParameterInput{Name: aws.String("/cfn-snapshot/queue")}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCloudFormationAutomaticImportDoesNotAdoptExistingOwner(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			repositories := ecr.New(ecr.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			existing, err := repositories.CreateRepository(t.Context(), &ecr.CreateRepositoryInput{RepositoryName: aws.String("cfn-autoimport-existing"), ImageTagMutability: ecrtypes.ImageTagMutabilityImmutable, Tags: []ecrtypes.Tag{{Key: aws.String("owner"), Value: aws.String("external")}}})
			if err != nil {
				t.Fatal(err)
			}
			body := func(name string) string {
				return fmt.Sprintf(`{"Resources":{"Repository":{"Type":"AWS::ECR::Repository","DeletionPolicy":"Retain","Properties":{"RepositoryName":%q,"ImageTagMutability":"MUTABLE"}}}}`, name)
			}
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			_, err = root.CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{StackName: aws.String("import-existing"), ChangeSetName: aws.String("plan"), ChangeSetType: cfntypes.ChangeSetTypeCreate, ImportExistingResources: aws.Bool(true), TemplateBody: aws.String(body("cfn-autoimport-existing"))})
			assertAPIError(t, err, "NotImplementedException")
			attributes, err := repositories.DescribeRepositories(t.Context(), &ecr.DescribeRepositoriesInput{RepositoryNames: []string{"cfn-autoimport-existing"}})
			if err != nil || len(attributes.Repositories) != 1 || attributes.Repositories[0].ImageTagMutability != ecrtypes.ImageTagMutabilityImmutable {
				t.Fatalf("rejected adoption changed owner configuration: %v %v", attributes, err)
			}
			tags, err := repositories.ListTagsForResource(t.Context(), &ecr.ListTagsForResourceInput{ResourceArn: existing.Repository.RepositoryArn})
			if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Key) != "owner" || aws.ToString(tags.Tags[0].Value) != "external" {
				t.Fatalf("rejected adoption changed owner tags: %v %v", tags, err)
			}
			_, err = root.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: aws.String("import-existing")})
			assertAPIError(t, err, "ValidationError")
			absent, err := root.CreateChangeSet(t.Context(), &cloudformation.CreateChangeSetInput{StackName: aws.String("import-absent"), ChangeSetName: aws.String("plan"), ChangeSetType: cfntypes.ChangeSetTypeCreate, ImportExistingResources: aws.Bool(true), TemplateBody: aws.String(body("cfn-autoimport-absent"))})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := root.DescribeChangeSet(t.Context(), &cloudformation.DescribeChangeSetInput{ChangeSetName: absent.Id})
			if err != nil || len(plan.Changes) != 1 || plan.Changes[0].ResourceChange.Action != cfntypes.ChangeActionAdd {
				t.Fatalf("absent candidate was not planned as create: %v %v", plan, err)
			}
			_, err = repositories.DescribeRepositories(t.Context(), &ecr.DescribeRepositoriesInput{RepositoryNames: []string{"cfn-autoimport-absent"}})
			assertAPIError(t, err, "RepositoryNotFoundException")
			if _, err := root.DeleteChangeSet(t.Context(), &cloudformation.DeleteChangeSetInput{ChangeSetName: absent.Id}); err != nil {
				t.Fatal(err)
			}
			if _, err := repositories.DeleteRepository(t.Context(), &ecr.DeleteRepositoryInput{RepositoryName: existing.Repository.RepositoryName}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

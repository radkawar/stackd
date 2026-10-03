package stackd_test

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"testing"
)

func TestIAMPrincipalSimulationTracksOrganizationsAndQueueAuthorization(t *testing.T) {
	ctx := t.Context()
	c := newCloudClients(t)
	org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	if _, err := org.CreateOrganization(ctx, &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll}); err != nil {
		t.Fatal(err)
	}
	account, err := org.CreateAccount(ctx, &organizations.CreateAccountInput{AccountName: aws.String("simulation"), Email: aws.String("simulation@example.test")})
	if err != nil {
		t.Fatal(err)
	}
	account.CreateAccountStatus = waitAccountCreation(t, org, account.CreateAccountStatus, nil)
	accountID := aws.ToString(account.CreateAccountStatus.AccountId)
	root := c.iam(accountID, "test", "")
	arn, key, secret := c.user(t, accountID, "producer")
	putUserPolicy(t, root, "producer", allow(`"sqs:SendMessage"`, "*"))
	queue, err := c.sqs(accountID, "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("simulated")})
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := c.sqs(accountID, "test", "").GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
	if err != nil {
		t.Fatal(err)
	}
	input := &iam.SimulatePrincipalPolicyInput{PolicySourceArn: aws.String(arn), ActionNames: []string{"sqs:SendMessage"}, ResourceArns: []string{attributes.Attributes["QueueArn"]}}
	assertSimulation := func(expected iamtypes.PolicyEvaluationDecisionType, permitted bool) {
		t.Helper()
		result, err := root.SimulatePrincipalPolicy(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.EvaluationResults) != 1 {
			t.Fatalf("simulation result: %+v", result)
		}
		evaluation := result.EvaluationResults[0]
		if evaluation.EvalDecision != expected || evaluation.OrganizationsDecisionDetail == nil || evaluation.OrganizationsDecisionDetail.AllowedByOrganizations != permitted {
			t.Fatalf("simulation decision: %+v", evaluation)
		}
	}
	assertSimulation(iamtypes.PolicyEvaluationDecisionTypeAllowed, true)
	sender := c.sqs(key, secret, "")
	if _, err := sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("before guardrail")}); err != nil {
		t.Fatal(err)
	}
	policy, err := org.CreatePolicy(ctx, &organizations.CreatePolicyInput{Name: aws.String("simulation-deny-send"), Description: aws.String("simulation control"), Type: orgtypes.PolicyTypeServiceControlPolicy, Content: aws.String(`{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := org.AttachPolicy(ctx, &organizations.AttachPolicyInput{PolicyId: policy.Policy.PolicySummary.Id, TargetId: aws.String(accountID)}); err != nil {
		t.Fatal(err)
	}
	assertSimulation(iamtypes.PolicyEvaluationDecisionTypeExplicitDeny, false)
	_, err = sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("denied")})
	assertAPIError(t, err, "AccessDenied")
	input.PolicyExclusionList = []iamtypes.PolicyIdentifier{&iamtypes.PolicyIdentifierMemberPolicyType{Value: iamtypes.PolicyIdentifierPolicyTypeScp}}
	result, err := root.SimulatePrincipalPolicy(ctx, input)
	if err != nil || result.EvaluationResults[0].EvalDecision != iamtypes.PolicyEvaluationDecisionTypeAllowed || result.EvaluationResults[0].OrganizationsDecisionDetail != nil {
		t.Fatalf("hypothetical SCP exclusion: %+v %v", result, err)
	}
	// A hypothetical exclusion never changes the policy protecting actual calls.
	_, err = sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("still denied")})
	assertAPIError(t, err, "AccessDenied")
	if _, err := org.DetachPolicy(ctx, &organizations.DetachPolicyInput{PolicyId: policy.Policy.PolicySummary.Id, TargetId: aws.String(accountID)}); err != nil {
		t.Fatal(err)
	}
	input.PolicyExclusionList = nil
	assertSimulation(iamtypes.PolicyEvaluationDecisionTypeAllowed, true)
	messages, err := c.sqs(accountID, "test", "").ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	if err != nil || len(messages.Messages) != 1 || aws.ToString(messages.Messages[0].Body) != "before guardrail" {
		t.Fatalf("simulation or denied delivery changed queue: %+v %v", messages, err)
	}
}

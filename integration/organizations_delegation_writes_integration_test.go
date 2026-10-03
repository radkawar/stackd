package stackd_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestOrganizationsDelegatedPolicyWritesReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../testdata/aws/iam/organizations_delegation_writes.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Code string
			Input      organizations.PutResourcePolicyInput
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	for _, row := range fixture.Observations {
		codes[row.Case] = row.Code
	}
	check := func(name string, err error) {
		t.Helper()
		code, ok := codes[name]
		if !ok {
			t.Fatal("missing AWS capture", name)
		}
		if code == "Success" {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			return
		}
		assertAPIError(t, err, code)
	}
	f := newOrganizationReportFixture(t, nil)
	c, org := f.cloud, f.org
	member := f.account(t, f.rootID, "delegate")
	description, err := org.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	orgID := *description.Organization.Id
	policyARN := "arn:aws:organizations::000000000000:policy/" + orgID + "/service_control_policy/*"
	rpARN := "arn:aws:organizations::000000000000:resourcepolicy/" + orgID + "/*"
	// Match the native probe's roles in management and member accounts.
	var manager, actor *organizations.Client
	for _, owner := range []string{"000000000000", member} {
		root := c.iam(owner, "test", "")
		role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("OWNED_NAME"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
		if err != nil {
			t.Fatal(err)
		}
		permissions := allow(`"organizations:*"`, "*")
		if owner == "000000000000" {
			permissions = allow(`"organizations:PutResourcePolicy"`, rpARN)
		}
		putRolePolicy(t, root, "OWNED_NAME", permissions)
		session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("writes")})
		if err != nil {
			t.Fatal(err)
		}
		client := delegationSessionClient(c, session.Credentials)
		if owner == "000000000000" {
			manager = client
		} else {
			actor = client
		}
	}
	roleARN := "arn:aws:iam::" + member + ":role/OWNED_NAME"
	statement := map[string]any{"Effect": "Allow", "Principal": map[string]string{"AWS": member}, "Action": "organizations:DescribePolicy", "Resource": policyARN,
		"Condition": map[string]any{"ArnEquals": map[string]string{"aws:PrincipalArn": roleARN}}}
	document := func(statements ...map[string]any) string {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	content := document(statement)
	_, err = manager.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: &content})
	check("put-only-without-tags", err)
	if _, err := org.DeleteResourcePolicy(t.Context(), &organizations.DeleteResourcePolicyInput{}); err != nil {
		t.Fatal(err)
	}
	tagged := &organizations.PutResourcePolicyInput{Content: &content, Tags: []orgtypes.Tag{{Key: aws.String("stackd-probe"), Value: aws.String("OWNED_NAME")}}}
	_, err = manager.PutResourcePolicy(t.Context(), tagged)
	check("put-only-with-initial-tags", err)
	_, err = org.DescribeResourcePolicy(t.Context(), &organizations.DescribeResourcePolicyInput{})
	assertAPIError(t, err, "ResourcePolicyNotFoundException")
	putRolePolicy(t, f.iam, "OWNED_NAME", allow(`["organizations:PutResourcePolicy","organizations:TagResource"]`, rpARN))
	created, err := manager.PutResourcePolicy(t.Context(), tagged)
	check("put-and-tag-with-initial-tags", err)
	rpID := created.ResourcePolicy.ResourcePolicySummary.Id
	_, err = org.TagResource(t.Context(), &organizations.TagResourceInput{ResourceId: rpID, Tags: []orgtypes.Tag{{Key: aws.String("team"), Value: aws.String("probe")}}})
	check("tag-resource-policy", err)
	_, err = org.UntagResource(t.Context(), &organizations.UntagResourceInput{ResourceId: rpID, TagKeys: []string{"stackd-probe"}})
	check("untag-resource-policy", err)
	tags, err := org.ListTagsForResource(t.Context(), &organizations.ListTagsForResourceInput{ResourceId: rpID})
	check("remaining-resource-policy-tags", err)
	if !reflect.DeepEqual(tags.Tags, []orgtypes.Tag{{Key: aws.String("team"), Value: aws.String("probe")}}) {
		t.Fatalf("tags = %+v", tags.Tags)
	}
	// PutResourcePolicy resolves current tags from the singleton's resource ID.
	conditional := `{"Statement":{"Effect":"Allow","Action":"organizations:PutResourcePolicy","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"probe"}}}}`
	putRolePolicy(t, f.iam, "OWNED_NAME", conditional)
	if _, err := manager.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: &content}); err != nil {
		t.Fatal(err)
	}
	if _, err := org.TagResource(t.Context(), &organizations.TagResourceInput{ResourceId: rpID, Tags: []orgtypes.Tag{{Key: aws.String("team"), Value: aws.String("revoked")}}}); err != nil {
		t.Fatal(err)
	}
	_, err = manager.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: &content})
	assertAPIError(t, err, "AccessDeniedException")
	replacements := strings.NewReplacer("111111111111", "000000000000", "222222222222", member, "ORGANIZATION_ID", orgID)
	for _, row := range fixture.Observations {
		if strings.HasPrefix(row.Case, "validate-") {
			input := row.Input
			input.Content = aws.String(replacements.Replace(*input.Content))
			_, err := org.PutResourcePolicy(t.Context(), &input)
			check(row.Case, err)
		}
	}
	unitID := f.unit(t, f.rootID, "empty-target")
	unit, err := org.DescribeOrganizationalUnit(t.Context(), &organizations.DescribeOrganizationalUnitInput{OrganizationalUnitId: &unitID})
	if err != nil {
		t.Fatal(err)
	}
	statement["Action"] = "organizations:CreatePolicy"
	statement["Condition"].(map[string]any)["StringEquals"] = map[string]string{"aws:RequestTag/stackd-probe": "OWNED_NAME"}
	put := func(statements ...map[string]any) {
		t.Helper()
		body := document(statements...)
		if _, err := org.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: &body}); err != nil {
			t.Fatal(err)
		}
	}
	put(statement)
	input := &organizations.CreatePolicyInput{Name: aws.String("OWNED_NAME"), Description: aws.String("Owned delegation writes"), Type: orgtypes.PolicyTypeServiceControlPolicy,
		Content: aws.String(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`), Tags: []orgtypes.Tag{{Key: aws.String("stackd-probe"), Value: aws.String("OWNED_NAME")}}}
	_, err = actor.CreatePolicy(t.Context(), input)
	check("create-without-delegated-tag", err)
	before, err := org.ListPolicies(t.Context(), &organizations.ListPoliciesInput{Filter: orgtypes.PolicyTypeServiceControlPolicy})
	if err != nil || len(before.Policies) != 1 {
		t.Fatalf("denied creation leaked policy: %+v, %v", before, err)
	}
	statement["Action"] = []string{"organizations:CreatePolicy", "organizations:TagResource"}
	put(statement)
	target, err := actor.CreatePolicy(t.Context(), input)
	check("create-with-delegated-tag", err)
	targetID, targetARN := target.Policy.PolicySummary.Id, target.Policy.PolicySummary.Arn
	statement["Resource"] = *targetARN
	statement["Action"] = []string{"organizations:DescribePolicy", "organizations:UpdatePolicy", "organizations:DeletePolicy", "organizations:TagResource", "organizations:UntagResource", "organizations:ListTagsForResource", "organizations:AttachPolicy", "organizations:DetachPolicy"}
	delete(statement["Condition"].(map[string]any), "StringEquals")
	put(statement)
	_, err = actor.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: targetID, Name: aws.String("OWNED_NAME-updated")})
	check("update-policy", err)
	_, err = actor.TagResource(t.Context(), &organizations.TagResourceInput{ResourceId: targetID, Tags: []orgtypes.Tag{{Key: aws.String("team"), Value: aws.String("probe")}}})
	check("tag-policy", err)
	_, err = actor.UntagResource(t.Context(), &organizations.UntagResourceInput{ResourceId: targetID, TagKeys: []string{"team"}})
	check("untag-policy", err)
	_, err = actor.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: targetID, TargetId: &unitID})
	check("attach-without-target-grant", err)
	attached, err := org.ListTargetsForPolicy(t.Context(), &organizations.ListTargetsForPolicyInput{PolicyId: targetID})
	if err != nil || len(attached.Targets) != 0 {
		t.Fatalf("denied attachment changed hierarchy: %+v, %v", attached, err)
	}
	statement["Resource"] = []string{*targetARN, *unit.OrganizationalUnit.Arn}
	put(statement)
	_, err = actor.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: targetID, TargetId: &unitID})
	check("attach-with-target-grant", err)
	_, err = actor.DeletePolicy(t.Context(), &organizations.DeletePolicyInput{PolicyId: targetID})
	check("delete-attached-policy", err)

	// An actual delegated SCP update must reach other services. The delegate
	// stays outside the target OU so its own management permissions are unaffected.
	workload := f.account(t, unitID, "workload")
	queueClient := c.sqs(workload, "test", "")
	queue, err := queueClient.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("delegated-controls")})
	if err != nil {
		t.Fatal(err)
	}
	deny := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}]}`
	if _, err := actor.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: targetID, Content: &deny}); err != nil {
		t.Fatal(err)
	}
	_, err = queueClient.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("blocked")})
	assertAPIError(t, err, "AccessDenied")
	_, err = actor.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: targetID, TargetId: &unitID})
	check("detach-policy", err)
	if _, err := queueClient.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("allowed")}); err != nil {
		t.Fatal(err)
	}
	messages, err := queueClient.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	if err != nil || len(messages.Messages) != 1 || aws.ToString(messages.Messages[0].Body) != "allowed" {
		t.Fatalf("denied send persisted a message: %+v, %v", messages, err)
	}
	_, err = actor.DeletePolicy(t.Context(), &organizations.DeletePolicyInput{PolicyId: targetID})
	check("delete-policy", err)
	_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: targetID})
	check("describe-deleted-policy", err)
	_, err = org.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: targetID})
	assertAPIError(t, err, "PolicyNotFoundException")
	// Resource delegation never grants authority to replace the delegation itself.
	_, err = actor.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: &content})
	assertAPIError(t, err, "AccessDeniedException")
	_, err = actor.DeleteResourcePolicy(t.Context(), &organizations.DeleteResourcePolicyInput{})
	assertAPIError(t, err, "AccessDeniedException")
	// Preserve native resource-policy identity and tags across content updates.
	current, err := org.DescribeResourcePolicy(t.Context(), &organizations.DescribeResourcePolicyInput{})
	if err != nil || aws.ToString(current.ResourcePolicy.ResourcePolicySummary.Id) != *rpID {
		t.Fatalf("identity changed: %+v, %v", current, err)
	}
	if _, err := org.DeleteResourcePolicy(t.Context(), &organizations.DeleteResourcePolicyInput{}); err != nil {
		t.Fatal(err)
	}
	recreated, err := org.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: &content})
	if err != nil || aws.ToString(recreated.ResourcePolicy.ResourcePolicySummary.Id) == *rpID {
		t.Fatalf("recreation reused identity: %+v, %v", recreated, err)
	}
	_, err = org.ListTagsForResource(t.Context(), &organizations.ListTagsForResourceInput{ResourceId: rpID})
	assertAPIError(t, err, "TargetNotFoundException")
	tags, err = org.ListTagsForResource(t.Context(), &organizations.ListTagsForResourceInput{ResourceId: recreated.ResourcePolicy.ResourcePolicySummary.Id})
	if err != nil || len(tags.Tags) != 0 {
		t.Fatalf("recreation inherited deleted tags: %+v, %v", tags, err)
	}
}

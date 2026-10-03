package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// This replays observed AWS outcomes locally; no AWS credentials or endpoints
// are discovered by the test. The fixture describes its narrow comparison.
func TestAWSManagedSessionPolicyChangesAffectExistingCredentials(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/sts/managed_session_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Initial      string `json:"initial_policy_effect"`
		Updated      string `json:"updated_policy_effect"`
		Observations []struct {
			Phase   string `json:"phase"`
			Allowed bool   `json:"allowed"`
			Code    string `json:"error_code"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Observations) != 2 {
		t.Fatal("fixture must contain both AWS observations")
	}
	ctx := context.Background()
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("session-policy"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "session-policy", allow(`"iam:ListUsers"`, "*"))
	policyDoc := func(effect string) string {
		return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":%q,"Action":"iam:ListUsers","Resource":"*"}}`, effect)
	}
	managed, err := root.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String("session-permission"), PolicyDocument: aws.String(policyDoc(fixture.Initial))})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.sts("test", "test", "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("probe"), DurationSeconds: aws.Int32(900), PolicyArns: []ststypes.PolicyDescriptorType{{Arn: managed.Policy.Arn}}})
	if err != nil {
		t.Fatal(err)
	}
	token := session.Credentials
	client := c.iam(aws.ToString(token.AccessKeyId), aws.ToString(token.SecretAccessKey), aws.ToString(token.SessionToken))
	for i, observation := range fixture.Observations {
		if i == 1 {
			if _, err := root.CreatePolicyVersion(ctx, &iam.CreatePolicyVersionInput{PolicyArn: managed.Policy.Arn, PolicyDocument: aws.String(policyDoc(fixture.Updated)), SetAsDefault: true}); err != nil {
				t.Fatal(err)
			}
		}
		_, err := client.ListUsers(ctx, &iam.ListUsersInput{MaxItems: aws.Int32(1)})
		if observation.Allowed {
			if err != nil {
				t.Fatalf("%s: %v", observation.Phase, err)
			}
		} else {
			assertAPIError(t, err, observation.Code)
		}
	}
}

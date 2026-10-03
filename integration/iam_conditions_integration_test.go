package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestIAMConditionsAWSReplay(t *testing.T) {
	for _, suite := range []string{"sets", "values", "ip", "strings"} {
		t.Run(suite, func(t *testing.T) { replayIAMConditions(t, suite) })
	}
}

func TestIAMIPConditionsEnforceObservedPeerSDK(t *testing.T) {
	c := newCloudClients(t)
	_, key, secret := c.user(t, "test", "network-client")
	root := c.iam("test", "test", "")
	queue, err := c.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("ip-guarded")})
	if err != nil {
		t.Fatal(err)
	}
	client := c.sqs(key, secret, "")
	for _, test := range []struct {
		network string
		allowed bool
	}{
		{"127.000.000.0/008", true},
		{"127.0.0.1/32", true},
		{"192.0.2.0/24", false},
		{"::ffff:7f00:1/128", false},
	} {
		document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":%q}}}}`, test.network)
		putUserPolicy(t, root, "network-client", document)
		_, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String(test.network)})
		if test.allowed {
			if err != nil {
				t.Fatalf("network %s should permit the loopback peer: %v", test.network, err)
			}
		} else {
			assertAPIError(t, err, "AccessDenied")
		}
	}
	got, err := c.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil || len(got.Messages) != 2 {
		t.Fatal("IP-denied calls published messages", got, err)
	}
}

func replayIAMConditions(t *testing.T, suite string) {
	var fixture struct {
		Observations []struct {
			Condition json.RawMessage
			Tags      []iamtypes.Tag
			Deny      bool
			BaseAllow bool `json:"base_allow"`
			Code      string
		}
		Simulation []struct {
			Input  iam.SimulateCustomPolicyInput
			Code   string
			Output iam.SimulateCustomPolicyOutput
		}
		PolicyStorage []struct {
			Document json.RawMessage
			Code     string
		} `json:"policy_storage"`
		ResourceReports []struct {
			Document json.RawMessage
			Output   iam.ListPoliciesGrantingServiceAccessOutput
		} `json:"resource_reports"`
	}
	data, err := os.ReadFile("../testdata/aws/iam/condition_" + suite + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	user, err := root.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("condition-target")})
	if err != nil {
		t.Fatal(err)
	}
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("condition-actor"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]any{"Effect": "Allow", "Action": "iam:TagUser", "Resource": aws.ToString(user.User.Arn)}
	putRolePolicy(t, root, aws.ToString(role.Role.RoleName), allow(`"iam:TagUser"`, aws.ToString(user.User.Arn)))
	wantTags := make(map[string]string)
	for i, row := range fixture.Observations {
		t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
			statement := map[string]any{"Effect": "Allow", "Action": "iam:TagUser", "Resource": aws.ToString(user.User.Arn), "Condition": row.Condition}
			statements := []any{statement}
			if row.Deny {
				statement["Effect"] = "Deny"
			}
			if row.Deny || row.BaseAllow {
				statements = []any{base, statement}
			}
			document, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
			if err != nil {
				t.Fatal(err)
			}
			session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("sets"), DurationSeconds: aws.Int32(900), Policy: aws.String(string(document))})
			if code, ok := strings.CutPrefix(row.Code, "AssumeRole:"); ok {
				assertAPIError(t, err, code)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			creds := session.Credentials
			client := c.iam(aws.ToString(creds.AccessKeyId), aws.ToString(creds.SecretAccessKey), aws.ToString(creds.SessionToken))
			_, err = client.TagUser(t.Context(), &iam.TagUserInput{UserName: user.User.UserName, Tags: row.Tags})
			if row.Code == "Success" {
				if err != nil {
					t.Fatalf("AWS allowed condition %s, tags %v, deny %t: %v", row.Condition, row.Tags, row.Deny, err)
				}
				for _, tag := range row.Tags {
					wantTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
				}
			} else {
				assertAPIError(t, err, row.Code)
			}
			out, err := root.ListUserTags(t.Context(), &iam.ListUserTagsInput{UserName: user.User.UserName})
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[string]string)
			for _, tag := range out.Tags {
				got[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			if !reflect.DeepEqual(got, wantTags) {
				t.Fatalf("tag state = %v, want only authorized writes %v", got, wantTags)
			}
		})
	}
	for i, row := range fixture.Simulation {
		t.Run(fmt.Sprintf("simulation/%02d", i), func(t *testing.T) {
			out, err := root.SimulateCustomPolicy(t.Context(), &row.Input)
			if row.Code != "Success" {
				assertAPIError(t, err, row.Code)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(out.EvaluationResults) != len(row.Output.EvaluationResults) {
				t.Fatal("simulation result count differs from AWS")
			}
			for j, got := range out.EvaluationResults {
				want := row.Output.EvaluationResults[j]
				if got.EvalDecision != want.EvalDecision || aws.ToString(got.EvalActionName) != aws.ToString(want.EvalActionName) || aws.ToString(got.EvalResourceName) != aws.ToString(want.EvalResourceName) {
					t.Fatalf("simulation decision = %s, want %s for %s", got.EvalDecision, want.EvalDecision, row.Input.PolicyInputList)
				}
			}
		})
	}
	for i, row := range fixture.PolicyStorage {
		t.Run(fmt.Sprintf("policy_storage/%02d", i), func(t *testing.T) {
			_, err := root.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("syntax"), PolicyDocument: aws.String(string(row.Document))})
			if row.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				assertAPIError(t, err, row.Code)
			}
		})
	}
	for i, row := range fixture.ResourceReports {
		t.Run(fmt.Sprintf("resource_report/%02d", i), func(t *testing.T) {
			_, err := root.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("strings"), PolicyDocument: aws.String(string(row.Document))})
			if err != nil {
				t.Fatal(err)
			}
			out, err := root.ListPoliciesGrantingServiceAccess(t.Context(), &iam.ListPoliciesGrantingServiceAccessInput{Arn: user.User.Arn, ServiceNamespaces: []string{"s3"}})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(out.PoliciesGrantingServiceAccess, row.Output.PoliciesGrantingServiceAccess) {
				t.Fatalf("resource permission report = %#v, want %#v", out.PoliciesGrantingServiceAccess, row.Output.PoliciesGrantingServiceAccess)
			}
		})
	}
}

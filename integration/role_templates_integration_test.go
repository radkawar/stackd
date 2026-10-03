package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const powerRoleTemplate = "arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1"

func acquireTemplate(t *testing.T, client *iam.Client, arn, name string, values map[string][]string) (*iam.AcquireRoleOutput, error) {
	t.Helper()
	replacements := map[string]types.ReplacementValueEntry{"RoleName": {Values: []string{name}}}
	for key, value := range values {
		replacements[key] = types.ReplacementValueEntry{Values: value}
	}
	return client.AcquireRole(t.Context(), &iam.AcquireRoleInput{TemplateArn: aws.String(arn), ReplacementValues: replacements})
}

func templateFixture(t *testing.T, filename string) map[string]map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/iam/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations map[string]json.RawMessage `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]map[string]json.RawMessage)
	for label, raw := range fixture.Observations {
		if strings.HasSuffix(label, "_propagation") {
			continue
		}
		var row map[string]json.RawMessage
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Fatal(err)
		}
		rows[label] = row
	}
	return rows
}

// Compare configuration and field presence while preserving separate assertions
// for resource identity. IAM service/principal arrays have no specified order.
func templateJSON(value any) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any)
		for key, child := range value {
			if child == nil || key == "RoleId" || key == "CreateDate" {
				continue
			}
			if key == "MaxSessionDuration" && child == float64(0) {
				continue
			}
			if key == "CreateTimestamp" || key == "UpdateTimestamp" {
				if timestamp, ok := child.(string); ok {
					if parsed, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
						child = parsed.UTC().Format(time.RFC3339Nano)
					}
				}
			}
			if document, ok := child.(string); ok && (strings.Contains(key, "PolicyDocument") || key == "PolicyDocument") {
				if decoded, err := url.QueryUnescape(document); err == nil {
					document = decoded
				}
				var parsed any
				if json.Unmarshal([]byte(document), &parsed) == nil {
					child = parsed
				}
			}
			if strings.Contains(key, "PolicyDocument") {
				child = templatePolicyLists(child)
			}
			out[key] = templateJSON(child)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = templateJSON(child)
		}
		slices.SortFunc(out, func(a, b any) int {
			left, _ := json.Marshal(a)
			right, _ := json.Marshal(b)
			return strings.Compare(string(left), string(right))
		})
		return out
	default:
		return value
	}
}

func templatePolicyLists(value any) any {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			value[key] = templatePolicyLists(child)
		}
		return value
	case []any:
		for i, child := range value {
			value[i] = templatePolicyLists(child)
		}
		if len(value) == 1 {
			return value[0]
		}
		return value
	default:
		return value
	}
}

func assertTemplateJSON(t *testing.T, got any, raw json.RawMessage) {
	t.Helper()
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected any
	if err := json.Unmarshal(data, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(templateJSON(actual), templateJSON(expected)) {
		t.Fatalf("template behavior differs\ngot: %s\nwant: %s", data, raw)
	}
}

func assertTemplateAcquisition(t *testing.T, fixture map[string]map[string]json.RawMessage, label string, out *iam.AcquireRoleOutput, err error) {
	t.Helper()
	row := fixture[label]
	if expected := row["error"]; expected != nil {
		var failure struct{ Code string }
		if err := json.Unmarshal(expected, &failure); err != nil {
			t.Fatal(err)
		}
		assertAPIError(t, err, failure.Code)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var expected struct{ Role json.RawMessage }
	if err := json.Unmarshal(row["result"], &expected); err != nil {
		t.Fatal(err)
	}
	assertTemplateJSON(t, out.Role, expected.Role)
}

func TestRoleTemplateCatalogueAWSReplay(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("111111111111", "test", "")
	fixture := templateFixture(t, "role_template_catalogue.json")
	for label, row := range fixture {
		if !strings.HasPrefix(label, "template_") {
			continue
		}
		t.Run(label, func(t *testing.T) {
			if row["result"] == nil {
				return
			} // Unavailable directory entries are exercised below.
			var tree struct{ RoleTemplateVersion map[string]any }
			if err := json.Unmarshal(row["result"], &tree); err != nil {
				t.Fatal(err)
			}
			arn := tree.RoleTemplateVersion["TemplateArn"].(string)
			out, err := root.GetRoleTemplateVersion(t.Context(), &iam.GetRoleTemplateVersionInput{TemplateArn: aws.String(arn)})
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(tree.RoleTemplateVersion)
			assertTemplateJSON(t, out.RoleTemplateVersion, data)
			// Returned contracts are detached from the embedded source.
			out.RoleTemplateVersion.ParametersDefinition[0].DefaultValue = aws.String("caller edit")
			again, err := root.GetRoleTemplateVersion(t.Context(), &iam.GetRoleTemplateVersionInput{TemplateArn: aws.String(arn), MinorVersion: aws.Int32(0)})
			if err != nil {
				t.Fatal(err)
			}
			assertTemplateJSON(t, again.RoleTemplateVersion, data)
		})
	}
	for _, arn := range []string{
		"arn:aws:iam::aws:role-template/logs.amazonaws.com/AmazonCloudWatchLogsScheduledQueryExecutionRoleTemplate:1",
		"arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:99",
	} {
		_, err := root.GetRoleTemplateVersion(t.Context(), &iam.GetRoleTemplateVersionInput{TemplateArn: aws.String(arn)})
		assertAPIError(t, err, "NoSuchEntity")
	}
	_, err := root.GetRoleTemplateVersion(t.Context(), &iam.GetRoleTemplateVersionInput{TemplateArn: aws.String(powerRoleTemplate), MinorVersion: aws.Int32(-1)})
	assertAPIError(t, err, "NoSuchEntity")
}

func TestRoleAcquisitionAWSReplayAndCurrentPermissions(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("111111111111", "test", "")
	fixture := templateFixture(t, "role_templates.json")
	power := map[string][]string{"AWSServiceName": {"lambda.amazonaws.com"}}
	first, err := acquireTemplate(t, root, powerRoleTemplate, "OWNED_ROLE-power", power)
	assertTemplateAcquisition(t, fixture, "create", first, err)
	reused, err := acquireTemplate(t, root, powerRoleTemplate, "OWNED_ROLE-power", power)
	assertTemplateAcquisition(t, fixture, "reuse", reused, err)
	if *first.Role.RoleId != *reused.Role.RoleId || !first.Role.CreateDate.Equal(*reused.Role.CreateDate) {
		t.Fatal("reuse changed role identity")
	}
	get, err := root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: first.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	assertTemplateJSON(t, get.Role, fixture["created_role"]["role"])
	_, err = root.UpdateRoleDescription(t.Context(), &iam.UpdateRoleDescriptionInput{RoleName: first.Role.RoleName, Description: aws.String("customer description")})
	if err != nil {
		t.Fatal(err)
	}
	out, err := acquireTemplate(t, root, powerRoleTemplate, "OWNED_ROLE-power", power)
	assertTemplateAcquisition(t, fixture, "description_changed", out, err)
	_, err = root.AttachRolePolicy(t.Context(), &iam.AttachRolePolicyInput{RoleName: first.Role.RoleName, PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")})
	if err != nil {
		t.Fatal(err)
	}
	out, err = acquireTemplate(t, root, powerRoleTemplate, "OWNED_ROLE-power", power)
	assertTemplateAcquisition(t, fixture, "extra_attachment", out, err)
	_, err = root.DetachRolePolicy(t.Context(), &iam.DetachRolePolicyInput{RoleName: first.Role.RoleName, PolicyArn: aws.String("arn:aws:iam::aws:policy/PowerUserAccess")})
	if err != nil {
		t.Fatal(err)
	}
	out, err = acquireTemplate(t, root, powerRoleTemplate, "OWNED_ROLE-power", power)
	assertTemplateAcquisition(t, fixture, "required_attachment_removed", out, err)
	for _, tc := range []struct {
		label  string
		values map[string][]string
	}{
		{"missing_required", nil}, {"multiple_string_values", map[string][]string{"AWSServiceName": {"lambda.amazonaws.com", "ec2.amazonaws.com"}}},
		{"extra_parameter", map[string][]string{"AWSServiceName": {"lambda.amazonaws.com"}, "Unused": {"ignored"}}},
		{"invalid_service", map[string][]string{"AWSServiceName": {"not-a-service"}}},
	} {
		out, err := acquireTemplate(t, root, powerRoleTemplate, "OWNED_ROLE-"+tc.label, tc.values)
		assertTemplateAcquisition(t, fixture, tc.label, out, err)
		_, err = root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("OWNED_ROLE-" + tc.label)})
		assertAPIError(t, err, "NoSuchEntity")
	}
	for _, minor := range []int32{-1, 999} {
		_, err := root.AcquireRole(t.Context(), &iam.AcquireRoleInput{TemplateArn: aws.String(powerRoleTemplate), TemplateMinorVersion: aws.Int32(minor)})
		assertAPIError(t, err, "NoSuchEntity")
	}
	// A separately acquired role uses the same live policies and STS authority
	// as an ordinary role; detaching its policy revokes an existing session.
	worker, err := acquireTemplate(t, root, powerRoleTemplate, "worker", power)
	if err != nil {
		t.Fatal(err)
	}
	trust := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}}`
	_, err = root.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{RoleName: worker.Role.RoleName, PolicyDocument: aws.String(trust)})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.sts("111111111111", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: worker.Role.Arn, RoleSessionName: aws.String("worker")})
	if err != nil {
		t.Fatal(err)
	}
	queueClient := c.sessionSQS(session.Credentials)
	_, err = queueClient.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("template-permissions")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.DetachRolePolicy(t.Context(), &iam.DetachRolePolicyInput{RoleName: worker.Role.RoleName, PolicyArn: aws.String("arn:aws:iam::aws:policy/PowerUserAccess")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = queueClient.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("revoked")})
	assertAPIError(t, err, "AccessDenied")
}

func TestRoleTemplateRenderedPoliciesAWSReplay(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("111111111111", "test", "")
	fixture := templateFixture(t, "role_templates.json")
	rotation := "arn:aws:iam::aws:role-template/secretsmanager.amazonaws.com/AWSSecretsManagerRotationRoleTemplate:1"
	admin := "arn:aws:iam::aws:role-template/datazone.amazonaws.com/AmazonSageMakerAdminIAMPermissiveExecutionRoleTemplate:1"
	for _, tc := range []struct {
		label, template string
		values          map[string][]string
	}{
		{"backup", "arn:aws:iam::aws:role-template/backup.amazonaws.com/AWSBackupDefaultServiceRoleTemplate:1", map[string][]string{"accountId": {"111111111111"}}},
		{"rotation_inactive_missing", rotation, map[string][]string{"accountId": {"111111111111"}, "region": {"us-east-1"}, "resourceType": {"probe"}}},
		{"rotation_disabled", rotation, map[string][]string{"accountId": {"111111111111"}, "region": {"us-east-1"}, "resourceType": {"probe"}, "adminType": {"admin-probe"}, "kmsKeyArn": {"arn:aws:kms:us-east-1:111111111111:key/11111111-1111-1111-1111-111111111111", "arn:aws:kms:us-east-1:111111111111:key/22222222-2222-2222-2222-222222222222"}}},
		{"rotation_enabled", rotation, map[string][]string{"accountId": {"111111111111"}, "region": {"us-east-1"}, "resourceType": {"probe"}, "adminType": {"admin-probe"}, "kmsKeyArn": {"arn:aws:kms:us-east-1:111111111111:key/11111111-1111-1111-1111-111111111111", "arn:aws:kms:us-east-1:111111111111:key/22222222-2222-2222-2222-222222222222"}, "ADMIN_RESOURCE_ENABLED": {"True"}, "CMK_ENABLED": {"True"}}},
		{"rotation_lowercase", rotation, map[string][]string{"accountId": {"111111111111"}, "region": {"us-east-1"}, "resourceType": {"probe"}, "adminType": {"admin-probe"}, "kmsKeyArn": {"arn:aws:kms:us-east-1:111111111111:key/11111111-1111-1111-1111-111111111111", "arn:aws:kms:us-east-1:111111111111:key/22222222-2222-2222-2222-222222222222"}, "ADMIN_RESOURCE_ENABLED": {"true"}, "CMK_ENABLED": {"true"}}},
		{"studio_admin_disabled", admin, map[string][]string{"accountId": {"111111111111"}}},
		{"studio_admin_enabled", admin, map[string][]string{"accountId": {"111111111111"}, "keyAccountId": {"111111111111"}, "keyRegion": {"us-east-1"}, "kmsKeyId": {"11111111-1111-1111-1111-111111111111"}, "CMK_ENABLED": {"True"}}},
		{"studio_user", "arn:aws:iam::aws:role-template/datazone.amazonaws.com/AmazonSageMakerUserIAMPermissiveExecutionRoleTemplate:1", map[string][]string{"accountId": {"111111111111"}}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			out, err := acquireTemplate(t, root, tc.template, "OWNED_ROLE-"+tc.label, tc.values)
			assertTemplateAcquisition(t, fixture, tc.label, out, err)
			if fixture[tc.label+"_role"] == nil {
				return
			}
			state, err := root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: out.Role.RoleName})
			if err != nil {
				t.Fatal(err)
			}
			assertTemplateJSON(t, state.Role, fixture[tc.label+"_role"]["role"])
			attached, err := root.ListAttachedRolePolicies(t.Context(), &iam.ListAttachedRolePoliciesInput{RoleName: out.Role.RoleName})
			if err != nil {
				t.Fatal(err)
			}
			assertTemplateJSON(t, attached.AttachedPolicies, fixture[tc.label+"_role"]["attached"])
			names, err := root.ListRolePolicies(t.Context(), &iam.ListRolePoliciesInput{RoleName: out.Role.RoleName})
			if err != nil {
				t.Fatal(err)
			}
			policies := make(map[string]any)
			for _, name := range names.PolicyNames {
				policy, err := root.GetRolePolicy(t.Context(), &iam.GetRolePolicyInput{RoleName: out.Role.RoleName, PolicyName: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				document, err := url.QueryUnescape(aws.ToString(policy.PolicyDocument))
				if err != nil {
					t.Fatal(err)
				}
				var tree any
				if err := json.Unmarshal([]byte(document), &tree); err != nil {
					t.Fatal(err)
				}
				policies[name] = tree
			}
			assertTemplateJSON(t, policies, fixture[tc.label+"_role"]["inline"])
		})
	}
}

func TestRoleAcquisitionUnderlyingPermissionsAndIsolation(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("111111111111", "test", "")
	_, key, secret := c.user(t, "111111111111", "template-caller")
	caller := c.iam(key, secret, "")
	power := map[string][]string{"AWSServiceName": {"lambda.amazonaws.com"}}
	_, err := acquireTemplate(t, caller, powerRoleTemplate, "missing", power)
	assertAPIError(t, err, "AccessDenied")
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRoleTemplateVersion","Resource":%q},{"Effect":"Allow","Action":"iam:CreateRole","Resource":"arn:aws:iam::111111111111:role/allowed-*","Condition":{"ArnEquals":{"iam:RoleTemplateARN":%q}}}]}`, powerRoleTemplate, powerRoleTemplate)
	putUserPolicy(t, root, "template-caller", policy)
	_, err = acquireTemplate(t, caller, powerRoleTemplate, "allowed-no-attachment", power)
	assertAPIError(t, err, "AccessDenied")
	_, err = root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("allowed-no-attachment")})
	assertAPIError(t, err, "NoSuchEntity")
	policy = strings.Replace(policy, `"iam:CreateRole"`, `["iam:CreateRole","iam:AttachRolePolicy"]`, 1)
	putUserPolicy(t, root, "template-caller", policy)
	created, err := acquireTemplate(t, caller, powerRoleTemplate, "allowed-role", power)
	if err != nil {
		t.Fatal(err)
	}
	_, err = acquireTemplate(t, caller, powerRoleTemplate, "allowed-role", power)
	assertAPIError(t, err, "AccessDenied") // Creation permission does not grant reuse.
	putUserPolicy(t, root, "template-caller", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRoleTemplateVersion","Resource":%q,"Condition":{"ArnEquals":{"iam:RoleTemplateARN":%q}}},{"Effect":"Allow","Action":"iam:GetRole","Resource":%q,"Condition":{"ArnEquals":{"iam:RoleTemplateARN":%q}}}]}`, powerRoleTemplate, powerRoleTemplate, *created.Role.Arn, powerRoleTemplate))
	_, err = caller.GetRoleTemplateVersion(t.Context(), &iam.GetRoleTemplateVersionInput{TemplateArn: aws.String(powerRoleTemplate)})
	assertAPIError(t, err, "AccessDenied")
	_, err = acquireTemplate(t, caller, powerRoleTemplate, "allowed-role", power)
	assertAPIError(t, err, "AccessDenied") // Template reads omit RoleTemplateARN even during acquisition.
	putUserPolicy(t, root, "template-caller", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRoleTemplateVersion","Resource":%q},{"Effect":"Allow","Action":"iam:GetRole","Resource":%q,"Condition":{"ArnEquals":{"iam:RoleTemplateARN":%q}}}]}`, powerRoleTemplate, *created.Role.Arn, powerRoleTemplate))
	reused, err := acquireTemplate(t, caller, powerRoleTemplate, "allowed-role", power)
	if err != nil || *created.Role.RoleId != *reused.Role.RoleId {
		t.Fatalf("reuse under read permission: %v", err)
	}
	_, err = caller.GetRole(t.Context(), &iam.GetRoleInput{RoleName: created.Role.RoleName})
	assertAPIError(t, err, "AccessDenied")
	other, err := acquireTemplate(t, c.iam("222222222222", "test", ""), powerRoleTemplate, "allowed-role", power)
	if err != nil || *other.Role.RoleId == *created.Role.RoleId {
		t.Fatalf("account isolation: %v", err)
	}
	// Ordinary creation does not supply trusted template condition context.
	_, err = caller.CreateRole(context.Background(), &iam.CreateRoleInput{RoleName: aws.String("allowed-spoof"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
	assertAPIError(t, err, "AccessDenied")
}

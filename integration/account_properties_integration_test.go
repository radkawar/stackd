package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/smithy-go"
)

const roleManagerName = "AWSServiceRoleForIAMRoleManager"
const roleManagerService = "role-manager.iam.amazonaws.com"
const roleManagerARN = "arn:aws:iam::111111111111:role/aws-service-role/role-manager.iam.amazonaws.com/" + roleManagerName

func assertRoleManagerEnabled(t *testing.T, client *iam.Client, want string) {
	t.Helper()
	out, err := client.GetAccountProperties(t.Context(), &iam.GetAccountPropertiesInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Properties) != 1 || out.Properties["RoleManager/Enabled"] != want {
		t.Fatalf("account properties = %v, want RoleManager/Enabled=%s", out.Properties, want)
	}
}

func putRoleManager(client *iam.Client, t *testing.T, value string) error {
	t.Helper()
	_, err := client.PutAccountProperties(t.Context(), &iam.PutAccountPropertiesInput{Properties: map[string]string{"RoleManager/Enabled": value}})
	return err
}

func TestAccountPropertiesAWSValidationReplay(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("111111111111", "test", "")
	fixture := templateFixture(t, "account_properties.json")
	assertRoleManagerEnabled(t, root, "false")
	for _, tc := range []struct {
		label      string
		properties map[string]string
	}{
		{"empty", map[string]string{}},
		{"missing_separator", map[string]string{"RoleManager": "false"}},
		{"extra_separator", map[string]string{"RoleManager/Enabled/Other": "false"}},
		{"unknown_namespace", map[string]string{"StackdProbe/Enabled": "false"}},
		{"unknown_property", map[string]string{"RoleManager/StackdProbe": "false"}},
		{"mixed_namespaces", map[string]string{"RoleManager/Enabled": "false", "StackdProbe/Enabled": "false"}},
		{"unknown_property_same_namespace", map[string]string{"RoleManager/Enabled": "false", "RoleManager/StackdProbe": "false"}},
		{"uppercase_false", map[string]string{"RoleManager/Enabled": "FALSE"}},
		{"spaced_false", map[string]string{"RoleManager/Enabled": "false "}},
		{"zero", map[string]string{"RoleManager/Enabled": "0"}},
		{"false", map[string]string{"RoleManager/Enabled": "false"}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			_, err := root.PutAccountProperties(t.Context(), &iam.PutAccountPropertiesInput{Properties: tc.properties})
			if raw := fixture[tc.label]["error"]; raw != nil {
				var expected struct{ Code, Message string }
				if err := json.Unmarshal(raw, &expected); err != nil {
					t.Fatal(err)
				}
				assertAPIError(t, err, expected.Code)
				if expected.Code == "InvalidInput" {
					var apiErr smithy.APIError
					if !errors.As(err, &apiErr) || !strings.HasSuffix(expected.Message, apiErr.ErrorMessage()) {
						t.Fatalf("diagnostic = %v; captured %s", err, expected.Message)
					}
				}
			} else if err != nil {
				t.Fatal(err)
			}
			assertRoleManagerEnabled(t, root, "false")
		})
	}
}

func TestAccountPropertiesPermissionsAndServiceRole(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("111111111111", "test", "")
	_, key, secret := c.user(t, "111111111111", "property-operator")
	caller := c.iam(key, secret, "")
	_, err := caller.GetAccountProperties(t.Context(), &iam.GetAccountPropertiesInput{})
	assertAPIError(t, err, "AccessDenied")
	assertAPIError(t, putRoleManager(caller, t, "false"), "AccessDenied")
	propertyPermission := `{"Effect":"Allow","Action":["iam:GetAccountProperties","iam:PutAccountProperties"],"Resource":"*","Condition":{"ForAnyValue:StringEquals":{"iam:AccountPropertyNamespaces":"RoleManager"}}}`
	putUserPolicy(t, root, "property-operator", `{"Statement":[`+propertyPermission+`,{"Effect":"Deny","Action":"iam:CreateServiceLinkedRole","Resource":"*"}]}`)
	assertRoleManagerEnabled(t, caller, "false")
	assertAPIError(t, putRoleManager(caller, t, "true"), "AccessDenied")
	assertRoleManagerEnabled(t, root, "false")
	_, err = root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(roleManagerName)})
	assertAPIError(t, err, "NoSuchEntity")
	if err := putRoleManager(caller, t, "false"); err != nil {
		t.Fatal(err)
	}
	// The dependency uses the exact service role ARN and trusted service name.
	permission := fmt.Sprintf(`{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":%q,"Condition":{"StringEquals":{"iam:AWSServiceName":%q}}}`, roleManagerARN, roleManagerService)
	putUserPolicy(t, root, "property-operator", `{"Statement":[`+propertyPermission+`,`+strings.Replace(permission, "111111111111", "222222222222", 1)+`]}`)
	assertAPIError(t, putRoleManager(caller, t, "true"), "AccessDenied")
	putUserPolicy(t, root, "property-operator", `{"Statement":[`+propertyPermission+`,`+permission+`]}`)
	if err := putRoleManager(caller, t, "true"); err != nil {
		t.Fatal(err)
	}
	assertRoleManagerEnabled(t, caller, "true")
	first, err := root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(roleManagerName)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../testdata/aws/iam/role_manager_cleanup.json")
	if err != nil {
		t.Fatal(err)
	}
	var captured struct {
		Role     json.RawMessage
		Policies struct{ AttachedPolicies json.RawMessage }
	}
	if err := json.Unmarshal(data, &captured); err != nil {
		t.Fatal(err)
	}
	assertTemplateJSON(t, first.Role, captured.Role)
	attached, err := root.ListAttachedRolePolicies(t.Context(), &iam.ListAttachedRolePoliciesInput{RoleName: first.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	assertTemplateJSON(t, attached.AttachedPolicies, captured.Policies.AttachedPolicies)
	if err := putRoleManager(caller, t, "true"); err != nil {
		t.Fatal(err)
	}
	// AWS requires the dependency permission even for an existing owned role.
	putUserPolicy(t, root, "property-operator", `{"Statement":[`+propertyPermission+`]}`)
	assertAPIError(t, putRoleManager(caller, t, "true"), "AccessDenied")
	if err := putRoleManager(caller, t, "false"); err != nil {
		t.Fatal(err)
	}
	assertRoleManagerEnabled(t, caller, "false")
	retained, err := root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: first.Role.RoleName})
	if err != nil || aws.ToString(retained.Role.RoleId) != aws.ToString(first.Role.RoleId) || !retained.Role.CreateDate.Equal(*first.Role.CreateDate) {
		t.Fatalf("toggle changed role identity: %+v, %v", retained, err)
	}
	_, err = root.DeleteRole(t.Context(), &iam.DeleteRoleInput{RoleName: first.Role.RoleName})
	assertAPIError(t, err, "UnmodifiableEntity")
	_, err = root.CreateServiceLinkedRole(t.Context(), &iam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String(roleManagerService), CustomSuffix: aws.String("probe")})
	assertAPIError(t, err, "InvalidInput")
	assertRoleManagerEnabled(t, c.iam("222222222222", "test", ""), "false")
	_, err = c.iam("222222222222", "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: first.Role.RoleName})
	assertAPIError(t, err, "NoSuchEntity")
	// A different namespace never satisfies the condition on the property API.
	putUserPolicy(t, root, "property-operator", strings.Replace(`{"Statement":[`+propertyPermission+`]}`, `:"RoleManager"`, `:"Other"`, 1))
	_, err = caller.GetAccountProperties(t.Context(), &iam.GetAccountPropertiesInput{})
	assertAPIError(t, err, "AccessDenied")
}

func TestAccountPropertiesOrganizationControls(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	member := f.account(t, f.rootID, "role-manager-member")
	caller := f.cloud.iam(member, "test", "")
	policy := f.policy(t, "block-feature", `{"Statement":{"Effect":"Deny","Action":"iam:PutAccountProperties","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"iam:AccountPropertyNamespaces":"RoleManager"}}}}`, member)
	assertAPIError(t, putRoleManager(caller, t, "true"), "AccessDenied")
	assertRoleManagerEnabled(t, caller, "false")
	_, err := caller.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(roleManagerName)})
	assertAPIError(t, err, "NoSuchEntity")
	if _, err := f.org.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: &policy, TargetId: &member}); err != nil {
		t.Fatal(err)
	}
	dependency := f.policy(t, "block-service-role", `{"Statement":{"Effect":"Deny","Action":"iam:CreateServiceLinkedRole","Resource":"*","Condition":{"StringEquals":{"iam:AWSServiceName":"role-manager.iam.amazonaws.com"}}}}`, member)
	assertAPIError(t, putRoleManager(caller, t, "true"), "AccessDenied")
	assertRoleManagerEnabled(t, caller, "false")
	if _, err := f.org.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: &dependency, TargetId: &member}); err != nil {
		t.Fatal(err)
	}
	if err := putRoleManager(caller, t, "true"); err != nil {
		t.Fatal(err)
	}
	assertRoleManagerEnabled(t, caller, "true")
	assertRoleManagerEnabled(t, f.iam, "false")
}

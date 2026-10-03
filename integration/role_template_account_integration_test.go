package stackd_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestRoleTemplateResourceAccountAWSReplay(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/template_account.json")
	if err != nil {
		t.Fatal(err)
	}
	const account = "111111111111"
	data = bytes.ReplaceAll(data, []byte("<caller-account>"), []byte(account))
	var fixture struct {
		Observations []struct {
			Case           string
			Condition      map[string]json.RawMessage
			TemplateARN    string `json:"template_arn"`
			Acquire        bool
			RequestedMinor *int32 `json:"requested_minor"`
			Code           string
			HTTPStatus     int   `json:"http_status"`
			MinorVersion   int32 `json:"minor_version"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	c := newCloudClients(t)
	root := c.iam(account, "test", "")
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String("template-actor"),
		AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	const target = "template-target"
	const targetARN = "arn:aws:iam::111111111111:role/" + target
	permission := func(condition map[string]json.RawMessage) string {
		t.Helper()
		read := map[string]any{"Effect": "Allow", "Action": "iam:GetRoleTemplateVersion", "Resource": "*"}
		if len(condition) != 0 {
			read["Condition"] = condition
		}
		downstream := map[string]any{
			"Effect": "Allow", "Action": []string{"iam:GetRole", "iam:CreateRole", "iam:AttachRolePolicy"}, "Resource": targetARN,
			"Condition": map[string]any{"StringEquals": map[string]string{"aws:ResourceAccount": account}},
		}
		document, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{read, downstream}})
		if err != nil {
			t.Fatal(err)
		}
		return string(document)
	}
	if _, err := root.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("TemplateAccount"), PolicyDocument: aws.String(permission(nil))}); err != nil {
		t.Fatal(err)
	}
	roleID := ""
	for _, row := range fixture.Observations {
		operation := "read"
		if row.Acquire {
			operation = "acquire"
		}
		t.Run(row.Case+"/"+row.TemplateARN+"/"+operation, func(t *testing.T) {
			session, err := c.sts(account, "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{
				RoleArn: role.Role.Arn, RoleSessionName: aws.String("template-account"), DurationSeconds: aws.Int32(900),
				Policy: aws.String(permission(row.Condition)),
			})
			if err != nil {
				t.Fatal(err)
			}
			credentials := session.Credentials
			client := c.iam(*credentials.AccessKeyId, *credentials.SecretAccessKey, *credentials.SessionToken)
			if row.Acquire {
				out, acquireErr := acquireTemplate(t, client, row.TemplateARN, target, map[string][]string{"AWSServiceName": {"lambda.amazonaws.com"}})
				err = acquireErr
				if err == nil {
					if aws.ToString(out.Role.Arn) != targetARN || aws.ToString(out.Role.RoleName) != target {
						t.Fatalf("unexpected acquired role: %+v", out.Role)
					}
					if roleID != "" && roleID != aws.ToString(out.Role.RoleId) {
						t.Fatal("repeated acquisition changed the role identity")
					}
					roleID = aws.ToString(out.Role.RoleId)
				}
			} else {
				out, readErr := client.GetRoleTemplateVersion(t.Context(), &iam.GetRoleTemplateVersionInput{TemplateArn: &row.TemplateARN, MinorVersion: row.RequestedMinor})
				err = readErr
				if err == nil && (aws.ToString(out.RoleTemplateVersion.TemplateArn) != row.TemplateARN || aws.ToInt32(out.RoleTemplateVersion.MinorVersion) != row.MinorVersion) {
					t.Fatalf("template differs from AWS: %+v", out.RoleTemplateVersion)
				}
			}
			if row.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var api interface{ ErrorCode() string }
				var response interface{ HTTPStatusCode() int }
				if !errors.As(err, &api) || api.ErrorCode() != row.Code || !errors.As(err, &response) || response.HTTPStatusCode() != row.HTTPStatus {
					t.Fatalf("error = %v; AWS code/status = %s/%d", err, row.Code, row.HTTPStatus)
				}
			}
		})
	}
	attached, err := root.ListAttachedRolePolicies(t.Context(), &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(target)})
	if err != nil || len(attached.AttachedPolicies) != 1 || aws.ToString(attached.AttachedPolicies[0].PolicyArn) != "arn:aws:iam::aws:policy/PowerUserAccess" {
		t.Fatalf("acquisition did not retain the template's actual permission attachment: %+v %v", attached, err)
	}
}

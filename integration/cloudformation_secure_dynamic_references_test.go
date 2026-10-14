package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"stackd"
	"stackd/clock"
	cfnstore "stackd/storage/cloudformation"
)

// This fixture delays the real, committed resolution intent before its first
// native effect. It does not intercept secret reads or fabricate owner results.
type secureCFNCheckpointRepository struct {
	cfnstore.Repository
	mode     *atomic.Int32
	selected chan string
	source   *clock.Manual
}

type secureCFNCheckpointTransaction struct {
	cfnstore.Transaction
	owner *secureCFNCheckpointRepository
}

func (r *secureCFNCheckpointRepository) Update(ctx context.Context, fn func(cfnstore.Transaction) error) error {
	return r.Repository.Update(ctx, func(tx cfnstore.Transaction) error {
		return fn(&secureCFNCheckpointTransaction{Transaction: tx, owner: r})
	})
}

func (tx *secureCFNCheckpointTransaction) PutOperation(op cfnstore.OperationRecord) error {
	mode := tx.owner.mode.Load()
	checkpoint := false
	if op.Cursor >= 0 && op.Cursor < len(op.Steps) {
		step := op.Steps[op.Cursor]
		switch mode {
		case 1:
			checkpoint = op.Phase == "APPLY" && step.State == "PENDING" && len(step.After.DynamicReferences) > 0
		case 2:
			checkpoint = op.Phase == "ROLLBACK"
		case 3:
			if op.Phase == "ROLLBACK" {
				for _, pin := range step.Before.DynamicReferences {
					checkpoint = checkpoint || pin.Service == "secretsmanager"
				}
				for _, pin := range step.Restore.DynamicReferences {
					checkpoint = checkpoint || pin.Service == "secretsmanager"
				}
			}
		case 4:
			if op.Phase == "APPLY" {
				for _, completed := range op.Steps {
					checkpoint = checkpoint || completed.State == "SUCCEEDED" && len(completed.After.RedactedAttributes) > 0
				}
			}
		}
	}
	checkpoint = checkpoint && tx.owner.mode.CompareAndSwap(mode, 0)
	if checkpoint {
		op.Due = tx.owner.source.Now().Add(time.Hour)
	}
	if err := tx.Transaction.PutOperation(op); err != nil {
		return err
	}
	if checkpoint {
		tx.owner.selected <- op.ID
	}
	return nil
}

func TestCloudFormationSecureDynamicReferencesNativePasswordReplay(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"ssm-secure", "secret-string", "secret-json-key", "secret-stage", "secret-version"} {
			for _, revocation := range []string{"none", "read", "decrypt"} {
				t.Run(backend+"/"+kind+"/"+revocation, func(t *testing.T) {
					source := clock.NewManual(time.Date(2031, 7, 8, 9, 10, 11, 0, time.UTC))
					var repository cfnstore.Repository
					var mode atomic.Int32
					mode.Store(1)
					selected := make(chan string, 1)
					c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
						repository = config.Storage.CloudFormation
						config.Storage.CloudFormation = &secureCFNCheckpointRepository{Repository: repository, mode: &mode, selected: selected, source: source}
						return startPublicCloud(t, config)
					})
					identity := c.iam("test", "test", "")
					keyClient := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
					key, err := keyClient.CreateKey(t.Context(), &kms.CreateKeyInput{})
					if err != nil {
						t.Fatal(err)
					}
					parameterClient := func() *ssm.Client {
						return ssm.New(ssm.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
					}
					secretClient := func() *secretsmanager.Client {
						return secretsmanager.New(secretsmanager.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
					}
					const first = "CloudSecret-First!72"
					const second = "CloudSecret-Second!83"
					const parameterName = "/cfn-secure/password"
					const secretName = "cfn-secure-password"
					var reference, selectedVersion string
					put := func(value string, create bool) {
						t.Helper()
						if kind == "ssm-secure" {
							_, err := parameterClient().PutParameter(t.Context(), &ssm.PutParameterInput{Name: aws.String(parameterName), Type: ssmtypes.ParameterTypeSecureString, Value: aws.String(value), KeyId: key.KeyMetadata.KeyId, Overwrite: aws.Bool(!create)})
							if err != nil {
								t.Fatal(err)
							}
							return
						}
						if kind == "secret-json-key" {
							value = fmt.Sprintf(`{"password":%q,"unrelated":"not-a-password"}`, value)
						}
						if create {
							out, err := secretClient().CreateSecret(t.Context(), &secretsmanager.CreateSecretInput{Name: aws.String(secretName), SecretString: aws.String(value), KmsKeyId: key.KeyMetadata.KeyId})
							if err != nil {
								t.Fatal(err)
							}
							selectedVersion = aws.ToString(out.VersionId)
						} else {
							if _, err := secretClient().PutSecretValue(t.Context(), &secretsmanager.PutSecretValueInput{SecretId: aws.String(secretName), SecretString: aws.String(value)}); err != nil {
								t.Fatal(err)
							}
						}
					}
					put(first, true)
					switch kind {
					case "ssm-secure":
						reference = "{{resolve:ssm-secure:" + parameterName + "}}"
					case "secret-string":
						reference = "{{resolve:secretsmanager:" + secretName + "}}"
					case "secret-json-key":
						reference = "{{resolve:secretsmanager:" + secretName + ":SecretString:password}}"
					case "secret-stage":
						reference = "{{resolve:secretsmanager:" + secretName + ":SecretString::AWSPREVIOUS}}"
						put(second, false)
					case "secret-version":
						reference = "{{resolve:secretsmanager:" + secretName + ":SecretString:::" + selectedVersion + "}}"
					}
					role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("secure-cfn-role"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudformation.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := identity.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("deployment"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*","ssm:GetParameters","secretsmanager:GetSecretValue","kms:Decrypt"],"Resource":"*"}]}`)}); err != nil {
						t.Fatal(err)
					}
					template := func(reset bool, fail bool) string {
						resources := map[string]any{"User": map[string]any{"Type": "AWS::IAM::User", "Properties": map[string]any{"UserName": "secure-consumer", "LoginProfile": map[string]any{"Password": reference, "PasswordResetRequired": reset}}}}
						if fail {
							resources["Failure"] = map[string]any{"Type": "AWS::IAM::User", "DependsOn": "User", "Properties": map[string]any{"UserName": "already-exists"}}
						}
						body, err := json.Marshal(map[string]any{"Resources": resources})
						if err != nil {
							t.Fatal(err)
						}
						return string(body)
					}
					body := template(false, false)
					root := cloudFormationClient(c, "us-east-1", "test", "test")
					created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("secure-reference"), TemplateBody: aws.String(body), RoleARN: role.Role.Arn, Capabilities: []cfntypes.Capability{cfntypes.CapabilityCapabilityNamedIam}, DisableRollback: aws.Bool(true)})
					if err != nil {
						t.Fatal(err)
					}
					select {
					case <-selected:
					case <-time.After(10 * time.Second):
						t.Fatal("real resolution intent was not committed")
					}
					if err := repository.View(t.Context(), func(reader cfnstore.Reader) error {
						stack, err := reader.Stack(aws.ToString(created.StackId))
						if err != nil {
							return err
						}
						op, err := reader.Operation(stack.OperationID)
						if err != nil {
							return err
						}
						pin := op.Steps[op.Cursor].After.DynamicReferences[reference]
						if kind == "ssm-secure" {
							if pin.Service != "ssm-secure" || pin.ParameterVersion != 1 || pin.SecretVersionID != "" {
								t.Fatalf("wrong secure parameter pin: %#v", pin)
							}
						} else if pin.Service != "secretsmanager" || pin.SecretVersionID != selectedVersion || pin.ParameterVersion != 0 {
							t.Fatalf("wrong secret pin: %#v", pin)
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					put(second, false)
					if revocation != "none" {
						action := "kms:Decrypt"
						if revocation == "read" {
							action = "secretsmanager:GetSecretValue"
							if kind == "ssm-secure" {
								action = "ssm:GetParameters"
							}
						}
						policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":%q,"Resource":"*"}]}`, action)
						if _, err := identity.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("revoked"), PolicyDocument: aws.String(policy)}); err != nil {
							t.Fatal(err)
						}
					}
					c = reopen()
					root = cloudFormationClient(c, "us-east-1", "test", "test")
					advanceClock(t, source, time.Hour)
					wanted := cfntypes.StackStatusCreateComplete
					if revocation != "none" {
						wanted = cfntypes.StackStatusCreateFailed
					}
					stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), wanted)
					secureCFNRetainedState(t, repository, root, aws.ToString(created.StackId), []string{first, second})
					if revocation != "none" {
						if !strings.Contains(aws.ToString(stack.StackStatusReason), "AccessDenied") {
							t.Fatalf("revocation did not deny current authorization: %s", aws.ToString(stack.StackStatusReason))
						}
						_, err := c.iam("test", "test", "").GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("secure-consumer")})
						assertAPIError(t, err, "NoSuchEntity")
						return
					}
					identity = c.iam("test", "test", "")
					access, err := identity.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: aws.String("secure-consumer")})
					if err != nil {
						t.Fatal(err)
					}
					putUserPolicy(t, identity, "secure-consumer", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ChangePassword","Resource":"*"}]}`)
					consumer := c.iam(aws.ToString(access.AccessKey.AccessKeyId), aws.ToString(access.AccessKey.SecretAccessKey), "")
					if _, err := consumer.ChangePassword(t.Context(), &iam.ChangePasswordInput{OldPassword: aws.String(second), NewPassword: aws.String("Temporary-Password!94")}); err == nil {
						t.Fatal("native password drifted to rotated, unpinned version")
					}
					if _, err := consumer.ChangePassword(t.Context(), &iam.ChangePasswordInput{OldPassword: aws.String(first), NewPassword: aws.String("Temporary-Password!94")}); err != nil {
						t.Fatalf("native IAM did not consume decrypted pinned password: %v", err)
					}
					unchanged := strings.Replace(body, `{"Resources":`, `{"Description":"unchanged secure resource","Resources":`, 1)
					if _, err := root.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(unchanged), Capabilities: []cfntypes.Capability{cfntypes.CapabilityCapabilityNamedIam}}); err != nil {
						t.Fatal(err)
					}
					cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
					if _, err := consumer.ChangePassword(t.Context(), &iam.ChangePasswordInput{OldPassword: aws.String("Temporary-Password!94"), NewPassword: aws.String("Unchanged-Verified!16")}); err != nil {
						t.Fatalf("unchanged dynamic resource refreshed a rotated secret: %v", err)
					}
					if _, err := identity.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("already-exists")}); err != nil {
						t.Fatal(err)
					}
					mode.Store(2)
					if _, err := root.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(template(true, true)), Capabilities: []cfntypes.Capability{cfntypes.CapabilityCapabilityNamedIam}}); err != nil {
						t.Fatal(err)
					}
					select {
					case <-selected:
					case <-time.After(10 * time.Second):
						t.Fatal("native update failure did not commit rollback intent")
					}
					const third = "CloudSecret-Third!27"
					const fourth = "CloudSecret-Fourth!38"
					const fifth = "CloudSecret-Fifth!49"
					put(third, false)
					put(fourth, false)
					c = reopen()
					root = cloudFormationClient(c, "us-east-1", "test", "test")
					if kind != "ssm-secure" {
						mode.Store(3)
					}
					advanceClock(t, source, time.Hour)
					if kind != "ssm-secure" {
						select {
						case <-selected:
						case <-time.After(10 * time.Second):
							t.Fatal("rollback did not select its template's current secret version")
						}
						// Moving the selector after rollback's fresh selection must
						// not change replay of that accepted rollback intent.
						put(fifth, false)
						c = reopen()
						root = cloudFormationClient(c, "us-east-1", "test", "test")
						advanceClock(t, source, time.Hour)
					}
					cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateRollbackComplete)
					consumer = c.iam(aws.ToString(access.AccessKey.AccessKeyId), aws.ToString(access.AccessKey.SecretAccessKey), "")
					rollbackPassword := fourth
					switch kind {
					case "ssm-secure", "secret-version":
						rollbackPassword = first
					case "secret-stage":
						rollbackPassword = third
					}
					if rollbackPassword != first {
						if _, err := consumer.ChangePassword(t.Context(), &iam.ChangePasswordInput{OldPassword: aws.String(first), NewPassword: aws.String("Rollback-Verified!05")}); err == nil {
							t.Fatal("rollback replayed an inferred version from a previous deployment")
						}
					}
					if _, err := consumer.ChangePassword(t.Context(), &iam.ChangePasswordInput{OldPassword: aws.String(rollbackPassword), NewPassword: aws.String("Rollback-Verified!05")}); err != nil {
						t.Fatalf("rollback did not consume its freshly selected template selector: %v", err)
					}
					secureCFNRetainedState(t, repository, root, aws.ToString(created.StackId), []string{first, second, third, fourth, fifth, "Temporary-Password!94", "Unchanged-Verified!16", "Rollback-Verified!05"})
				})
			}
		}
	}
}

func secureCFNRetainedState(t *testing.T, repository cfnstore.Repository, client *cloudformation.Client, id string, secrets []string) {
	t.Helper()
	var values []any
	if err := repository.View(t.Context(), func(reader cfnstore.Reader) error {
		stack, err := reader.Stack(id)
		if err != nil {
			return err
		}
		op, err := reader.Operation(stack.OperationID)
		if err != nil {
			return err
		}
		resources, err := reader.Resources(id)
		if err != nil {
			return err
		}
		events, err := reader.Events(id)
		if err != nil {
			return err
		}
		check := func(resource cfnstore.ResourceRecord) {
			for _, pin := range resource.DynamicReferences {
				if pin.Service == "secretsmanager" {
					t.Fatal("CFN retained an inferred prior-deployment secret version")
				}
			}
		}
		for _, resource := range resources {
			check(resource)
		}
		if op.Phase == "DONE" {
			for _, step := range op.Steps {
				check(step.Before)
				check(step.After)
				check(step.Restore)
			}
		}
		values = append(values, stack, op, resources, events)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	template, err := client.GetTemplate(t.Context(), &cloudformation.GetTemplateInput{StackName: aws.String(id)})
	if err != nil {
		t.Fatal(err)
	}
	events, err := client.DescribeStackEvents(t.Context(), &cloudformation.DescribeStackEventsInput{StackName: aws.String(id)})
	if err != nil {
		t.Fatal(err)
	}
	values = append(values, template, events)
	body, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(body), secret) {
			t.Fatal("resolved plaintext leaked into CFN retained state or SDK history")
		}
	}
}

// Expected strings are the actual native AWS SSM String consumer observations
// from cloudformation_probe.py --secure-dynamic-references, 2026-10-14.
func TestCloudFormationSecretJSONKeyNativeCoercion(t *testing.T) {
	const document = `{"string": "public-two", "number": 42, "boolean": true, "object": {"nested": "public"}, "array": [1, "public"], "null": null}`
	cases := []struct{ logicalID, key, value string }{
		{"String", "string", "public-two"},
		{"Number", "number", "42"},
		{"Boolean", "boolean", "true"},
		{"Object", "object", `{"nested":"public"}`},
		{"Array", "array", `[1,"public"]`},
		{"Null", "null", "null"},
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 7, 8, 9, 10, 11, 0, time.UTC))
			var repository cfnstore.Repository
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				repository = config.Storage.CloudFormation
				return startPublicCloud(t, config)
			})
			secrets := secretsmanager.New(secretsmanager.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			if _, err := secrets.CreateSecret(t.Context(), &secretsmanager.CreateSecretInput{Name: aws.String("json-coercion-public"), SecretString: aws.String(document)}); err != nil {
				t.Fatal(err)
			}
			resources := map[string]any{}
			references := map[string]string{}
			for i, tc := range cases {
				reference := "{{resolve:secretsmanager:json-coercion-public:SecretString:" + tc.key + "}}"
				if tc.key == "string" {
					reference = "{{resolve:secretsmanager:json-coercion-public::string}}"
				}
				references[tc.logicalID] = reference
				resources[tc.logicalID] = map[string]any{"Type": "AWS::SSM::Parameter", "Properties": map[string]any{"Name": fmt.Sprintf("json-key-%d", i), "Type": "String", "Value": reference}}
			}
			body, err := json.Marshal(map[string]any{"Resources": resources})
			if err != nil {
				t.Fatal(err)
			}
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("json-key-coercion"), TemplateBody: aws.String(string(body))})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			c = reopen()
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			parameters := ssm.New(ssm.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			for i, tc := range cases {
				value, err := parameters.GetParameter(t.Context(), &ssm.GetParameterInput{Name: aws.String(fmt.Sprintf("json-key-%d", i))})
				if err != nil || value.Parameter == nil || aws.ToString(value.Parameter.Value) != tc.value {
					t.Fatalf("native SSM consumer differs from captured %s coercion: %+v %v", tc.key, value, err)
				}
			}
			if err := repository.View(t.Context(), func(reader cfnstore.Reader) error {
				rows, err := reader.Resources(aws.ToString(created.StackId))
				if err != nil {
					return err
				}
				for _, row := range rows {
					if row.Properties["Value"] != references[row.LogicalID] || row.Attributes["Value"] != "****" {
						t.Fatalf("CFN retained a coerced secret instead of its reference/mask: %#v", row)
					}
					if !row.RedactedAttributes["Value"] || row.RedactedAttributes["Arn"] {
						t.Fatalf("CFN lost typed secret-attribute metadata: %#v", row)
					}
					for _, pin := range row.DynamicReferences {
						if pin.Service == "secretsmanager" {
							t.Fatal("published coercion resource retained inferred secret version")
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			template, err := root.GetTemplate(t.Context(), &cloudformation.GetTemplateInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(template.TemplateBody) != string(body) {
				t.Fatal("native secret consumption rewrote the original template")
			}
			events, err := root.DescribeStackEvents(t.Context(), &cloudformation.DescribeStackEventsInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events.StackEvents {
				reference, exists := references[aws.ToString(event.LogicalResourceId)]
				if !exists || event.ResourceProperties == nil {
					continue
				}
				var properties map[string]any
				if err := json.Unmarshal([]byte(aws.ToString(event.ResourceProperties)), &properties); err != nil {
					t.Fatal(err)
				}
				if properties["Value"] != reference {
					t.Fatal("native secret consumption rewrote retained event properties")
				}
			}
			// A missing key is an actual owner-resolution failure, not an empty
			// string or a successfully fabricated parameter.
			missingBody := `{"Resources":{"Missing":{"Type":"AWS::SSM::Parameter","Properties":{"Name":"json-key-missing","Type":"String","Value":"{{resolve:secretsmanager:json-coercion-public:SecretString:missing}}"}}}}`
			missing, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("json-key-missing"), TemplateBody: aws.String(missingBody)})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(missing.StackId), cfntypes.StackStatusRollbackComplete)
			_, err = parameters.GetParameter(t.Context(), &ssm.GetParameterInput{Name: aws.String("json-key-missing")})
			assertAPIError(t, err, "ParameterNotFound")
			failedEvents, err := root.DescribeStackEvents(t.Context(), &cloudformation.DescribeStackEventsInput{StackName: missing.StackId})
			if err != nil {
				t.Fatal(err)
			}
			foundReason := false
			for _, event := range failedEvents.StackEvents {
				foundReason = foundReason || strings.Contains(aws.ToString(event.ResourceStatusReason), "Could not find a value associated with JSONKey in SecretString")
			}
			if !foundReason {
				t.Fatal("missing JSON key did not report the captured native diagnostic")
			}
		})
	}
}

func TestCloudFormationSecureResultAttributesRejectConsumption(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, consumer := range []string{"source-only", "downstream", "output"} {
			t.Run(backend+"/"+consumer, func(t *testing.T) {
				source := clock.NewManual(time.Date(2031, 7, 8, 9, 10, 11, 0, time.UTC))
				var repository cfnstore.Repository
				var mode atomic.Int32
				mode.Store(4)
				selected := make(chan string, 1)
				c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					repository = config.Storage.CloudFormation
					config.Storage.CloudFormation = &secureCFNCheckpointRepository{Repository: repository, mode: &mode, selected: selected, source: source}
					return startPublicCloud(t, config)
				})
				const plaintext = "Secure-Attribute!762"
				secrets := secretsmanager.New(secretsmanager.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				if _, err := secrets.CreateSecret(t.Context(), &secretsmanager.CreateSecretInput{Name: aws.String("secure-result-secret"), SecretString: aws.String(plaintext)}); err != nil {
					t.Fatal(err)
				}
				resources := map[string]any{
					"Source": map[string]any{"Type": "AWS::SSM::Parameter", "Properties": map[string]any{"Name": "secure-result-source", "Type": "String", "Value": "{{resolve:secretsmanager:secure-result-secret}}"}},
					"Safe":   map[string]any{"Type": "AWS::SSM::Parameter", "Properties": map[string]any{"Name": "secure-result-safe", "Type": "String", "Value": map[string]any{"Fn::GetAtt": []any{"Source", "Arn"}}}},
				}
				outputs := map[string]any{"SafeArn": map[string]any{"Value": map[string]any{"Fn::GetAtt": []any{"Source", "Arn"}}}}
				switch consumer {
				case "downstream":
					resources["Rejected"] = map[string]any{"Type": "AWS::SSM::Parameter", "DependsOn": "Safe", "Properties": map[string]any{"Name": "secure-result-rejected", "Type": "String", "Value": map[string]any{"Fn::GetAtt": []any{"Source", "Value"}}}}
				case "output":
					outputs["Rejected"] = map[string]any{"Value": map[string]any{"Fn::GetAtt": []any{"Source", "Value"}}}
				}
				body, err := json.Marshal(map[string]any{"Resources": resources, "Outputs": outputs})
				if err != nil {
					t.Fatal(err)
				}
				root := cloudFormationClient(c, "us-east-1", "test", "test")
				created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("secure-result-attributes"), TemplateBody: aws.String(string(body)), DisableRollback: aws.Bool(true)})
				if err != nil {
					t.Fatal(err)
				}
				select {
				case <-selected:
				case <-time.After(10 * time.Second):
					t.Fatal("secure source result was not retained before consumer admission")
				}
				checkMetadata := func() {
					t.Helper()
					if err := repository.View(t.Context(), func(reader cfnstore.Reader) error {
						stack, err := reader.Stack(aws.ToString(created.StackId))
						if err != nil {
							return err
						}
						op, err := reader.Operation(stack.OperationID)
						if err != nil {
							return err
						}
						rows, err := reader.Resources(stack.ID)
						if err != nil {
							return err
						}
						foundResource, foundStep := false, false
						for _, row := range rows {
							if row.LogicalID == "Source" && row.Current {
								foundResource = true
								if row.Attributes["Value"] != "****" || !row.RedactedAttributes["Value"] || row.RedactedAttributes["Arn"] {
									t.Fatalf("source result lost protected attribute metadata: %#v", row)
								}
							}
						}
						for _, step := range op.Steps {
							if step.LogicalID == "Source" {
								foundStep = true
								if step.After.Attributes["Value"] != "****" || !step.After.RedactedAttributes["Value"] || step.After.RedactedAttributes["Arn"] {
									t.Fatalf("operation result lost protected attribute metadata: %#v", step)
								}
							}
						}
						if !foundResource || !foundStep {
							t.Fatal("completed source result was not retained")
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}
				checkMetadata()
				secureCFNRetainedState(t, repository, root, aws.ToString(created.StackId), []string{plaintext})
				c = reopen()
				root = cloudFormationClient(c, "us-east-1", "test", "test")
				checkMetadata()
				advanceClock(t, source, time.Hour)
				wanted := cfntypes.StackStatusCreateFailed
				if consumer == "source-only" {
					wanted = cfntypes.StackStatusCreateComplete
				}
				result := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), wanted)
				if consumer != "source-only" && (!strings.Contains(aws.ToString(result.StackStatusReason), "NotImplementedException") || !strings.Contains(aws.ToString(result.StackStatusReason), "stackd cannot consume secure resource attribute Source.Value")) {
					t.Fatalf("secret attribute was not explicitly rejected: %s", aws.ToString(result.StackStatusReason))
				}
				parameters := ssm.New(ssm.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				native, err := parameters.GetParameter(t.Context(), &ssm.GetParameterInput{Name: aws.String("secure-result-source")})
				if err != nil || native.Parameter == nil || aws.ToString(native.Parameter.Value) != plaintext {
					t.Fatalf("source-only native consumption changed: %+v %v", native, err)
				}
				arn := aws.ToString(native.Parameter.ARN)
				safe, err := parameters.GetParameter(t.Context(), &ssm.GetParameterInput{Name: aws.String("secure-result-safe")})
				if err != nil || safe.Parameter == nil || aws.ToString(safe.Parameter.Value) != arn {
					t.Fatalf("safe attribute did not reach the native consumer: %+v %v", safe, err)
				}
				if consumer == "downstream" {
					_, err := parameters.GetParameter(t.Context(), &ssm.GetParameterInput{Name: aws.String("secure-result-rejected")})
					assertAPIError(t, err, "ParameterNotFound")
				}
				foundSafeOutput := false
				for _, output := range result.Outputs {
					if aws.ToString(output.OutputKey) == "Rejected" {
						t.Fatal("secure output pretended to resolve the masked value")
					}
					if aws.ToString(output.OutputKey) == "SafeArn" {
						foundSafeOutput = aws.ToString(output.OutputValue) == arn
					}
				}
				if consumer == "source-only" && !foundSafeOutput {
					t.Fatal("safe attribute output did not resolve")
				}
				c = reopen()
				root = cloudFormationClient(c, "us-east-1", "test", "test")
				retained, err := root.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: created.StackId})
				if err != nil || len(retained.Stacks) != 1 || retained.Stacks[0].StackStatus != wanted {
					t.Fatalf("secure attribute result did not survive restart: %+v %v", retained, err)
				}
				if consumer != "source-only" && !strings.Contains(aws.ToString(retained.Stacks[0].StackStatusReason), "NotImplementedException") {
					t.Fatal("explicit secure attribute failure was lost on restart")
				}
				checkMetadata()
				secureCFNRetainedState(t, repository, root, aws.ToString(created.StackId), []string{plaintext})
			})
		}
	}
}

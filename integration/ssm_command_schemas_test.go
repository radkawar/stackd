package stackd_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"stackd"
)

func commandSchemaContent(schema, format, message string) string {
	if format == "YAML" {
		base := fmt.Sprintf("schemaVersion: '%s'\ndescription: %s\nparameters:\n  message:\n    type: String\n    default: hello\n    allowedPattern: '^[a-z]+$'\n    minChars: 2\n    maxChars: 12\n  executionTimeout:\n    type: String\n    default: '17'\n", schema, message)
		if schema == "1.2" {
			return base + "runtimeConfig:\n  aws:runShellScript:\n    properties:\n      - id: shell\n        runCommand: ['printf {{ message }}']\n        timeoutSeconds: '{{ executionTimeout }}'\n"
		}
		return base + "mainSteps:\n  - action: aws:runShellScript\n    name: shell\n    inputs:\n      runCommand: ['printf {{ message }}']\n      timeoutSeconds: '{{ executionTimeout }}'\n"
	}
	base := fmt.Sprintf(`{"schemaVersion":%q,"description":%q,"parameters":{"message":{"type":"String","default":"hello","allowedPattern":"^[a-z]+$","minChars":2,"maxChars":12},"executionTimeout":{"type":"String","default":"17"}},`, schema, message)
	if schema == "1.2" {
		return base + `"runtimeConfig":{"aws:runShellScript":{"properties":[{"id":"shell","runCommand":["printf {{ message }}"],"timeoutSeconds":"{{ executionTimeout }}"}]}}}`
	}
	return base + `"mainSteps":[{"action":"aws:runShellScript","name":"shell","inputs":{"runCommand":["printf {{ message }}"],"timeoutSeconds":"{{ executionTimeout }}"}}]}`
}

func TestSSMCommandSchemasLifecycleAuthorityAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			client := cl.ssm("us-east-1", account, "test")
			drain := func() {
				t.Helper()
				if _, err := cl.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
					t.Fatal(err)
				}
			}
			for _, schema := range []string{"1.2", "2.0", "2.2"} {
				for _, format := range []string{"JSON", "YAML"} {
					name := "Schema" + strings.ReplaceAll(schema, ".", "") + format
					content := commandSchemaContent(schema, format, "first")
					made, err := client.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new(name), Content: new(content), DocumentType: ssmtypes.DocumentTypeCommand, DocumentFormat: ssmtypes.DocumentFormat(format)})
					if err != nil {
						t.Fatal(err)
					}
					if aws.ToString(made.DocumentDescription.SchemaVersion) != schema || aws.ToString(made.DocumentDescription.Hash) != fmt.Sprintf("%x", sha256.Sum256([]byte(content))) {
						t.Fatalf("source metadata: %+v", made)
					}
					drain()
					send := func(parameters map[string][]string) (*ssm.SendCommandOutput, error) {
						return client.SendCommand(ctx, &ssm.SendCommandInput{DocumentName: new(name), DocumentVersion: new("1"), TimeoutSeconds: new(int32(30)), Targets: []ssmtypes.Target{{Key: new("tag:schema-test"), Values: []string{"absent"}}}, Parameters: parameters})
					}
					for _, row := range []struct {
						parameters map[string][]string
						expiry     time.Duration
					}{{nil, 3630 * time.Second}, {map[string][]string{"message": {"custom"}, "executionTimeout": {"31"}}, 61 * time.Second}, {map[string][]string{"executionTimeout": {"0"}}, 3630 * time.Second}} {
						sent, err := send(row.parameters)
						if err != nil {
							t.Fatal(err)
						}
						if sent.Command.ExpiresAfter.Sub(*sent.Command.RequestedDateTime) != row.expiry || sent.Command.TargetCount != 0 {
							t.Fatalf("schema %s expiry/target accounting: %+v", schema, sent.Command)
						}
					}
					_, err = send(map[string][]string{"message": {"1"}})
					assertAPIError(t, err, "InvalidParameters")
					_, err = send(map[string][]string{"undeclared": {"x"}})
					assertAPIError(t, err, "InvalidParameters")
					updated := commandSchemaContent(schema, format, "second")
					_, err = client.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new(name), DocumentVersion: new("$LATEST"), Content: new(updated), DocumentFormat: ssmtypes.DocumentFormat(format)})
					if schema == "1.2" {
						assertAPIError(t, err, "InvalidDocumentSchemaVersion")
					} else {
						if err != nil {
							t.Fatal(err)
						}
						drain()
						_, err = client.UpdateDocumentDefaultVersion(ctx, &ssm.UpdateDocumentDefaultVersionInput{Name: new(name), DocumentVersion: new("2")})
						if err != nil {
							t.Fatal(err)
						}
					}
					other := commandSchemaContent("1.2", "JSON", "downgrade")
					if schema == "1.2" {
						other = commandSchemaContent("2.2", "JSON", "upgrade")
					}
					_, err = client.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new(name), DocumentVersion: new("$LATEST"), Content: new(other)})
					assertAPIError(t, err, "InvalidDocumentSchemaVersion")
					cl = reopen()
					client = cl.ssm("us-east-1", account, "test")
					got, err := client.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(name), DocumentVersion: new("1"), DocumentFormat: ssmtypes.DocumentFormat(format)})
					if err != nil || aws.ToString(got.Content) != content {
						t.Fatalf("immutable original after restart: %+v %v", got, err)
					}
					latest, err := client.DescribeDocument(ctx, &ssm.DescribeDocumentInput{Name: new(name), DocumentVersion: new("$DEFAULT")})
					want := "2"
					if schema == "1.2" {
						want = "1"
					}
					if err != nil || aws.ToString(latest.Document.DocumentVersion) != want || aws.ToString(latest.Document.SchemaVersion) != schema {
						t.Fatalf("default retained: %+v %v", latest, err)
					}
					_, err = cl.ssm("us-west-2", account, "test").GetDocument(ctx, &ssm.GetDocumentInput{Name: new(name)})
					assertAPIError(t, err, "InvalidDocument")
					_, err = cl.ssm("us-east-1", "444455556666", "test").GetDocument(ctx, &ssm.GetDocumentInput{Name: new(name)})
					assertAPIError(t, err, "InvalidDocument")
				}
			}
			_, key, secret := cl.user(t, account, "schema-reader")
			arn := "arn:aws:ssm:us-east-1:" + account + ":document/Schema12JSON"
			putUserPolicy(t, cl.iam(account, "test", ""), "schema-reader", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetDocument","ssm:SendCommand"],"Resource":%q}]}`, arn))
			reader := cl.ssm("us-east-1", key, secret)
			if _, err := reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new("Schema12JSON")}); err != nil {
				t.Fatal(err)
			}
			_, err := reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new("Schema20JSON")})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = reader.SendCommand(ctx, &ssm.SendCommandInput{DocumentName: new("Schema20JSON"), Targets: []ssmtypes.Target{{Key: new("tag:schema-test"), Values: []string{"absent"}}}})
			assertAPIError(t, err, "AccessDeniedException")
		})
	}
}

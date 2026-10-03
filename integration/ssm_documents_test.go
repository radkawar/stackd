package stackd_test

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"stackd"
)

func shellDocument(version string) string {
	return fmt.Sprintf("{\n  \"schemaVersion\":\"2.2\",\"description\":%q,\"parameters\":{\"commands\":{\"type\":\"StringList\",\"default\":[\"printf 'original\\\\n'\"]}},\"mainSteps\":[{\"action\":\"aws:runShellScript\",\"name\":\"shell\",\"inputs\":{\"runCommand\":\"{{ commands }}\"}}]\n}", version)
}
func TestSSMDocumentsImmutableSelectionAuthorityAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			client := cl.ssm("us-east-1", account, "test")
			drain := func() {
				t.Helper()
				if jobs, err := cl.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil || jobs.More {
					t.Fatalf("document activation did not settle: %+v %v", jobs, err)
				}
			}
			name := "CommandDocument"
			arn := "arn:aws:ssm:us-east-1:" + account + ":document/" + name
			create, err := client.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new(name), Content: new(shellDocument("one")), DocumentType: ssmtypes.DocumentTypeCommand, VersionName: new("one"), Tags: []ssmtypes.Tag{{Key: new("team"), Value: new("compute")}}})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(create.DocumentDescription.Hash) != fmt.Sprintf("%x", sha256.Sum256([]byte(shellDocument("one")))) {
				t.Fatal("hash does not bind original source")
			}
			if create.DocumentDescription.Status != ssmtypes.DocumentStatusCreating {
				t.Fatalf("native initial document status: %s", create.DocumentDescription.Status)
			}
			drain()
			_, err = client.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new(name), Content: new(shellDocument("two"))})
			assertAPIError(t, err, "InvalidDocumentVersion")
			for _, version := range []string{"two", "three"} {
				_, err = client.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new(name), Content: new(shellDocument(version)), DocumentVersion: new("$LATEST"), VersionName: new(version)})
				if err != nil {
					t.Fatal(err)
				}
				drain()
			}
			_, err = client.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new(name), Content: new(shellDocument("three")), DocumentVersion: new("$LATEST")})
			assertAPIError(t, err, "DuplicateDocumentContent")
			_, err = client.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new(name), Content: new(shellDocument("stale")), DocumentVersion: new("1")})
			assertAPIError(t, err, "InvalidDocumentVersion")
			_, err = client.UpdateDocumentDefaultVersion(ctx, &ssm.UpdateDocumentDefaultVersionInput{Name: new(name), DocumentVersion: new("2")})
			if err != nil {
				t.Fatal(err)
			}
			for selector, want := range map[string]string{"1": "one", "$DEFAULT": "two", "$LATEST": "three"} {
				got, err := client.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn), DocumentVersion: new(selector)})
				if err != nil || aws.ToString(got.Content) != shellDocument(want) {
					t.Fatalf("selected %s: %+v %v", selector, got, err)
				}
			}
			_, err = client.DeleteDocument(ctx, &ssm.DeleteDocumentInput{Name: new(name), DocumentVersion: new("$DEFAULT")})
			assertAPIError(t, err, "InvalidDocumentOperation")
			_, err = client.DeleteDocument(ctx, &ssm.DeleteDocumentInput{Name: new(name), DocumentVersion: new("$LATEST")})
			if err != nil {
				t.Fatal(err)
			}
			cl = reopen()
			client = cl.ssm("us-east-1", account, "test")
			updated, err := client.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new(name), Content: new(shellDocument("four")), DocumentVersion: new("$LATEST")})
			if err != nil || aws.ToString(updated.DocumentDescription.DocumentVersion) != "4" {
				t.Fatalf("deleted immutable version reused: %+v %v", updated, err)
			}
			drain()
			page, err := client.ListDocumentVersions(ctx, &ssm.ListDocumentVersionsInput{Name: new(name), MaxResults: new(int32(1))})
			if err != nil || len(page.DocumentVersions) != 1 || aws.ToString(page.DocumentVersions[0].DocumentVersion) != "4" {
				t.Fatalf("version page: %+v %v", page, err)
			}
			next, err := client.ListDocumentVersions(ctx, &ssm.ListDocumentVersionsInput{Name: new(name), MaxResults: new(int32(1)), NextToken: page.NextToken})
			if err != nil || len(next.DocumentVersions) != 1 || aws.ToString(next.DocumentVersions[0].DocumentVersion) != "2" || !next.DocumentVersions[0].IsDefaultVersion {
				t.Fatalf("default page: %+v %v", next, err)
			}
			_, err = cl.ssm("us-west-2", account, "test").GetDocument(ctx, &ssm.GetDocumentInput{Name: new(name)})
			assertAPIError(t, err, "InvalidDocument")
			_, err = cl.ssm("us-east-1", "444455556666", "test").GetDocument(ctx, &ssm.GetDocumentInput{Name: new(name)})
			assertAPIError(t, err, "InvalidDocument")
			_, key, secret := cl.user(t, account, "document-reader")
			putUserPolicy(t, cl.iam(account, "test", ""), "document-reader", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetDocument","Resource":%q,"Condition":{"StringEquals":{"ssm:resourceTag/team":"compute"}}}]}`, arn))
			reader := cl.ssm("us-east-1", key, secret)
			got, err := reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(name)})
			if err != nil || aws.ToString(got.DocumentVersion) != "2" {
				t.Fatalf("tag-authorized read: %+v %v", got, err)
			}
			putUserPolicy(t, cl.iam(account, "test", ""), "document-reader", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ssm:GetDocument","Resource":%q}]}`, arn))
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(name)})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = client.DeleteDocument(ctx, &ssm.DeleteDocumentInput{Name: new(name)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(name)})
			assertAPIError(t, err, "InvalidDocument")
		})
	}
}

func TestSSMBuiltinDocumentUsesCapturedResourceAccount(t *testing.T) {
	var native struct {
		Owner string `json:"observed_builtin_resource_account"`
	}
	awsReadFixture(t, "ssm/managed_execution_admission_accounting.json.gz", &native)
	if native.Owner == "" {
		t.Fatal("native exact-match resource owner evidence missing")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			cl, _ := retainedCloud(t, backend, stackd.Config{AccountID: account})
			_, key, secret := cl.user(t, account, "builtin-operator")
			client := cl.ssm("us-east-1", key, secret)
			for _, row := range []struct {
				name, condition string
				allowed         bool
			}{
				{"caller", fmt.Sprintf(`"StringEquals":{"aws:ResourceAccount":%q}`, account), false},
				{"absent", `"Null":{"aws:ResourceAccount":"true"}`, false},
				{"present", `"Null":{"aws:ResourceAccount":"false"}`, true},
				{"provider", fmt.Sprintf(`"StringEquals":{"aws:ResourceAccount":%q}`, native.Owner), true},
			} {
				policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:SendCommand","ssm:GetDocument"],"Resource":"arn:aws:ssm:us-east-1::document/AWS-RunShellScript","Condition":{%s}}]}`, row.condition)
				putUserPolicy(t, cl.iam(account, "test", ""), "builtin-operator", policy)
				command, err := client.SendCommand(t.Context(), &ssm.SendCommandInput{DocumentName: new("AWS-RunShellScript"), Parameters: map[string][]string{"commands": {"true"}}, Targets: []ssmtypes.Target{{Key: new("tag:never-applied"), Values: []string{"none"}}}})
				if !row.allowed {
					assertAPIError(t, err, "AccessDeniedException")
				} else if err != nil || command.Command.TargetCount != 0 {
					t.Fatalf("%s native owner condition: %+v %v", row.name, command, err)
				}
				// The document owner is shared authority, not a command-only override.
				document, err := client.GetDocument(t.Context(), &ssm.GetDocumentInput{Name: new("AWS-RunShellScript")})
				if !row.allowed {
					assertAPIError(t, err, "AccessDeniedException")
				} else if err != nil || aws.ToString(document.DocumentVersion) != "1" {
					t.Fatalf("%s document owner condition: %+v %v", row.name, document, err)
				}
			}
		})
	}
}

package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"stackd"
)

func TestSSMDocumentSharingAuthorityVersionsAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const owner, recipient, other = "111122223333", "444455556666", "777788889999"
			ctx := t.Context()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner})
			writer := cl.ssm("us-east-1", owner, "test")
			name := "SharedCommand"
			arn := "arn:aws:ssm:us-east-1:" + owner + ":document/" + name
			_, err := writer.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new(name), Content: new(shellDocument("one")), DocumentType: ssmtypes.DocumentTypeCommand, VersionName: new("one")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = writer.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new(name), Content: new(shellDocument("two")), DocumentVersion: new("$LATEST"), VersionName: new("two")})
			if err != nil {
				t.Fatal(err)
			}
			_, key, secret := cl.user(t, recipient, "shared-reader")
			reader := cl.ssm("us-east-1", key, secret)
			allow := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:*","Resource":"*","Condition":{"StringEquals":{"aws:ResourceAccount":%q}}}]}`, owner)
			putUserPolicy(t, cl.iam(recipient, "test", ""), "shared-reader", allow)
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
			share := func(selector string, add, remove []string) {
				t.Helper()
				_, e := writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new(name), PermissionType: ssmtypes.DocumentPermissionTypeShare, SharedDocumentVersion: new(selector), AccountIdsToAdd: add, AccountIdsToRemove: remove})
				if e != nil {
					t.Fatal(e)
				}
			}
			get := func(selector, want string) {
				t.Helper()
				out, e := reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn), DocumentVersion: new(selector)})
				if e != nil || aws.ToString(out.Content) != shellDocument(want) {
					t.Fatalf("read %s: %+v %v", selector, out, e)
				}
			}
			share("$DEFAULT", []string{recipient, other, "123456789012"}, nil)
			get("$DEFAULT", "one")
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn), DocumentVersion: new("2")})
			assertAPIError(t, err, "InvalidDocumentVersion")
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn), VersionName: new("two")})
			assertAPIError(t, err, "InvalidDocumentVersion")
			versions, err := reader.ListDocumentVersions(ctx, &ssm.ListDocumentVersionsInput{Name: new(arn)})
			if err != nil || len(versions.DocumentVersions) != 1 || aws.ToString(versions.DocumentVersions[0].DocumentVersion) != "1" {
				t.Fatalf("version disclosure: %+v %v", versions, err)
			}
			// Mutation APIs accept owned names, not ARNs. Even the recipient's
			// root authority must not resolve this shared name into the owner.
			_, err = cl.ssm("us-east-1", recipient, "test").UpdateDocumentDefaultVersion(ctx, &ssm.UpdateDocumentDefaultVersionInput{Name: new(name), DocumentVersion: new("2")})
			assertAPIError(t, err, "InvalidDocument")
			_, err = writer.DeleteDocument(ctx, &ssm.DeleteDocumentInput{Name: new(name)})
			assertAPIError(t, err, "InvalidDocumentOperation")
			page, err := writer.DescribeDocumentPermission(ctx, &ssm.DescribeDocumentPermissionInput{Name: new(name), PermissionType: ssmtypes.DocumentPermissionTypeShare, MaxResults: new(int32(1))})
			if err != nil || len(page.AccountSharingInfoList) != 1 || page.AccountIds[0] != "123456789012" || aws.ToString(page.AccountSharingInfoList[0].SharedDocumentVersion) != "$DEFAULT" || page.NextToken == nil {
				t.Fatalf("share page: %+v %v", page, err)
			}
			next, err := writer.DescribeDocumentPermission(ctx, &ssm.DescribeDocumentPermissionInput{Name: new(name), PermissionType: ssmtypes.DocumentPermissionTypeShare, MaxResults: new(int32(200)), NextToken: page.NextToken})
			if err != nil || len(next.AccountIds) != 2 || next.AccountIds[0] != recipient || next.AccountIds[1] != other || next.NextToken != nil {
				t.Fatalf("share next page: %+v %v", next, err)
			}
			_, err = writer.UpdateDocumentDefaultVersion(ctx, &ssm.UpdateDocumentDefaultVersionInput{Name: new(name), DocumentVersion: new("2")})
			if err != nil {
				t.Fatal(err)
			}
			get("$DEFAULT", "two")
			share("$LATEST", []string{recipient}, nil)
			_, err = writer.UpdateDocument(ctx, &ssm.UpdateDocumentInput{Name: new(name), Content: new(shellDocument("three")), DocumentVersion: new("$LATEST")})
			if err != nil {
				t.Fatal(err)
			}
			get("$LATEST", "three")
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn), DocumentVersion: new("2")})
			assertAPIError(t, err, "InvalidDocumentVersion")
			share("$ALL", []string{recipient}, nil)
			get("1", "one")
			cl = reopen()
			writer, reader = cl.ssm("us-east-1", owner, "test"), cl.ssm("us-east-1", key, secret)
			get("3", "three")
			// Share and caller identity are independent, evaluated on every read/use.
			putUserPolicy(t, cl.iam(recipient, "test", ""), "shared-reader", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ssm:*","Resource":"*"}]}`)
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = reader.SendCommand(ctx, &ssm.SendCommandInput{DocumentName: new(arn), Targets: []ssmtypes.Target{{Key: new("tag:absent"), Values: []string{"none"}}}})
			assertAPIError(t, err, "AccessDeniedException")
			_, deniedKey, deniedSecret := cl.user(t, recipient, "no-document-policy")
			_, err = cl.ssm("us-east-1", deniedKey, deniedSecret).GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
			putUserPolicy(t, cl.iam(recipient, "test", ""), "shared-reader", allow)
			command, err := reader.SendCommand(ctx, &ssm.SendCommandInput{DocumentName: new(arn), DocumentVersion: new("1"), Targets: []ssmtypes.Target{{Key: new("tag:absent"), Values: []string{"none"}}}})
			if err != nil || aws.ToString(command.Command.DocumentVersion) != "1" {
				t.Fatalf("shared command admission: %+v %v", command, err)
			}
			_, err = cl.ssm("us-west-2", key, secret).GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn)})
			assertAPIError(t, err, "InvalidDocument")
			_, err = writer.DeleteDocument(ctx, &ssm.DeleteDocumentInput{Name: new(name), DocumentVersion: new("3")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn), DocumentVersion: new("3")})
			assertAPIError(t, err, "InvalidDocumentVersion")
			// Equal local names cannot alias foreign discovery or pagination keys.
			rootReader := cl.ssm("us-east-1", recipient, "test")
			_, err = rootReader.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new(name), Content: new(shellDocument("recipient")), DocumentType: ssmtypes.DocumentTypeCommand})
			if err != nil {
				t.Fatal(err)
			}
			listing, err := rootReader.ListDocuments(ctx, &ssm.ListDocumentsInput{Filters: []ssmtypes.DocumentKeyValuesFilter{{Key: new("Owner"), Values: []string{"Private"}}}, MaxResults: new(int32(1))})
			if err != nil || len(listing.DocumentIdentifiers) != 1 || aws.ToString(listing.DocumentIdentifiers[0].Name) != arn || aws.ToString(listing.DocumentIdentifiers[0].Owner) != owner {
				t.Fatalf("shared discovery: %+v %v", listing, err)
			}
			filter := []ssmtypes.DocumentKeyValuesFilter{{Key: new("Name"), Values: []string{name}}}
			first, err := rootReader.ListDocuments(ctx, &ssm.ListDocumentsInput{Filters: filter, MaxResults: new(int32(1))})
			if err != nil || len(first.DocumentIdentifiers) != 1 || aws.ToString(first.DocumentIdentifiers[0].Name) != name || first.NextToken == nil {
				t.Fatalf("same-name first page: %+v %v", first, err)
			}
			second, err := rootReader.ListDocuments(ctx, &ssm.ListDocumentsInput{Filters: filter, MaxResults: new(int32(1)), NextToken: first.NextToken})
			if err != nil || len(second.DocumentIdentifiers) != 1 || aws.ToString(second.DocumentIdentifiers[0].Name) != arn || second.NextToken != nil {
				t.Fatalf("same-name next page: %+v %v", second, err)
			}
			_, err = writer.ListDocuments(ctx, &ssm.ListDocumentsInput{Filters: filter, MaxResults: new(int32(1)), NextToken: first.NextToken})
			assertAPIError(t, err, "InvalidNextToken")
			// Removing All revokes only public access; native leaves private grants.
			share("$DEFAULT", nil, []string{"All"})
			get("1", "one")
			share("$LATEST", []string{recipient}, []string{recipient})
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = reader.SendCommand(ctx, &ssm.SendCommandInput{DocumentName: new(arn), Targets: []ssmtypes.Target{{Key: new("tag:absent"), Values: []string{"none"}}}})
			assertAPIError(t, err, "InvalidDocument")
			share("$DEFAULT", nil, []string{other, "123456789012"})
			_, err = writer.DeleteDocument(ctx, &ssm.DeleteDocumentInput{Name: new(name)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = writer.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new(name), Content: new(shellDocument("recreated")), DocumentType: ssmtypes.DocumentTypeCommand})
			if err != nil {
				t.Fatal(err)
			}
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
		})
	}
}

func TestSSMDocumentPublicSharingSettingAndIsolation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const owner, recipient = "111122223333", "444455556666"
			const setting = "/ssm/documents/console/public-sharing-permission"
			ctx := t.Context()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner})
			writer := cl.ssm("us-east-1", owner, "test")
			settingARN := "arn:aws:ssm:us-east-1:" + owner + ":servicesetting" + setting
			for _, name := range []string{"PublicCommand", "BlockedCommand"} {
				_, err := writer.CreateDocument(ctx, &ssm.CreateDocumentInput{Name: new(name), Content: new(shellDocument(name)), DocumentType: ssmtypes.DocumentTypeCommand})
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err := writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new("PublicCommand"), PermissionType: ssmtypes.DocumentPermissionTypeShare, AccountIdsToAdd: []string{"All"}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = writer.UpdateServiceSetting(ctx, &ssm.UpdateServiceSettingInput{SettingId: new(settingARN), SettingValue: new("Disable")})
			if err != nil {
				t.Fatal(err)
			}
			cl = reopen()
			writer = cl.ssm("us-east-1", owner, "test")
			got, err := writer.GetServiceSetting(ctx, &ssm.GetServiceSettingInput{SettingId: new(setting)})
			if err != nil || aws.ToString(got.ServiceSetting.SettingValue) != "Disable" {
				t.Fatalf("retained public block: %+v %v", got, err)
			}
			_, err = writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new("BlockedCommand"), PermissionType: ssmtypes.DocumentPermissionTypeShare, AccountIdsToAdd: []string{"all"}})
			assertAPIError(t, err, "InvalidDocumentOperation")
			reader := cl.ssm("us-east-1", recipient, "test")
			arn := "arn:aws:ssm:us-east-1:" + owner + ":document/PublicCommand"
			out, err := reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn)})
			if err != nil || aws.ToString(out.Content) != shellDocument("PublicCommand") {
				t.Fatalf("block revoked existing grant: %+v %v", out, err)
			}
			other, err := cl.ssm("us-west-2", owner, "test").GetServiceSetting(ctx, &ssm.GetServiceSettingInput{SettingId: new(setting)})
			if err != nil || aws.ToString(other.ServiceSetting.SettingValue) != "Enable" {
				t.Fatalf("region leaked setting: %+v %v", other, err)
			}
			other, err = reader.GetServiceSetting(ctx, &ssm.GetServiceSettingInput{SettingId: new(setting)})
			if err != nil || aws.ToString(other.ServiceSetting.SettingValue) != "Enable" {
				t.Fatalf("account leaked setting: %+v %v", other, err)
			}
			_, key, secret := cl.user(t, owner, "setting-denied")
			putUserPolicy(t, cl.iam(owner, "test", ""), "setting-denied", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ssm:UpdateServiceSetting","Resource":%q}]}`, settingARN))
			_, err = cl.ssm("us-east-1", key, secret).UpdateServiceSetting(ctx, &ssm.UpdateServiceSettingInput{SettingId: new(setting), SettingValue: new("Enable")})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = writer.ResetServiceSetting(ctx, &ssm.ResetServiceSettingInput{SettingId: new(setting)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new("BlockedCommand"), PermissionType: ssmtypes.DocumentPermissionTypeShare, AccountIdsToAdd: []string{"all"}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new("PublicCommand"), PermissionType: ssmtypes.DocumentPermissionTypeShare, AccountIdsToAdd: []string{recipient}})
			assertAPIError(t, err, "DocumentPermissionLimit")
			_, err = writer.ModifyDocumentPermission(ctx, &ssm.ModifyDocumentPermissionInput{Name: new("PublicCommand"), PermissionType: ssmtypes.DocumentPermissionTypeShare, AccountIdsToRemove: []string{"all"}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = reader.GetDocument(ctx, &ssm.GetDocumentInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
		})
	}
}

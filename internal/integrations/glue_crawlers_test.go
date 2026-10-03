package integrations

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	glueapi "stackd/internal/awsapi/glue"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/glue"
	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	gluestore "stackd/storage/sqlite/glue"
	iamstore "stackd/storage/sqlite/iam"
)

type crawlerOutcomes chan string

func (c crawlerOutcomes) Publish(_ context.Context, _ glue.CrawlerRecord, state, _ string) error {
	if state != "Started" {
		c <- state
	}
	return nil
}

func TestJDBCCrawlerCurrentAuthoritySharesSQLiteTransaction(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "crawler.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := iamstore.New(db)
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	role := iam.Role{Arn: "arn:aws:iam::123456789012:role/crawler", RoleName: "crawler", RoleId: "AROACRAWLER", MaxSessionDuration: 3600, AssumeRolePolicyDocument: `{"Statement":{"Effect":"Allow","Principal":{"Service":"glue.amazonaws.com"},"Action":"sts:AssumeRole"}}`, IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"connection": `{"Statement":{"Effect":"Allow","Action":"glue:GetConnection","Resource":"*"}}`}}}
	updateRole := func() {
		t.Helper()
		if err := repository.Update(ctx, func(tx iam.WriteTx) error { return tx.PutRole(scope, role) }); err != nil {
			t.Fatal(err)
		}
	}
	updateRole()
	credentials := identity.NewWithConfig(identity.Config{AccountID: scope.AccountID, Repository: iam.NewCredentialRepository(repository, nil)})
	identityService := iam.NewWithConfig(iam.Config{Repository: repository, Credentials: credentials})
	authorizer := authorization.NewWithClock(identityService, nil, nil)
	outcomes := make(crawlerOutcomes, 2)
	service := glue.New(glue.Config{Repository: gluestore.New(db), Authorizer: authorizer, CrawlerSource: &GlueCrawlers{Roles: ServiceRoles{IAM: identityService, Credentials: credentials, Authorizer: authorizer}}, CrawlerEvents: outcomes})
	defer service.Close()
	call := func(action string, input any) any {
		t.Helper()
		model, _ := awscatalog.LookupService("glue")
		operation, _ := model.Operation(action)
		out, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
		if rejected != nil {
			t.Fatalf("%s: %v", action, rejected)
		}
		return out
	}
	name := new(glueapi.NameString("current-authority"))
	call("CreateDatabase", &glueapi.CreateDatabaseInput{DatabaseInput: &glueapi.DatabaseInput{Name: name}})
	// Invalid TLS configuration is a deterministic post-authorization rejection;
	// no PostgreSQL installation or network endpoint is needed for this boundary.
	call("CreateConnection", &glueapi.CreateConnectionInput{ConnectionInput: &glueapi.ConnectionInput{Name: name, ConnectionType: new(glueapi.ConnectionTypeJDBC), ConnectionProperties: glueapi.ConnectionProperties{"JDBC_CONNECTION_URL": "jdbc:postgresql://localhost/catalog?sslmode=invalid", "USERNAME": "reader", "PASSWORD": "unused"}}})
	call("CreateCrawler", &glueapi.CreateCrawlerInput{Name: name, Role: new(glueapi.Role(role.Arn)), DatabaseName: new(glueapi.DatabaseName(*name)), Targets: &glueapi.CrawlerTargets{JdbcTargets: glueapi.JdbcTargetList{{ConnectionName: new(glueapi.ConnectionName(*name)), Path: new(glueapi.Path("catalog/public/%"))}}}})
	call("StartCrawler", &glueapi.StartCrawlerInput{Name: name})
	// Admission is not a credential/policy cache. Change IAM before execution.
	role.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"glue:GetConnection","Resource":"*"}}`
	updateRole()
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	awaitFailure := func(code string) {
		t.Helper()
		select {
		case state := <-outcomes:
			if state != "Failed" {
				t.Fatalf("crawler outcome %s", state)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("JDBC authorization blocked the shared SQLite transaction")
		}
		crawler := call("GetCrawler", &glueapi.GetCrawlerInput{Name: name}).(*glueapi.GetCrawlerOutput).Crawler
		if crawler.LastCrawl == nil || crawler.LastCrawl.ErrorMessage == nil || !strings.HasPrefix(string(*crawler.LastCrawl.ErrorMessage), code+":") {
			t.Fatalf("crawler did not retain %q: %+v", code, crawler.LastCrawl)
		}
	}
	awaitFailure("AccessDeniedException")
	delete(role.IdentityPolicies.Inline, "deny")
	updateRole()
	call("StartCrawler", &glueapi.StartCrawlerInput{Name: name})
	awaitFailure("InvalidInputException")
}

func TestConnectionPasswordProjectionUsesActualKMSDecryption(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	domain := memory.NewDomain()
	keys := kms.NewWithStorage(kms.NewMemoryStorage(domain), nil)
	defer keys.Close()
	model, _ := awscatalog.LookupService("kms")
	operation, _ := model.Operation("CreateKey")
	output, rejected := keys.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &kmsapi.CreateKeyInput{}})
	if rejected != nil {
		t.Fatal(rejected)
	}
	key := output.(*kmsapi.CreateKeyOutput).KeyMetadata
	service := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), ConnectionCrypto: keys})
	defer service.Close()
	call := func(action string, input any) any {
		t.Helper()
		model, _ := awscatalog.LookupService("glue")
		operation, _ := model.Operation(action)
		output, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
		if rejected != nil {
			t.Fatalf("%s: %v", action, rejected)
		}
		return output
	}
	settings := &glueapi.ConnectionPasswordEncryption{ReturnConnectionPasswordEncrypted: new(glueapi.Boolean(true)), AwsKmsKeyId: new(glueapi.NameString(*key.Arn))}
	call("PutDataCatalogEncryptionSettings", &glueapi.PutDataCatalogEncryptionSettingsInput{DataCatalogEncryptionSettings: &glueapi.DataCatalogEncryptionSettings{ConnectionPasswordEncryption: settings}})
	name := new(glueapi.NameString("encrypted-password"))
	call("CreateConnection", &glueapi.CreateConnectionInput{ConnectionInput: &glueapi.ConnectionInput{Name: name, ConnectionType: new(glueapi.ConnectionTypeJDBC), ConnectionProperties: glueapi.ConnectionProperties{"JDBC_CONNECTION_URL": "jdbc:postgresql://localhost/catalog", "USERNAME": "reader", "PASSWORD": "owned-secret"}}})
	properties := call("GetConnection", &glueapi.GetConnectionInput{Name: name}).(*glueapi.GetConnectionOutput).Connection.ConnectionProperties
	if properties["PASSWORD"] != "" || properties["ENCRYPTED_PASSWORD"] == "" || properties["ENCRYPTED_PASSWORD"] == "owned-secret" {
		t.Fatal("encrypted projection exposed plaintext or omitted KMS ciphertext")
	}
	settings.ReturnConnectionPasswordEncrypted = new(glueapi.Boolean(false))
	call("PutDataCatalogEncryptionSettings", &glueapi.PutDataCatalogEncryptionSettingsInput{DataCatalogEncryptionSettings: &glueapi.DataCatalogEncryptionSettings{ConnectionPasswordEncryption: settings}})
	properties = call("GetConnection", &glueapi.GetConnectionInput{Name: name}).(*glueapi.GetConnectionOutput).Connection.ConnectionProperties
	if properties["PASSWORD"] != "owned-secret" || properties["ENCRYPTED_PASSWORD"] != "" {
		t.Fatal("authorized projection did not decrypt the retained KMS ciphertext")
	}
	hidden := call("GetConnection", &glueapi.GetConnectionInput{Name: name, HidePassword: new(glueapi.Boolean(true))}).(*glueapi.GetConnectionOutput).Connection.ConnectionProperties
	if hidden["PASSWORD"] != "" || hidden["ENCRYPTED_PASSWORD"] != "" {
		t.Fatal("HidePassword exposed connection credentials")
	}
}

func TestConnectionPasswordUpdateUsesCurrentKMSAuthority(t *testing.T) {
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	domain := memory.NewDomain()
	repository := iam.NewMemoryRepository(domain)
	identityService := iam.NewWithConfig(iam.Config{Repository: repository})
	authorizer := authorization.NewWithClock(identityService, nil, nil)
	keys := kms.NewWithStorage(kms.NewMemoryStorage(domain), authorizer)
	defer keys.Close()
	model, _ := awscatalog.LookupService("kms")
	operation, _ := model.Operation("CreateKey")
	output, rejected := keys.ExecuteCommand(root, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &kmsapi.CreateKeyInput{}})
	if rejected != nil {
		t.Fatal(rejected)
	}
	key := output.(*kmsapi.CreateKeyOutput).KeyMetadata
	service := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), Authorizer: authorizer, ConnectionCrypto: keys})
	defer service.Close()
	user := iam.User{UserName: "reader", UserId: "AIDAREADER", Arn: "arn:aws:iam::123456789012:user/reader", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	caller := awsctx.WithMetadata(root, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId})
	setPolicy := func(denied string) {
		t.Helper()
		policy := `{"Statement":[{"Effect":"Allow","Action":["glue:*","kms:*"],"Resource":"*"}`
		if denied != "" {
			policy += `,{"Effect":"Deny","Action":"kms:` + denied + `","Resource":"` + string(*key.Arn) + `"}`
		}
		user.IdentityPolicies.Inline["connection"] = policy + `]}`
		if err := repository.Update(root, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
		}); err != nil {
			t.Fatal(err)
		}
	}
	call := func(ctx context.Context, action string, input any, code string) any {
		t.Helper()
		model, _ := awscatalog.LookupService("glue")
		operation, _ := model.Operation(action)
		output, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
		if code != "" {
			if rejected == nil || rejected.Code != code {
				t.Fatalf("%s: %v, want %s", action, rejected, code)
			}
		} else if rejected != nil {
			t.Fatalf("%s: %v", action, rejected)
		}
		return output
	}
	name := new(glueapi.NameString("existing-password"))
	input := &glueapi.ConnectionInput{Name: name, ConnectionType: new(glueapi.ConnectionTypeJDBC), ConnectionProperties: glueapi.ConnectionProperties{"JDBC_CONNECTION_URL": "jdbc:postgresql://localhost/catalog", "USERNAME": "reader", "PASSWORD": "synthetic-current-kms-password"}}
	call(root, "CreateConnection", &glueapi.CreateConnectionInput{ConnectionInput: input}, "")
	settings := &glueapi.ConnectionPasswordEncryption{ReturnConnectionPasswordEncrypted: new(glueapi.Boolean(true)), AwsKmsKeyId: new(glueapi.NameString(*key.Arn))}
	call(root, "PutDataCatalogEncryptionSettings", &glueapi.PutDataCatalogEncryptionSettingsInput{DataCatalogEncryptionSettings: &glueapi.DataCatalogEncryptionSettings{ConnectionPasswordEncryption: settings}}, "")
	// AWS documents encryption on CreateConnection/UpdateConnection, not a
	// retroactive rewrite or kms:Encrypt authorization on GetConnection.
	setPolicy("Encrypt")
	update := &glueapi.UpdateConnectionInput{Name: name, ConnectionInput: input}
	call(caller, "UpdateConnection", update, "AccessDeniedException")
	setPolicy("")
	call(caller, "UpdateConnection", update, "")
	get := &glueapi.GetConnectionInput{Name: name}
	encrypted := call(caller, "GetConnection", get, "").(*glueapi.GetConnectionOutput).Connection.ConnectionProperties
	list := call(caller, "GetConnections", &glueapi.GetConnectionsInput{}, "").(*glueapi.GetConnectionsOutput).ConnectionList
	if encrypted["PASSWORD"] != "" || encrypted["ENCRYPTED_PASSWORD"] == "" || len(list) != 1 || list[0].ConnectionProperties["ENCRYPTED_PASSWORD"] != encrypted["ENCRYPTED_PASSWORD"] {
		t.Fatal("explicit update did not store and return encrypted password")
	}
	settings.ReturnConnectionPasswordEncrypted = new(glueapi.Boolean(false))
	call(root, "PutDataCatalogEncryptionSettings", &glueapi.PutDataCatalogEncryptionSettingsInput{DataCatalogEncryptionSettings: &glueapi.DataCatalogEncryptionSettings{ConnectionPasswordEncryption: settings}}, "")
	setPolicy("Decrypt")
	call(caller, "GetConnection", get, "AccessDeniedException")
	call(caller, "GetConnections", &glueapi.GetConnectionsInput{}, "AccessDeniedException")
	hidden := call(caller, "GetConnection", &glueapi.GetConnectionInput{Name: name, HidePassword: new(glueapi.Boolean(true))}, "").(*glueapi.GetConnectionOutput).Connection.ConnectionProperties
	if hidden["PASSWORD"] != "" || hidden["ENCRYPTED_PASSWORD"] != "" {
		t.Fatal("HidePassword returned a credential")
	}
	setPolicy("")
	plain := call(caller, "GetConnection", get, "").(*glueapi.GetConnectionOutput).Connection.ConnectionProperties
	if plain["PASSWORD"] != input.ConnectionProperties["PASSWORD"] || plain["ENCRYPTED_PASSWORD"] != "" {
		t.Fatal("current KMS authority did not decrypt the retained password")
	}
}

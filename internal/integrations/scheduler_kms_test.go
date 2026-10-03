package integrations

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
	scheduler "stackd/internal/services/scheduler"
	"stackd/storage/memory"
)

func TestSchedulerEncryptionUsesCurrentCallerAndExecutionRole(t *testing.T) {
	d := memory.NewDomain()
	c := clock.NewManual(time.Date(2031, 1, 2, 0, 0, 0, 0, time.UTC))
	r := iam.NewMemoryRepository(d)
	scope := iam.Scope{
		Partition: "aws",
		AccountID: "123456789012",
	}
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{
		Partition:    "aws",
		AccountID:    scope.AccountID,
		Region:       "us-east-1",
		PrincipalARN: "arn:aws:iam::123456789012:root",
	})
	role := iam.Role{
		Arn:                      "arn:aws:iam::123456789012:role/scheduler-encrypted",
		RoleName:                 "scheduler-encrypted",
		RoleId:                   "AROASCHEDULERKEY",
		MaxSessionDuration:       3600,
		AssumeRolePolicyDocument: `{"Statement":{"Effect":"Allow","Principal":{"Service":"scheduler.amazonaws.com"},"Action":"sts:AssumeRole"}}`,
	}
	user := iam.User{
		Arn:              "arn:aws:iam::123456789012:user/deployer",
		UserName:         "deployer",
		UserId:           "AIDASCHEDULERKEY",
		IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"key": `{"Statement":{"Effect":"Allow","Action":["kms:DescribeKey","kms:GenerateDataKey"],"Resource":"*"}}`}},
	}
	update := func() {
		t.Helper()
		if err := r.Update(root, func(tx iam.WriteTx) error {
			if err := tx.PutRole(scope, role); err != nil {
				return err
			}
			return tx.PutUser(scope, user)
		}); err != nil {
			t.Fatal(err)
		}
	}
	update()
	credentials := identity.NewWithConfig(identity.Config{
		AccountID:  scope.AccountID,
		Repository: iam.NewCredentialRepository(r, nil),
		Clock:      c,
	})
	identities := iam.NewWithConfig(iam.Config{
		Repository:  r,
		Credentials: credentials,
		Clock:       c,
	})
	auth := authorization.NewWithClock(identities, nil, c)
	keysService := kms.NewWithConfig(kms.Config{
		Storage:    kms.NewMemoryStorage(d),
		Authorizer: auth,
		Clock:      c,
	})
	defer keysService.Close()
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kms": keysService})
	result, rejected := commands.Call(root, "kms", "CreateKey", []byte(`{}`))
	if rejected != nil {
		t.Fatal(rejected)
	}
	arn := string(*result.Output.(*kmsapi.CreateKeyOutput).KeyMetadata.Arn)
	keys := SchedulerKeys{
		KMS:      keysService,
		Activity: identities,
		Roles: ServiceRoles{
			IAM:         identities,
			Credentials: credentials,
			Authorizer:  auth,
		},
	}
	key := scheduler.ScheduleKey{
		Group: scheduler.GroupKey{
			Scope: scheduler.Scope{
				Partition: "aws",
				Account:   scope.AccountID,
				Region:    "us-east-1",
			},
			Name: "default",
		},
		Name: "encrypted",
	}
	credential, err := credentials.CreateAccessKey(identity.Principal{
		AccountID: scope.AccountID,
		ARN:       user.Arn,
		ID:        user.UserId,
		UserName:  user.UserName,
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := identity.RequestMetadata(credential, credential.AccessKeyID, "us-east-1", "scheduler-key-test")
	if err != nil {
		t.Fatal(err)
	}
	deployer := awsctx.WithMetadata(t.Context(), metadata)
	payload := []byte(`{"secret":"do-not-store-plaintext"}`)
	if _, _, _, rejected := keys.Seal(deployer, key, arn, payload); rejected == nil || rejected.Code != "AccessDeniedException" {
		t.Fatalf("GenerateDataKey without caller Decrypt admitted: %v", rejected)
	}
	user.IdentityPolicies.Inline["decrypt"] = `{"Statement":{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}}`
	update()
	encrypted, wrapped, resolved, rejected := keys.Seal(deployer, key, arn, payload)
	if rejected != nil {
		t.Fatal(rejected)
	}
	if resolved != arn || bytes.Contains(encrypted, payload) || bytes.Contains(wrapped, payload) {
		t.Fatal("CMK payload was not encrypted")
	}
	plain, rejected := keys.Open(deployer, key, "", encrypted, wrapped)
	if rejected != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("caller decrypt failed: %v", rejected)
	}
	if _, rejected := keys.Open(root, key, role.Arn, encrypted, wrapped); rejected == nil || rejected.Code != "AccessDeniedException" {
		t.Fatalf("execution borrowed deployer key permission: %v", rejected)
	}
	role.IdentityPolicies.Inline = map[string]string{"decrypt": `{"Statement":{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}}`}
	update()
	plain, rejected = keys.Open(root, key, role.Arn, encrypted, wrapped)
	if rejected != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("current role decrypt permission not honored: %v", rejected)
	}
	other := key
	other.Name = "different"
	if _, rejected := keys.Open(root, other, role.Arn, encrypted, wrapped); rejected == nil {
		t.Fatal("encryption context allowed a different schedule to decrypt")
	}
	raw, _ := json.Marshal(map[string]string{"KeyId": arn})
	if _, rejected = commands.Call(root, "kms", "DisableKey", raw); rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected := keys.Open(root, key, role.Arn, encrypted, wrapped); rejected == nil {
		t.Fatal("disabled KMS key decrypted retained payload")
	}
}

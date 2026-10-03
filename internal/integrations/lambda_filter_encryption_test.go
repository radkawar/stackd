package integrations

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"testing"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
	"stackd/internal/services/lambda"
)

func TestLambdaSignedFiltersAuthorityAndMappingBinding(t *testing.T) {
	f := newLambdaRoleFixture(t)
	f.user.IdentityPolicies.Inline = map[string]string{"kms": `{"Statement":{"Effect":"Allow","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*"}}`}
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	credential, err := f.adapter.Credentials.CreateAccessKey(identity.Principal{AccountID: f.scope.AccountID, ARN: f.user.Arn, ID: f.user.UserId, UserName: f.user.UserName})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := identity.RequestMetadata(credential, credential.AccessKeyID, "us-east-1", "signed-filter-test")
	if err != nil {
		t.Fatal(err)
	}
	f.ctx = awsctx.WithMetadata(t.Context(), metadata)
	owner := kms.NewWithConfig(kms.Config{Clock: f.clock, Authorizer: f.adapter.Authorizer})
	defer owner.Close()
	adapter := LambdaFilterEncryption{KMS: owner, Activity: f.adapter.IAM.(IAMActivity)}
	scope := lambda.Scope{Partition: "aws", Account: f.scope.AccountID, Region: "us-east-1"}
	mapping := lambda.EventSourceMappingRecord{
		Key:            lambda.EventSourceMappingKey{Scope: scope, UUID: "mapping"},
		Function:       lambda.FunctionReference{FunctionKey: lambda.FunctionKey{Scope: scope, Name: "f"}},
		EventSourceARN: "arn:aws:sqs:us-east-1:123456789012:source",
	}
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root"})
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kms": owner})
	ownerStatement := `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"}`
	serviceStatement := `{"Effect":"Allow","Principal":{"Service":"lambda.us-east-1.amazonaws.com"},"Action":"kms:Decrypt","Resource":"*","Condition":{"ArnEquals":{"aws:SourceArn":"` + mapping.Key.ARN() + `"}}}`
	requirePublicKey := `{"Effect":"Deny","Principal":"*","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*","Condition":{"Null":{"kms:EncryptionContext:aws-crypto-public-key":"true"}}}`
	basePolicy := `{"Statement":[` + ownerStatement + `,` + serviceStatement + `]}`
	signedPolicy := `{"Statement":[` + ownerStatement + `,` + serviceStatement + `,` + requirePublicKey + `]}`
	input, err := json.Marshal(map[string]string{"Policy": signedPolicy})
	if err != nil {
		t.Fatal(err)
	}
	result, wire := commands.Call(root, "kms", "CreateKey", input)
	if wire != nil {
		t.Fatal(wire)
	}
	keyARN := string(*result.Output.(*kmsapi.CreateKeyOutput).KeyMetadata.Arn)
	mapping.Settings.KMSKeyARN = keyARN
	plain := []byte(`["{\"body\":{\"kind\":[\"keep\"]}}"]`)
	encrypted, wire := adapter.Protect(f.ctx, mapping, keyARN, plain)
	if wire != nil {
		t.Fatal(wire)
	}
	mapping.Settings.EncryptedFilters = encrypted
	for _, processing := range []bool{false, true} {
		got, rejected := adapter.Unprotect(f.ctx, mapping, processing)
		if rejected != nil || !bytes.Equal(got, plain) {
			t.Fatalf("processing=%t: %s %v", processing, got, rejected)
		}
	}
	for name, mutate := range map[string]func(*lambda.EventSourceMappingRecord){
		"mapping":          func(v *lambda.EventSourceMappingRecord) { v.Key.UUID = "other" },
		"source":           func(v *lambda.EventSourceMappingRecord) { v.EventSourceARN += "other" },
		"function context": func(v *lambda.EventSourceMappingRecord) { v.Settings.EncryptedFilters.FunctionARN += "other" },
		"signature": func(v *lambda.EventSourceMappingRecord) {
			v.Settings.EncryptedFilters.Content[len(v.Settings.EncryptedFilters.Content)-1] ^= 1
		},
		"unknown format":   func(v *lambda.EventSourceMappingRecord) { v.Settings.EncryptedFilters.Format = "unknown" },
		"format downgrade": func(v *lambda.EventSourceMappingRecord) { v.Settings.EncryptedFilters.Format = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := mapping
			copyEncrypted := *encrypted
			copyEncrypted.Content = bytes.Clone(encrypted.Content)
			candidate.Settings.EncryptedFilters = &copyEncrypted
			mutate(&candidate)
			if got, rejected := adapter.Unprotect(f.ctx, candidate, false); rejected == nil || got != nil {
				t.Fatalf("substitution released %q: %v", got, rejected)
			}
		})
	}
	f.user.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"kms:Decrypt","Resource":"*"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	if got, rejected := adapter.Unprotect(f.ctx, mapping, false); rejected == nil || rejected.Code != "AccessDeniedException" || got != nil {
		t.Fatalf("revoked caller: %q %v", got, rejected)
	}
	// Source processing must use the regional Lambda principal, not the caller
	// whose IAM was just revoked, or a function execution-role session.
	if got, rejected := adapter.Unprotect(f.ctx, mapping, true); rejected != nil || !bytes.Equal(got, plain) {
		t.Fatalf("regional service authority: %q %v", got, rejected)
	}
	delete(f.user.IdentityPolicies.Inline, "deny")
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	putPolicy := func(policy string) {
		t.Helper()
		body, err := json.Marshal(map[string]string{"KeyId": keyARN, "PolicyName": "default", "Policy": policy})
		if err != nil {
			t.Fatal(err)
		}
		if _, wire := commands.Call(root, "kms", "PutKeyPolicy", body); wire != nil {
			t.Fatal(wire)
		}
	}
	putPolicy(`{"Statement":[` + ownerStatement + `,` + requirePublicKey + `]}`)
	if got, rejected := adapter.Unprotect(f.ctx, mapping, true); rejected == nil || rejected.Code != "AccessDeniedException" || got != nil {
		t.Fatalf("revoked service: %q %v", got, rejected)
	}
	if got, rejected := adapter.Unprotect(f.ctx, mapping, false); rejected != nil || !bytes.Equal(got, plain) {
		t.Fatalf("independent caller grant: %q %v", got, rejected)
	}

	// Legacy records have neither a signing key nor SDK framing. Reconstruct
	// their actual cipher contract, not a fake fallback returned by an adapter.
	putPolicy(basePolicy)
	key, wrapped, _, rejected := owner.GenerateDataKey(kms.WithViaService(f.ctx, "lambda"), keyARN, lambdaFilterContext(mapping.Function.ARN(), mapping.EventSourceARN))
	if rejected != nil {
		t.Fatal(rejected)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	legacy := mapping
	legacy.Settings.EncryptedFilters = &lambda.EncryptedMappingFilters{FunctionARN: mapping.Function.ARN(), DataKey: wrapped, Content: aead.Seal(nonce, nonce, plain, []byte(mapping.Key.ARN()))}
	if got, rejected := adapter.Unprotect(f.ctx, legacy, false); rejected != nil || !bytes.Equal(got, plain) {
		t.Fatalf("legacy recovery: %q %v", got, rejected)
	}
	legacy.Key.UUID = "other"
	if got, rejected := adapter.Unprotect(f.ctx, legacy, false); rejected == nil || got != nil {
		t.Fatalf("legacy mapping substitution: %q %v", got, rejected)
	}
	putPolicy(signedPolicy)
	legacy.Key = mapping.Key
	if got, rejected := adapter.Unprotect(f.ctx, legacy, false); rejected == nil || rejected.Code != "AccessDeniedException" || got != nil {
		t.Fatalf("legacy read bypassed new public-key requirement: %q %v", got, rejected)
	}
}

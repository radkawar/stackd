package integrations

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	appconfigapi "stackd/internal/awsapi/appconfig"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awsenvelope"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
	"stackd/internal/services/ssm"
)

func TestAppConfigParameterVersionUsesCurrentRoleAuthority(t *testing.T) {
	f := newLambdaRoleFixture(t)
	scope := appconfig.Scope{Partition: "aws", AccountID: f.scope.AccountID, Region: "us-east-1"}
	source := appConfigARN(scope, "application/app0001/configurationprofile/prof001")
	f.role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Allow","Principal":{"Service":"appconfig.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:SourceArn":"` + source + `"}}}}`
	f.role.IdentityPolicies.Inline = map[string]string{"parameter": `{"Statement":{"Effect":"Allow","Action":"ssm:GetParameter","Resource":"arn:aws:ssm:us-east-1:123456789012:parameter/configuration"}}`}
	f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	owner := ssm.New(ssm.Config{Clock: f.clock, Authorizer: f.adapter.Authorizer})
	defer owner.Close()
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root"})
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ssm": owner})
	for _, body := range []string{`{"Name":"configuration","Value":"first","Type":"String"}`, `{"Name":"configuration","Value":"second","Type":"String","Overwrite":true}`} {
		if _, wire := commands.Call(root, "ssm", "PutParameter", []byte(body)); wire != nil {
			t.Fatal(wire)
		}
	}
	effects := AppConfigEffects{Roles: f.adapter.ServiceRoles, Parameters: owner}
	profile := appconfig.Profile{Scope: scope, ApplicationID: "app0001", ID: "prof001", LocationURI: "ssm-parameter://configuration", RetrievalRoleARN: f.role.Arn}
	first, err := effects.Retrieve(root, profile, "1")
	if err != nil || string(first.Content) != "first" || first.Version != "1" {
		t.Fatalf("exact version after overwrite: %+v %v", first, err)
	}
	profile.LocationURI = "arn:aws:ssm:us-east-1:123456789012:parameter/configuration"
	second, err := effects.Retrieve(root, profile, "2")
	if err != nil || string(second.Content) != "second" || second.Version != "2" {
		t.Fatalf("ARN version: %+v %v", second, err)
	}
	f.role.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"ssm:GetParameter","Resource":"*"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	if _, err = effects.Retrieve(root, profile, "1"); err == nil {
		t.Fatal("parameter retrieval cached previous permission or borrowed root authority")
	}
	delete(f.role.IdentityPolicies.Inline, "deny")
	f.role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Principal":{"Service":"appconfig.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	if _, err = effects.Retrieve(root, profile, "1"); err == nil {
		t.Fatal("parameter retrieval reused trust after revocation")
	}
}

func TestAppConfigEncryptedContentUsesCurrentKeyAndVersionContext(t *testing.T) {
	f := newLambdaRoleFixture(t)
	scope := appconfig.Scope{Partition: "aws", AccountID: f.scope.AccountID, Region: "us-east-1"}
	resource := appConfigARN(scope, "application/app0001/configurationprofile/prof001/hostedconfigurationversion/1")
	f.user.IdentityPolicies.Inline = map[string]string{"generate": `{"Statement":{"Effect":"Allow","Action":"kms:GenerateDataKey","Resource":"*","Condition":{"StringEquals":{"kms:EncryptionContext:aws:appconfig:hostedconfigurationversion:arn":"` + resource + `"}}}}`}
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	credential, err := f.adapter.Credentials.CreateAccessKey(identity.Principal{AccountID: scope.AccountID, ARN: f.user.Arn, ID: f.user.UserId, UserName: f.user.UserName})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := identity.RequestMetadata(credential, credential.AccessKeyID, scope.Region, "appconfig-kms-test")
	if err != nil {
		t.Fatal(err)
	}
	f.ctx = awsctx.WithMetadata(t.Context(), metadata)
	owner := kms.NewWithConfig(kms.Config{Clock: f.clock, Authorizer: f.adapter.Authorizer})
	defer owner.Close()
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root"})
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kms": owner})
	result, wire := commands.Call(root, "kms", "CreateKey", []byte(`{}`))
	if wire != nil {
		t.Fatal(wire)
	}
	keyARN := string(*result.Output.(*kmsapi.CreateKeyOutput).KeyMetadata.Arn)
	effects := AppConfigEffects{Keys: ServiceDataKeys{KMS: owner, Activity: f.adapter.IAM.(IAMActivity), Service: "appconfig"}}
	plain := bytes.Repeat([]byte("protected configuration value "), 400)
	encrypted, resolved, err := effects.Protect(f.ctx, scope, keyARN, resource, plain)
	if err != nil || resolved != keyARN {
		t.Fatalf("GenerateDataKey with native version context: %s %v", resolved, err)
	}
	if bytes.Contains(encrypted, plain) {
		t.Fatal("retained ciphertext exposes configuration")
	}
	_, err = effects.Unprotect(f.ctx, scope, keyARN, resource, encrypted)
	var rejected *awswire.Error
	if !errors.As(err, &rejected) || rejected.Code != "AccessDeniedException" {
		t.Fatalf("caller without Decrypt should fail: %v", err)
	}
	f.user.IdentityPolicies.Inline["decrypt"] = `{"Statement":{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	recovered, err := effects.Unprotect(f.ctx, scope, keyARN, resource, encrypted)
	if err != nil || !bytes.Equal(recovered, plain) {
		t.Fatalf("authorized framed content decrypt: %v", err)
	}
	// Previously persisted unsigned envelopes still carry only the resource
	// context and must remain readable after signed writes are enabled.
	contextKey, err := appConfigEncryptionContext(resource)
	if err != nil {
		t.Fatal(err)
	}
	legacyKey, legacyWrapped, _, wire := effects.Keys.GenerateDataKey(f.ctx, keyARN, map[string]string{contextKey: resource})
	if wire != nil {
		t.Fatal(wire)
	}
	defer clear(legacyKey)
	legacyEnvelope, err := awsenvelope.Seal(legacyKey, legacyWrapped, keyARN, map[string]string{contextKey: resource}, plain)
	if err != nil {
		t.Fatal(err)
	}
	legacy := make([]byte, 4, 4+len(legacyWrapped)+len(legacyEnvelope))
	binary.BigEndian.PutUint32(legacy, uint32(len(legacyWrapped)))
	legacy = append(legacy, legacyWrapped...)
	legacy = append(legacy, legacyEnvelope...)
	recovered, err = effects.Unprotect(f.ctx, scope, keyARN, resource, legacy)
	if err != nil || !bytes.Equal(recovered, plain) {
		t.Fatalf("legacy unsigned content recovery: %v", err)
	}
	if _, err = effects.Unprotect(f.ctx, scope, keyARN, resource+"2", encrypted); err == nil {
		t.Fatal("ciphertext moved to another hosted version")
	}
	tampered := bytes.Clone(encrypted)
	tampered[len(tampered)-1] ^= 1
	if _, err = effects.Unprotect(f.ctx, scope, keyARN, resource, tampered); err == nil {
		t.Fatal("tampered encrypted configuration accepted")
	}
	keyInput, _ := json.Marshal(map[string]string{"KeyId": keyARN})
	if _, wire = commands.Call(root, "kms", "DisableKey", keyInput); wire != nil {
		t.Fatal(wire)
	}
	if _, err = effects.Unprotect(f.ctx, scope, keyARN, resource, encrypted); err == nil {
		t.Fatal("configuration decrypt cached a disabled KMS key")
	}
}

func TestAppConfigExtensionTaggedCreateRequiresCurrentIAM(t *testing.T) {
	f := newLambdaRoleFixture(t)
	f.user.IdentityPolicies.Inline = map[string]string{
		"controls":  `{"Statement":{"Effect":"Allow","Action":"appconfig:*","Resource":"*"}}`,
		"deny-tags": `{"Statement":{"Effect":"Deny","Action":"appconfig:TagResource","Resource":"*"}}`,
	}
	update := func() {
		t.Helper()
		f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	}
	update()
	service := appconfig.New(appconfig.Config{Clock: f.clock, Authorizer: f.adapter.Authorizer})
	defer service.Close()
	call := func(action string, input any) (any, error) {
		return appConfigCommand(f.ctx, service, "appconfig", action, input)
	}
	must := func(action string, input any) any {
		t.Helper()
		out, err := call(action, input)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return out
	}
	denied := func(action string, input any) {
		t.Helper()
		_, err := call(action, input)
		var wire *awswire.Error
		if !errors.As(err, &wire) || (wire.Code != "AccessDenied" && wire.Code != "AccessDeniedException") {
			t.Fatalf("%s must enforce dependent TagResource: %v", action, err)
		}
	}
	create := &appconfigapi.CreateExtensionInput{
		Name: new(appconfigapi.ExtensionOrParameterName("tag-gated-extension")),
		Actions: appconfigapi.ActionsMap{appconfigapi.ActionPointPRE_START_DEPLOYMENT: {{
			Name: new(appconfigapi.Name("validate")),
			Uri:  new(appconfigapi.Uri("arn:aws:lambda:us-east-1:123456789012:function:validate")),
		}}},
		Tags: appconfigapi.TagMap{"gate": "required"},
	}
	denied("CreateExtension", create)
	listed := must("ListExtensions", &appconfigapi.ListExtensionsInput{}).(*appconfigapi.Extensions)
	if len(listed.Items) != 0 {
		t.Fatal("denied tagging committed an extension")
	}
	create.Tags = nil
	first := must("CreateExtension", create).(*appconfigapi.Extension)
	create.Tags = appconfigapi.TagMap{"gate": "required"}
	denied("CreateExtension", create) // Idempotency does not bypass current IAM.
	create.LatestVersionNumber = new(appconfigapi.Integer(1))
	create.Description = new(appconfigapi.Description("version-two"))
	denied("CreateExtension", create)
	retained := must("GetExtension", &appconfigapi.GetExtensionInput{ExtensionIdentifier: new(appconfigapi.Identifier(*first.Id))}).(*appconfigapi.Extension)
	if *retained.VersionNumber != 1 {
		t.Fatal("denied tagged version advanced the extension")
	}
	app := must("CreateApplication", &appconfigapi.CreateApplicationInput{Name: new(appconfigapi.Name("tag-gated-app"))}).(*appconfigapi.Application)
	associate := &appconfigapi.CreateExtensionAssociationInput{
		ExtensionIdentifier: new(appconfigapi.Identifier(*first.Id)),
		ResourceIdentifier:  new(appconfigapi.Identifier("arn:aws:appconfig:us-east-1:123456789012:application/" + string(*app.Id))),
		Tags:                appconfigapi.TagMap{"gate": "required"},
	}
	denied("CreateExtensionAssociation", associate)
	associations := must("ListExtensionAssociations", &appconfigapi.ListExtensionAssociationsInput{}).(*appconfigapi.ExtensionAssociations)
	if len(associations.Items) != 0 {
		t.Fatal("denied tagging committed an association")
	}
	delete(f.user.IdentityPolicies.Inline, "deny-tags")
	update()
	second := must("CreateExtension", create).(*appconfigapi.Extension)
	if *second.VersionNumber != 2 || *second.Id != *first.Id {
		t.Fatal("current TagResource permission did not admit the next version")
	}
	create.LatestVersionNumber = nil
	same := must("CreateExtension", create).(*appconfigapi.Extension)
	if *same.VersionNumber != 2 {
		t.Fatal("authorized idempotent create advanced the extension")
	}
	association := must("CreateExtensionAssociation", associate).(*appconfigapi.ExtensionAssociation)
	tags := must("ListTagsForResource", &appconfigapi.ListTagsForResourceInput{ResourceArn: association.Arn}).(*appconfigapi.ResourceTags)
	if tags.Tags["gate"] != "required" {
		t.Fatal("authorized association lost its tags")
	}
	f.user.IdentityPolicies.Inline["deny-tags"] = `{"Statement":{"Effect":"Deny","Action":"appconfig:TagResource","Resource":"*"}}`
	update()
	denied("CreateExtensionAssociation", associate)
	associations = must("ListExtensionAssociations", &appconfigapi.ListExtensionAssociationsInput{}).(*appconfigapi.ExtensionAssociations)
	if len(associations.Items) != 1 || *associations.Items[0].Id != *association.Id {
		t.Fatal("revoked tag authority created another association")
	}
}

func TestAppConfigSignedContentRequiresCurrentKMSContextPolicy(t *testing.T) {
	f := newLambdaRoleFixture(t)
	scope := appconfig.Scope{Partition: "aws", AccountID: f.scope.AccountID, Region: "us-east-1"}
	resource := appConfigARN(scope, "application/app0001/configurationprofile/prof001/hostedconfigurationversion/1")
	contextKey, err := appConfigEncryptionContext(resource)
	if err != nil {
		t.Fatal(err)
	}
	f.user.IdentityPolicies.Inline = map[string]string{"kms": `{"Statement":{"Effect":"Allow","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*"}}`}
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	credential, err := f.adapter.Credentials.CreateAccessKey(identity.Principal{AccountID: scope.AccountID, ARN: f.user.Arn, ID: f.user.UserId, UserName: f.user.UserName})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := identity.RequestMetadata(credential, credential.AccessKeyID, scope.Region, "appconfig-signed-kms-test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := awsctx.WithMetadata(t.Context(), metadata)
	owner := kms.NewWithConfig(kms.Config{Clock: f.clock, Authorizer: f.adapter.Authorizer})
	defer owner.Close()
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root"})
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kms": owner})
	ownerStatement := `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"}`
	// Explicit key-policy denials apply even though the caller's current IAM
	// policy allows both data-key operations.
	policy := `{"Statement":[` + ownerStatement + `,{"Effect":"Deny","Principal":"*","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*","Condition":{"Null":{"kms:EncryptionContext:aws-crypto-public-key":"true"}}},{"Effect":"Deny","Principal":"*","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*","Condition":{"StringNotEquals":{"kms:EncryptionContext:` + contextKey + `":"` + resource + `"}}}]}`
	input, err := json.Marshal(map[string]string{"Policy": policy})
	if err != nil {
		t.Fatal(err)
	}
	result, wire := commands.Call(root, "kms", "CreateKey", input)
	if wire != nil {
		t.Fatal(wire)
	}
	keyARN := string(*result.Output.(*kmsapi.CreateKeyOutput).KeyMetadata.Arn)
	effects := AppConfigEffects{Keys: ServiceDataKeys{KMS: owner, Activity: f.adapter.IAM.(IAMActivity), Service: "appconfig"}}
	plain := []byte("configuration protected by signed encryption context")
	payload, _, err := effects.Protect(ctx, scope, keyARN, resource, plain)
	if err != nil {
		t.Fatalf("signed GenerateDataKey denied by public-key policy: %v", err)
	}
	size := binary.BigEndian.Uint32(payload)
	wrapped := payload[4 : 4+size]
	encryptionContext, err := awsenvelope.EncryptionContext(payload[4+size:], map[string]string{contextKey: resource})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := encryptionContext["aws-crypto-public-key"]
	if publicKey == "" {
		t.Fatal("signed envelope omitted public key")
	}
	// Pin the actual signer to prove Decrypt forwards the retained public key,
	// not a newly generated key or merely a nonempty placeholder.
	policy = `{"Statement":[` + ownerStatement + `,{"Effect":"Deny","Principal":"*","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*","Condition":{"StringNotEquals":{"kms:EncryptionContext:aws-crypto-public-key":"` + publicKey + `"}}},{"Effect":"Deny","Principal":"*","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*","Condition":{"StringNotEquals":{"kms:EncryptionContext:` + contextKey + `":"` + resource + `"}}}]}`
	putPolicy := func(document string) {
		t.Helper()
		body, marshalErr := json.Marshal(map[string]string{"KeyId": keyARN, "PolicyName": "default", "Policy": document})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, rejected := commands.Call(root, "kms", "PutKeyPolicy", body); rejected != nil {
			t.Fatal(rejected)
		}
	}
	putPolicy(policy)
	for name, candidate := range map[string]map[string]string{
		"missing public key": {contextKey: resource},
		"wrong public key":   {contextKey: resource, "aws-crypto-public-key": "wrong"},
		"wrong resource":     {contextKey: resource + "2", "aws-crypto-public-key": publicKey},
	} {
		t.Run(name, func(t *testing.T) {
			key, _, _, rejected := effects.Keys.GenerateDataKey(ctx, keyARN, candidate)
			clear(key)
			if rejected == nil || rejected.Code != "AccessDeniedException" {
				t.Fatalf("GenerateDataKey context policy: %v", rejected)
			}
			key, _, rejected = effects.Keys.Decrypt(ctx, wrapped, candidate)
			clear(key)
			if rejected == nil || rejected.Code != "AccessDeniedException" {
				t.Fatalf("Decrypt context policy: %v", rejected)
			}
		})
	}
	key, _, _, rejected := effects.Keys.GenerateDataKey(ctx, keyARN, encryptionContext)
	clear(key)
	if rejected != nil {
		t.Fatalf("GenerateDataKey with exact signed context: %v", rejected)
	}
	recovered, err := effects.Unprotect(ctx, scope, keyARN, resource, payload)
	if err != nil || !bytes.Equal(recovered, plain) {
		t.Fatalf("Decrypt with exact signed context: %v", err)
	}
	if _, err = effects.Unprotect(ctx, scope, keyARN, resource+"2", payload); err == nil {
		t.Fatal("signed ciphertext accepted under another resource")
	}
	f.user.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"kms:Decrypt","Resource":"*"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	if _, err = effects.Unprotect(ctx, scope, keyARN, resource, payload); err == nil {
		t.Fatal("signed decrypt reused revoked IAM authority")
	}
	delete(f.user.IdentityPolicies.Inline, "deny")
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	putPolicy(`{"Statement":[` + ownerStatement + `,{"Effect":"Deny","Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}`)
	if _, err = effects.Unprotect(ctx, scope, keyARN, resource, payload); err == nil {
		t.Fatal("signed decrypt reused revoked key policy")
	}
}

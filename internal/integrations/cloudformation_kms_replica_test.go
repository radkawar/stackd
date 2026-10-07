package integrations

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/kms"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/account"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
	"stackd/storage/memory"
)

const cfnKMSReplicaTestAccount = "111122223333"

func cfnKMSReplicaTestContext(ctx context.Context, accountID, region, partition string) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{AccountID: accountID, Region: region, Partition: partition, PrincipalARN: fmt.Sprintf("arn:%s:iam::%s:root", partition, accountID), PrincipalID: accountID})
}

func cfnKMSReplicaTestService(t *testing.T, backend kms.Storage, source *clock.Manual) *kms.Service {
	t.Helper()
	regions := account.New(account.Config{Clock: source})
	roles := iam.NewWithConfig(iam.Config{Clock: source})
	t.Cleanup(func() { _ = regions.Close(); _ = roles.Close() })
	s := kms.NewWithConfig(kms.Config{Storage: backend, Clock: source, Regions: regions, Roles: roles})
	t.Cleanup(func() { _ = s.Close() })
	if err := roles.RegisterServiceLinkedRole(KMSRoleTemplate(), KMSRoleUsage{Keys: s}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCFNKMSReplicaUnavailableDependenciesRemainNativeFailures(t *testing.T) {
	for _, dependency := range []string{"role provider", "role template", "region provider"} {
		t.Run(dependency, func(t *testing.T) {
			source := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
			regions := account.New(account.Config{Clock: source})
			roles := iam.NewWithConfig(iam.Config{Clock: source})
			t.Cleanup(func() { _ = regions.Close(); _ = roles.Close() })
			config := kms.Config{Storage: kms.NewMemoryStorage(nil), Clock: source, Regions: regions, Roles: roles}
			if dependency == "role provider" {
				config.Roles = nil
			}
			if dependency == "region provider" {
				config.Regions = nil
			}
			owner := kms.NewWithConfig(config)
			t.Cleanup(func() { _ = owner.Close() })
			if dependency == "region provider" {
				if err := roles.RegisterServiceLinkedRole(KMSRoleTemplate(), KMSRoleUsage{Keys: owner}); err != nil {
					t.Fatal(err)
				}
			}
			commands := cfnKMSReplicaTestCommands(owner)
			east := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-east-1", "aws")
			destination := east
			var err error
			if dependency == "region provider" {
				primary := cfnKMSReplicaTestPrimary(t, commands, east)
				destination = cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-west-2", "aws")
				_, err = (cfnKMSReplicaKey{commands}).Create(destination, cfnKMSReplicaTestRequest(cfnComputeValue(primary.Arn)))
			} else {
				r := cfnKMSReplicaTestRequest("")
				r.Type, r.Properties = "AWS::KMS::Key", cloudformation.Properties{"MultiRegion": true}
				_, err = (cfnKMSKey{commands}).Create(east, r)
			}
			cfnKMSReplicaTestCode(t, err, "UnsupportedOperationException")
			keys, err := cfnComputeCall[api.ListKeysOutput](destination, commands, "kms", "ListKeys", map[string]any{})
			if err != nil || len(keys.Keys) != 0 {
				t.Fatalf("missing dependency fabricated a key: %+v %v", keys, err)
			}
		})
	}
}

func cfnKMSReplicaTestCommands(s *kms.Service) StepFunctionsCommands {
	return NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kms": s})
}

func cfnKMSReplicaTestRequest(primary string) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{Type: "AWS::KMS::ReplicaKey", StackID: "stack", StackName: "stack", LogicalID: "Replica", Token: "incarnation-a", Scope: cloudformation.Scope{Account: cfnKMSReplicaTestAccount, Region: "us-west-2", Partition: "aws"}, Properties: cloudformation.Properties{
		"PrimaryKeyArn": primary, "KeyPolicy": map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::" + cfnKMSReplicaTestAccount + ":root"}, "Action": "kms:*", "Resource": "*"}}},
		"Description": "regional replica", "PendingWindowInDays": 7, "Tags": []any{map[string]any{"Key": "team", "Value": "replica"}},
	}}
}

func cfnKMSReplicaTestPrimary(t *testing.T, commands StepFunctionsCommands, ctx context.Context) *api.KeyMetadata {
	t.Helper()
	out, err := cfnComputeCall[api.CreateKeyOutput](ctx, commands, "kms", "CreateKey", map[string]any{"MultiRegion": true, "Description": "primary"})
	if err != nil {
		t.Fatal(err)
	}
	return out.KeyMetadata
}

func cfnKMSReplicaTestCode(t *testing.T, err error, code string) {
	t.Helper()
	var rejected *awswire.Error
	if !errors.As(err, &rejected) || rejected.Code != code {
		t.Fatalf("error = %v; want %s", err, code)
	}
}

func TestCFNKMSRegistryImplementsThreeOfficialTypes(t *testing.T) {
	registry := CloudFormationKMSHandlers(StepFunctionsCommands{})
	if len(registry) != 3 {
		t.Fatalf("KMS registry has %d resource types", len(registry))
	}
	for _, name := range []string{"Key", "Alias", "ReplicaKey"} {
		handler := registry["AWS::KMS::"+name]
		if handler == nil {
			t.Fatalf("missing %s", name)
		}
		if _, ok := handler.(cloudformation.ResourceReader); !ok {
			t.Fatalf("%s lacks live read/list", name)
		}
		if _, ok := handler.(cloudformation.ResourceResultReader); !ok {
			t.Fatalf("%s lacks fresh result attributes", name)
		}
	}
}

func TestCFNKMSReplicaLifecycleSharesActualCryptographicMaterial(t *testing.T) {
	source := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	backend := kms.NewMemoryStorage(memory.NewDomain())
	service := cfnKMSReplicaTestService(t, backend, source)
	commands := cfnKMSReplicaTestCommands(service)
	east := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-east-1", "aws")
	west := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-west-2", "aws")
	primary := cfnKMSReplicaTestPrimary(t, commands, east)
	r := cfnKMSReplicaTestRequest(cfnComputeValue(primary.Arn))
	h := cfnKMSReplicaKey{commands}
	result, err := h.Create(west, r)
	if err != nil {
		t.Fatal(err)
	}
	id := cfnComputeValue(primary.KeyId)
	arn := "arn:aws:kms:us-west-2:" + cfnKMSReplicaTestAccount + ":key/" + id
	if result.PhysicalID != id || result.Ref != id || result.Attributes["KeyId"] != id || result.Attributes["Arn"] != arn {
		t.Fatalf("official ReplicaKey identifier/Ref/GetAtt contract = %+v", result)
	}
	r.PhysicalID = id
	if ready, err := h.Stabilize(west, r); err != nil || ready {
		t.Fatalf("replica did not expose real Creating state: %v %v", ready, err)
	}
	if err := source.Advance(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if ready, err := h.Stabilize(west, r); err != nil || !ready {
		t.Fatalf("replica did not stabilize: %v %v", ready, err)
	}
	plain := []byte("CFN replica cross-Region plaintext")
	// SDK documents project blob fields as UTF-8 text. Preserve actual binary
	// ciphertext through the existing typed command boundary, not wire base64.
	encrypted, wire := commands.CallTyped(east, "kms", "Encrypt", &api.EncryptInput{KeyId: new(api.KeyIdType(id)), Plaintext: plain, EncryptionContext: api.EncryptionContextType{"consumer": "cloudformation"}})
	if wire != nil {
		t.Fatal(wire)
	}
	cipher := encrypted.Output.(*api.EncryptOutput)
	decryption, wire := commands.CallTyped(west, "kms", "Decrypt", &api.DecryptInput{CiphertextBlob: cipher.CiphertextBlob, EncryptionContext: api.EncryptionContextType{"consumer": "cloudformation"}})
	if wire != nil {
		t.Fatalf("replica could not decrypt the primary's actual ciphertext: %v", wire)
	}
	decrypted := decryption.Output.(*api.DecryptOutput)
	if !bytes.Equal(decrypted.Plaintext, plain) || cfnComputeValue(decrypted.KeyId) != arn {
		t.Fatalf("replica did not use the primary's real material and local routing: %+v", decrypted)
	}
	// Native mutation is independent of stack authority, and Read is live.
	if err := cfnComputeRun(west, commands, "kms", "UpdateKeyDescription", map[string]any{"KeyId": id, "Description": "native drift"}); err != nil {
		t.Fatal(err)
	}
	read, err := h.Read(west, cloudformation.ResourceRequest{PhysicalID: id, CloudControl: true})
	if err != nil || read["Description"] != "native drift" || read["PrimaryKeyArn"] != cfnComputeValue(primary.Arn) || read["Arn"] != arn || read["KeyId"] != id || read["KeyPolicy"] == nil {
		t.Fatalf("live replica read = %+v %v", read, err)
	}
	if _, present := read["PendingWindowInDays"]; present {
		t.Fatal("write-only PendingWindowInDays leaked into Read")
	}
	r.Previous = maps.Clone(r.Properties)
	r.Properties = maps.Clone(r.Properties)
	r.Properties["Description"], r.Properties["Enabled"] = "CFN update", false
	r.Properties["Tags"] = []any{map[string]any{"Key": "project", "Value": "updated"}}
	policy := maps.Clone(r.Properties["KeyPolicy"].(map[string]any))
	policy["Id"] = "updated regional policy"
	r.Properties["KeyPolicy"] = policy
	if _, err := h.Update(west, r); err != nil {
		t.Fatal(err)
	}
	read, err = h.Read(west, cloudformation.ResourceRequest{PhysicalID: id, CloudControl: true})
	if err != nil || read["Description"] != "CFN update" || read["Enabled"] != false || !reflect.DeepEqual(read["Tags"], []any{map[string]any{"Key": "project", "Value": "updated"}}) {
		t.Fatalf("real replica update = %+v %v", read, err)
	}
	if read["KeyPolicy"].(map[string]any)["Id"] != "updated regional policy" {
		t.Fatal("replica policy update did not reach the real KMS policy owner", read)
	}
	original, err := cfnComputeCall[api.DescribeKeyOutput](east, commands, "kms", "DescribeKey", map[string]any{"KeyId": id})
	if err != nil || cfnComputeValue(original.KeyMetadata.Description) != "primary" || original.KeyMetadata.Enabled == nil || !bool(*original.KeyMetadata.Enabled) {
		t.Fatalf("replica mutation changed primary's independent metadata: %+v %v", original, err)
	}
	r.Previous = maps.Clone(r.Properties)
	delete(r.Properties, "Enabled")
	if _, err := h.Update(west, r); err != nil {
		t.Fatal(err)
	}
	read, err = h.Read(west, cloudformation.ResourceRequest{PhysicalID: id, CloudControl: true})
	if err != nil || read["Enabled"] != true {
		t.Fatalf("removing Enabled did not restore the official true default: %+v %v", read, err)
	}
	if err := h.Delete(west, r); err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(west, r); err != nil {
		t.Fatal("scheduled deletion was not idempotent", err)
	}
	deleted, err := cfnComputeCall[api.DescribeKeyOutput](west, commands, "kms", "DescribeKey", map[string]any{"KeyId": id})
	if err != nil || cfnComputeValue(deleted.KeyMetadata.KeyState) != "PendingDeletion" || deleted.KeyMetadata.DeletionDate == nil || !deleted.KeyMetadata.DeletionDate.Equal(source.Now().Add(7*24*time.Hour)) {
		t.Fatalf("CFN deletion was not actual scheduled deletion: %+v %v", deleted, err)
	}
	_, err = h.Read(west, cloudformation.ResourceRequest{PhysicalID: id, CloudControl: true})
	cfnKMSReplicaTestCode(t, err, "NotFoundException")
	rows, err := h.List(west, cloudformation.ResourceRequest{CloudControl: true})
	if err != nil || len(rows) != 0 {
		t.Fatalf("official Cloud Control list exposed a scheduled-deletion replica: %+v %v", rows, err)
	}
	if err := backend.View(west, func(reader kms.Reader) error {
		keys, err := reader.Keys(kms.StorageScope{Partition: "aws", AccountID: cfnKMSReplicaTestAccount, Region: "us-west-2"})
		if err == nil && (len(keys) != 1 || keys[0].Owner != (kms.KeyResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})) {
			t.Fatal("scheduled deletion lost its regional incarnation", keys)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCFNKMSReplicaRecoveryAndStaleRollbackNeverAdoptRecreatedKey(t *testing.T) {
	source := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	backend := kms.NewMemoryStorage(nil)
	service := cfnKMSReplicaTestService(t, backend, source)
	commands := cfnKMSReplicaTestCommands(service)
	east := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-east-1", "aws")
	west := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-west-2", "aws")
	primary := cfnKMSReplicaTestPrimary(t, commands, east)
	r := cfnKMSReplicaTestRequest(cfnComputeValue(primary.Arn))
	h := cfnKMSReplicaKey{commands}
	first, err := h.Create(west, r)
	if err != nil {
		t.Fatal(err)
	}
	_ = service.Close()
	service = cfnKMSReplicaTestService(t, backend, source)
	commands = cfnKMSReplicaTestCommands(service)
	h = cfnKMSReplicaKey{commands}
	recovered, err := h.Create(west, r)
	if err != nil || !reflect.DeepEqual(first, recovered) {
		t.Fatalf("durable owner replay did not recover the same replica: %+v %v", recovered, err)
	}
	r.PhysicalID = first.PhysicalID
	wrong := r
	wrong.Token = "incarnation-b"
	_, err = h.Create(west, wrong)
	cfnKMSReplicaTestCode(t, err, "AlreadyExistsException")
	if err := h.Delete(west, r); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(7 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	// The same multi-Region ID and identical tags/policy do not identify the
	// old regional incarnation after the real KMS deletion window expires.
	if _, err := cfnComputeCall[api.ReplicateKeyOutput](east, commands, "kms", "ReplicateKey", map[string]any{"KeyId": cfnComputeValue(primary.KeyId), "ReplicaRegion": "us-west-2", "Description": "regional replica", "Tags": cfnKMSTags(cfnComputeOwnedTags(r))}); err != nil {
		t.Fatal(err)
	}
	_, err = h.Create(west, r)
	cfnKMSReplicaTestCode(t, err, "AlreadyExistsException")
	cfnKMSReplicaTestCode(t, h.Delete(west, r), "AccessDeniedException")
	if err := source.Advance(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	r.Previous = maps.Clone(r.Properties)
	_, err = h.Update(west, r)
	cfnKMSReplicaTestCode(t, err, "AccessDeniedException")
	foreign, err := cfnComputeCall[api.DescribeKeyOutput](west, commands, "kms", "DescribeKey", map[string]any{"KeyId": r.PhysicalID})
	if err != nil || cfnComputeValue(foreign.KeyMetadata.KeyState) != "Enabled" {
		t.Fatalf("stale rollback changed the foreign key: %+v %v", foreign, err)
	}
}

func TestCFNKMSReplicaOfficialAdmissionAndReplacement(t *testing.T) {
	p := cfnKMSReplicaTestRequest("arn:aws:kms:us-east-1:" + cfnKMSReplicaTestAccount + ":key/mrk-0123456789abcdef0123456789abcdef").Properties
	h := cfnKMSReplicaKey{}
	if err := h.Validate(p); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"PrimaryKeyArn": "mrk-0123456789abcdef0123456789abcdef", "KeyPolicy": nil, "PendingWindowInDays": 6, "Enabled": "true", "Arn": "read-only", "MultiRegion": true, "EnableKeyRotation": true} {
		bad := maps.Clone(p)
		bad[name] = value
		if err := h.Validate(bad); err == nil {
			t.Fatalf("accepted invalid official ReplicaKey property %s", name)
		}
	}
	bad := maps.Clone(p)
	bad["PrimaryKeyArn"] = "arn:aws:kms:us-east-1:" + cfnKMSReplicaTestAccount + ":alias/primary"
	if err := h.Validate(bad); err == nil {
		t.Fatal("accepted a primary alias ARN")
	}
	bad = maps.Clone(p)
	bad["Description"] = strings.Repeat("x", 8193)
	if err := h.Validate(bad); err == nil {
		t.Fatal("accepted an oversized Description")
	}
	changed := maps.Clone(p)
	changed["PrimaryKeyArn"] = "arn:aws:kms:us-east-1:" + cfnKMSReplicaTestAccount + ":key/mrk-fedcba9876543210fedcba9876543210"
	if replace, err := h.Replacement(p, changed); err != nil || !replace {
		t.Fatalf("PrimaryKeyArn is not replacement-only: %v %v", replace, err)
	}
	changed = maps.Clone(p)
	changed["Description"], changed["Enabled"], changed["PendingWindowInDays"] = "update", false, 30
	if replace, err := h.Replacement(p, changed); err != nil || replace {
		t.Fatalf("mutable replica properties replaced the key: %v %v", replace, err)
	}
	if err := h.ValidateDeletionPolicy("Snapshot"); err == nil {
		t.Fatal("KMS admitted a fake snapshot effect")
	}
}

func TestCFNKMSReplicaDiscoveryAndMutationsKeepNativeAuthorityAndScope(t *testing.T) {
	source := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	service := cfnKMSReplicaTestService(t, kms.NewMemoryStorage(nil), source)
	commands := cfnKMSReplicaTestCommands(service)
	east := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-east-1", "aws")
	west := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-west-2", "aws")
	primary := cfnKMSReplicaTestPrimary(t, commands, east)
	h := cfnKMSReplicaKey{commands}
	r := cfnKMSReplicaTestRequest(cfnComputeValue(primary.Arn))
	result, err := h.Create(west, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	rows, err := h.List(west, cloudformation.ResourceRequest{CloudControl: true})
	if err != nil || len(rows) != 1 || rows[0].Identifier != result.PhysicalID || rows[0].Properties["PrimaryKeyArn"] != cfnComputeValue(primary.Arn) {
		t.Fatalf("regional replica discovery = %+v %v", rows, err)
	}
	for _, ctx := range []context.Context{east, cfnKMSReplicaTestContext(t.Context(), "999988887777", "us-west-2", "aws"), cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-west-2", "aws-us-gov")} {
		rows, err := h.List(ctx, cloudformation.ResourceRequest{CloudControl: true})
		if err != nil || len(rows) != 0 {
			t.Fatalf("replica discovery leaked across scope: %+v %v", rows, err)
		}
		_, err = h.Read(ctx, cloudformation.ResourceRequest{CloudControl: true, PhysicalID: result.Attributes["Arn"].(string)})
		cfnKMSReplicaTestCode(t, err, "NotFoundException")
	}
	denied := awsctx.FromContext(west)
	denied.PrincipalARN, denied.PrincipalID = "arn:aws:iam::"+cfnKMSReplicaTestAccount+":user/denied", "denied"
	deniedctx := awsctx.WithMetadata(west, denied)
	_, err = h.List(deniedctx, cloudformation.ResourceRequest{CloudControl: true})
	cfnKMSReplicaTestCode(t, err, "AccessDeniedException")
	_, err = h.Read(deniedctx, cloudformation.ResourceRequest{CloudControl: true, PhysicalID: result.PhysicalID})
	cfnKMSReplicaTestCode(t, err, "AccessDeniedException")
	_, err = h.Create(deniedctx, r)
	cfnKMSReplicaTestCode(t, err, "AccessDeniedException")
	// Direct Cloud Control mutates under native authority without claiming or
	// stripping the stack's hard owner incarnation.
	r.CloudControl, r.PhysicalID = true, result.PhysicalID
	r.Previous = maps.Clone(r.Properties)
	r.Properties = maps.Clone(r.Properties)
	r.Properties["Description"] = "native-authority Cloud Control"
	_, err = h.Update(deniedctx, r)
	cfnKMSReplicaTestCode(t, err, "AccessDeniedException")
	cfnKMSReplicaTestCode(t, h.Delete(deniedctx, r), "AccessDeniedException")
	if _, err := h.Update(west, r); err != nil {
		t.Fatal(err)
	}
	r.CloudControl = false
	if _, err := h.Read(west, r); err != nil {
		t.Fatal("Cloud Control destroyed the stack's incarnation", err)
	}
}

func TestCFNKMSReplicaRejectsInvalidPrimaryStateAndPolicyWithoutCreatingOrdinaryKeys(t *testing.T) {
	source := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	owner := cfnKMSReplicaTestService(t, kms.NewMemoryStorage(nil), source)
	commands := cfnKMSReplicaTestCommands(owner)
	east := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-east-1", "aws")
	west := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-west-2", "aws")
	h := cfnKMSReplicaKey{commands}
	single, err := cfnComputeCall[api.CreateKeyOutput](east, commands, "kms", "CreateKey", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Create(west, cfnKMSReplicaTestRequest(cfnComputeValue(single.KeyMetadata.Arn)))
	cfnKMSReplicaTestCode(t, err, "UnsupportedOperationException")
	primary := cfnKMSReplicaTestPrimary(t, commands, east)
	r := cfnKMSReplicaTestRequest(cfnComputeValue(primary.Arn))
	if _, err := h.Create(east, r); err == nil {
		t.Fatal("accepted the primary Region as the replica Region")
	}
	if err := cfnComputeRun(east, commands, "kms", "DisableKey", map[string]any{"KeyId": cfnComputeValue(primary.KeyId)}); err != nil {
		t.Fatal(err)
	}
	// Matches the retained native replicate_disabled_primary observation.
	_, err = h.Create(west, r)
	cfnKMSReplicaTestCode(t, err, "DisabledException")
	if err := cfnComputeRun(east, commands, "kms", "EnableKey", map[string]any{"KeyId": cfnComputeValue(primary.KeyId)}); err != nil {
		t.Fatal(err)
	}
	r.Properties["KeyPolicy"] = map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::" + cfnKMSReplicaTestAccount + ":root"}, "Action": "kms:Encrypt", "Resource": "*"}}}
	_, err = h.Create(west, r)
	cfnKMSReplicaTestCode(t, err, "MalformedPolicyDocumentException")
	keys, err := cfnComputeCall[api.ListKeysOutput](west, commands, "kms", "ListKeys", map[string]any{})
	if err != nil || len(keys.Keys) != 0 {
		t.Fatalf("failed replication fabricated a regional ordinary key: %+v %v", keys, err)
	}
}

func TestCFNKMSReplicaDisabledCreationAndDirectCreateRecovery(t *testing.T) {
	source := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	owner := cfnKMSReplicaTestService(t, kms.NewMemoryStorage(nil), source)
	commands := cfnKMSReplicaTestCommands(owner)
	east := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-east-1", "aws")
	west := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-west-2", "aws")
	primary := cfnKMSReplicaTestPrimary(t, commands, east)
	r := cfnKMSReplicaTestRequest(cfnComputeValue(primary.Arn))
	r.CloudControl = true
	r.Properties["Enabled"] = false
	h := cfnKMSReplicaKey{commands}
	first, err := h.Create(west, r)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := h.Create(west, r)
	if err != nil || !reflect.DeepEqual(first, recovered) {
		t.Fatalf("direct create retry lost its actual owner incarnation: %+v %v", recovered, err)
	}
	r.PhysicalID = first.PhysicalID
	if err := source.Advance(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if ready, err := h.Stabilize(west, r); err != nil || !ready {
		t.Fatalf("disabled replica creation did not finish: %v %v", ready, err)
	}
	read, err := h.Read(west, cloudformation.ResourceRequest{CloudControl: true, PhysicalID: first.PhysicalID})
	if err != nil || read["Enabled"] != false {
		t.Fatalf("creation did not call the actual regional DisableKey owner: %+v %v", read, err)
	}
	primaryKeys, err := (cfnKMSKey{commands}).List(east, cloudformation.ResourceRequest{CloudControl: true})
	if err != nil || len(primaryKeys) != 1 || primaryKeys[0].Identifier != first.PhysicalID {
		t.Fatalf("primary key type discovery = %+v %v", primaryKeys, err)
	}
	replicaAsKeys, err := (cfnKMSKey{commands}).List(west, cloudformation.ResourceRequest{CloudControl: true})
	if err != nil || len(replicaAsKeys) != 0 {
		t.Fatalf("AWS::KMS::Key discovery mislabeled a replica: %+v %v", replicaAsKeys, err)
	}
}

func TestCFNKMSKeyHardOwnerDoesNotAdoptForgedOwnershipTags(t *testing.T) {
	source := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	owner := cfnKMSReplicaTestService(t, kms.NewMemoryStorage(nil), source)
	commands := cfnKMSReplicaTestCommands(owner)
	ctx := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-west-2", "aws")
	r := cfnKMSReplicaTestRequest("")
	r.Type, r.LogicalID, r.Properties = "AWS::KMS::Key", "Key", cloudformation.Properties{}
	foreign, err := cfnComputeCall[api.CreateKeyOutput](ctx, commands, "kms", "CreateKey", map[string]any{"Tags": cfnKMSTags(cfnComputeOwnedTags(r))})
	if err != nil {
		t.Fatal(err)
	}
	h := cfnKMSKey{commands}
	result, err := h.Create(ctx, r)
	if err != nil || result.PhysicalID == cfnComputeValue(foreign.KeyMetadata.KeyId) {
		t.Fatalf("tag-based recovery adopted a foreign key: %+v %v", result, err)
	}
	recovered, err := h.Create(ctx, r)
	if err != nil || recovered.PhysicalID != result.PhysicalID {
		t.Fatalf("hard-owner key create retry lost identity: %+v %v", recovered, err)
	}
	r.PhysicalID = cfnComputeValue(foreign.KeyMetadata.KeyId)
	cfnKMSReplicaTestCode(t, h.Delete(ctx, r), "AccessDeniedException")
}

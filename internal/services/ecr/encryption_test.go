package ecr_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	ecrapi "stackd/internal/awsapi/ecr"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/integrations"
	"stackd/internal/services/ecr"
	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
	"stackd/journal"
	"stackd/storage/memory"
)

func TestRepositoryEncryptionPayloadsAndTamper(t *testing.T) {
	for _, kind := range []string{"AES256", "KMS"} {
		t.Run(kind, func(t *testing.T) {
			f := newEncryptionFixture(t)
			repo := f.create(t, "encrypted-images", kind)
			manifest, digest := f.push(t, repo.Key)
			f.requireManifest(t, repo.Key, manifest)

			var stored ecr.ImageRecord
			if err := f.repository.View(f.ctx, func(tx ecr.Reader) error {
				var err error
				stored, err = tx.Image(ecr.ImageKey{Repository: repo.Key, Digest: digest})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(stored.Payload, []byte(manifest)) {
				t.Fatal("plaintext manifest was persisted")
			}
			if kind == "KMS" && len(repo.DataKey) != 0 {
				t.Fatal("plaintext KMS data key was persisted")
			}
			original := bytes.Clone(stored.Payload)
			stored.Payload[len(stored.Payload)-1] ^= 1
			if err := f.repository.Update(f.ctx, func(tx ecr.Transaction) error { return tx.PutImage(stored) }); err != nil {
				t.Fatal(err)
			}
			f.requireUnreadable(t, repo.Key, "ServerException")

			// Even under the same repository key, another object identity must
			// not accept a valid ciphertext copied from the first manifest.
			stored.Payload = original
			stored.Key.Digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			stored.Tags = []string{"substituted"}
			if err := f.repository.Update(f.ctx, func(tx ecr.Transaction) error { return tx.PutImage(stored) }); err != nil {
				t.Fatal(err)
			}
			out, rejected := encryptionCommand(f.ctx, f.service, "ecr", "BatchGetImage", &ecrapi.BatchGetImageInput{
				RepositoryName: new(ecrapi.RepositoryName(repo.Key.Name)),
				ImageIds:       ecrapi.ImageIdentifierList{{ImageTag: new(ecrapi.ImageTag("substituted"))}},
			})
			want := "ServerException"
			if kind == "KMS" {
				want = "KmsException"
			}
			if rejected == nil || rejected.Code != want {
				t.Fatalf("ciphertext substitution did not reject the wrong object identity: %v, %v", out, rejected)
			}
		})
	}
}

func TestRepositoryEncryptionManagedKey(t *testing.T) {
	f := newEncryptionFixture(t)
	name := new(ecrapi.RepositoryName("managed-key"))
	out := f.mustECR(t, "CreateRepository", &ecrapi.CreateRepositoryInput{
		RepositoryName:          name,
		EncryptionConfiguration: &ecrapi.EncryptionConfiguration{EncryptionType: new(ecrapi.EncryptionTypeKMS)},
	}).(*ecrapi.CreateRepositoryOutput)
	id := new(kmsapi.KeyIdType(*out.Repository.EncryptionConfiguration.KmsKey))
	metadata := f.mustKMS(t, "DescribeKey", &kmsapi.DescribeKeyInput{KeyId: id}).(*kmsapi.DescribeKeyOutput).KeyMetadata
	if metadata.KeyManager == nil || string(*metadata.KeyManager) != "AWS" {
		t.Fatal("default KMS encryption did not resolve an AWS-managed key")
	}
	manifest, _ := f.push(t, f.key(string(*name)))
	f.requireManifest(t, f.key(string(*name)), manifest)
	f.mustECR(t, "DeleteRepository", &ecrapi.DeleteRepositoryInput{RepositoryName: name, Force: new(ecrapi.ForceFlag(true))})
	remaining := f.mustKMS(t, "ListGrants", &kmsapi.ListGrantsInput{KeyId: id}).(*kmsapi.ListGrantsOutput)
	if len(remaining.Grants) != 0 {
		t.Fatal("managed-key repository deletion retained its grants")
	}
}

func TestRepositoryKMSCurrentKeyAndGrantDenial(t *testing.T) {
	f := newEncryptionFixture(t)
	repo := f.create(t, "current-key", "KMS")
	manifest, _ := f.push(t, repo.Key)
	f.requireManifest(t, repo.Key, manifest)
	id := kmsapi.KeyIdType(repo.KMSKeyID)
	f.mustKMS(t, "DisableKey", &kmsapi.DisableKeyInput{KeyId: &id})
	f.requireUnreadable(t, repo.Key, "KmsException")
	f.mustKMS(t, "EnableKey", &kmsapi.EnableKeyInput{KeyId: &id})
	f.requireManifest(t, repo.Key, manifest)

	policyName := kmsapi.PolicyNameType("default")
	policyOut := f.mustKMS(t, "GetKeyPolicy", &kmsapi.GetKeyPolicyInput{KeyId: &id, PolicyName: &policyName}).(*kmsapi.GetKeyPolicyOutput)
	denyGenerate := kmsapi.PolicyType(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":"kms:GenerateDataKey","Resource":"*","Condition":{"StringEquals":{"kms:EncryptionContext:aws:ecr:arn":%q}}}]}`, repo.ARN))
	f.mustKMS(t, "PutKeyPolicy", &kmsapi.PutKeyPolicyInput{KeyId: &id, PolicyName: &policyName, Policy: &denyGenerate})
	// Blocking new keys must reject a new push, not revoke previously
	// encrypted content whose Decrypt permission is still intact.
	f.requireManifest(t, repo.Key, manifest)
	secondManifest := " " + manifest
	second := &ecrapi.PutImageInput{
		RepositoryName: new(ecrapi.RepositoryName(repo.Key.Name)),
		ImageManifest:  new(ecrapi.ImageManifest(secondManifest)), ImageTag: new(ecrapi.ImageTag("second")),
	}
	_, rejected := encryptionCommand(f.ctx, f.service, "ecr", "PutImage", second)
	if rejected == nil || rejected.Code != "KmsException" {
		t.Fatalf("GenerateDataKey denial did not reject a new manifest: %v", rejected)
	}
	missing := f.mustECR(t, "BatchGetImage", &ecrapi.BatchGetImageInput{
		RepositoryName: second.RepositoryName, ImageIds: ecrapi.ImageIdentifierList{{ImageTag: second.ImageTag}},
	}).(*ecrapi.BatchGetImageOutput)
	if len(missing.Images) != 0 || len(missing.Failures) != 1 || missing.Failures[0].FailureCode == nil || string(*missing.Failures[0].FailureCode) != "ImageNotFound" {
		t.Fatalf("denied manifest push retained image state: %+v", missing)
	}
	f.mustKMS(t, "PutKeyPolicy", &kmsapi.PutKeyPolicyInput{KeyId: &id, PolicyName: &policyName, Policy: policyOut.Policy})
	f.mustECR(t, "PutImage", second)
	readSecond := f.mustECR(t, "BatchGetImage", &ecrapi.BatchGetImageInput{
		RepositoryName: second.RepositoryName, ImageIds: ecrapi.ImageIdentifierList{{ImageTag: second.ImageTag}},
	}).(*ecrapi.BatchGetImageOutput)
	if len(readSecond.Failures) != 0 || len(readSecond.Images) != 1 || readSecond.Images[0].ImageManifest == nil || string(*readSecond.Images[0].ImageManifest) != secondManifest {
		t.Fatalf("restored GenerateDataKey permission did not allow encrypted push/pull: %+v", readSecond)
	}
	policy := kmsapi.PolicyType(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:EncryptionContext:aws:ecr:arn":%q}}}]}`, repo.ARN))
	f.mustKMS(t, "PutKeyPolicy", &kmsapi.PutKeyPolicyInput{KeyId: &id, PolicyName: &policyName, Policy: &policy})
	f.requireUnreadable(t, repo.Key, "KmsException")
	f.mustKMS(t, "PutKeyPolicy", &kmsapi.PutKeyPolicyInput{KeyId: &id, PolicyName: &policyName, Policy: policyOut.Policy})
	f.requireManifest(t, repo.Key, manifest)

	// Each grant is part of the repository's live authority. Keeping another
	// matching grant must not allow a revoked repository grant to be bypassed.
	for index := range repo.Grants {
		t.Run(fmt.Sprintf("grant-%d", index), func(t *testing.T) {
			current := f.create(t, fmt.Sprintf("revoked-%d", index), "KMS")
			f.push(t, current.Key)
			grantID := kmsapi.GrantIdType(current.Grants[index])
			keyID := kmsapi.KeyIdType(current.KMSKeyID)
			f.mustKMS(t, "RevokeGrant", &kmsapi.RevokeGrantInput{KeyId: &keyID, GrantId: &grantID})
			f.requireUnreadable(t, current.Key, "KmsException")
			f.mustECR(t, "DeleteRepository", &ecrapi.DeleteRepositoryInput{
				RepositoryName: new(ecrapi.RepositoryName(current.Key.Name)), Force: new(ecrapi.ForceFlag(true)),
			})
			for _, grant := range f.grants(t) {
				for _, owned := range current.Grants {
					if string(*grant.GrantId) == owned {
						t.Fatal("repository deletion retained an owned KMS grant")
					}
				}
			}
		})
	}
}

func TestRepositoryEncryptionRollbackIncludesGrantsAndEvents(t *testing.T) {
	f := newEncryptionFixture(t)
	f.fail.event = "CreateRepository"
	_, rejected := encryptionCommand(f.ctx, f.service, "ecr", "CreateRepository", f.createInput("rollback-create", "KMS"))
	if rejected == nil {
		t.Fatal("repository creation succeeded after its journal append failed")
	}
	if err := f.repository.View(f.ctx, func(tx ecr.Reader) error {
		_, err := tx.Repository(f.key("rollback-create"))
		return err
	}); !errors.Is(err, ecr.ErrNotFound) {
		t.Fatalf("failed creation retained a repository: %v", err)
	}
	if grants := f.grants(t); len(grants) != 0 {
		t.Fatalf("failed creation retained %d KMS grants", len(grants))
	}
	events, err := f.events.Read(f.ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if call := event.APICallCompleted; call != nil && call.ErrorCode == "" && (call.EventName == "CreateGrant" || call.EventName == "GenerateDataKey" || call.EventName == "CreateRepository") {
			t.Fatalf("failed creation published a successful %s event", call.EventName)
		}
	}

	f.fail.event = ""
	repo := f.create(t, "rollback-delete", "KMS")
	manifest, _ := f.push(t, repo.Key)
	f.fail.event = "DeleteRepository"
	_, rejected = encryptionCommand(f.ctx, f.service, "ecr", "DeleteRepository", &ecrapi.DeleteRepositoryInput{
		RepositoryName: new(ecrapi.RepositoryName(repo.Key.Name)), Force: new(ecrapi.ForceFlag(true)),
	})
	if rejected == nil {
		t.Fatal("repository deletion succeeded after its journal append failed")
	}
	f.fail.event = ""
	f.requireManifest(t, repo.Key, manifest)
	grants := f.grants(t)
	if len(grants) != 2 {
		t.Fatalf("failed deletion did not restore both grants: %d", len(grants))
	}
	f.mustECR(t, "DeleteRepository", &ecrapi.DeleteRepositoryInput{
		RepositoryName: new(ecrapi.RepositoryName(repo.Key.Name)), Force: new(ecrapi.ForceFlag(true)),
	})
	if grants := f.grants(t); len(grants) != 0 {
		t.Fatalf("successful deletion retained %d KMS grants", len(grants))
	}
}

type encryptionFixture struct {
	ctx        context.Context
	service    *ecr.Service
	repository *ecr.MemoryRepository
	kms        *kms.Service
	keyID      string
	events     journal.Storage
	fail       *encryptionRecordFailure
}

func newEncryptionFixture(t *testing.T) *encryptionFixture {
	t.Helper()
	domain := memory.NewDomain()
	c := clock.NewManual(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	events := journal.NewMemory(domain)
	recorder := apievents.New(events)
	activity := iam.NewWithConfig(iam.Config{Repository: iam.NewMemoryRepository(domain), Clock: c})
	keyService := kms.NewWithConfig(kms.Config{Storage: kms.NewMemoryStorage(domain), Clock: c, APIEvents: recorder})
	repo := ecr.NewMemoryRepository(domain)
	fail := &encryptionRecordFailure{Recorder: recorder}
	svc := ecr.New(ecr.Config{Repository: repo, Clock: c, Recorder: fail, PublicEndpoint: "http://127.0.0.1:4566", Keys: integrations.ECRKeys{KMS: keyService, Activity: activity}})
	t.Cleanup(func() { _ = svc.Close(); _ = keyService.Close(); _ = activity.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{
		Partition: "aws", AccountID: "111122223333", Region: "us-east-1", AccessKeyID: "111122223333",
		PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalID: "111122223333", RequestID: "ecr-encryption-test",
	})
	f := &encryptionFixture{ctx: ctx, service: svc, repository: repo, kms: keyService, events: events, fail: fail}
	created := f.mustKMS(t, "CreateKey", &kmsapi.CreateKeyInput{}).(*kmsapi.CreateKeyOutput)
	f.keyID = string(*created.KeyMetadata.Arn)
	return f
}

type encryptionCommands interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}

func encryptionCommand(ctx context.Context, service encryptionCommands, namespace, name string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService(namespace)
	op, _ := model.Operation(name)
	return service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
}

func (f *encryptionFixture) mustECR(t *testing.T, name string, input any) any {
	t.Helper()
	out, rejected := encryptionCommand(f.ctx, f.service, "ecr", name, input)
	if rejected != nil {
		t.Fatalf("%s: %v", name, rejected)
	}
	return out
}

func (f *encryptionFixture) mustKMS(t *testing.T, name string, input any) any {
	t.Helper()
	out, rejected := encryptionCommand(f.ctx, f.kms, "kms", name, input)
	if rejected != nil {
		t.Fatalf("%s: %v", name, rejected)
	}
	return out
}

func (f *encryptionFixture) key(name string) ecr.RepositoryKey {
	return ecr.RepositoryKey{Scope: ecr.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, Name: name}
}

func (f *encryptionFixture) createInput(name, kind string) *ecrapi.CreateRepositoryInput {
	in := &ecrapi.CreateRepositoryInput{RepositoryName: new(ecrapi.RepositoryName(name)), EncryptionConfiguration: &ecrapi.EncryptionConfiguration{EncryptionType: new(ecrapi.EncryptionType(kind))}}
	if kind == "KMS" {
		in.EncryptionConfiguration.KmsKey = new(ecrapi.KmsKey(f.keyID))
	}
	return in
}

func (f *encryptionFixture) create(t *testing.T, name, kind string) ecr.RepositoryRecord {
	t.Helper()
	f.mustECR(t, "CreateRepository", f.createInput(name, kind))
	var repo ecr.RepositoryRecord
	if err := f.repository.View(f.ctx, func(tx ecr.Reader) error { var err error; repo, err = tx.Repository(f.key(name)); return err }); err != nil {
		t.Fatal(err)
	}
	return repo
}

func (f *encryptionFixture) push(t *testing.T, key ecr.RepositoryKey) (string, string) {
	t.Helper()
	payload := []byte(`{"architecture":"amd64","os":"linux","config":{"Labels":{"encrypted":"repository-test-payload"}},"rootfs":{"type":"layers","diff_ids":[]}}`)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
	name := new(ecrapi.RepositoryName(key.Name))
	upload := f.mustECR(t, "InitiateLayerUpload", &ecrapi.InitiateLayerUploadInput{RepositoryName: name}).(*ecrapi.InitiateLayerUploadOutput)
	f.mustECR(t, "UploadLayerPart", &ecrapi.UploadLayerPartInput{RepositoryName: name, UploadId: upload.UploadId,
		PartFirstByte: new(ecrapi.PartSize(0)), PartLastByte: new(ecrapi.PartSize(len(payload) - 1)), LayerPartBlob: payload})
	if err := f.repository.View(f.ctx, func(tx ecr.Reader) error {
		stored, err := tx.Upload(ecr.UploadKey{Repository: key, ID: string(*upload.UploadId)})
		if err == nil && bytes.Contains(stored.Payload, payload) {
			t.Error("plaintext incomplete upload was persisted")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.mustECR(t, "CompleteLayerUpload", &ecrapi.CompleteLayerUploadInput{RepositoryName: name, UploadId: upload.UploadId, LayerDigests: ecrapi.LayerDigestList{ecrapi.LayerDigest(digest)}})
	if err := f.repository.View(f.ctx, func(tx ecr.Reader) error {
		stored, err := tx.Blob(ecr.ImageKey{Repository: key, Digest: digest})
		if err == nil && bytes.Contains(stored.Payload, payload) {
			t.Error("plaintext layer was persisted")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[]}`, digest, len(payload))
	image := f.mustECR(t, "PutImage", &ecrapi.PutImageInput{RepositoryName: name, ImageManifest: new(ecrapi.ImageManifest(manifest)), ImageTag: new(ecrapi.ImageTag("latest"))}).(*ecrapi.PutImageOutput)
	return manifest, string(*image.Image.ImageId.ImageDigest)
}

func (f *encryptionFixture) get(key ecr.RepositoryKey) (any, *awswire.Error) {
	return encryptionCommand(f.ctx, f.service, "ecr", "BatchGetImage", &ecrapi.BatchGetImageInput{
		RepositoryName: new(ecrapi.RepositoryName(key.Name)), ImageIds: ecrapi.ImageIdentifierList{{ImageTag: new(ecrapi.ImageTag("latest"))}},
	})
}

func (f *encryptionFixture) requireManifest(t *testing.T, key ecr.RepositoryKey, want string) {
	t.Helper()
	out, rejected := f.get(key)
	if rejected != nil {
		t.Fatal(rejected)
	}
	images := out.(*ecrapi.BatchGetImageOutput)
	if len(images.Failures) != 0 || len(images.Images) != 1 || images.Images[0].ImageManifest == nil || string(*images.Images[0].ImageManifest) != want {
		t.Fatalf("decrypted manifest mismatch: %+v", images)
	}
}

func (f *encryptionFixture) requireUnreadable(t *testing.T, key ecr.RepositoryKey, code string) {
	t.Helper()
	out, rejected := f.get(key)
	if rejected == nil || rejected.Code != code {
		t.Fatalf("encrypted image was not rejected with %s: %v, %v", code, out, rejected)
	}
}

func (f *encryptionFixture) grants(t *testing.T) kmsapi.GrantList {
	t.Helper()
	return f.mustKMS(t, "ListGrants", &kmsapi.ListGrantsInput{KeyId: new(kmsapi.KeyIdType(f.keyID))}).(*kmsapi.ListGrantsOutput).Grants
}

type encryptionRecordFailure struct {
	apievents.Recorder
	event string
}

func (r *encryptionRecordFailure) Record(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := r.Recorder.Record(ctx, envelope, call); err != nil {
		return err
	}
	if call.ErrorCode == "" && call.EventName == r.event {
		return errors.New("injected journal failure after append")
	}
	return nil
}

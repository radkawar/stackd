package stackd_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
	"stackd/clock"
)

func TestKMSImportConditionsAndCrossAccountDenial(t *testing.T) {
	source := clock.NewManual(time.Now().UTC().Truncate(time.Second))
	c := clockCloud(t, stackd.Config{Clock: source})
	root := c.iam("test", "test", "")
	_, access, secret := c.user(t, "test", "key-importer")
	operator := c.kms(access, secret, "")
	putUserPolicy(t, root, "key-importer", `{"Statement":[{"Effect":"Allow","Action":"kms:CreateKey","Resource":"*","Condition":{"StringEquals":{"kms:KeyOrigin":"EXTERNAL"}}}]}`)
	_, err := operator.CreateKey(t.Context(), &kms.CreateKeyInput{})
	assertAPIError(t, err, "AccessDeniedException")
	k := kmsExternalKey(t, operator, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, false)
	params := &kms.GetParametersForImportInput{KeyId: k.KeyId, WrappingAlgorithm: types.AlgorithmSpecRsaesOaepSha256, WrappingKeySpec: types.WrappingKeySpecRsa2048}
	_, err = operator.GetParametersForImport(t.Context(), params)
	assertAPIError(t, err, "AccessDeniedException")
	deadline := source.Now().Add(time.Hour)
	putUserPolicy(t, root, "key-importer", fmt.Sprintf(`{"Statement":[
	{"Effect":"Allow","Action":"kms:GetParametersForImport","Resource":%q,"Condition":{"StringEquals":{"kms:WrappingAlgorithm":"RSAES_OAEP_SHA_256","kms:WrappingKeySpec":"RSA_2048","kms:KeyOrigin":"EXTERNAL"}}},
	{"Effect":"Allow","Action":"kms:ImportKeyMaterial","Resource":%q,"Condition":{"StringEquals":{"kms:ExpirationModel":"KEY_MATERIAL_EXPIRES"},"DateLessThanEquals":{"kms:ValidTo":%q}}},
	{"Effect":"Allow","Action":"kms:DeleteImportedKeyMaterial","Resource":%q} ]}`, aws.ToString(k.Arn), aws.ToString(k.Arn), deadline.Format(time.RFC3339), aws.ToString(k.Arn)))
	p, err := operator.GetParametersForImport(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"algorithm", "spec"} {
		bad := *params
		if field == "algorithm" {
			bad.WrappingAlgorithm = types.AlgorithmSpecRsaesOaepSha1
		} else {
			bad.WrappingKeySpec = types.WrappingKeySpecRsa3072
		}
		_, err := operator.GetParametersForImport(t.Context(), &bad)
		assertAPIError(t, err, "AccessDeniedException")
	}
	in := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{7}, 32), types.AlgorithmSpecRsaesOaepSha256)
	_, err = operator.ImportKeyMaterial(t.Context(), in)
	assertAPIError(t, err, "AccessDeniedException")
	in.ExpirationModel, in.ValidTo = types.ExpirationModelTypeKeyMaterialExpires, aws.Time(deadline.Add(time.Second))
	_, err = operator.ImportKeyMaterial(t.Context(), in)
	assertAPIError(t, err, "AccessDeniedException")
	in.ValidTo = &deadline
	if _, err := operator.ImportKeyMaterial(t.Context(), in); err != nil {
		t.Fatal("allowed conditional import", err)
	}
	owner := c.kms("test", "test", "")
	keyPolicy := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:*","Resource":"*"}]}`
	if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: k.KeyId, Policy: &keyPolicy}); err != nil {
		t.Fatal(err)
	}
	// These management APIs prohibit cross-account use even with both policy
	// sides allowing it; cryptographic operations retain their separate rules.
	_, extAccess, extSecret := c.user(t, "222222222222", "foreign-importer")
	putUserPolicy(t, c.iam("222222222222", "test", ""), "foreign-importer", allow(`"kms:*"`, "*"))
	external := c.kms(extAccess, extSecret, "")
	params.KeyId = k.Arn
	_, err = external.GetParametersForImport(t.Context(), params)
	assertAPIError(t, err, "AccessDeniedException")
	in.KeyId = k.Arn
	_, err = external.ImportKeyMaterial(t.Context(), in)
	assertAPIError(t, err, "AccessDeniedException")
	_, err = external.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: k.Arn})
	assertAPIError(t, err, "AccessDeniedException")
	if _, err := operator.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	kmsImportMetadata(t, owner, k.KeyId, types.KeyStatePendingImport)
}

func TestKMSImportParametersBindingsExpiryAndValidation(t *testing.T) {
	codes := kmsNativeCodes(t, "imports_edges")
	source := clock.NewManual(time.Now().UTC().Truncate(time.Second))
	c := clockCloud(t, stackd.Config{Clock: source}).kms("test", "test", "")
	k := kmsExternalKey(t, c, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, false)
	other := kmsExternalKey(t, c, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, false)
	p := kmsImportParameters(t, c, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	p2 := kmsImportParameters(t, c, other.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	in := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{1}, 32), types.AlgorithmSpecRsaesOaepSha256)
	for name, change := range map[string]func(*kms.ImportKeyMaterialInput){
		"token_other_key":    func(in *kms.ImportKeyMaterialInput) { in.ImportToken = p2.ImportToken },
		"token_corrupt":      func(in *kms.ImportKeyMaterialInput) { in.ImportToken = bytes.Repeat([]byte{'x'}, 32) },
		"ciphertext_corrupt": func(in *kms.ImportKeyMaterialInput) { in.EncryptedKeyMaterial = bytes.Repeat([]byte{'x'}, 256) },
	} {
		bad := *in
		change(&bad)
		_, err := c.ImportKeyMaterial(t.Context(), &bad)
		checkKMSNative(t, codes, name, err)
	}
	for _, change := range []func(*kms.ImportKeyMaterialInput){
		func(in *kms.ImportKeyMaterialInput) { in.ExpirationModel = "" },
		func(in *kms.ImportKeyMaterialInput) { in.ExpirationModel = types.ExpirationModelTypeKeyMaterialExpires },
		func(in *kms.ImportKeyMaterialInput) { in.ValidTo = aws.Time(source.Now().Add(time.Hour)) },
		func(in *kms.ImportKeyMaterialInput) {
			in.ExpirationModel = types.ExpirationModelTypeKeyMaterialExpires
			in.ValidTo = aws.Time(source.Now())
		},
		func(in *kms.ImportKeyMaterialInput) {
			in.ExpirationModel = types.ExpirationModelTypeKeyMaterialExpires
			in.ValidTo = aws.Time(source.Now().Add(366 * 24 * time.Hour))
		},
		func(in *kms.ImportKeyMaterialInput) {
			in.ImportType = types.ImportTypeNewKeyMaterial
			in.KeyMaterialId = aws.String(string(bytes.Repeat([]byte{'0'}, 64)))
		},
	} {
		bad := *in
		change(&bad)
		_, err := c.ImportKeyMaterial(t.Context(), &bad)
		assertAPIError(t, err, "ValidationException")
	}
	kmsImportMetadata(t, c, k.KeyId, types.KeyStatePendingImport)
	advanceClock(t, source, 24*time.Hour)
	_, err := c.ImportKeyMaterial(t.Context(), in)
	assertAPIError(t, err, "ExpiredImportTokenException")
	p = kmsImportParameters(t, c, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa4096)
	if _, err := c.ImportKeyMaterial(t.Context(), kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{1}, 32), types.AlgorithmSpecRsaesOaepSha256)); err != nil {
		t.Fatal(err)
	}
}

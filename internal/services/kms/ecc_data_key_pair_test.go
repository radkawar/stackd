package kms

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestSDKECCDataKeyPairs(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is required for independent PKCS8 interoperability")
	}
	c := sdkClient(t, New(), rootMetadata("111111111111", "us-east-1", "aws"))
	key := createSDKKey(t, c)
	ec := map[string]string{"purpose": "ECC private key"}
	for _, spec := range []types.DataKeyPairSpec{types.DataKeyPairSpecEccNistP256, types.DataKeyPairSpecEccNistP384, types.DataKeyPairSpecEccNistP521, types.DataKeyPairSpecEccSecgP256k1, types.DataKeyPairSpecEccNistEdwards25519} {
		t.Run(string(spec), func(t *testing.T) {
			for _, without := range []bool{false, true} {
				var private, public, blob []byte
				if without {
					out, err := c.GenerateDataKeyPairWithoutPlaintext(t.Context(), &sdkkms.GenerateDataKeyPairWithoutPlaintextInput{KeyId: key.KeyId, KeyPairSpec: spec, EncryptionContext: ec})
					if err != nil {
						t.Fatal(err)
					}
					public, blob = out.PublicKey, out.PrivateKeyCiphertextBlob
					if out.KeyPairSpec != spec || aws.ToString(out.KeyId) != aws.ToString(key.Arn) {
						t.Fatal("data-key-pair metadata")
					}
				} else {
					out, err := c.GenerateDataKeyPair(t.Context(), &sdkkms.GenerateDataKeyPairInput{KeyId: key.KeyId, KeyPairSpec: spec, EncryptionContext: ec})
					if err != nil {
						t.Fatal(err)
					}
					private, public, blob = out.PrivateKeyPlaintext, out.PublicKey, out.PrivateKeyCiphertextBlob
					if out.KeyPairSpec != spec || aws.ToString(out.KeyId) != aws.ToString(key.Arn) {
						t.Fatal("data-key-pair metadata")
					}
				}
				decoded, err := c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: blob, EncryptionContext: ec})
				if err != nil {
					t.Fatal(err)
				}
				if !without && !bytes.Equal(private, decoded.Plaintext) {
					t.Fatal("private key ciphertext lost material")
				}
				path := filepath.Join(t.TempDir(), "private.der")
				if err := os.WriteFile(path, decoded.Plaintext, 0600); err != nil {
					t.Fatal(err)
				}
				clear(private)
				clear(decoded.Plaintext)
				derived, err := exec.CommandContext(t.Context(), openssl, "pkey", "-inform", "DER", "-in", path, "-pubout", "-outform", "DER").Output()
				if err != nil || !bytes.Equal(derived, public) {
					t.Fatal("OpenSSL private/public interoperability", err)
				}
				_, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: blob})
				requireCode(t, err, "InvalidCiphertextException")
			}
		})
	}
}

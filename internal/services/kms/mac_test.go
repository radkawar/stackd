package kms

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

func TestSDKHMACMatchesAWS(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/kms/hmac.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Keys         []types.KeyMetadata
		Observations []struct {
			Case, Spec, Code, Algorithm string
			Output                      struct {
				MacBytes int `json:"mac_bytes"`
			}
			Error struct{ Message string }
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, native := range capture.Keys {
		t.Run(string(native.KeySpec), func(t *testing.T) {
			c := sdkClient(t, New(), rootMetadata("111111111111", "us-east-1", "aws"))
			created, err := c.CreateKey(t.Context(), &sdkkms.CreateKeyInput{KeySpec: native.KeySpec, KeyUsage: native.KeyUsage})
			if err != nil {
				t.Fatal(err)
			}
			key := created.KeyMetadata
			if key.KeySpec != native.KeySpec || key.KeyUsage != native.KeyUsage || key.CurrentKeyMaterialId != nil || !reflect.DeepEqual(key.MacAlgorithms, native.MacAlgorithms) || len(key.EncryptionAlgorithms) != 0 || len(key.SigningAlgorithms) != 0 {
				t.Fatalf("HMAC metadata differs from AWS: %+v", key)
			}
			var mac []byte
			for _, row := range capture.Observations {
				if row.Spec != string(native.KeySpec) {
					continue
				}
				t.Run(row.Case, func(t *testing.T) {
					var err error
					algorithm := types.MacAlgorithmSpec(row.Algorithm)
					message := []byte("stackd HMAC behavior")
					switch row.Case {
					case "default_usage", "incompatible_usage":
						input := &sdkkms.CreateKeyInput{KeySpec: native.KeySpec}
						if row.Case == "incompatible_usage" {
							input.KeyUsage = types.KeyUsageTypeEncryptDecrypt
						}
						_, err = c.CreateKey(t.Context(), input)
					case "generate", "repeat", "wrong_algorithm", "dry_generate", "max_message", "empty_message", "disabled_generate", "disabled_wrong_algorithm", "pending_deletion_generate":
						if row.Case == "disabled_generate" {
							if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
								t.Fatal(err)
							}
						}
						if row.Case == "pending_deletion_generate" {
							if _, err := c.ScheduleKeyDeletion(t.Context(), &sdkkms.ScheduleKeyDeletionInput{KeyId: key.KeyId, PendingWindowInDays: aws.Int32(7)}); err != nil {
								t.Fatal(err)
							}
						}
						if row.Case == "max_message" {
							message = bytes.Repeat([]byte("a"), 4096)
						}
						if row.Case == "empty_message" {
							message = []byte{}
						}
						var out *sdkkms.GenerateMacOutput
						out, err = c.GenerateMac(t.Context(), &sdkkms.GenerateMacInput{KeyId: key.KeyId, Message: message, MacAlgorithm: algorithm, DryRun: aws.Bool(row.Case == "dry_generate")})
						if err == nil {
							if len(out.Mac) != row.Output.MacBytes || aws.ToString(out.KeyId) != aws.ToString(key.Arn) || out.MacAlgorithm != algorithm {
								t.Fatal("MAC response differs from AWS", out)
							}
							if row.Case == "repeat" && !bytes.Equal(mac, out.Mac) {
								t.Fatal("MAC changed for the same key and message")
							}
							if row.Case == "generate" {
								mac = out.Mac
							}
						}
					case "verify", "wrong_mac", "short_mac", "dry_verify_wrong_mac":
						supplied := bytes.Clone(mac)
						if row.Case != "verify" {
							supplied[0] ^= 1
						}
						if row.Case == "short_mac" {
							supplied = []byte("x")
						}
						var out *sdkkms.VerifyMacOutput
						out, err = c.VerifyMac(t.Context(), &sdkkms.VerifyMacInput{KeyId: key.KeyId, Message: message, MacAlgorithm: algorithm, Mac: supplied, DryRun: aws.Bool(row.Case == "dry_verify_wrong_mac")})
						if err == nil && (!out.MacValid || aws.ToString(out.KeyId) != aws.ToString(key.Arn) || out.MacAlgorithm != algorithm) {
							t.Fatal("verification response differs from AWS", out)
						}
					case "encrypt_with_hmac":
						_, err = c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: key.KeyId, Plaintext: message})
					case "mac_grant", "encryption_grant", "constrained_mac_grant":
						in := &sdkkms.CreateGrantInput{KeyId: key.KeyId, GranteePrincipal: aws.String("arn:aws:iam::111111111111:root"), Operations: []types.GrantOperation{types.GrantOperationGenerateMac, types.GrantOperationVerifyMac}}
						if row.Case == "encryption_grant" {
							in.Operations = []types.GrantOperation{types.GrantOperationEncrypt}
						}
						if row.Case == "constrained_mac_grant" {
							in.Operations = []types.GrantOperation{types.GrantOperationGenerateMac}
							in.Constraints = &types.GrantConstraints{EncryptionContextEquals: map[string]string{"purpose": "probe"}}
						}
						_, err = c.CreateGrant(t.Context(), in)
					default:
						t.Fatal("unhandled native case", row.Case)
					}
					if row.Code == "Success" {
						if err != nil {
							t.Fatal(err)
						}
						return
					}
					requireCode(t, err, row.Code)
					if row.Case == "wrong_algorithm" || row.Code == "KMSInvalidMacException" || row.Case == "default_usage" || row.Case == "incompatible_usage" || row.Case == "constrained_mac_grant" {
						var apiErr smithy.APIError
						if !errors.As(err, &apiErr) || apiErr.ErrorMessage() != row.Error.Message {
							t.Fatalf("native error message differs: %v", err)
						}
					}
				})
			}
		})
	}
}

func TestSDKHMACRFC4231AndStorageReconstruction(t *testing.T) {
	// RFC 4231 section 4.2. Zero-padding its 20-byte key to the KMS key-spec
	// length preserves the RFC 2104 result while using valid stored key lengths.
	for _, test := range []struct {
		spec types.KeySpec
		size int
		want string
	}{
		{types.KeySpecHmac224, 28, "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"},
		{types.KeySpecHmac256, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
		{types.KeySpecHmac384, 48, "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"},
		{types.KeySpecHmac512, 64, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
	} {
		t.Run(string(test.spec), func(t *testing.T) {
			storage := NewMemoryStorage(nil)
			metadata := rootMetadata("111111111111", "us-east-1", "aws")
			c := sdkClient(t, NewWithStorage(storage, nil), metadata)
			created, err := c.CreateKey(t.Context(), &sdkkms.CreateKeyInput{KeySpec: test.spec, KeyUsage: types.KeyUsageTypeGenerateVerifyMac})
			if err != nil {
				t.Fatal(err)
			}
			if err := storage.Transact(t.Context(), func(tx Transaction) error {
				owner := KeyOwner{Partition: "aws", AccountID: "111111111111"}
				set, err := tx.KeySet(owner, aws.ToString(created.KeyMetadata.KeyId))
				if err != nil {
					return err
				}
				if len(set.Materials[0].Material) != test.size {
					t.Fatal("generated HMAC material has the wrong size")
				}
				clear(set.Materials[0].Material)
				copy(set.Materials[0].Material, bytes.Repeat([]byte{0x0b}, 20))
				return tx.PutKeySet(owner, set)
			}); err != nil {
				t.Fatal(err)
			}
			c = sdkClient(t, NewWithStorage(storage, nil), metadata)
			out, err := c.GenerateMac(t.Context(), &sdkkms.GenerateMacInput{KeyId: created.KeyMetadata.KeyId, MacAlgorithm: created.KeyMetadata.MacAlgorithms[0], Message: []byte("Hi There")})
			if err != nil || hex.EncodeToString(out.Mac) != test.want {
				t.Fatal("SDK MAC differs from RFC 4231", err)
			}
		})
	}
}

package stackd_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"golang.org/x/crypto/ssh"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type ec2KeyPairCapture struct {
	ec2NetworkCapture
	Crypto struct {
		KeyType          string `json:"key_type"`
		KeyFormat        string `json:"key_format"`
		Header           string
		Bits             int
		PPKComment       string `json:"ppk_comment"`
		DerivedPublicKey string `json:"derived_public_key"`
	} `json:"crypto"`
}

func TestEC2NativeKeyPairs(t *testing.T) {
	for _, name := range []string{"key_pairs.json", "key_pairs_supplement.json", "key_pairs_import_boundaries.json", "key_pairs_dry_run.json"} {
		t.Run(name, func(t *testing.T) { replayEC2KeyPairs(t, name) })
	}
}

func replayEC2KeyPairs(t *testing.T, fixtureName string) {
	t.Helper()
	var fixture struct {
		Account, Region string
		Calls           []ec2KeyPairCapture
		CloudTrail      struct{ Events []map[string]any }
	}
	awsReadFixture(t, "ec2/"+fixtureName, &fixture)
	audits := map[string]map[string]any{}
	for _, event := range fixture.CloudTrail.Events {
		audits[event["requestID"].(string)] = event
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Calls[0].StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source})
			bindings := map[string]string{}
			created := map[string]time.Time{}
			for _, row := range fixture.Calls {
				if row.Code == "CLIError" {
					continue
				}
				if row.StartedAt.After(source.Now()) {
					source.Advance(row.StartedAt.Sub(source.Now()))
				}
				action := ec2NetworkAction(row.Operation)
				if !t.Run(row.Label, func(t *testing.T) {
					wire := &awstest.WireClient{Client: clients.server.Client()}
					options := ec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: wire, RetryMaxAttempts: 1}
					input := ec2AuditReplace(t, row.Input, bindings)
					actual, err := awstest.CallSDK(t.Context(), ec2.New(options), action, input)
					if row.Code != "Success" {
						assertAPIError(t, err, row.Code)
					} else if err != nil {
						t.Fatal(err)
					}
					if wire.Status != row.HTTPStatus {
						t.Fatalf("HTTP %d, native %d", wire.Status, row.HTTPStatus)
					}
					if err == nil {
						options.HTTPClient = nativeXMLResponse(row.RawResponseBody)
						expected, decodeErr := awstest.CallSDK(t.Context(), ec2.New(options), action, row.Input)
						if decodeErr != nil {
							t.Fatal(decodeErr)
						}
						want, got := ec2NetworkDocument(t, expected), ec2NetworkDocument(t, actual)
						if action == "CreateKeyPair" || action == "ImportKeyPair" {
							before, after := want["KeyPairId"].(string), got["KeyPairId"].(string)
							if !regexp.MustCompile(`^key-[0-9a-f]{17}$`).MatchString(after) {
								t.Fatalf("invalid key pair ID %q", after)
							}
							for other, bound := range bindings {
								if other != before && bound == after {
									t.Fatalf("key pair ID reused: %s", after)
								}
							}
							bindings[before] = after
							created[after] = source.Now()
							if action == "CreateKeyPair" {
								public := assertEC2PrivateKey(t, row, got["KeyMaterial"].(string), got["KeyFingerprint"].(string))
								bindings[row.Crypto.DerivedPublicKey] = public
								bindings[want["KeyFingerprint"].(string)] = got["KeyFingerprint"].(string)
								delete(want, "KeyMaterial")
								delete(got, "KeyMaterial")
							}
						}
						if action == "DescribeKeyPairs" {
							// Public metadata is compared after reopening the repository. Only
							// independently generated crypto bytes and timestamps are bound.
							ec2NetworkSort(t, want, bindings, true)
							ec2NetworkSort(t, got, bindings, false)
							wantPairs, _ := want["KeyPairs"].([]any)
							gotPairs, _ := got["KeyPairs"].([]any)
							if len(wantPairs) != len(gotPairs) {
								t.Fatalf("native key pairs %d, got %d", len(wantPairs), len(gotPairs))
							}
							for index, value := range wantPairs {
								before, after := value.(map[string]any), gotPairs[index].(map[string]any)
								if before["CreateTime"] != nil {
									when, parseErr := time.Parse(time.RFC3339Nano, after["CreateTime"].(string))
									start := created[after["KeyPairId"].(string)]
									if parseErr != nil || when.Before(start.Truncate(time.Second)) || when.After(start.Add(10*time.Second)) {
										t.Fatalf("creation timestamp %v, operation %v", after["CreateTime"], start)
									}
									bindings[before["CreateTime"].(string)] = after["CreateTime"].(string)
								}
							}
						}
						ec2NetworkSort(t, want, bindings, true)
						ec2NetworkSort(t, got, bindings, false)
						ec2NetworkCompare(t, "response", want, got, bindings)
					}
					if native := audits[row.RequestID]; native != nil {
						requestID := nativeAuditRequestID(t, actual, err)
						trails := cloudtrail.New(cloudtrail.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: options.Credentials, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
						record := auditLookupRecord(t, trails, requestID, action)
						var normalize func(any)
						if action == "ImportKeyPair" && err != nil {
							// Unlike native AWS, rejected uploads remain unvalidated
							// secret-bearing blobs and must not enter retained audit.
							parameters, _ := record["requestParameters"].(map[string]any)
							if _, present := parameters["publicKeyMaterial"]; present {
								t.Fatal("rejected import material leaked into audit")
							}
							normalize = func(value any) {
								event := value.(map[string]any)
								parameters, _ := event["requestParameters"].(map[string]any)
								delete(parameters, "publicKeyMaterial")
							}
						}
						assertEC2AuditCapture(t, source.Now(), native, record, requestID, err, bindings, normalize)
						encoded, marshalErr := json.Marshal(record)
						if marshalErr != nil {
							t.Fatal(marshalErr)
						}
						if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("PuTTY-User-Key-File")) {
							t.Fatal("private key leaked into retained CloudTrail record")
						}
					}
				}) {
					return
				}
				if row.Code == "Success" && !strings.HasPrefix(action, "Describe") {
					clients = reopen()
				}
			}
		})
	}
}

// AWS's fingerprint differs for generated RSA and imported RSA. The native
// fixture retains only these public derived assertions, never generated secrets.
func assertEC2PrivateKey(t *testing.T, row ec2KeyPairCapture, material, fingerprint string) string {
	t.Helper()
	if strings.SplitN(material, "\n", 2)[0] != row.Crypto.Header {
		t.Fatal("private key encoding differs from native")
	}
	var private any
	var err error
	if row.Crypto.KeyFormat == "ppk" {
		private = ec2PPKPrivateKey(t, material, row.Crypto.PPKComment)
	} else {
		private, err = ssh.ParseRawPrivateKey([]byte(material))
		if err != nil {
			t.Fatal(err)
		}
	}
	if pointer, ok := private.(*ed25519.PrivateKey); ok {
		private = *pointer
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		t.Fatalf("unsupported private key %T", private)
	}
	public, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	var expected string
	if key, ok := private.(*rsa.PrivateKey); ok {
		if key.N.BitLen() != row.Crypto.Bits || key.Validate() != nil {
			t.Fatal("invalid generated RSA key")
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha1.Sum(der)
		parts := make([]string, len(digest))
		for index, value := range digest {
			parts[index] = fmt.Sprintf("%02x", value)
		}
		expected = strings.Join(parts, ":")
	} else {
		digest := sha256.Sum256(public.Marshal())
		expected = base64.StdEncoding.EncodeToString(digest[:])
	}
	if fingerprint != expected {
		t.Fatal("private key does not match returned fingerprint")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
}

func ec2PPKPrivateKey(t *testing.T, material, comment string) crypto.Signer {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(material), "\n")
	values := map[string]string{}
	sections := map[string][]byte{}
	for index := 0; index < len(lines); {
		key, value, ok := strings.Cut(strings.TrimSuffix(lines[index], "\r"), ": ")
		if !ok {
			t.Fatal("malformed PPK field")
		}
		index++
		if key == "Public-Lines" || key == "Private-Lines" {
			count, err := strconv.Atoi(value)
			if err != nil || count < 1 || index+count > len(lines) {
				t.Fatal("invalid PPK section")
			}
			sections[key], err = base64.StdEncoding.DecodeString(strings.Join(lines[index:index+count], ""))
			if err != nil {
				t.Fatal(err)
			}
			index += count
		} else {
			values[key] = value
		}
	}
	if values["Encryption"] != "none" || values["Comment"] != comment {
		t.Fatal("PPK metadata differs from native")
	}
	algorithm := values["PuTTY-User-Key-File-2"]
	macKey := sha1.Sum([]byte("putty-private-key-file-mac-key"))
	mac := hmac.New(sha1.New, macKey[:])
	mac.Write(ssh.Marshal(struct {
		Algorithm, Encryption, Comment string
		Public, Private                []byte
	}{algorithm, values["Encryption"], values["Comment"], sections["Public-Lines"], sections["Private-Lines"]}))
	if hex.EncodeToString(mac.Sum(nil)) != values["Private-MAC"] {
		t.Fatal("PPK private MAC invalid")
	}
	var private crypto.Signer
	switch algorithm {
	case "ssh-rsa":
		var public struct {
			Algorithm string
			E, N      *big.Int
		}
		var secret struct{ D, P, Q, IQMP *big.Int }
		if err := ssh.Unmarshal(sections["Public-Lines"], &public); err != nil {
			t.Fatal(err)
		}
		if err := ssh.Unmarshal(sections["Private-Lines"], &secret); err != nil {
			t.Fatal(err)
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: public.N, E: int(public.E.Int64())}, D: secret.D, Primes: []*big.Int{secret.P, secret.Q}}
		if err := key.Validate(); err != nil {
			t.Fatal(err)
		}
		if new(big.Int).ModInverse(secret.Q, secret.P).Cmp(secret.IQMP) != 0 {
			t.Fatal("invalid PPK inverse")
		}
		private = key
	case "ssh-ed25519":
		var secret struct{ Seed []byte }
		if err := ssh.Unmarshal(sections["Private-Lines"], &secret); err != nil {
			t.Fatal(err)
		}
		if len(secret.Seed) != ed25519.SeedSize {
			t.Fatalf("PPK Ed25519 seed length %d", len(secret.Seed))
		}
		private = ed25519.NewKeyFromSeed(secret.Seed)
	default:
		t.Fatalf("unsupported PPK algorithm %q", algorithm)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil || !bytes.Equal(public.Marshal(), sections["Public-Lines"]) {
		t.Fatal("PPK private/public mismatch")
	}
	return private
}

func TestEC2KeyPairAuthorityAndIsolation(t *testing.T) {
	var fixture struct {
		Account, Region string
		Calls           []ec2KeyPairCapture
	}
	awsReadFixture(t, "ec2/key_pairs.json", &fixture)
	var imported ec2.ImportKeyPairInput
	for _, row := range fixture.Calls {
		if row.Label == "import-rsa-openssh" {
			awsDecodeJSON(t, row.Input, &imported)
			break
		}
	}
	if len(imported.PublicKeyMaterial) == 0 {
		t.Fatal("native import fixture missing")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			imported := imported
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account})
			clientFor := func(account, secret, region string) *ec2.Client {
				return ec2.New(ec2.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, secret, ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			root := clientFor(fixture.Account, "test", fixture.Region)
			owned, err := root.ImportKeyPair(t.Context(), &imported)
			if err != nil {
				t.Fatal(err)
			}
			_, key, secret := clients.user(t, fixture.Account, "KeyPairDelegate")
			clients = reopen()
			root = clientFor(fixture.Account, "test", fixture.Region)
			delegate := clientFor(key, secret, fixture.Region)
			_, err = delegate.DeleteKeyPair(t.Context(), &ec2.DeleteKeyPairInput{KeyPairId: owned.KeyPairId})
			assertAPIError(t, err, "UnauthorizedOperation")
			_, err = delegate.CreateKeyPair(t.Context(), &ec2.CreateKeyPairInput{KeyName: aws.String("denied"), DryRun: aws.Bool(true)})
			assertAPIError(t, err, "UnauthorizedOperation")
			_, err = delegate.DescribeKeyPairs(t.Context(), &ec2.DescribeKeyPairsInput{KeyPairIds: []string{aws.ToString(owned.KeyPairId)}, IncludePublicKey: aws.Bool(true)})
			assertAPIError(t, err, "UnauthorizedOperation")
			for _, other := range []*ec2.Client{clientFor("222222222222", "test", fixture.Region), clientFor(fixture.Account, "test", "us-west-2")} {
				_, err = other.DescribeKeyPairs(t.Context(), &ec2.DescribeKeyPairsInput{KeyPairIds: []string{aws.ToString(owned.KeyPairId)}})
				assertAPIError(t, err, "InvalidParameterValue")
				if _, err = other.DeleteKeyPair(t.Context(), &ec2.DeleteKeyPairInput{KeyPairId: owned.KeyPairId}); err != nil {
					t.Fatal(err)
				}
			}
			retained, err := root.DescribeKeyPairs(t.Context(), &ec2.DescribeKeyPairsInput{KeyPairIds: []string{aws.ToString(owned.KeyPairId)}, IncludePublicKey: aws.Bool(true)})
			if err != nil || len(retained.KeyPairs) != 1 {
				t.Fatalf("denial/isolation changed key pair: %+v %v", retained, err)
			}
			public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(aws.ToString(retained.KeyPairs[0].PublicKey)))
			if err != nil {
				t.Fatal(err)
			}
			inputPublic, _, _, _, err := ssh.ParseAuthorizedKey(imported.PublicKeyMaterial)
			if err != nil || !bytes.Equal(public.Marshal(), inputPublic.Marshal()) {
				t.Fatal("import public key lost across reopen")
			}
			arn := "arn:aws:ec2:" + fixture.Region + ":" + fixture.Account + ":key-pair/" + aws.ToString(owned.KeyName)
			var suite string
			for _, tag := range imported.TagSpecifications[0].Tags {
				if aws.ToString(tag.Key) == "suite" {
					suite = aws.ToString(tag.Value)
				}
			}
			putUserPolicy(t, clients.iam(fixture.Account, "test", ""), "KeyPairDelegate", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"ec2:DeleteKeyPair","Resource":%q,"Condition":{"StringEquals":{"ec2:ResourceTag/suite":%q}}},{"Effect":"Allow","Action":["ec2:CreateTags","ec2:DeleteTags"],"Resource":%q}]}`, arn, suite, arn))
			_, err = delegate.DeleteKeyPair(t.Context(), &ec2.DeleteKeyPairInput{KeyPairId: owned.KeyPairId, DryRun: aws.Bool(true)})
			assertAPIError(t, err, "DryRunOperation")
			if _, err = delegate.DeleteTags(t.Context(), &ec2.DeleteTagsInput{Resources: []string{aws.ToString(owned.KeyPairId)}, Tags: []ec2types.Tag{{Key: aws.String("suite")}}}); err != nil {
				t.Fatal(err)
			}
			_, err = delegate.DeleteKeyPair(t.Context(), &ec2.DeleteKeyPairInput{KeyPairId: owned.KeyPairId})
			assertAPIError(t, err, "UnauthorizedOperation")
			if _, err = delegate.CreateTags(t.Context(), &ec2.CreateTagsInput{Resources: []string{aws.ToString(owned.KeyPairId)}, Tags: []ec2types.Tag{{Key: aws.String("suite"), Value: aws.String(suite)}}}); err != nil {
				t.Fatal(err)
			}
			if _, err = delegate.DeleteKeyPair(t.Context(), &ec2.DeleteKeyPairInput{KeyPairId: owned.KeyPairId}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			root = clientFor(fixture.Account, "test", fixture.Region)
			_, err = root.DescribeKeyPairs(t.Context(), &ec2.DescribeKeyPairsInput{KeyNames: []string{aws.ToString(imported.KeyName)}})
			assertAPIError(t, err, "InvalidKeyPair.NotFound")
			putUserPolicy(t, clients.iam(fixture.Account, "test", ""), "KeyPairDelegate", allow(`["ec2:ImportKeyPair"]`, "*"))
			delegate = clientFor(key, secret, fixture.Region)
			_, err = delegate.ImportKeyPair(t.Context(), &imported)
			assertAPIError(t, err, "UnauthorizedOperation") // creation tags need dependent CreateTags authority
			imported.TagSpecifications = nil
			if _, err = delegate.ImportKeyPair(t.Context(), &imported); err != nil {
				t.Fatal(err)
			}
			pairs, err := root.DescribeKeyPairs(t.Context(), &ec2.DescribeKeyPairsInput{Filters: []ec2types.Filter{{Name: aws.String("key-name"), Values: []string{aws.ToString(imported.KeyName)}}}})
			if err != nil || len(pairs.KeyPairs) != 1 || len(pairs.KeyPairs[0].Tags) != 0 {
				t.Fatalf("authorized import metadata: %+v %v", pairs, err)
			}
		})
	}
}

package ec2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Public-only vectors from testdata/aws/ec2/key_pairs.json. RSA must hash
// SPKI DER, not the wire blob used by ssh-keygen's MD5 fingerprint.
const nativeRSAImportPublic = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPdLiuIZFRggfQLcwdudVinG1cFTm365uurK22eyXyAzlEC5ExdKwaOevJsuvuVw1lQVCWY8HX92w230G8lWMD5eHiqG4Rh9kmkSTj8Lvr2NZIoqi4bYiZ1b5eoswgfKN8wDsULdpuPQl1MhPRnkDeyU8PIAm7KQxxxmqw6h3jKKmEpfUxaRjvr/22loTwH3pEF3LrQDKbQanIbtjA2MhHRN47P5fFVBuYt4aeH+c5ksYZbRaR77BlP+4SbDQw688YIB0Fp5kAKcJ43zbxIVBvTVbSBCBTDus2wkjdEWmOmOx0Lx4/0Zjvis/Quurb8+TiOOXGvTL26A5GESb6Uswl"

func TestKeyPairNativeImportFingerprints(t *testing.T) {
	for _, tc := range []struct{ public, fingerprint string }{
		{nativeRSAImportPublic, "9a:c9:9c:35:5b:af:8d:2c:1a:6a:61:b3:06:eb:e5:25"},
		{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMduvWA7Q35QVLBez30EIH7qXgyHjmUqQgB6+Klj7oM1", "HMXWyhG4gbktWdKgkzX/THR2+GMkRLG8rKsKj1oW86k="},
	} {
		public, err := parseKeyPairPublicKey([]byte(tc.public))
		if err != nil {
			t.Fatal(err)
		}
		got, err := keyPairFingerprint(public, nil)
		if err != nil || got != tc.fingerprint {
			t.Fatalf("native fingerprint = %q, %v; want %q", got, err, tc.fingerprint)
		}
	}
}

func TestKeyPairImportFormatBoundaries(t *testing.T) {
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(nativeRSAImportPublic))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public.(ssh.CryptoPublicKey).CryptoPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	rfc := "---- BEGIN SSH2 PUBLIC KEY ----\r\nComment: \"continued \\\r\nheader\"\r\n" + base64.StdEncoding.EncodeToString(public.Marshal()) + "\r\n---- END SSH2 PUBLIC KEY ----\r\n"
	for _, material := range []string{nativeRSAImportPublic + " ignored-comment\n", rfc, base64.StdEncoding.EncodeToString(der)} {
		parsed, err := parseKeyPairPublicKey([]byte(material))
		if err != nil || !bytes.Equal(parsed.Marshal(), public.Marshal()) {
			t.Fatalf("RSA import changed public key: %v", err)
		}
	}
	for name, material := range map[string][]byte{
		"pem":                  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		"binary-der":           der,
		"private-pem":          []byte("-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----"),
		"authorized-options":   []byte("no-agent-forwarding " + nativeRSAImportPublic),
		"second-key":           []byte(nativeRSAImportPublic + "\n" + nativeRSAImportPublic),
		"leading-comment":      []byte("# ignored by authorized_keys readers\n" + nativeRSAImportPublic),
		"unterminated-rfc4716": []byte(strings.TrimSuffix(rfc, "---- END SSH2 PUBLIC KEY ----\r\n")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseKeyPairPublicKey(material); err == nil {
				t.Fatal("accepted invalid public-key encoding")
			}
		})
	}
}

func TestKeyPairImportMaterialLimitNotRSAStrengthPolicy(t *testing.T) {
	// Native accepts a public-only 512-bit modulus; import admission is not a
	// cryptographic strength policy. Its concrete boundary is input size.
	modulus := new(big.Int).Lsh(big.NewInt(1), 511)
	modulus.Add(modulus, big.NewInt(65537))
	public, err := ssh.NewPublicKey(&rsa.PublicKey{N: modulus, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	material := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))) + " "
	material += strings.Repeat("c", 2048-len(material))
	parsed, err := parseKeyPairPublicKey([]byte(material))
	if err != nil || !bytes.Equal(parsed.Marshal(), public.Marshal()) {
		t.Fatalf("native-admitted key changed: %v", err)
	}
	if _, err := parseKeyPairPublicKey([]byte(material + "c")); err == nil || wireError(err).Code != "InvalidParameterValue" {
		t.Fatalf("oversized material error = %v", err)
	}
}

// PuTTY's Ed25519 field is a fixed 32-byte unsigned seed, unlike RSA mpints.
// Leading zeroes and a set sign bit must survive; otherwise the downloaded
// key's signatures do not verify against EC2's retained public key.
func TestKeyPairPPKEd25519SeedAndMAC(t *testing.T) {
	for _, seed := range [][]byte{
		bytes.Repeat([]byte{0x80}, ed25519.SeedSize),
		append(make([]byte, ed25519.SeedSize-1), 1),
	} {
		private := ed25519.NewKeyFromSeed(seed)
		public, err := ssh.NewPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(marshalKeyPairPPK(private, public, "owned"), "\n")
		publicBlob, next := keyPairTestPPKBlob(t, lines, 3)
		privateBlob, next := keyPairTestPPKBlob(t, lines, next)
		if len(privateBlob) != 4+ed25519.SeedSize || binary.BigEndian.Uint32(privateBlob) != ed25519.SeedSize || !bytes.Equal(privateBlob[4:], seed) {
			t.Fatal("PPK failed to preserve fixed-length Ed25519 seed")
		}
		decodedPublic, err := ssh.ParsePublicKey(publicBlob)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(privateBlob[4:]))
		if err != nil {
			t.Fatal(err)
		}
		message := []byte("EC2 key pair PPK signing proof")
		signature, err := signer.Sign(nil, message)
		if err != nil || decodedPublic.Verify(message, signature) != nil {
			t.Fatalf("PPK private key does not sign for retained public key: %v", err)
		}
		var preimage bytes.Buffer
		for _, field := range [][]byte{[]byte(ssh.KeyAlgoED25519), []byte("none"), []byte("owned"), publicBlob, privateBlob} {
			if err := binary.Write(&preimage, binary.BigEndian, uint32(len(field))); err != nil {
				t.Fatal(err)
			}
			preimage.Write(field)
		}
		macKey := sha1.Sum([]byte("putty-private-key-file-mac-key"))
		mac := hmac.New(sha1.New, macKey[:])
		mac.Write(preimage.Bytes())
		if lines[next] != "Private-MAC: "+hex.EncodeToString(mac.Sum(nil)) {
			t.Fatal("PPK MAC does not authenticate complete key and comment")
		}
	}
}

func keyPairTestPPKBlob(t *testing.T, lines []string, at int) ([]byte, int) {
	t.Helper()
	_, value, ok := strings.Cut(lines[at], ": ")
	if !ok {
		t.Fatal("missing PPK block header")
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < 1 || at+1+count >= len(lines) {
		t.Fatal("invalid PPK block length")
	}
	blob, err := base64.StdEncoding.DecodeString(strings.Join(lines[at+1:at+1+count], ""))
	if err != nil {
		t.Fatal(err)
	}
	return blob, at + 1 + count
}

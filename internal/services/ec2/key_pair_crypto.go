package ec2

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

// EC2 fingerprints are compatibility identifiers, not signature algorithms.
// In particular, RSA imports hash SPKI DER, not the SSH wire representation.
func keyPairFingerprint(public ssh.PublicKey, private crypto.PrivateKey) (string, error) {
	if public.Type() == ssh.KeyAlgoED25519 {
		digest := sha256.Sum256(public.Marshal())
		return base64.StdEncoding.EncodeToString(digest[:]), nil
	}
	if private != nil {
		der, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return "", err
		}
		digest := sha1.Sum(der)
		return keyPairHexFingerprint(digest[:]), nil
	}
	der, err := x509.MarshalPKIXPublicKey(public.(ssh.CryptoPublicKey).CryptoPublicKey())
	if err != nil {
		return "", err
	}
	digest := md5.Sum(der)
	return keyPairHexFingerprint(digest[:]), nil
}

func keyPairHexFingerprint(digest []byte) string {
	out := make([]byte, len(digest)*3-1)
	for i, b := range digest {
		hex.Encode(out[i*3:i*3+2], []byte{b})
		if i+1 < len(digest) {
			out[i*3+2] = ':'
		}
	}
	return string(out)
}

func generateKeyPair(kind, format, name string) (public, fingerprint, material string, err error) {
	var private crypto.Signer
	if kind == "ed25519" {
		_, private, err = ed25519.GenerateKey(rand.Reader)
	} else {
		private, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return "", "", "", err
	}
	sshPublic, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return "", "", "", err
	}
	fingerprint, err = keyPairFingerprint(sshPublic, private)
	if err != nil {
		return "", "", "", err
	}
	if format == "ppk" {
		material = marshalKeyPairPPK(private, sshPublic, name)
	} else {
		var block *pem.Block
		if rsaKey, ok := private.(*rsa.PrivateKey); ok {
			block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}
		} else {
			block, err = ssh.MarshalPrivateKey(private, name)
			if err != nil {
				return "", "", "", err
			}
		}
		material = string(pem.EncodeToMemory(block))
	}
	public = keyPairPublicMaterial(sshPublic, name)
	return public, fingerprint, material, nil
}

func keyPairPublicMaterial(public ssh.PublicKey, name string) string {
	return public.Type() + " " + base64.StdEncoding.EncodeToString(public.Marshal()) + " " + name + "\n"
}

// PPK v2 uses SSH mpints for RSA, but an unsigned, fixed-length seed string
// for Ed25519. Its MAC authenticates both halves and the comment, even without
// encryption. See PuTTY's Appendix C and crypto/ecc-ssh.c eddsa_private_blob.
func marshalKeyPairPPK(private crypto.Signer, public ssh.PublicKey, comment string) string {
	var privateBlob []byte
	switch k := private.(type) {
	case *rsa.PrivateKey:
		privateBlob = ssh.Marshal(struct{ D, P, Q, Qinv *big.Int }{k.D, k.Primes[0], k.Primes[1], k.Precomputed.Qinv})
	case ed25519.PrivateKey:
		privateBlob = ssh.Marshal(struct{ Seed []byte }{k.Seed()})
	}
	publicBlob := public.Marshal()
	macKey := sha1.Sum([]byte("putty-private-key-file-mac-key"))
	mac := hmac.New(sha1.New, macKey[:])
	mac.Write(ssh.Marshal(struct {
		Algorithm, Encryption, Comment string
		Public, Private                []byte
	}{public.Type(), "none", comment, publicBlob, privateBlob}))
	var out strings.Builder
	fmt.Fprintf(&out, "PuTTY-User-Key-File-2: %s\nEncryption: none\nComment: %s\n", public.Type(), comment)
	writeKeyPairPPKLines(&out, "Public", publicBlob)
	writeKeyPairPPKLines(&out, "Private", privateBlob)
	fmt.Fprintf(&out, "Private-MAC: %x\n", mac.Sum(nil))
	return out.String()
}

func writeKeyPairPPKLines(out *strings.Builder, label string, blob []byte) {
	encoded := base64.StdEncoding.EncodeToString(blob)
	fmt.Fprintf(out, "%s-Lines: %d\n", label, (len(encoded)+63)/64)
	for len(encoded) > 64 {
		out.WriteString(encoded[:64])
		out.WriteByte('\n')
		encoded = encoded[64:]
	}
	out.WriteString(encoded)
	out.WriteByte('\n')
}

func invalidKeyPairMaterial() error {
	return failure("InvalidKey.Format", "Key is not in valid OpenSSH public key format")
}

func parseKeyPairPublicKey(material []byte) (ssh.PublicKey, error) {
	if len(material) > 2048 {
		return nil, failure("InvalidParameterValue", "Value for parameter PublicKeyMaterial is invalid. Length exceeds maximum of 2048.")
	}
	for _, c := range material {
		if c > 127 {
			return nil, failure("InvalidParameterValue", "Value for parameter PublicKeyMaterial is invalid. Character sets beyond ASCII are not supported.")
		}
	}
	body := bytes.TrimSpace(material)
	var public ssh.PublicKey
	var err error
	rsaOnly := false
	switch {
	case bytes.HasPrefix(body, []byte("---- BEGIN SSH2 PUBLIC KEY ----")):
		rsaOnly = true
		public, err = parseKeyPairRFC4716(body)
	case bytes.HasPrefix(body, []byte("ssh-")):
		var options []string
		var rest []byte
		public, _, options, rest, err = ssh.ParseAuthorizedKey(body)
		if err == nil && (len(options) != 0 || len(bytes.TrimSpace(rest)) != 0) {
			return nil, invalidKeyPairMaterial()
		}
	default:
		rsaOnly = true
		der, decodeErr := base64.StdEncoding.DecodeString(string(body))
		if decodeErr != nil {
			return nil, invalidKeyPairMaterial()
		}
		key, parseErr := x509.ParsePKIXPublicKey(der)
		if parseErr != nil {
			return nil, invalidKeyPairMaterial()
		}
		public, err = ssh.NewPublicKey(key)
	}
	if err != nil {
		return nil, invalidKeyPairMaterial()
	}
	cryptoKey, ok := public.(ssh.CryptoPublicKey)
	if !ok {
		return nil, invalidKeyPairMaterial()
	}
	switch cryptoKey.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
	case ed25519.PublicKey:
		if rsaOnly {
			return nil, invalidKeyPairMaterial()
		}
	default:
		return nil, invalidKeyPairMaterial()
	}
	return public, nil
}

func parseKeyPairRFC4716(body []byte) (ssh.PublicKey, error) {
	lines := strings.Split(string(body), "\n")
	var encoded strings.Builder
	inHeaders, continuation, ended := true, false, false
	for _, raw := range lines[1:] {
		line := strings.TrimSpace(raw)
		if continuation {
			continuation = strings.HasSuffix(line, "\\")
			continue
		}
		if inHeaders && strings.Contains(line, ":") {
			continuation = strings.HasSuffix(line, "\\")
			continue
		}
		if line == "---- END SSH2 PUBLIC KEY ----" {
			ended = true
			continue
		}
		if ended {
			if line != "" {
				return nil, errors.New("trailing SSH2 data")
			}
			continue
		}
		inHeaders = false
		encoded.WriteString(line)
	}
	if !ended || continuation {
		return nil, errors.New("unterminated SSH2 key")
	}
	wire, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return nil, err
	}
	return ssh.ParsePublicKey(wire)
}

package ec2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// OpenSSL is the verifier prescribed by the EC2 documentation, independent of
// this encoder. Locally re-signed captures use explicit fixture certificates,
// never AWS trust.
func TestInstanceIdentitySignatureInteroperability(t *testing.T) {
	for _, name := range []string{"identity", "empty_tags", "secondary", "tag_convergence"} {
		t.Run(name, func(t *testing.T) {
			testInstanceIdentitySignatureInteroperability(t, "instances_metadata_"+name+"_handoff.json")
		})
	}
}

func testInstanceIdentitySignatureInteroperability(t *testing.T, fixtureName string) {
	t.Helper()
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is required for EC2 identity signature interoperability")
	}
	run := func(args ...string) error {
		output, err := exec.Command(openssl, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("openssl %s: %w: %s", args[0], err, output)
		}
		return nil
	}
	load := func(name string, value any) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("../../../testdata/aws/ec2", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, value); err != nil {
			t.Fatal(err)
		}
	}
	var capture struct {
		MetadataHTTP []struct {
			Path, Body   string
			Code, Repeat int
		} `json:"metadata_http"`
		Certificates map[string]string `json:"identity_signature_certificates"`
	}
	var certificates struct {
		Certificates map[string]string `json:"certificates"`
	}
	load(fixtureName, &capture)
	load("instance_identity_certificates.json", &certificates)
	bodies := map[string]string{}
	for _, row := range capture.MetadataHTTP {
		if row.Repeat == 0 && row.Code == 200 && strings.HasPrefix(row.Path, "/latest/dynamic/instance-identity/") {
			bodies[strings.TrimPrefix(row.Path, "/latest/dynamic/instance-identity/")] = row.Body
		}
	}
	document := []byte(bodies["document"])
	for _, endpoint := range []struct{ kind, leaf string }{{"rsa", "signature"}, {"dsa", "pkcs7"}, {"rsa2048", "rsa2048"}} {
		record, err := newIdentitySigningKey(endpoint.kind)
		if err != nil {
			t.Fatal(err)
		}
		local, err := parseIdentitySigningKey(record)
		if err != nil {
			t.Fatal(err)
		}
		localSignature, err := local.signedDocument(document, time.Date(2026, 9, 26, 11, 7, 54, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		fixtureSignature, err := base64.StdEncoding.DecodeString(bodies[endpoint.leaf])
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range []struct {
			name                                     string
			signature, certificate, wrongCertificate []byte
		}{
			{"locally-resigned-fixture", fixtureSignature, []byte(capture.Certificates[endpoint.kind]), []byte(certificates.Certificates[endpoint.kind])},
			{"local", localSignature, local.certificatePEM, []byte(certificates.Certificates[endpoint.kind])},
		} {
			t.Run(endpoint.leaf+"/"+source.name, func(t *testing.T) {
				dir := t.TempDir()
				put := func(name string, data []byte) string {
					t.Helper()
					path := filepath.Join(dir, name)
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					return path
				}
				docPath := put("document", document)
				sigPath := put("signature", source.signature)
				certPath := put("certificate", source.certificate)
				wrongPath := put("wrong-certificate", source.wrongCertificate)
				verify := func(cert string) error {
					if endpoint.kind == "rsa" {
						pubPath := filepath.Join(dir, "public-key")
						if err := run("x509", "-in", cert, "-pubkey", "-noout", "-out", pubPath); err != nil {
							t.Fatal(err)
						}
						return run("dgst", "-sha256", "-verify", pubPath, "-signature", sigPath, docPath)
					}
					verifiedPath := filepath.Join(dir, "verified-document")
					if err := run("smime", "-verify", "-inform", "DER", "-in", sigPath, "-certfile", cert, "-noverify", "-out", verifiedPath); err != nil {
						return err
					}
					verified, err := os.ReadFile(verifiedPath)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(verified, document) {
						t.Fatal("verified CMS document differs from IMDS document")
					}
					return nil
				}
				if err := verify(certPath); err != nil {
					t.Fatalf("trusted signature rejected: %v", err)
				}
				if err := verify(wrongPath); err == nil {
					t.Fatal("signature accepted without the explicitly trusted signer")
				}
				if endpoint.kind == "rsa" {
					changed := bytes.Clone(document)
					changed[len(changed)-1] ^= 1
					put("document", changed)
				} else {
					changed := bytes.Clone(source.signature)
					index := bytes.Index(changed, document)
					if index < 0 {
						t.Fatal("CMS omits the identity document")
					}
					changed[index+len(document)-1] ^= 1
					put("signature", changed)
				}
				if err := verify(certPath); err == nil {
					t.Fatal("modified identity document accepted")
				}
			})
		}
	}
}

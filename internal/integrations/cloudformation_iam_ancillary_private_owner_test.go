package integrations

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"stackd/internal/services/cloudformation"
)

func cfnIAMPrivateCertificate(t *testing.T) (string, string) {
	t.Helper()
	var scalar [32]byte
	scalar[len(scalar)-1] = 1
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2120, 1, 1, 0, 0, 0, 0, time.UTC), DNSNames: []string{"private.example.com"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}

func TestCFNIAMAncillaryPrivateClaimsSurviveReopenAndRejectCounterfeitTags(t *testing.T) {
	body, private := cfnIAMPrivateCertificate(t)
	metadata, err := os.ReadFile("../services/iam/testdata/federation/metadata.xml")
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"InstanceProfile", "OIDCProvider", "SAMLProvider", "VirtualMFADevice", "ServerCertificate"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newCFNIAMPrivateFixture(t, backend)
				var properties cloudformation.Properties
				var op, tagOp, key string
				var input map[string]any
				switch kind {
				case "InstanceProfile":
					properties = cloudformation.Properties{"InstanceProfileName": "private-profile", "Roles": []any{}}
					op, tagOp, key = "CreateInstanceProfile", "TagInstanceProfile", "InstanceProfileName"
					input = map[string]any{key: "private-profile"}
				case "OIDCProvider":
					properties = cloudformation.Properties{"Url": "https://private.example.com", "ThumbprintList": []any{strings.Repeat("a", 40)}}
					op, tagOp, key = "CreateOpenIDConnectProvider", "TagOpenIDConnectProvider", "OpenIDConnectProviderArn"
					input = map[string]any{"Url": "https://private.example.com", "ThumbprintList": properties["ThumbprintList"]}
				case "SAMLProvider":
					properties = cloudformation.Properties{"Name": "private-saml", "SamlMetadataDocument": string(metadata)}
					op, tagOp, key = "CreateSAMLProvider", "TagSAMLProvider", "SAMLProviderArn"
					input = map[string]any{"Name": "private-saml", "SAMLMetadataDocument": string(metadata)}
				case "VirtualMFADevice":
					properties = cloudformation.Properties{"VirtualMfaDeviceName": "private-mfa", "Users": []any{}}
					op, tagOp, key = "CreateVirtualMFADevice", "TagMFADevice", "SerialNumber"
					input = map[string]any{"VirtualMFADeviceName": "private-mfa"}
				case "ServerCertificate":
					properties = cloudformation.Properties{"ServerCertificateName": "private-certificate", "CertificateBody": body, "PrivateKey": private}
					op, tagOp, key = "UploadServerCertificate", "TagServerCertificate", "ServerCertificateName"
					input = map[string]any{key: "private-certificate", "CertificateBody": body, "PrivateKey": private}
				}
				r := cfnIAMOwnerRequest(kind, kind, properties)
				r.CloudControl = true
				h := CloudFormationIAMAdditionalHandlers(f.commands)[r.Type]
				created, err := h.Create(f.ctx, r)
				if err != nil || created.PhysicalID == "" {
					t.Fatalf("native create: %+v %v", created, err)
				}
				// Even an authorized public tag writer cannot change the native claim.
				foreign := r
				foreign.Token = "counterfeit-incarnation"
				tagID := created.PhysicalID
				f.run(tagOp, map[string]any{key: tagID, "Tags": cfnComputeTagList(cfnComputeOwnedTags(foreign))})
				f.reopen()
				h = CloudFormationIAMAdditionalHandlers(f.commands)[r.Type]
				actual, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
				if err != nil || actual.PhysicalID != created.PhysicalID {
					t.Fatalf("public tag mutation overwrote private owner: %+v %v", actual, err)
				}
				absent, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, foreign)
				if !cfnComputeMissing(err) || absent.PhysicalID != "" {
					t.Fatalf("counterfeit tags forged recovery: %+v %v", absent, err)
				}
				r.PhysicalID = created.PhysicalID
				r.CloudControl = false
				if err := h.Delete(f.ctx, r); err != nil {
					t.Fatal(err)
				}
				input["Tags"] = cfnComputeTagList(cfnComputeOwnedTags(r))
				f.run(op, input)
				if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err == nil {
					t.Fatal("same-identifier foreign recreation adopted")
				}
				if _, err := h.Update(f.ctx, r); err == nil {
					t.Fatal("same-identifier foreign recreation mutated")
				}
				if err := h.Delete(f.ctx, r); err == nil {
					t.Fatal("same-identifier foreign recreation deleted")
				}
				absent, err = h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
				if !cfnComputeMissing(err) || absent.PhysicalID != "" {
					t.Fatalf("foreign recreation was recovered: %+v %v", absent, err)
				}
				direct := r
				direct.CloudControl = true
				if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, direct); err != nil {
					t.Fatalf("ordinary IAM-permitted read blocked: %v", err)
				}
				failed, err := h.Create(f.ctx, direct)
				if err == nil || failed.PhysicalID != "" {
					t.Fatalf("CC CREATE adopted foreign recreation: %+v %v", failed, err)
				}
			})
		}
	}
}

package sts

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type samlAWSObservation struct {
	Scenario          string `json:"scenario"`
	Code              string `json:"code"`
	Message           string `json:"message,omitempty"`
	Audience          string `json:"audience,omitempty"`
	Subject           string `json:"subject,omitempty"`
	SubjectType       string `json:"subject_type,omitempty"`
	SourceIdentity    string `json:"source_identity,omitempty"`
	DurationSeconds   int    `json:"duration_seconds,omitempty"`
	RepeatedAssertion bool   `json:"repeated_assertion,omitempty"`
}

type samlAWSFixture struct {
	ObservedAt                string               `json:"observed_at"`
	Region                    string               `json:"region"`
	CleanupVerified           bool                 `json:"cleanup_verified"`
	SigningCertificateExpired bool                 `json:"signing_certificate_expired"`
	EncryptionMode            string               `json:"encryption_mode"`
	Observations              []samlAWSObservation `json:"observations"`
}

var samlAWSScenarios = []string{
	"assertion_signed", "response_signed", "both_signed", "unsigned", "tampered_subject",
	"wrong_audience", "no_audience_restriction", "no_conditions", "wrong_recipient", "recipient_provider_id", "missing_subject_expiry",
	"expired_conditions", "expired_subject", "future_conditions_60", "future_conditions_240", "future_conditions_360",
	"session_expired", "session_expires_600", "session_duration_900", "session_duration_7200", "api_duration_7200",
	"reversed_role_pair", "wrong_role", "subject_email_format", "subject_missing_format", "source_and_tags", "duplicate_subject_confirmation",
	"encrypted_aes128_cbc", "encrypted_aes256_cbc", "encrypted_aes128_gcm", "encrypted_aes256_gcm", "encrypted_oaep_sha256_mgf1sha1", "encrypted_oaep_sha256_mgf1sha256",
	"future_conditions_86400", "malformed_notbefore", "future_subject_notbefore", "missing_conditions_expiry", "no_authn_statement", "one_time_use", "proxy_restriction", "missing_recipient", "arbitrary_recipient", "response_issuer_mismatch", "invalid_response_signature", "subject_arbitrary_format", "required_plaintext", "required_encrypted_no_id", "required_encrypted_id", "required_encrypted_wrong_id",
}

func samlAWSScenario(t *testing.T, f samlTestFixture, name string) ([]byte, *int32) {
	t.Helper()
	a := f.assertion()
	conditions, _ := samlOne(a, samlAssertionNS, "Conditions")
	subject, _ := samlOne(a, samlAssertionNS, "Subject")
	confirmation, _ := samlOne(subject, samlAssertionNS, "SubjectConfirmation")
	data, _ := samlOne(confirmation, samlAssertionNS, "SubjectConfirmationData")
	authn, _ := samlOne(a, samlAssertionNS, "AuthnStatement")
	nameID, _ := samlOne(subject, samlAssertionNS, "NameID")
	var duration *int32
	switch name {
	case "wrong_audience":
		samlChildren(samlChildren(conditions, samlAssertionNS, "AudienceRestriction")[0], samlAssertionNS, "Audience")[0].SetText("urn:unrelated:application")
	case "no_audience_restriction":
		conditions.RemoveChild(conditions.ChildElements()[0])
	case "no_conditions":
		a.RemoveChild(conditions)
	case "wrong_recipient":
		data.CreateAttr("Recipient", "https://unrelated.example.test/saml")
	case "recipient_provider_id":
		data.CreateAttr("Recipient", "https://us-east-1.signin.aws.amazon.com/saml/acs/"+f.provider.ID)
	case "missing_subject_expiry":
		data.RemoveAttr("NotOnOrAfter")
	case "expired_conditions":
		conditions.CreateAttr("NotOnOrAfter", f.now.Add(-time.Minute).Format(time.RFC3339))
	case "expired_subject":
		data.CreateAttr("NotOnOrAfter", f.now.Add(-time.Minute).Format(time.RFC3339))
	case "future_conditions_60":
		conditions.CreateAttr("NotBefore", f.now.Add(time.Minute).Format(time.RFC3339))
	case "future_conditions_240":
		conditions.CreateAttr("NotBefore", f.now.Add(4*time.Minute).Format(time.RFC3339))
	case "future_conditions_360":
		conditions.CreateAttr("NotBefore", f.now.Add(6*time.Minute).Format(time.RFC3339))
	case "future_conditions_86400":
		conditions.CreateAttr("NotBefore", f.now.Add(24*time.Hour).Format(time.RFC3339))
	case "malformed_notbefore":
		conditions.CreateAttr("NotBefore", "invalid")
	case "future_subject_notbefore":
		data.CreateAttr("NotBefore", f.now.Add(24*time.Hour).Format(time.RFC3339))
	case "missing_conditions_expiry":
		conditions.RemoveAttr("NotOnOrAfter")
	case "no_authn_statement":
		a.RemoveChild(authn)
	case "one_time_use":
		samlTestChild(conditions, "saml:OneTimeUse", "")
	case "proxy_restriction":
		samlTestChild(conditions, "saml:ProxyRestriction", "").CreateAttr("Count", "0")
	case "missing_recipient":
		data.RemoveAttr("Recipient")
	case "arbitrary_recipient":
		data.CreateAttr("Recipient", "not-a-url")
	case "subject_arbitrary_format":
		nameID.CreateAttr("Format", "custom-format")
	case "required_encrypted_id":
		data.CreateAttr("Recipient", "https://us-east-1.signin.aws.amazon.com/saml/acs/"+f.provider.ID)
	case "required_encrypted_wrong_id":
		data.CreateAttr("Recipient", "https://us-east-1.signin.aws.amazon.com/saml/acs/SAMLWRONGPROVIDER")
	case "session_expired":
		authn.CreateAttr("SessionNotOnOrAfter", f.now.Add(-time.Minute).Format(time.RFC3339))
	case "session_expires_600":
		authn.CreateAttr("SessionNotOnOrAfter", f.now.Add(10*time.Minute).Format(time.RFC3339))
	case "session_duration_900":
		samlTestAttribute(a, "SessionDuration", "900")
	case "session_duration_7200":
		samlTestAttribute(a, "SessionDuration", "7200")
	case "api_duration_7200":
		duration = aws.Int32(7200)
	case "reversed_role_pair":
		samlChildren(samlChildren(a, samlAssertionNS, "AttributeStatement")[0], samlAssertionNS, "Attribute")[0].ChildElements()[0].SetText(f.provider.ARN + "," + f.roleARN)
	case "wrong_role":
		samlChildren(samlChildren(a, samlAssertionNS, "AttributeStatement")[0], samlAssertionNS, "Attribute")[0].ChildElements()[0].SetText("arn:aws:iam::123456789012:role/other," + f.provider.ARN)
	case "subject_email_format":
		nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	case "subject_missing_format":
		nameID.RemoveAttr("Format")
	case "source_and_tags":
		samlTestAttribute(a, "SourceIdentity", "source-123")
		samlTestAttribute(a, "PrincipalTag:team", "engineering")
		samlTestAttribute(a, "TransitiveTagKeys", "team")
	case "duplicate_subject_confirmation":
		subject.AddChild(confirmation.Copy())
	}
	if name != "response_signed" && name != "unsigned" {
		a = f.sign(t, a)
	}
	if strings.HasPrefix(name, "encrypted_") || strings.HasPrefix(name, "required_encrypted_") {
		size, gcm := 16, false
		if strings.Contains(name, "256_c") || strings.Contains(name, "256_g") {
			size = 32
		}
		if strings.Contains(name, "gcm") {
			gcm = true
		}
		options := &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}
		legacy := true
		if strings.Contains(name, "oaep_sha256") {
			options.Hash = crypto.SHA256
		}
		if strings.Contains(name, "mgf1sha256") {
			options.MGFHash = crypto.SHA256
			legacy = false
		}
		a = f.encrypt(t, a, size, gcm, options, legacy)
	}
	r := f.response(a)
	if name == "response_issuer_mismatch" {
		r.ChildElements()[0].SetText("https://other.example.test")
	}
	if name == "response_signed" || name == "both_signed" || name == "invalid_response_signature" {
		r = f.sign(t, r)
	}
	if name == "invalid_response_signature" {
		sig, _ := samlOne(r, samlSignatureNS, "Signature")
		v, _ := samlOne(sig, samlSignatureNS, "SignatureValue")
		v.SetText(base64.StdEncoding.EncodeToString(make([]byte, 256)))
	}
	raw := samlTestBytes(t, r)
	if name == "tampered_subject" {
		raw = []byte(strings.Replace(string(raw), "subject-123", "subject-999", 1))
	}
	return raw, duration
}

// TestSAMLProbeAWS is an explicit, opt-in fixture capture. It creates one uniquely
// named provider and role, attaches no permission policies, and verifies cleanup.
// Returned session credentials are never written to disk or included in logs.
func TestSAMLProbeAWS(t *testing.T) {
	if os.Getenv("STACKD_SAML_AWS_PROBE_WRITE") != "1" {
		t.Skip("owned AWS resource probe requires explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	iam := sdkiam.NewFromConfig(cfg)
	sts := sdksts.NewFromConfig(cfg)
	caller, err := sts.GetCallerIdentity(ctx, &sdksts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("stackd-saml-probe-%d", time.Now().UnixNano())
	f := newSAMLTestFixture(t)
	cert, err := x509.ParseCertificate(f.certificate)
	if err != nil {
		t.Fatal(err)
	}
	cert.NotAfter = f.now.Add(-time.Hour)
	f.certificate, err = x509.CreateCertificate(rand.Reader, cert, cert, &f.key.PublicKey, f.key)
	if err != nil {
		t.Fatal(err)
	}
	f.provider.Issuers[0].SigningCertificates = [][]byte{f.certificate}
	f.provider.ARN = "arn:aws:iam::" + aws.ToString(caller.Account) + ":saml-provider/" + name
	f.roleARN = "arn:aws:iam::" + aws.ToString(caller.Account) + ":role/" + name
	metadata := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(f.certificate) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/login"/></IDPSSODescriptor></EntityDescriptor>`
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: f.provider.PrivateKeys[0].PKCS8DER})
	mode := iamtypes.AssertionEncryptionModeTypeAllowed
	if os.Getenv("STACKD_SAML_AWS_PROBE_REQUIRED") == "1" {
		mode = iamtypes.AssertionEncryptionModeTypeRequired
		f.provider.AssertionEncryptionMode = "Required"
	}
	_, err = iam.CreateSAMLProvider(ctx, &sdkiam.CreateSAMLProviderInput{Name: aws.String(name), SAMLMetadataDocument: aws.String(metadata), AssertionEncryptionMode: mode, AddPrivateKey: aws.String(string(private))})
	if err != nil {
		t.Fatal(err)
	}
	roleCreated := false
	fixture := samlAWSFixture{ObservedAt: time.Now().UTC().Format(time.RFC3339), Region: "us-east-1", SigningCertificateExpired: true, EncryptionMode: string(mode)}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if roleCreated {
			if _, err := iam.DeleteRole(cleanup, &sdkiam.DeleteRoleInput{RoleName: aws.String(name)}); err != nil {
				t.Errorf("delete owned role: %v", err)
				return
			}
		}
		if _, err := iam.DeleteSAMLProvider(cleanup, &sdkiam.DeleteSAMLProviderInput{SAMLProviderArn: aws.String(f.provider.ARN)}); err != nil {
			t.Errorf("delete owned provider: %v", err)
			return
		}
		_, roleErr := iam.GetRole(cleanup, &sdkiam.GetRoleInput{RoleName: aws.String(name)})
		_, providerErr := iam.GetSAMLProvider(cleanup, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: aws.String(f.provider.ARN)})
		var re, pe *iamtypes.NoSuchEntityException
		fixture.CleanupVerified = errors.As(roleErr, &re) && errors.As(providerErr, &pe)
		if !fixture.CleanupVerified {
			t.Errorf("cleanup absence verification failed")
			return
		}
		if err := os.MkdirAll("testdata", 0755); err != nil {
			t.Error(err)
			return
		}
		body, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Error(err)
			return
		}
		path := "testdata/saml_aws.json"
		if mode == iamtypes.AssertionEncryptionModeTypeRequired {
			path = "testdata/saml_required_aws.json"
		}
		if err := os.WriteFile(path, append(body, '\n'), 0644); err != nil {
			t.Error(err)
		}
	}()
	configured, err := iam.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: aws.String(f.provider.ARN)})
	if err != nil {
		t.Fatal(err)
	}
	f.provider.ID = aws.ToString(configured.SAMLProviderUUID)
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":["sts:AssumeRoleWithSAML","sts:TagSession","sts:SetSourceIdentity"]}]}`, f.provider.ARN)
	_, err = iam.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(trust), MaxSessionDuration: aws.Int32(14400)})
	if err != nil {
		t.Fatal(err)
	}
	roleCreated = true
	scenarios := samlAWSScenarios
	if mode == iamtypes.AssertionEncryptionModeTypeRequired {
		scenarios = []string{"required_encrypted_id", "required_plaintext", "required_encrypted_no_id", "required_encrypted_wrong_id"}
	}
	for _, scenario := range scenarios {
		if mode == iamtypes.AssertionEncryptionModeTypeAllowed && strings.HasPrefix(scenario, "required_") {
			continue
		}
		f.now = time.Now().UTC().Truncate(time.Second)
		raw, duration := samlAWSScenario(t, f, scenario)
		input := &sdksts.AssumeRoleWithSAMLInput{PrincipalArn: aws.String(f.provider.ARN), RoleArn: aws.String(f.roleARN), SAMLAssertion: aws.String(base64.StdEncoding.EncodeToString(raw)), DurationSeconds: duration}
		before := time.Now()
		out, err := sts.AssumeRoleWithSAML(ctx, input)
		if scenario == "one_time_use" && err == nil {
			// Reuse the exact signed bytes: accepting the first assertion alone
			// does not establish whether STS enforces OneTimeUse replay state.
			before = time.Now()
			out, err = sts.AssumeRoleWithSAML(ctx, input)
		}
		for attempt := 0; err != nil && attempt < 12; attempt++ {
			var api smithy.APIError
			if !errors.As(err, &api) || api.ErrorCode() != "AccessDenied" {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(2 * time.Second):
			}
			before = time.Now()
			out, err = sts.AssumeRoleWithSAML(ctx, input)
		}
		observation := samlAWSObservation{Scenario: scenario, Code: "Success"}
		observation.RepeatedAssertion = scenario == "one_time_use"
		if err != nil {
			var api smithy.APIError
			if !errors.As(err, &api) {
				t.Fatal(err)
			}
			observation.Code = api.ErrorCode()
			observation.Message = strings.ReplaceAll(api.ErrorMessage(), aws.ToString(caller.Account), "123456789012")
		} else {
			observation.Audience = aws.ToString(out.Audience)
			observation.Audience = strings.ReplaceAll(observation.Audience, f.provider.ID, "SAMLTESTPROVIDER")
			observation.Subject = aws.ToString(out.Subject)
			observation.SubjectType = aws.ToString(out.SubjectType)
			observation.SourceIdentity = aws.ToString(out.SourceIdentity)
			if out.Credentials != nil && out.Credentials.Expiration != nil {
				observation.DurationSeconds = int(out.Credentials.Expiration.Sub(before).Round(time.Second) / time.Second)
			}
		}
		fixture.Observations = append(fixture.Observations, observation)
		t.Logf("%s: %s duration=%d", scenario, observation.Code, observation.DurationSeconds)
		if scenario == "assertion_signed" && err != nil {
			t.Fatalf("baseline assertion rejected: %s", observation.Message)
		}
	}
}

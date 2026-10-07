package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	acmapi "stackd/internal/awsapi/acm"
	sesapi "stackd/internal/awsapi/sesv2"
	signerapi "stackd/internal/awsapi/signer"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/acm"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sesv2"
	"stackd/internal/services/signer"
	"stackd/storage/sqlite"
	acmstore "stackd/storage/sqlite/acm"
	sesstore "stackd/storage/sqlite/sesv2"
	signerstore "stackd/storage/sqlite/signer"
)

type cfnTrustOwnerDNS struct{}

func (cfnTrustOwnerDNS) LookupCNAME(_ context.Context, name string) (string, error) {
	return "", &net.DNSError{Name: name, IsNotFound: true}
}

type cfnTrustOwnerAuthorizer struct{ denied bool }

func (a *cfnTrustOwnerAuthorizer) Authorize(context.Context, authorization.Request) *awswire.Error {
	if a.denied {
		return &awswire.Error{Code: "AccessDenied", Message: "current IAM denies the operation", StatusCode: 403}
	}
	return nil
}

type cfnTrustOwnerExecutor func(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)

func (e cfnTrustOwnerExecutor) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	return e(ctx, r)
}

type cfnTrustOwnerFixture struct {
	t             *testing.T
	ctx           context.Context
	backend, path string
	db            *sql.DB
	at            *clock.Manual
	auth          *cfnTrustOwnerAuthorizer
	signerRepo    signer.Repository
	sesRepo       sesv2.Repository
	acmRepo       acm.Repository
	signer        *signer.Service
	ses           *sesv2.Service
	acm           *acm.Service
	commands      StepFunctionsCommands
}

func newCFNTrustOwnerFixture(t *testing.T, backend string) *cfnTrustOwnerFixture {
	t.Helper()
	f := &cfnTrustOwnerFixture{t: t, backend: backend, path: filepath.Join(t.TempDir(), "trust.sqlite"), at: clock.NewManual(time.Date(2032, 1, 2, 3, 4, 0, 0, time.UTC)), auth: &cfnTrustOwnerAuthorizer{}}
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	f.signerRepo = signer.NewMemoryRepository(nil)
	f.sesRepo = sesv2.NewMemoryRepository(nil)
	f.acmRepo = acm.NewMemoryRepository(nil)
	f.open()
	f.assemble()
	t.Cleanup(func() {
		_ = f.ses.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}
func (f *cfnTrustOwnerFixture) open() {
	f.t.Helper()
	if f.backend != "sqlite" {
		return
	}
	var err error
	f.db, err = sqlite.Open(f.ctx, f.path)
	if err != nil {
		f.t.Fatal(err)
	}
	f.signerRepo = signerstore.New(f.db)
	f.sesRepo = sesstore.New(f.db)
	f.acmRepo = acmstore.New(f.db)
}
func (f *cfnTrustOwnerFixture) assemble() {
	f.signer = signer.New(signer.Config{Repository: f.signerRepo, Clock: f.at, Authorizer: f.auth})
	f.ses = sesv2.NewWithConfig(sesv2.Config{Repository: f.sesRepo, Clock: f.at, Authorizer: f.auth, PublicEndpoint: "http://localhost:4566"})
	f.acm = acm.New(acm.Config{Repository: f.acmRepo, Clock: f.at, Authorizer: f.auth, DNS: cfnTrustOwnerDNS{}})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"signer": f.signer, "sesv2": f.ses, "acm": f.acm})
}
func (f *cfnTrustOwnerFixture) reopen() {
	f.t.Helper()
	if err := f.ses.Close(); err != nil {
		f.t.Fatal(err)
	}
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			f.t.Fatal(err)
		}
	}
	f.open()
	f.assemble()
}
func (f *cfnTrustOwnerFixture) request(kind string) cloudformation.ResourceRequest {
	r := cloudformation.ResourceRequest{Type: kind, StackID: "trust-stack", StackName: "trust", LogicalID: "Resource", Token: "exact-native-incarnation", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}}
	switch kind {
	case "AWS::Signer::SigningProfile":
		r.Properties = cloudformation.Properties{"ProfileName": "trust_profile", "PlatformId": cfnSignerLambdaPlatform}
	case "AWS::SES::EmailIdentity":
		r.Properties = cloudformation.Properties{"EmailIdentity": "identity@example.invalid"}
	case "AWS::SES::ConfigurationSet":
		r.Properties = cloudformation.Properties{"Name": "trust-set", "SendingOptions": map[string]any{"SendingEnabled": true}}
	case "AWS::CertificateManager::Certificate":
		r.Properties = cloudformation.Properties{"DomainName": "trust.example.invalid", "ValidationMethod": "DNS", "KeyAlgorithm": "EC_prime256v1"}
	}
	return r
}
func (f *cfnTrustOwnerFixture) handler(kind string) cloudformation.ResourceHandler {
	return CloudFormationTrustDNSHandlers(f.commands)[kind]
}
func (f *cfnTrustOwnerFixture) foreign(r cloudformation.ResourceRequest, domain string) string {
	f.t.Helper()
	tags := cfnComputeOwnedTags(r)
	switch r.Type {
	case "AWS::Signer::SigningProfile":
		out, err := cfnTrustTyped[signerapi.PutSigningProfileOutput](f.ctx, f.commands, "signer", "PutSigningProfile", &signerapi.PutSigningProfileInput{ProfileName: new(signerapi.ProfileName(cfnSignerName(r))), PlatformId: new(signerapi.PlatformId(cfnSignerLambdaPlatform)), Tags: cfnSignerTagMap(tags)})
		if err != nil {
			f.t.Fatal(err)
		}
		return cfnComputeValue(out.Arn)
	case "AWS::SES::EmailIdentity":
		name := cfnComputeString(r.Properties, "EmailIdentity")
		_, err := cfnTrustTyped[sesapi.CreateEmailIdentityOutput](f.ctx, f.commands, "sesv2", "CreateEmailIdentity", &sesapi.CreateEmailIdentityInput{EmailIdentity: new(sesapi.Identity(name)), Tags: cfnSESTagList(tags)})
		if err != nil {
			f.t.Fatal(err)
		}
		return name
	case "AWS::SES::ConfigurationSet":
		name := cfnComputeName(r, "Name", 64)
		_, err := cfnTrustTyped[sesapi.CreateConfigurationSetOutput](f.ctx, f.commands, "sesv2", "CreateConfigurationSet", &sesapi.CreateConfigurationSetInput{ConfigurationSetName: new(sesapi.ConfigurationSetName(name)), Tags: cfnSESTagList(tags)})
		if err != nil {
			f.t.Fatal(err)
		}
		return name
	default:
		if domain == "" {
			domain = cfnComputeString(r.Properties, "DomainName")
		}
		out, err := cfnTrustTyped[acmapi.RequestCertificateResponse](f.ctx, f.commands, "acm", "RequestCertificate", &acmapi.RequestCertificateRequest{DomainName: new(acmapi.DomainNameString(domain)), ValidationMethod: new(acmapi.ValidationMethod("DNS")), KeyAlgorithm: new(acmapi.KeyAlgorithm("EC_prime256v1")), IdempotencyToken: new(acmapi.IdempotencyToken(cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Token)[:24] + "cfn")), Tags: cfnACMTagList(tags)})
		if err != nil {
			f.t.Fatal(err)
		}
		return cfnComputeValue(out.CertificateArn)
	}
}
func (f *cfnTrustOwnerFixture) nativeTags(r cloudformation.ResourceRequest, tags map[string]string) {
	f.t.Helper()
	var err error
	switch r.Type {
	case "AWS::Signer::SigningProfile":
		_, err = cfnTrustTyped[signerapi.TagResourceOutput](f.ctx, f.commands, "signer", "TagResource", &signerapi.TagResourceInput{ResourceArn: new(signerapi.String(r.PhysicalID)), Tags: cfnSignerTagMap(tags)})
	case "AWS::SES::EmailIdentity":
		_, err = cfnTrustTyped[sesapi.TagResourceOutput](f.ctx, f.commands, "sesv2", "TagResource", &sesapi.TagResourceInput{ResourceArn: new(sesapi.AmazonResourceName(cfnSESARN(r, "identity", r.PhysicalID))), Tags: cfnSESTagList(tags)})
	case "AWS::SES::ConfigurationSet":
		_, err = cfnTrustTyped[sesapi.TagResourceOutput](f.ctx, f.commands, "sesv2", "TagResource", &sesapi.TagResourceInput{ResourceArn: new(sesapi.AmazonResourceName(cfnSESARN(r, "configuration-set", r.PhysicalID))), Tags: cfnSESTagList(tags)})
	default:
		_, err = cfnTrustTyped[acmapi.Unit](f.ctx, f.commands, "acm", "AddTagsToCertificate", &acmapi.AddTagsToCertificateRequest{CertificateArn: new(acmapi.Arn(r.PhysicalID)), Tags: cfnACMTagList(tags)})
	}
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *cfnTrustOwnerFixture) nativeDelete(r cloudformation.ResourceRequest) {
	f.t.Helper()
	direct := r
	direct.CloudControl = true
	if err := f.handler(r.Type).Delete(f.ctx, direct); err != nil {
		f.t.Fatal(err)
	}
}
func cfnTrustOwnerKinds() []string {
	return []string{"AWS::Signer::SigningProfile", "AWS::SES::EmailIdentity", "AWS::SES::ConfigurationSet", "AWS::CertificateManager::Certificate"}
}

func TestCFNTrustPrivateAuthorityRejectsCounterfeitPublicTags(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range cfnTrustOwnerKinds() {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newCFNTrustOwnerFixture(t, backend)
				r := f.request(kind)
				r.CloudControl = true
				r.PhysicalID = f.foreign(r, "")
				h := f.handler(kind)
				if rejected, err := h.Create(f.ctx, r); err == nil || rejected.PhysicalID != "" {
					t.Fatalf("counterfeit tags adopted native resource: %+v %v", rejected, err)
				}
				if rejected, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil || rejected.PhysicalID != "" {
					t.Fatalf("counterfeit tags authorized recovery: %+v %v", rejected, err)
				}
				stack := r
				stack.CloudControl = false
				stack.Previous = stack.Properties
				if _, err := h.Update(f.ctx, stack); err == nil {
					t.Fatal("counterfeit tags authorized stack update")
				}
				if err := h.Delete(f.ctx, stack); err == nil {
					t.Fatal("counterfeit tags authorized stack deletion")
				}
				if kind == "AWS::Signer::SigningProfile" {
					readonly := r
					readonly.Previous = r.Properties
					if _, err := h.Update(f.ctx, readonly); err == nil {
						t.Fatal("Cloud Control accepted read-only ProfileName as desired input")
					}
				}
				model, err := h.(cloudformation.ResourceReader).Read(f.ctx, r)
				if err != nil {
					t.Fatal("rejected stack damaged native resource", err)
				}
				r.Previous, err = cloudformation.WritableResourceProperties(r.Type, model)
				if err != nil {
					t.Fatal(err)
				}
				r.Properties, err = cloudformation.WritableResourceProperties(r.Type, model)
				if err != nil {
					t.Fatal(err)
				}
				r.Properties["Tags"] = []any{map[string]any{"Key": "direct", "Value": "permitted"}}
				if _, err := h.Update(f.ctx, r); err != nil {
					t.Fatal("direct Cloud Control mutation denied", err)
				}
				f.nativeTags(r, map[string]string{"native": "permitted"})
				f.nativeDelete(r)
			})
		}
	}
}

func TestCFNACMPrivateAuthorityRejectsWrongDomainReceipt(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNTrustOwnerFixture(t, backend)
			r := f.request("AWS::CertificateManager::Certificate")
			r.CloudControl = true
			foreign := f.foreign(r, "different.example.invalid")
			h := f.handler(r.Type)
			if rejected, err := h.Create(f.ctx, r); err == nil || rejected.PhysicalID != "" {
				t.Fatalf("preempted token adopted wrong-domain certificate: %+v %v", rejected, err)
			}
			r.PhysicalID = foreign
			live, err := h.(cloudformation.ResourceReader).Read(f.ctx, r)
			if err != nil || live["DomainName"] != "different.example.invalid" {
				t.Fatalf("foreign receipt certificate damaged: %+v %v", live, err)
			}
		})
	}
}

func TestCFNTrustPrivateRecoverySurvivesLostReplyAndReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range cfnTrustOwnerKinds() {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newCFNTrustOwnerFixture(t, backend)
				r := f.request(kind)
				r.CloudControl = true
				service, operation := "sesv2", "CreateConfigurationSet"
				var owner awscommands.CommandExecutor = f.ses
				switch kind {
				case "AWS::Signer::SigningProfile":
					service, operation, owner = "signer", "PutSigningProfile", f.signer
				case "AWS::SES::EmailIdentity":
					operation = "CreateEmailIdentity"
				case "AWS::CertificateManager::Certificate":
					service, operation, owner = "acm", "RequestCertificate", f.acm
				}
				lost := true
				executor := cfnTrustOwnerExecutor(func(ctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
					out, err := owner.ExecuteCommand(ctx, req)
					if err == nil && lost && string(req.Operation.Name) == operation {
						lost = false
						return nil, &awswire.Error{Code: "RequestTimeout", Message: "admitted native reply lost", StatusCode: 504}
					}
					return out, err
				})
				commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{service: executor})
				h := CloudFormationTrustDNSHandlers(commands)[kind]
				admitted, err := h.Create(f.ctx, r)
				if err == nil || admitted.PhysicalID == "" {
					t.Fatalf("lost native reply forgot admission: %+v %v", admitted, err)
				}
				r.PhysicalID = admitted.PhysicalID
				f.reopen()
				h = f.handler(kind)
				if err := f.at.Advance(2 * time.Hour); err != nil {
					t.Fatal(err)
				}
				recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
				if err != nil || recovered.PhysicalID != admitted.PhysicalID {
					t.Fatalf("reopened private claim recovery: %+v %v", recovered, err)
				}
				replayed, err := h.Create(f.ctx, r)
				if err != nil || replayed.PhysicalID != admitted.PhysicalID {
					t.Fatalf("expired public token changed admitted incarnation: %+v %v", replayed, err)
				}
				forged := r
				forged.Token = "foreign-token"
				f.nativeTags(r, cfnComputeOwnedTags(forged))
				if rejected, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, forged); err == nil || rejected.PhysicalID != "" {
					t.Fatalf("public tag rewrite changed private claim: %+v %v", rejected, err)
				}
				live, err := h.(cloudformation.ResourceReader).Read(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(live)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), "stackd-cfn-") {
					t.Fatal("private owner claim leaked through Read")
				}
				listed, err := h.(cloudformation.ResourceReader).List(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err = json.Marshal(listed)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), "stackd-cfn-") {
					t.Fatal("private owner claim leaked through List")
				}
				stack := r
				stack.CloudControl = false
				stack.Previous = stack.Properties
				if _, err := h.Update(f.ctx, stack); err != nil {
					t.Fatal("counterfeit public tags revoked genuine native owner", err)
				}
				if err := h.Delete(f.ctx, stack); err != nil {
					t.Fatal("genuine rollback denied after tag forgery", err)
				}
				if kind == "AWS::Signer::SigningProfile" {
					recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
					if err != nil || recovered.PhysicalID != admitted.PhysicalID {
						t.Fatalf("retained canceled profile lost private authority: %+v %v", recovered, err)
					}
					replayed, err := h.Create(f.ctx, r)
					if err == nil || replayed.PhysicalID != admitted.PhysicalID {
						t.Fatalf("canceled profile reused or forgotten: %+v %v", replayed, err)
					}
					return
				}
				foreignID := f.foreign(r, "")
				f.reopen()
				h = f.handler(kind)
				if rejected, err := h.Create(f.ctx, r); err == nil || rejected.PhysicalID != "" {
					t.Fatalf("foreign recreation adopted: %+v %v", rejected, err)
				}
				if rejected, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil || rejected.PhysicalID != "" {
					t.Fatalf("foreign recreation recovered: %+v %v", rejected, err)
				}
				if err := h.Delete(f.ctx, stack); err == nil && kind != "AWS::CertificateManager::Certificate" {
					t.Fatal("old stack deleted foreign same-name recreation")
				}
				direct := r
				direct.PhysicalID = foreignID
				direct.CloudControl = true
				if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, direct); err != nil {
					t.Fatal("foreign recreation damaged", err)
				}
				f.nativeTags(direct, map[string]string{"native": "still-permitted"})
			})
		}
	}
}

func TestCFNSESPrivateFenceRechecksRecreatedRowInsideMutation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"AWS::SES::EmailIdentity", "AWS::SES::ConfigurationSet"} {
			for _, deleting := range []bool{false, true} {
				t.Run(backend+"/"+kind+"/delete="+map[bool]string{false: "false", true: "true"}[deleting], func(t *testing.T) {
					f := newCFNTrustOwnerFixture(t, backend)
					r := f.request(kind)
					h := f.handler(kind)
					admitted, err := h.Create(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					r.PhysicalID = admitted.PhysicalID
					target := "TagResource"
					if deleting {
						target = "DeleteConfigurationSet"
						if kind == "AWS::SES::EmailIdentity" {
							target = "DeleteEmailIdentity"
						}
					}
					replaced := false
					executor := cfnTrustOwnerExecutor(func(ctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
						if !replaced && string(req.Operation.Name) == target {
							replaced = true
							f.nativeDelete(r)
							recreated := f.request(kind)
							f.foreign(recreated, "")
						}
						return f.ses.ExecuteCommand(ctx, req)
					})
					h = CloudFormationTrustDNSHandlers(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sesv2": executor}))[kind]
					if deleting {
						if err := h.Delete(f.ctx, r); err == nil {
							t.Fatal("pre-read authorized deletion of recreated native row")
						}
					} else {
						r.Previous = r.Properties
						r.Properties["Tags"] = []any{map[string]any{"Key": "must-not-write", "Value": "yes"}}
						if _, err := h.Update(f.ctx, r); err == nil {
							t.Fatal("pre-read authorized mutation of recreated native row")
						}
					}
					if !replaced {
						t.Fatal("native target mutation was not reached")
					}
					live, err := f.handler(kind).(cloudformation.ResourceReader).Read(f.ctx, r)
					if err != nil {
						t.Fatal("foreign native row was deleted", err)
					}
					encoded, _ := json.Marshal(live)
					if strings.Contains(string(encoded), "must-not-write") {
						t.Fatal("private mutation fence failed")
					}
				})
			}
		}
	}
}

func TestCFNTrustPrivateAuthorityDoesNotBypassCurrentIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range cfnTrustOwnerKinds() {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newCFNTrustOwnerFixture(t, backend)
				r := f.request(kind)
				h := f.handler(kind)
				admitted, err := h.Create(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				r.PhysicalID = admitted.PhysicalID
				r.Previous = r.Properties
				f.auth.denied = true
				if _, err := h.Update(f.ctx, r); cfnTrustCode(err) != "AccessDeniedException" {
					t.Fatalf("private claim bypassed current update IAM: %v", err)
				}
				if err := h.Delete(f.ctx, r); cfnTrustCode(err) != "AccessDeniedException" {
					t.Fatalf("private claim bypassed current delete IAM: %v", err)
				}
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); cfnTrustCode(err) != "AccessDeniedException" {
					t.Fatalf("private recovery bypassed current read IAM: %v", err)
				}
				f.auth.denied = false
				if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err != nil {
					t.Fatal("denied operations damaged native owner", err)
				}
			})
		}
	}
}

type cfnTrustOwnerUsageFailure struct{}

func (cfnTrustOwnerUsageFailure) CertificateUsers(context.Context, string, string, string, string, string) ([]string, error) {
	return nil, errors.New("native consumer metadata unavailable")
}
func TestCFNACMPostAdmissionConsumerErrorRetainsAuthenticID(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, lostReply := range []bool{false, true} {
			t.Run(backend+"/lost-reply="+map[bool]string{false: "false", true: "true"}[lostReply], func(t *testing.T) {
				f := newCFNTrustOwnerFixture(t, backend)
				r := f.request("AWS::CertificateManager::Certificate")
				owner := acm.New(acm.Config{Repository: f.acmRepo, Clock: f.at, Authorizer: f.auth, DNS: cfnTrustOwnerDNS{}, Usage: cfnTrustOwnerUsageFailure{}})
				lost := lostReply
				executor := cfnTrustOwnerExecutor(func(ctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
					out, err := owner.ExecuteCommand(ctx, req)
					if err == nil && lost && string(req.Operation.Name) == "RequestCertificate" {
						lost = false
						return nil, &awswire.Error{Code: "RequestTimeout", Message: "admitted native reply lost", StatusCode: 504}
					}
					return out, err
				})
				h := cfnACMCertificate{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"acm": executor})}
				admitted, err := h.Create(f.ctx, r)
				if err == nil || admitted.PhysicalID == "" {
					t.Fatalf("post-admission consumer error forgot authentic ID: %+v %v", admitted, err)
				}
				recovered, err := h.RecoverCreation(f.ctx, r)
				if err == nil || recovered.PhysicalID != admitted.PhysicalID {
					t.Fatalf("consumer error erased authorized private observation: %+v %v", recovered, err)
				}
				f.reopen()
				recovered, err = f.handler(r.Type).(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
				if err != nil || recovered.PhysicalID != admitted.PhysicalID {
					t.Fatalf("post-admission error lost persisted certificate: %+v %v", recovered, err)
				}
				r.PhysicalID = admitted.PhysicalID
				if err := f.handler(r.Type).Delete(f.ctx, r); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

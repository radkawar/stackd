package integrations

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"stackd/internal/awsapi"
	idpapi "stackd/internal/awsapi/cognitoidp"
	sesapi "stackd/internal/awsapi/sesv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cognitoidp"
	"stackd/internal/services/iam"
	"stackd/internal/services/sesv2"
	"stackd/storage/sqlite"
	sesstore "stackd/storage/sqlite/sesv2"
)

// Lookup faults exercise the real admission boundary, without changing storage
// writes or replacing the verification and capture owners.
type cognitoEmailLookupRepository struct {
	sesv2.Repository
	identityError, configurationError error
}

func (r *cognitoEmailLookupRepository) View(ctx context.Context, fn func(sesv2.Reader) error) error {
	return r.Repository.View(ctx, func(reader sesv2.Reader) error {
		return fn(cognitoEmailLookupReader{Reader: reader, repository: r})
	})
}

type cognitoEmailLookupReader struct {
	sesv2.Reader
	repository *cognitoEmailLookupRepository
}

func (r cognitoEmailLookupReader) Identity(key sesv2.ResourceKey) (sesv2.Identity, error) {
	if r.repository.identityError != nil {
		return sesv2.Identity{}, r.repository.identityError
	}
	return r.Reader.Identity(key)
}

func (r cognitoEmailLookupReader) ConfigurationSet(key sesv2.ResourceKey) (sesv2.ConfigurationSet, error) {
	if r.repository.configurationError != nil {
		return sesv2.ConfigurationSet{}, r.repository.configurationError
	}
	return r.Reader.ConfigurationSet(key)
}

func TestCognitoDeveloperEmailAdmissionAndCapturedVerification(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
			scope := sesv2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
			var storage sesv2.Repository = sesv2.NewMemoryRepository(nil)
			if backend == "sqlite" {
				db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "ses.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				storage = sesstore.New(db)
			}
			repository := &cognitoEmailLookupRepository{Repository: storage}
			captureDirectory := t.TempDir()
			ses := sesv2.NewWithConfig(sesv2.Config{Repository: repository, CaptureDirectory: captureDirectory, PublicEndpoint: "http://localhost:4566"})
			t.Cleanup(func() { _ = ses.Close() })
			identity := iam.New()
			t.Cleanup(func() { _ = identity.Close() })
			email := &CognitoEmail{SES: ses, Provisioner: identity}
			pools := cognitoidp.New(cognitoidp.Config{EmailSetup: email})
			if err := identity.RegisterServiceLinkedRole(CognitoEmailRoleTemplate(), CognitoEmailRoleUsage{Pools: pools}); err != nil {
				t.Fatal(err)
			}
			idpModel, _ := awscatalog.LookupService("cognitoidp")
			call := func(action string, input any) (any, *awswire.Error) {
				op, _ := idpModel.Operation(action)
				return pools.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: idpModel.Protocol, Input: input})
			}
			sesCall := func(action string, input any) any {
				t.Helper()
				model, _ := awscatalog.LookupService("sesv2")
				op, _ := model.Operation(action)
				out, err := ses.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
				if err != nil {
					t.Fatalf("%s: %v", action, err)
				}
				return out
			}
			address := "sender@example.invalid"
			source := sesv2.ResourceKey{Scope: scope, Name: address}.ARN("identity")
			configuration := &idpapi.EmailConfigurationType{EmailSendingAccount: new(idpapi.EmailSendingAccountType("DEVELOPER")), SourceArn: new(idpapi.ArnType(source))}
			create := func(name string) (any, *awswire.Error) {
				return call("CreateUserPool", &idpapi.CreateUserPoolInput{PoolName: new(idpapi.UserPoolNameType(name)), EmailConfiguration: configuration})
			}
			wantError := func(err *awswire.Error, code string, status int) {
				t.Helper()
				if err == nil || err.Code != code || err.StatusCode != status {
					t.Fatalf("want %s HTTP %d, got %v", code, status, err)
				}
			}
			_, err := create("missing-identity")
			wantError(err, "InvalidParameterException", http.StatusBadRequest)
			repository.identityError = fmt.Errorf("identity lookup: %w", sesv2.ErrNotFound)
			_, err = create("wrapped-missing-identity")
			wantError(err, "InvalidParameterException", http.StatusBadRequest)
			repository.identityError = nil
			sesCall("CreateEmailIdentity", &sesapi.CreateEmailIdentityInput{EmailIdentity: new(sesapi.Identity(address))})
			_, err = create("unverified-identity")
			wantError(err, "MessageRejected", http.StatusBadRequest)

			// Consume the link from the actual captured verification email, never
			// an administrator override or a token read from identity storage.
			if _, err := ses.JobDriver().RunDue(ctx, 100); err != nil {
				t.Fatal(err)
			}
			var messages []sesv2.Message
			if err := storage.View(ctx, func(r sesv2.Reader) error {
				var err error
				messages, err = r.Messages(scope)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if len(messages) != 1 || messages[0].ContentKind != "SES_VERIFICATION" {
				t.Fatalf("verification messages: %+v", messages)
			}
			captured, captureErr := os.ReadFile(sesv2.CapturePath(captureDirectory, messages[0].Key))
			if captureErr != nil {
				t.Fatal(captureErr)
			}
			message, parseErr := mail.ReadMessage(bytes.NewReader(captured))
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			body, parseErr := io.ReadAll(quotedprintable.NewReader(message.Body))
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			var verificationURL string
			for _, word := range strings.Fields(string(body)) {
				if strings.HasPrefix(word, "http://localhost:4566"+sesv2.VerificationPath+"?token=") {
					verificationURL = word
				}
			}
			if verificationURL == "" {
				t.Fatalf("captured verification URL missing: %s", body)
			}
			request := httptest.NewRequest(http.MethodGet, verificationURL, nil)
			response := httptest.NewRecorder()
			ses.VerificationHandler().ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("verification: HTTP %d %s", response.Code, response.Body.String())
			}
			response = httptest.NewRecorder()
			ses.VerificationHandler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("verification URL reused: HTTP %d", response.Code)
			}
			out, err := create("verified-identity")
			if err != nil {
				t.Fatal(err)
			}
			pool := out.(*idpapi.CreateUserPoolOutput).UserPool
			configuration.SourceArn = new(idpapi.ArnType(sesv2.ResourceKey{Scope: scope, Name: "missing@example.invalid"}.ARN("identity")))
			_, err = call("UpdateUserPool", &idpapi.UpdateUserPoolInput{UserPoolId: pool.Id, EmailConfiguration: configuration})
			wantError(err, "InvalidParameterException", http.StatusBadRequest)
			configuration.SourceArn = new(idpapi.ArnType(source))
			configuration.ConfigurationSet = new(idpapi.SESConfigurationSet("missing"))
			_, err = create("missing-configuration")
			wantError(err, "InvalidParameterException", http.StatusBadRequest)
			_, err = call("UpdateUserPool", &idpapi.UpdateUserPoolInput{UserPoolId: pool.Id, EmailConfiguration: configuration})
			wantError(err, "InvalidParameterException", http.StatusBadRequest)
			described, err := call("DescribeUserPool", &idpapi.DescribeUserPoolInput{UserPoolId: pool.Id})
			if err != nil {
				t.Fatal(err)
			}
			retained := described.(*idpapi.DescribeUserPoolOutput).UserPool.EmailConfiguration
			if retained == nil || retained.SourceArn == nil || string(*retained.SourceArn) != source || retained.ConfigurationSet != nil {
				t.Fatalf("rejected configuration changed pool: %+v", retained)
			}
			sesCall("CreateConfigurationSet", &sesapi.CreateConfigurationSetInput{ConfigurationSetName: new(sesapi.ConfigurationSetName("missing"))})
			_, err = call("UpdateUserPool", &idpapi.UpdateUserPoolInput{UserPoolId: pool.Id, EmailConfiguration: configuration})
			if err != nil {
				t.Fatal(err)
			}
			fault := errors.New("SES storage unavailable")
			for _, lookup := range []string{"identity", "configuration"} {
				if lookup == "identity" {
					repository.identityError = fault
				} else {
					repository.configurationError = fault
				}
				if err := ses.ValidateCognitoIdentity(ctx, scope, source, address, "missing"); !errors.Is(err, fault) {
					t.Fatalf("%s storage error lost: %v", lookup, err)
				}
				_, err = create(lookup + "-storage-fault")
				wantError(err, "InternalErrorException", http.StatusInternalServerError)
				repository.identityError, repository.configurationError = nil, nil
			}
			// Missing host integrations are internal wiring faults, not evidence
			// that the client's identity or configuration set is absent.
			email.SES = nil
			_, err = create("missing-host-integration")
			wantError(err, "InternalErrorException", http.StatusInternalServerError)
			email.SES, email.Provisioner = ses, nil
			_, err = create("missing-host-provisioner")
			wantError(err, "InternalErrorException", http.StatusInternalServerError)
		})
	}
}

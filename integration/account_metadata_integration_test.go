package stackd_test

import (
	"context"
	"encoding/csv"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
	iamstore "stackd/storage/iam"
)

type accountMetadataRepository struct {
	iamstore.Repository
	failMetadata atomic.Bool
	reports      chan iamstore.Scope
}

func (r *accountMetadataRepository) Update(ctx context.Context, fn func(iamstore.WriteTx) error) error {
	var completed []iamstore.Scope
	err := r.Repository.Update(ctx, func(tx iamstore.WriteTx) error {
		return fn(accountMetadataTx{WriteTx: tx, failMetadata: r.failMetadata.Load(), completed: &completed})
	})
	if err == nil {
		for _, scope := range completed {
			r.reports <- scope
		}
	}
	return err
}

type accountMetadataTx struct {
	iamstore.WriteTx
	failMetadata bool
	completed    *[]iamstore.Scope
}

func (tx accountMetadataTx) PutAccountMetadata(scope iamstore.Scope, record iamstore.AccountMetadata) error {
	if err := tx.WriteTx.PutAccountMetadata(scope, record); err != nil {
		return err
	}
	if tx.failMetadata {
		return errors.New("injected account metadata commit failure")
	}
	return nil
}

func (tx accountMetadataTx) PutCredentialReport(scope iamstore.Scope, record iamstore.CredentialReportRecord) error {
	if err := tx.WriteTx.PutCredentialReport(scope, record); err != nil {
		return err
	}
	if record.State == iamstore.CredentialReportComplete {
		*tx.completed = append(*tx.completed, scope)
	}
	return nil
}

func TestAccountCreationMetadataFromOrganizationsSDK(t *testing.T) {
	for _, start := range []time.Time{time.Time{}.UTC(), time.Unix(0, 0).UTC(), time.Date(2026, 9, 11, 12, 34, 56, 123000000, time.UTC)} {
		t.Run(start.Format(time.RFC3339Nano), func(t *testing.T) {
			for _, firstOperation := range []string{"GetUser", "GenerateCredentialReport"} {
				t.Run(firstOperation, func(t *testing.T) {
					backends := storage.NewMemory()
					repository := &accountMetadataRepository{Repository: backends.IAM, reports: make(chan iamstore.Scope, 1)}
					backends.IAM = repository
					source := clock.NewManual(start.Add(-time.Second))
					c := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
					org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
					if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll}); err != nil {
						t.Fatal(err)
					}
					created, err := org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("Created1Account"), Email: aws.String("created@example.test")})
					if err != nil {
						t.Fatal(err)
					}
					created.CreateAccountStatus = waitAccountCreation(t, org, created.CreateAccountStatus, source)
					accountID := aws.ToString(created.CreateAccountStatus.AccountId)
					client := c.iam(accountID, "test", "")
					advanceClock(t, source, 7*time.Hour)
					if firstOperation == "GetUser" {
						assertRootCreationDate(t, client, start)
					}
					if _, err := client.GenerateCredentialReport(t.Context(), &iam.GenerateCredentialReportInput{}); err != nil {
						t.Fatal(err)
					}
					assertRootReportCreationDate(t, client, repository.reports, iamstore.Scope{Partition: "aws", AccountID: accountID}, start)
					advanceClock(t, source, time.Hour)
					assertRootCreationDate(t, client, start)
					// The unified identity source still supplies the default password
					// name/email restrictions after metadata has been persisted.
					if _, err := client.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("password-user")}); err != nil {
						t.Fatal(err)
					}
					for _, password := range []string{"Created1Account", "created@example.test"} {
						_, err := client.CreateLoginProfile(t.Context(), &iam.CreateLoginProfileInput{UserName: aws.String("password-user"), Password: &password})
						assertAPIError(t, err, "PasswordPolicyViolation")
					}
				})
			}
		})
	}
}

func TestAccountCreationMetadataBootstrapAndInvitedFallbackSDK(t *testing.T) {
	for _, known := range []bool{false, true} {
		name := "standalone"
		if known {
			name = "organization management invited timestamp"
		}
		t.Run(name, func(t *testing.T) {
			start := time.Unix(0, 0).UTC()
			source := clock.NewManual(start)
			c := clockCloud(t, stackd.Config{Clock: source})
			if known {
				org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll}); err != nil {
					t.Fatal(err)
				}
			}
			advanceClock(t, source, 9*time.Hour)
			firstUse := source.Now()
			client := c.iam("test", "test", "")
			assertRootCreationDate(t, client, firstUse)
			advanceClock(t, source, time.Hour)
			assertRootCreationDate(t, client, firstUse)
		})
	}
}

func TestAccountCreationMetadataRollsBackWithFirstRequestSDK(t *testing.T) {
	backends := storage.NewMemory()
	repository := &accountMetadataRepository{Repository: backends.IAM, reports: make(chan iamstore.Scope, 1)}
	backends.IAM = repository
	source := clock.NewManual(time.Unix(0, 0).UTC())
	c := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
	client := c.iam("test", "test", "")
	scope := iamstore.Scope{Partition: "aws", AccountID: "000000000000"}
	repository.failMetadata.Store(true)
	out, err := client.GetUser(t.Context(), &iam.GetUserInput{})
	assertAPIError(t, err, "ServiceFailure")
	if out != nil {
		t.Fatalf("failed metadata commit returned a root response: %+v", out)
	}
	_, err = client.GenerateCredentialReport(t.Context(), &iam.GenerateCredentialReportInput{})
	assertAPIError(t, err, "ServiceFailure")
	if err := repository.View(t.Context(), func(tx iamstore.ReadTx) error {
		if _, err := tx.AccountMetadata(scope); !errors.Is(err, iamstore.ErrRecordNotFound) {
			t.Fatalf("metadata survived rollback: %v", err)
		}
		if _, err := tx.CredentialReport(scope); !errors.Is(err, iamstore.ErrRecordNotFound) {
			t.Fatalf("report generation survived rollback: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	repository.failMetadata.Store(false)
	// A semantic handler failure must not establish a bootstrap date either.
	_, err = client.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("missing")})
	assertAPIError(t, err, "NoSuchEntity")
	advanceClock(t, source, time.Hour)
	firstSuccess := source.Now()
	assertRootCreationDate(t, client, firstSuccess)
	if _, err := client.GenerateCredentialReport(t.Context(), &iam.GenerateCredentialReportInput{}); err != nil {
		t.Fatal(err)
	}
	assertRootReportCreationDate(t, client, repository.reports, scope, firstSuccess)
}

func assertRootCreationDate(t *testing.T, client *iam.Client, want time.Time) {
	t.Helper()
	out, err := client.GetUser(t.Context(), &iam.GetUserInput{})
	if err != nil || out == nil || out.User == nil || out.User.CreateDate == nil || !out.User.CreateDate.Equal(want) {
		t.Fatalf("root GetUser creation date: %+v %v; want %s", out, err, want)
	}
}

func assertRootReportCreationDate(t *testing.T, client *iam.Client, reports <-chan iamstore.Scope, wantScope iamstore.Scope, want time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case scope := <-reports:
		if scope != wantScope {
			t.Fatalf("report committed for wrong account: %+v", scope)
		}
	case <-ctx.Done():
		t.Fatal("credential report worker did not commit:", ctx.Err())
	}
	out, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(out.Content))).ReadAll()
	if err != nil || len(rows) < 2 {
		t.Fatalf("credential report rows: %+v %v", rows, err)
	}
	for _, row := range rows[1:] {
		if row[0] == "<root_account>" {
			for column, field := range rows[0] {
				if field == "user_creation_time" && row[column] != want.Format(time.RFC3339) {
					t.Fatalf("root credential report creation date %q, want %s", row[column], want)
				}
			}
			return
		}
	}
	t.Fatal("credential report omitted root account")
}

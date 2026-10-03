package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
	"stackd/mail"
	"stackd/storage"
	accountstorage "stackd/storage/account"
)

type accountEmailSender func(context.Context, mail.Message) error

func (send accountEmailSender) Send(ctx context.Context, message mail.Message) error {
	return send(ctx, message)
}

func TestAccountPrimaryEmailReadsMatchAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/account/primary_email_reads.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case, Operation, Caller, Code string
			Input                         struct{ AccountID *string }
			Output                        struct {
				Matches bool `json:"email_matches_organizations"`
			}
			Error struct{ Message string }
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	f := newOrganizationReportFixture(t, storage.NewMemory())
	member := f.account(t, f.rootID, "primary-email-reads")
	session, err := f.cloud.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: aws.String("arn:aws:iam::" + member + ":role/OrganizationAccountAccessRole"), RoleSessionName: aws.String("primary-email-reads")})
	if err != nil {
		t.Fatal(err)
	}
	clients := map[string]*account.Client{
		"management": f.cloud.account("test", "test", ""),
		"member":     f.cloud.account(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken)),
	}
	for _, row := range capture.Observations {
		t.Run(row.Case, func(t *testing.T) {
			if row.Case == "email_member" {
				enableAccountAccess(t, f)
			}
			var target *string
			if row.Input.AccountID != nil {
				mapped := map[string]string{"111111111111": "000000000000", "222222222222": member}[*row.Input.AccountID]
				if mapped == "" {
					t.Fatal("unknown fixture account")
				}
				target = &mapped
			}
			client := clients[row.Caller]
			var err error
			switch row.Operation {
			case "get-primary-email":
				var out *account.GetPrimaryEmailOutput
				out, err = client.GetPrimaryEmail(t.Context(), &account.GetPrimaryEmailInput{AccountId: target})
				if err == nil {
					org, orgErr := f.org.DescribeAccount(t.Context(), &organizations.DescribeAccountInput{AccountId: target})
					if orgErr != nil || (aws.ToString(out.PrimaryEmail) == aws.ToString(org.Account.Email)) != row.Output.Matches {
						t.Fatal("Account and Organizations emails differ", orgErr)
					}
				}
			case "get-primary-email-update-status":
				_, err = client.GetPrimaryEmailUpdateStatus(t.Context(), &account.GetPrimaryEmailUpdateStatusInput{AccountId: target})
			default:
				t.Fatal("unknown fixture operation", row.Operation)
			}
			if row.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			assertAPIError(t, err, row.Code)
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) {
				t.Fatal(err)
			}
			got, want := apiErr.ErrorMessage(), row.Error.Message
			if row.Code == "AccessDeniedException" {
				_, got, _ = strings.Cut(got, " is not authorized to perform:")
				_, want, _ = strings.Cut(want, " is not authorized to perform:")
			}
			if got != want {
				t.Fatalf("message = %q; AWS = %q", got, want)
			}
			var validation *accounttypes.ValidationException
			if errors.As(err, &validation) && (validation.Reason != "" || len(validation.FieldList) != 0) {
				t.Fatal("no-history error invented validation details", validation)
			}
		})
	}
}

func enableAccountAccess(t *testing.T, f organizationReportFixture) {
	t.Helper()
	if _, err := f.org.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("account.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
}

func primaryEmailFixture(t *testing.T, backends *storage.Backends, sender stackd.EmailSender) organizationReportFixture {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC))
	f := organizationFixture(t, clockCloud(t, stackd.Config{Clock: source, Storage: backends, EmailSender: sender}), source)
	enableAccountAccess(t, f)
	return f
}

func verificationCode(t *testing.T, messages <-chan mail.Message, email string) string {
	t.Helper()
	select {
	case message := <-messages:
		code := regexp.MustCompile(`\b[0-9]{6}\b`).FindString(message.Text)
		if message.To != email || code == "" {
			t.Fatal("missing verification code or incorrect recipient")
		}
		return code
	case <-time.After(10 * time.Second):
		t.Fatal("verification message was not delivered")
		return ""
	}
}

func waitPrimaryEmailStatus(t *testing.T, client *account.Client, member string, want accounttypes.PrimaryEmailUpdateStatus) *account.GetPrimaryEmailUpdateStatusOutput {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		out, err := client.GetPrimaryEmailUpdateStatus(ctx, &account.GetPrimaryEmailUpdateStatusInput{AccountId: &member})
		if err != nil {
			t.Fatal(err)
		}
		if out.Status == want {
			return out
		}
		select {
		case <-ctx.Done():
			t.Fatalf("primary email status = %s, want %s", out.Status, want)
		case <-ticker.C:
		}
	}
}

func TestAccountPrimaryEmailVerificationAndIdentityPublication(t *testing.T) {
	backends := storage.NewMemory()
	messages := make(chan mail.Message, 1)
	var member string
	sender := accountEmailSender(func(ctx context.Context, message mail.Message) error {
		// This read would deadlock if the scheduler held a storage transaction
		// across external delivery. The pending request must already be visible.
		if err := backends.Account.View(ctx, func(reader accountstorage.Reader) error {
			pending, found, err := reader.PrimaryEmailUpdate(accountstorage.Scope{Partition: "aws", AccountID: member})
			if err != nil {
				return err
			}
			if !found || pending.Status != "PENDING" || pending.Email != message.To {
				return errors.New("verification message preceded committed request")
			}
			return nil
		}); err != nil {
			return err
		}
		messages <- message
		return nil
	})
	f := primaryEmailFixture(t, backends, sender)
	member = f.account(t, f.rootID, "primary-email-lifecycle")
	client, identity := f.cloud.account("test", "test", ""), f.cloud.iam(member, "test", "")
	if _, err := identity.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("email-user")}); err != nil {
		t.Fatal(err)
	}
	profile, err := identity.CreateLoginProfile(t.Context(), &iam.CreateLoginProfileInput{UserName: aws.String("email-user"), Password: aws.String("PreviousPassword1!")})
	if err != nil {
		t.Fatal(err)
	}
	email := "VerifiedIdentity1@example.test"
	started, err := client.StartPrimaryEmailUpdate(t.Context(), &account.StartPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: &email})
	if err != nil || started.Status != accounttypes.PrimaryEmailUpdateStatusPending {
		t.Fatalf("start: %+v %v", started, err)
	}
	code := verificationCode(t, messages, email)
	input := &account.AcceptPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: &email, Otp: aws.String("WRONG1")}
	_, err = client.AcceptPrimaryEmailUpdate(t.Context(), input)
	assertAPIError(t, err, "ValidationException")
	waitPrimaryEmailStatus(t, client, member, accounttypes.PrimaryEmailUpdateStatusPending)
	input.Otp = &code
	accepted, err := client.AcceptPrimaryEmailUpdate(t.Context(), input)
	if err != nil || accepted.Status != accounttypes.PrimaryEmailUpdateStatusAccepted {
		t.Fatalf("accept: %+v %v", accepted, err)
	}
	status := waitPrimaryEmailStatus(t, client, member, accounttypes.PrimaryEmailUpdateStatusAccepted)
	if !status.UpdatedAt.Equal(f.clock.Now()) {
		t.Fatal("status timestamp is not service time")
	}
	before, err := client.GetPrimaryEmail(t.Context(), &account.GetPrimaryEmailInput{AccountId: &member})
	if err != nil || aws.ToString(before.PrimaryEmail) != "primary-email-lifecycle@example.test" {
		t.Fatal("email changed before completion", err)
	}
	advanceClock(t, f.clock, time.Second)
	status = waitPrimaryEmailStatus(t, client, member, accounttypes.PrimaryEmailUpdateStatusCompleted)
	if !status.UpdatedAt.Equal(f.clock.Now()) {
		t.Fatal("completion timestamp is not service time")
	}
	current, err := client.GetPrimaryEmail(t.Context(), &account.GetPrimaryEmailInput{AccountId: &member})
	if err != nil || aws.ToString(current.PrimaryEmail) != email {
		t.Fatal("verified email was not published", err)
	}
	org, err := f.org.DescribeAccount(t.Context(), &organizations.DescribeAccountInput{AccountId: &member})
	if err != nil || aws.ToString(org.Account.Email) != email {
		t.Fatal("Organizations did not receive verified email", err)
	}
	retained, err := identity.GetLoginProfile(t.Context(), &iam.GetLoginProfileInput{UserName: aws.String("email-user")})
	if err != nil || !reflect.DeepEqual(retained.LoginProfile, profile.LoginProfile) {
		t.Fatal("email publication changed IAM login profile", err)
	}
	_, err = identity.UpdateLoginProfile(t.Context(), &iam.UpdateLoginProfileInput{UserName: aws.String("email-user"), Password: &email})
	assertAPIError(t, err, "PasswordPolicyViolation")
	_, err = client.StartPrimaryEmailUpdate(t.Context(), &account.StartPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: aws.String(strings.ToUpper(email))})
	assertAPIError(t, err, "ConflictException")
}

func TestAccountPrimaryEmailReplacementDuringDeliveryAndExpiry(t *testing.T) {
	messages := make(chan mail.Message, 2)
	release := make(chan struct{})
	f := primaryEmailFixture(t, storage.NewMemory(), accountEmailSender(func(ctx context.Context, message mail.Message) error {
		messages <- message
		if message.To == "first@example.test" {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}))
	member := f.account(t, f.rootID, "primary-email-replacement")
	client := f.cloud.account("test", "test", "")
	start := func(email string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		if _, err := client.StartPrimaryEmailUpdate(ctx, &account.StartPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: &email}); err != nil {
			t.Fatal(err)
		}
	}
	start("first@example.test")
	oldCode := verificationCode(t, messages, "first@example.test")
	start("second@example.test")
	_, err := client.AcceptPrimaryEmailUpdate(t.Context(), &account.AcceptPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: aws.String("first@example.test"), Otp: &oldCode})
	assertAPIError(t, err, "ResourceNotFoundException")
	close(release)
	code := verificationCode(t, messages, "second@example.test")
	advanceClock(t, f.clock, 24*time.Hour)
	_, err = client.AcceptPrimaryEmailUpdate(t.Context(), &account.AcceptPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: aws.String("second@example.test"), Otp: &code})
	assertAPIError(t, err, "ValidationException")
	current, err := client.GetPrimaryEmail(t.Context(), &account.GetPrimaryEmailInput{AccountId: &member})
	if err != nil || aws.ToString(current.PrimaryEmail) != "primary-email-replacement@example.test" {
		t.Fatal("expired verification changed email", err)
	}
}

func TestAccountPrimaryEmailRequiresDeliveryConfiguration(t *testing.T) {
	f := primaryEmailFixture(t, storage.NewMemory(), nil)
	member := f.account(t, f.rootID, "primary-email-unconfigured")
	client := f.cloud.account("test", "test", "")
	_, err := client.StartPrimaryEmailUpdate(t.Context(), &account.StartPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: aws.String("candidate@example.test")})
	assertAPIError(t, err, "InternalServerException")
	_, err = client.GetPrimaryEmailUpdateStatus(t.Context(), &account.GetPrimaryEmailUpdateStatusInput{AccountId: &member})
	assertAPIError(t, err, "ValidationException")
}

func TestAccountPrimaryEmailCompetingCandidatesAndIAMDenial(t *testing.T) {
	messages := make(chan mail.Message, 2)
	f := primaryEmailFixture(t, storage.NewMemory(), accountEmailSender(func(_ context.Context, message mail.Message) error {
		messages <- message
		return nil
	}))
	members := []string{f.account(t, f.rootID, "email-candidate-one"), f.account(t, f.rootID, "email-candidate-two")}
	slices.Sort(members) // Equal deadlines use the account ID as a stable job key.
	client := f.cloud.account("test", "test", "")
	_, key, secret := f.cloud.user(t, "test", "email-reader")
	putUserPolicy(t, f.iam, "email-reader", `{"Statement":{"Effect":"Allow","Action":"account:GetPrimaryEmail*","Resource":"*"}}`)
	reader := f.cloud.account(key, secret, "")
	email := "contested@example.test"
	for _, member := range members {
		_, err := reader.StartPrimaryEmailUpdate(t.Context(), &account.StartPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: &email})
		assertAPIError(t, err, "AccessDeniedException")
		if _, err := client.StartPrimaryEmailUpdate(t.Context(), &account.StartPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: &email}); err != nil {
			t.Fatal(err)
		}
		code := verificationCode(t, messages, email)
		input := &account.AcceptPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: &email, Otp: &code}
		_, err = reader.AcceptPrimaryEmailUpdate(t.Context(), input)
		assertAPIError(t, err, "AccessDeniedException")
		if _, err := client.AcceptPrimaryEmailUpdate(t.Context(), input); err != nil {
			t.Fatal(err)
		}
	}
	advanceClock(t, f.clock, time.Second)
	waitPrimaryEmailStatus(t, client, members[0], accounttypes.PrimaryEmailUpdateStatusCompleted)
	waitPrimaryEmailStatus(t, client, members[1], accounttypes.PrimaryEmailUpdateStatusFailed)
	for i, member := range members {
		current, err := client.GetPrimaryEmail(t.Context(), &account.GetPrimaryEmailInput{AccountId: &member})
		if err != nil || (aws.ToString(current.PrimaryEmail) == email) != (i == 0) {
			t.Fatal("candidate completion did not preserve exclusive ownership", err)
		}
	}
	_, err := client.StartPrimaryEmailUpdate(t.Context(), &account.StartPrimaryEmailUpdateInput{AccountId: &members[1], PrimaryEmail: aws.String(strings.ToUpper(email))})
	assertAPIError(t, err, "ConflictException")
}

func TestAccountPrimaryEmailDeliveryResumesAfterReconstruction(t *testing.T) {
	source, backends := clock.NewManual(time.Unix(1_900_000_000, 0)), storage.NewMemory()
	messages := make(chan mail.Message, 2)
	first, err := stackd.New(stackd.Config{Clock: source, Storage: backends, EmailSender: accountEmailSender(func(ctx context.Context, message mail.Message) error {
		messages <- message
		<-ctx.Done()
		return ctx.Err()
	})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	server := httptest.NewServer(first)
	t.Cleanup(server.Close)
	f := organizationFixture(t, cloudClients{server}, source)
	enableAccountAccess(t, f)
	member := f.account(t, f.rootID, "primary-email-recovery")
	email := "recovery@example.test"
	if _, err := f.cloud.account("test", "test", "").StartPrimaryEmailUpdate(t.Context(), &account.StartPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: &email}); err != nil {
		t.Fatal(err)
	}
	code := verificationCode(t, messages, email)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	c := clockCloud(t, stackd.Config{Clock: source, Storage: backends, EmailSender: accountEmailSender(func(_ context.Context, message mail.Message) error {
		messages <- message
		return nil
	})})
	if resumed := verificationCode(t, messages, email); resumed != code {
		t.Fatal("interrupted delivery generated a different code")
	}
	client := c.account("test", "test", "")
	if _, err := client.AcceptPrimaryEmailUpdate(t.Context(), &account.AcceptPrimaryEmailUpdateInput{AccountId: &member, PrimaryEmail: &email, Otp: &code}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, time.Second)
	waitPrimaryEmailStatus(t, client, member, accounttypes.PrimaryEmailUpdateStatusCompleted)
}

package iam

import (
	"context"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

type credentialRowsFixture struct {
	service    *Service
	repository Repository
	source     *clock.Manual
	metadata   awsctx.Metadata
	rootDate   time.Time
}

func newCredentialRowsFixture() credentialRowsFixture {
	source := clock.NewManual(time.Date(2035, 2, 3, 4, 5, 6, 999999999, time.UTC))
	repository := NewMemoryRepository(nil)
	return credentialRowsFixture{
		service: NewWithConfig(Config{Repository: repository, Clock: source}), repository: repository, source: source,
		metadata: awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"},
		rootDate: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func (f credentialRowsFixture) scope() Scope {
	return Scope{Partition: f.metadata.Partition, AccountID: f.metadata.AccountID}
}

func (f credentialRowsFixture) report(t *testing.T) ([]byte, map[string]map[string]string) {
	t.Helper()
	var content []byte
	ctx := awsctx.WithMetadata(t.Context(), f.metadata)
	err := f.repository.Update(ctx, func(tx WriteTx) error {
		a, err := loadAccount(tx, f.scope())
		if err != nil {
			return err
		}
		a.currentTime = f.source.Now()
		ctx := context.WithValue(ctx, transactionKey{}, serviceTransaction{service: f.service, tx: tx, currentTime: a.currentTime})
		var apiErr error
		data, reportErr := f.service.credentialReportCSV(ctx, a, f.metadata, f.rootDate)
		if reportErr != nil {
			apiErr = errors.New(reportErr.Code + ": " + reportErr.Message)
		}
		content = data
		return apiErr
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(content))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 || len(rows[0]) != 22 {
		t.Fatalf("invalid report shape: %d rows", len(rows))
	}
	if rows[1][0] != "<root_account>" {
		t.Fatal("root must precede IAM users")
	}
	result := make(map[string]map[string]string)
	for _, row := range rows[1:] {
		fields := make(map[string]string)
		for index, name := range rows[0] {
			fields[name] = row[index]
		}
		result[row[0]] = fields
	}
	return content, result
}

func requireCredentialFields(t *testing.T, actual map[string]string, want map[string]string) {
	t.Helper()
	for field, value := range want {
		if got, present := actual[field]; !present || got != value {
			t.Errorf("%s=%q (present=%t), want %q", field, got, present, value)
		}
	}
}

func TestCredentialReportRowsStateAndIdentity(t *testing.T) {
	f := newCredentialRowsFixture()
	zero := time.Time{}
	u := User{UserId: "AIDAREPORT", UserName: "z,comma", Arn: "arn:aws:iam::123456789012:user/team/z,comma", CreateDate: zero, PasswordLastUsed: &zero}
	rootARN := "arn:aws:iam::123456789012:root"
	if err := f.repository.Update(t.Context(), func(tx WriteTx) error {
		if err := tx.PutUser(f.scope(), u); err != nil {
			return err
		}
		if err := tx.PutLoginProfile(f.scope(), LoginProfileRecord{UserID: u.UserId, PasswordChangedAt: zero, PasswordResetRequired: true, Password: PasswordDigest{Hash: []byte("DO-NOT-REPORT-PASSWORD")}}); err != nil {
			return err
		}
		if err := tx.PutAccountSettings(f.scope(), AccountSettingsRecord{PasswordPolicy: &AccountPasswordPolicy{MaxPasswordAge: 10, HardExpiry: true}}); err != nil {
			return err
		}
		for _, device := range []MFADevice{{SerialNumber: "user", Binding: Propagated[MFABinding]{Value: MFABinding{UserID: u.UserId}}}, {SerialNumber: "root", Binding: Propagated[MFABinding]{Value: MFABinding{UserID: f.metadata.AccountID}}}, {SerialNumber: "unassigned"}} {
			if err := tx.PutMFADevice(f.scope(), device); err != nil {
				return err
			}
		}
		for _, certificate := range []SigningCertificateRecord{
			{ID: "AAA-later", UserID: u.UserId, UploadDate: zero.Add(time.Hour), Status: "Inactive", Body: "DO-NOT-REPORT-CERT"},
			{ID: "ZZZ-earlier", UserID: u.UserId, UploadDate: zero, Status: "Active"},
			{ID: "root", UserID: rootARN, UploadDate: f.rootDate, Status: "Active"},
		} {
			if err := tx.PutSigningCertificate(f.scope(), certificate); err != nil {
				return err
			}
		}
		for _, record := range []identity.Record{
			{Credential: identity.Credential{AccessKeyID: "AKIAAAA-later", SecretAccessKey: "DO-NOT-REPORT-KEY", AccountID: f.metadata.AccountID, PrincipalID: u.UserId, PrincipalARN: u.Arn, UserName: "old-name", CreateDate: zero.Add(time.Hour)}, Status: identity.Inactive, LastUsed: identity.LastUsed{Service: "N/A", Region: "N/A"}},
			{Credential: identity.Credential{AccessKeyID: "AKIAZZZ-earlier", AccountID: f.metadata.AccountID, PrincipalID: u.UserId, PrincipalARN: u.Arn, CreateDate: zero}, Status: identity.Active, LastUsed: identity.LastUsed{Date: zero, Service: "iam", Region: "N/A"}},
			{Credential: identity.Credential{AccessKeyID: "ASIASESSION", AccountID: f.metadata.AccountID, PrincipalID: u.UserId, PrincipalARN: u.Arn, SessionToken: "DO-NOT-REPORT-TOKEN"}, Status: identity.Active},
		} {
			if err := tx.PutCredential(record); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	content, rows := f.report(t)
	if strings.Contains(string(content), "DO-NOT-REPORT") || strings.Contains(string(content), "AKIA") || strings.Contains(string(content), "ASIASESSION") {
		t.Fatal("report exposed credential material or identifiers")
	}
	if !strings.Contains(string(content), `"z,comma"`) || len(rows) != 2 {
		t.Fatal("CSV escaping or user enumeration is incorrect")
	}
	requireCredentialFields(t, rows[u.UserName], map[string]string{
		"arn": u.Arn, "user_creation_time": "0001-01-01T00:00:00Z", "password_enabled": "true", "password_last_used": "0001-01-01T00:00:00Z",
		"password_last_changed": "0001-01-01T00:00:00Z", "password_next_rotation": "0001-01-11T00:00:00Z", "mfa_active": "true",
		"access_key_1_active": "false", "access_key_1_last_rotated": "0001-01-01T01:00:00Z", "access_key_1_last_used_date": "N/A",
		"access_key_2_active": "true", "access_key_2_last_rotated": "0001-01-01T00:00:00Z", "access_key_2_last_used_date": "0001-01-01T00:00:00Z", "access_key_2_last_used_service": "iam", "access_key_2_last_used_region": "N/A",
		"cert_1_active": "false", "cert_1_last_rotated": "0001-01-01T01:00:00Z", "cert_2_active": "true", "cert_2_last_rotated": "0001-01-01T00:00:00Z",
	})
	requireCredentialFields(t, rows["<root_account>"], map[string]string{"arn": rootARN, "user_creation_time": "2020-01-02T03:04:05Z", "password_enabled": "false", "password_last_used": "N/A", "password_next_rotation": "not_supported", "mfa_active": "true", "access_key_1_active": "false", "cert_1_active": "true"})
	if err := f.repository.Update(t.Context(), func(tx WriteTx) error {
		if err := tx.DeleteUser(f.scope(), u.UserName); err != nil {
			return err
		}
		u.UserName = "renamed"
		u.Arn = "arn:aws:iam::123456789012:user/renamed"
		return tx.PutUser(f.scope(), u)
	}); err != nil {
		t.Fatal(err)
	}
	_, rows = f.report(t)
	if rows["z,comma"] != nil || rows["renamed"] == nil {
		t.Fatal("report did not follow current user identity")
	}
	requireCredentialFields(t, rows["renamed"], map[string]string{"arn": u.Arn, "password_enabled": "true", "access_key_2_active": "true", "cert_2_active": "true", "mfa_active": "true"})
}

func TestCredentialReportRowsPasswordAbsenceAndRotation(t *testing.T) {
	a := newAccount()
	u := &user{UserId: "AIDAPASSWORD"}
	if got := credentialReportPassword(a, u, false); strings.Join(got, ",") != "false,N/A,N/A,N/A" {
		t.Fatalf("absent password=%v", got)
	}
	p := &LoginProfileRecord{UserID: u.UserId, PasswordChangedAt: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)}
	a.loginProfiles[u.UserId] = p
	if got := credentialReportPassword(a, u, false); strings.Join(got, ",") != "true,no_information,2020-01-02T03:04:05Z,N/A" {
		t.Fatalf("never-used password=%v", got)
	}
	a.settings.PasswordPolicy = &AccountPasswordPolicy{MaxPasswordAge: 30}
	p.PasswordChangedAt = p.PasswordChangedAt.Add(24 * time.Hour)
	if got := credentialReportPassword(a, u, false)[3]; got != "2020-02-02T03:04:05Z" {
		t.Fatalf("password rotation ignored current policy/change time: %q", got)
	}
	u.PasswordLastUsed = &p.PasswordChangedAt
	delete(a.loginProfiles, u.UserId)
	if got := credentialReportPassword(a, u, false)[1]; got != "N/A" {
		t.Fatalf("removed password retained a report sign-in date: %q", got)
	}
}

func TestCredentialReportRowsUserOrdering(t *testing.T) {
	f := newCredentialRowsFixture()
	if err := f.repository.Update(t.Context(), func(tx WriteTx) error {
		for _, u := range []User{
			{UserName: "Zed", UserId: "Z", Arn: "arn:aws:iam::123456789012:user/a/Zed"},
			{UserName: "apple", UserId: "A", Arn: "arn:aws:iam::123456789012:user/z/apple"},
			{UserName: "Beta", UserId: "B", Arn: "arn:aws:iam::123456789012:user/c/Beta"},
		} {
			if err := tx.PutUser(f.scope(), u); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	content, _ := f.report(t)
	rows, err := csv.NewReader(strings.NewReader(string(content))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for index, want := range []string{"<root_account>", "apple", "Beta", "Zed"} {
		if rows[index+1][0] != want {
			t.Errorf("row %d user=%s, want %s", index, rows[index+1][0], want)
		}
	}
}

func TestCredentialReportRowsRootPartitionIsolation(t *testing.T) {
	f := newCredentialRowsFixture()
	if err := f.repository.Update(t.Context(), func(tx WriteTx) error {
		for _, partition := range []string{"aws", "aws-cn"} {
			status := identity.Active
			if partition == "aws-cn" {
				status = identity.Inactive
			}
			if err := tx.PutCredential(identity.Record{Credential: identity.Credential{AccessKeyID: "AKIAROOT" + partition, AccountID: f.metadata.AccountID, PrincipalID: f.metadata.AccountID, PrincipalARN: "arn:" + partition + ":iam::" + f.metadata.AccountID + ":root", CreateDate: f.rootDate}, Status: status}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, partition := range []string{"aws", "aws-cn"} {
		f.metadata.Partition = partition
		_, rows := f.report(t)
		requireCredentialFields(t, rows["<root_account>"], map[string]string{"access_key_1_active": credentialReportBool(partition == "aws"), "access_key_2_active": "false", "access_key_2_last_rotated": "N/A"})
	}
	if err := f.repository.Update(t.Context(), func(tx WriteTx) error { return tx.DeleteCredential("AKIAROOTaws-cn") }); err != nil {
		t.Fatal(err)
	}
	ctx := awsctx.WithMetadata(t.Context(), f.metadata)
	if err := f.repository.Update(ctx, func(tx WriteTx) error {
		a, err := loadAccount(tx, f.scope())
		if err != nil {
			return err
		}
		ctx := context.WithValue(ctx, transactionKey{}, serviceTransaction{service: f.service, tx: tx})
		result, apiErr := f.service.getAccountSummary(ctx, a, f.metadata)
		if apiErr != nil {
			return errors.New(apiErr.Message)
		}
		if got := result.(*iamapi.GetAccountSummaryOutput).SummaryMap[iamapi.SummaryKeyTypeAccountAccessKeysPresent]; got != 0 {
			t.Error("AWS root key leaked into China root credential presence")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type credentialReportFailingStore struct {
	*identity.Store
	listError, useError error
}

func (s credentialReportFailingStore) ListAccessKeys(accountID, principalID string) ([]identity.AccessKey, error) {
	if s.listError != nil {
		return nil, s.listError
	}
	return s.Store.ListAccessKeys(accountID, principalID)
}

func (s credentialReportFailingStore) AccessKeyLastUsed(accountID, keyID string) (identity.AccessKey, identity.LastUsed, error) {
	if s.useError != nil {
		return identity.AccessKey{}, identity.LastUsed{}, s.useError
	}
	return s.Store.AccessKeyLastUsed(accountID, keyID)
}

func TestCredentialReportRowsFailureHasNoPartialCSV(t *testing.T) {
	for _, reason := range []string{"list", "usage", "extra keys", "extra certificates", "cancelled"} {
		t.Run(reason, func(t *testing.T) {
			f := newCredentialRowsFixture()
			a := newAccount()
			ctx := t.Context()
			if reason == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if reason == "extra certificates" {
				for _, id := range []string{"one", "two", "three"} {
					a.signingCertificates[id] = &SigningCertificateRecord{ID: id, UserID: "arn:aws:iam::123456789012:root"}
				}
			}
			if reason == "extra keys" || reason == "usage" {
				count := 1
				if reason == "extra keys" {
					count = 3
				}
				if err := f.repository.Update(t.Context(), func(tx WriteTx) error {
					for index := range count {
						if err := tx.PutCredential(identity.Record{Credential: identity.Credential{AccessKeyID: string(rune('A' + index)), AccountID: f.metadata.AccountID, PrincipalID: f.metadata.AccountID, PrincipalARN: "arn:aws:iam::123456789012:root"}}); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			store := credentialReportFailingStore{Store: identity.NewWithConfig(identity.Config{Repository: NewCredentialRepository(f.repository, nil), Clock: f.source})}
			if reason == "list" {
				store.listError = errors.New("injected listing failure")
			}
			if reason == "usage" {
				store.useError = errors.New("injected usage failure")
			}
			f.service.credentials = store
			data, err := f.service.credentialReportCSV(ctx, a, f.metadata, f.rootDate)
			if err == nil || err.Code != "ServiceFailure" || len(data) != 0 {
				t.Fatalf("partial report escaped failed generation: bytes=%d error=%v", len(data), err)
			}
		})
	}
}

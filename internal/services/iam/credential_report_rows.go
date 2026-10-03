package iam

import (
	"bytes"
	"context"
	"encoding/csv"
	"slices"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// The live normal-state report has 22 columns. The current guide additionally
// describes additional_credentials_info for more than two keys/certificates;
// those imported states exceed the supported lifecycle quotas and fail below.
var credentialReportHeader = [...]string{
	"user", "arn", "user_creation_time", "password_enabled", "password_last_used", "password_last_changed", "password_next_rotation", "mfa_active",
	"access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date", "access_key_1_last_used_region", "access_key_1_last_used_service",
	"access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date", "access_key_2_last_used_region", "access_key_2_last_used_service",
	"cert_1_active", "cert_1_last_rotated", "cert_2_active", "cert_2_last_rotated",
}

// credentialReportCSV consumes the same account/credential transaction used to
// generate the persisted report. It never resolves signing secrets or passwords.
func (s *Service) credentialReportCSV(ctx context.Context, a *account, m awsctx.Metadata, rootCreatedAt time.Time) ([]byte, *awswire.Error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write(credentialReportHeader[:]); err != nil {
		return nil, credentialReportRowsFailure()
	}
	rootARN := "arn:" + m.Partition + ":iam::" + m.AccountID + ":root"
	root := &user{UserName: "<root_account>", UserId: m.AccountID, Arn: rootARN, CreateDate: rootCreatedAt}
	users := make([]*user, 0, len(a.users)+1)
	users = append(users, root)
	for _, name := range sortedMapKeys(a.users) {
		users = append(users, a.users[name])
	}
	store := s.credentialStore(ctx)
	for _, u := range users {
		if err := ctx.Err(); err != nil {
			return nil, credentialReportRowsFailure()
		}
		row := []string{u.UserName, u.Arn, credentialReportDate(u.CreateDate)}
		row = append(row, credentialReportPassword(a, u, u == root)...)
		mfa := false
		for _, device := range a.mfaDevices {
			mfa = mfa || device.Binding.Value.UserID != "" && device.Binding.Value.UserID == u.UserId
		}
		row = append(row, credentialReportBool(mfa))
		keys, err := credentialReportKeys(store, m.AccountID, u.UserId)
		if err != nil {
			return nil, err
		}
		row = append(row, keys...)
		owner := u.UserId
		if u == root {
			owner = rootARN
		}
		certificates, err := credentialReportCertificates(a, owner)
		if err != nil {
			return nil, err
		}
		row = append(row, certificates...)
		if err := writer.Write(row); err != nil {
			return nil, credentialReportRowsFailure()
		}
	}
	writer.Flush()
	if writer.Error() != nil || ctx.Err() != nil {
		return nil, credentialReportRowsFailure()
	}
	// The captured AWS report uses LF separators without a final newline.
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func credentialReportPassword(a *account, u *user, root bool) []string {
	if root {
		if p := a.settings.RootLoginProfile; p != nil {
			return []string{"true", "no_information", credentialReportDate(p.CreateDate), "not_supported"}
		}
		return []string{"false", "N/A", "N/A", "not_supported"}
	}
	p := a.loginProfiles[u.UserId]
	if p == nil {
		return []string{"false", "N/A", "N/A", "N/A"}
	}
	used := "no_information"
	if u.PasswordLastUsed != nil {
		used = credentialReportDate(*u.PasswordLastUsed)
	}
	next := "N/A"
	if policy := a.settings.PasswordPolicy; policy != nil && policy.MaxPasswordAge > 0 {
		next = credentialReportDate(p.PasswordChangedAt.Add(time.Duration(policy.MaxPasswordAge) * 24 * time.Hour))
	}
	return []string{"true", used, credentialReportDate(p.PasswordChangedAt), next}
}

func credentialReportKeys(store CredentialStore, accountID, principalID string) ([]string, *awswire.Error) {
	keys, err := store.ListAccessKeys(accountID, principalID)
	if err != nil || len(keys) > 2 {
		return nil, credentialReportRowsFailure()
	}
	// Captured pairs are consistent with IAM's access-key ID ordering. The
	// report does not promise creation order, including within the same second.
	slices.SortFunc(keys, func(a, b identity.AccessKey) int {
		return strings.Compare(a.AccessKeyID, b.AccessKeyID)
	})
	result := make([]string, 0, 10)
	for index := range 2 {
		fields := []string{"false", "N/A", "N/A", "N/A", "N/A"}
		if index < len(keys) {
			key := keys[index]
			fields[0] = credentialReportBool(key.Status == identity.Active)
			fields[1] = credentialReportDate(key.CreateDate)
			_, used, err := store.AccessKeyLastUsed(accountID, key.AccessKeyID)
			if err != nil {
				return nil, credentialReportRowsFailure()
			}
			if used.Recorded() {
				fields[2] = credentialReportDate(used.Date)
				if used.Region != "" {
					fields[3] = used.Region
				}
				if used.Service != "" {
					fields[4] = used.Service
				}
			}
		}
		result = append(result, fields...)
	}
	return result, nil
}

func credentialReportCertificates(a *account, owner string) ([]string, *awswire.Error) {
	certificates := make([]*SigningCertificateRecord, 0)
	for _, record := range a.signingCertificates {
		if record.UserID == owner {
			certificates = append(certificates, record)
		}
	}
	if len(certificates) > 2 {
		return nil, credentialReportRowsFailure()
	}
	// Both captured mixed-status pairs put the inactive certificate first.
	// Date and ID provide deterministic local ordering within one status;
	// that tie order is not established by the AWS capture.
	slices.SortFunc(certificates, func(a, b *SigningCertificateRecord) int {
		if a.Status != b.Status {
			if a.Status == "Inactive" {
				return -1
			}
			if b.Status == "Inactive" {
				return 1
			}
		}
		if order := a.UploadDate.Compare(b.UploadDate); order != 0 {
			return order
		}
		return strings.Compare(a.ID, b.ID)
	})
	result := make([]string, 0, 4)
	for index := range 2 {
		fields := []string{"false", "N/A"}
		if index < len(certificates) {
			fields[0] = credentialReportBool(certificates[index].Status == "Active")
			fields[1] = credentialReportDate(certificates[index].UploadDate)
		}
		result = append(result, fields...)
	}
	return result, nil
}

func credentialReportBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func credentialReportDate(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

func credentialReportRowsFailure() *awswire.Error {
	return &awswire.Error{Code: "ServiceFailure", Message: "Unable to read IAM credential report state.", StatusCode: 500}
}

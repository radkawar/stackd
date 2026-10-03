package iam

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/internal/identity"
)

func TestCredentialReportRowsAWSReplay(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/iam/credential_report.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Setup []struct {
			User                  string `json:"user"`
			ARN                   string `json:"arn"`
			CreatedAt             string `json:"created_at"`
			Password              string `json:"password"`
			PasswordCreatedAt     string `json:"password_created_at"`
			PasswordResetRequired bool   `json:"password_reset_required"`
			MFAActive             bool   `json:"mfa_active"`
			KeyIDOrder            string `json:"key_id_order_by_creation"`
			Keys                  []struct {
				CreatedAt string `json:"created_at"`
				Status    string `json:"status"`
			} `json:"keys"`
			Certificates []struct {
				UploadedAt string `json:"uploaded_at"`
				Status     string `json:"status"`
			} `json:"certificates"`
		} `json:"setup"`
		Observations []struct {
			Case       string              `json:"case"`
			Header     []string            `json:"header"`
			OwnedRows  []map[string]string `json:"owned_rows"`
			TrailingLF bool                `json:"csv_ends_with_newline"`
			UsesCRLF   bool                `json:"csv_uses_crlf"`
			RootRow    int                 `json:"root_row_index"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	observed := make(map[string]map[string]string)
	var header []string
	var trailingLF, usesCRLF bool
	for _, observation := range capture.Observations {
		if observation.Case != "completed_report" {
			continue
		}
		header, trailingLF, usesCRLF = observation.Header, observation.TrailingLF, observation.UsesCRLF
		for _, row := range observation.OwnedRows {
			observed[row["user"]] = row
		}
		if observation.RootRow != 0 {
			t.Fatal("capture root ordering changed")
		}
	}
	if len(observed) == 0 {
		t.Fatal("capture has no completed owned-user rows")
	}
	parseDate := func(value string) time.Time {
		t.Helper()
		date, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatal(err)
		}
		return date
	}
	f := newCredentialRowsFixture()
	if err := f.repository.Update(t.Context(), func(tx WriteTx) error {
		for index, setup := range capture.Setup {
			if observed[setup.User] == nil {
				continue // The post-generation user is absent from this snapshot.
			}
			id := fmt.Sprintf("AIDAREPLAY%02d", index)
			u := User{UserId: id, UserName: setup.User, Arn: setup.ARN, CreateDate: parseDate(setup.CreatedAt)}
			if err := tx.PutUser(f.scope(), u); err != nil {
				return err
			}
			if setup.Password == "never_used" {
				if err := tx.PutLoginProfile(f.scope(), LoginProfileRecord{UserID: id, PasswordChangedAt: parseDate(setup.PasswordCreatedAt), PasswordResetRequired: setup.PasswordResetRequired}); err != nil {
					return err
				}
			}
			if setup.MFAActive {
				if err := tx.PutMFADevice(f.scope(), MFADevice{SerialNumber: "mfa-" + id, Binding: Propagated[MFABinding]{Value: MFABinding{UserID: id}}}); err != nil {
					return err
				}
			}
			for keyIndex, key := range setup.Keys {
				ordinal := keyIndex
				if setup.KeyIDOrder == "descending" {
					ordinal = len(setup.Keys) - keyIndex
				}
				record := identity.Record{
					Credential: identity.Credential{AccessKeyID: fmt.Sprintf("AKIA%s%02d", id, ordinal), AccountID: f.metadata.AccountID, PrincipalID: id, PrincipalARN: u.Arn, CreateDate: parseDate(key.CreatedAt)},
					Status:     identity.Status(key.Status), LastUsed: identity.LastUsed{Service: "N/A", Region: "N/A"},
				}
				if err := tx.PutCredential(record); err != nil {
					return err
				}
			}
			for certIndex, certificate := range setup.Certificates {
				if err := tx.PutSigningCertificate(f.scope(), SigningCertificateRecord{ID: fmt.Sprintf("CERT%s%02d", id, certIndex), UserID: id, UploadDate: parseDate(certificate.UploadedAt), Status: certificate.Status}); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	content, rows := f.report(t)
	if line := strings.SplitN(string(content), "\n", 2)[0]; line != strings.Join(header, ",") {
		t.Fatalf("header=%s, want captured %v", line, header)
	}
	if strings.HasSuffix(string(content), "\n") != trailingLF || strings.Contains(string(content), "\r\n") != usesCRLF {
		t.Fatal("CSV line endings differ from capture")
	}
	for name, expected := range observed {
		if !reflect.DeepEqual(rows[name], expected) {
			t.Errorf("%s: report=%v, AWS=%v", name, rows[name], expected)
		}
	}
}

package account_test

import (
	"errors"
	"testing"

	service "stackd/internal/services/account"
	organizationservice "stackd/internal/services/organizations"
	"stackd/storage"
	"stackd/storage/account"
	"stackd/storage/iam"
)

func TestContactCopyRollsBackWithAccountProvisioning(t *testing.T) {
	backends := storage.NewMemory()
	parent, child := account.Scope{Partition: "aws", AccountID: "111111111111"}, account.Scope{Partition: "aws", AccountID: "222222222222"}
	contact := account.ContactInformation{FullName: "Parent", CompanyName: "Company", AddressLine1: "1 Test Street"}
	if err := backends.Account.Update(t.Context(), func(tx account.Writer) error { return tx.PutContact(parent, contact) }); err != nil {
		t.Fatal(err)
	}
	accounts := service.New(service.Config{Repository: backends.Account})
	t.Cleanup(func() { _ = accounts.Close() })
	rejected := errors.New("organization publication failed")
	err := backends.IAM.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := accounts.InitializeMemberContact(tx.Context(), parent.Partition, parent.AccountID, child.AccountID, "Child"); err != nil {
			return err
		}
		return rejected
	})
	if !errors.Is(err, rejected) {
		t.Fatal(err)
	}
	if err := backends.Account.View(t.Context(), func(tx account.Reader) error {
		_, found, err := tx.Contact(child)
		if found {
			t.Fatal("failed account creation retained copied contact")
		}
		if err != nil {
			return err
		}
		got, found, err := tx.Contact(parent)
		if !found || got != contact {
			t.Fatal("copy changed management contact")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPrimaryEmailPublicationRollsBackWithStatus(t *testing.T) {
	backends := storage.NewMemory()
	scope := account.Scope{Partition: "aws", AccountID: "222222222222"}
	org := organizationservice.NewWithStorage(backends.Organizations)
	t.Cleanup(func() { _ = org.Close() })
	if err := org.PutAccountName(t.Context(), scope.Partition, scope.AccountID, "Email rollback"); err != nil {
		t.Fatal(err)
	}
	initial, err := org.AccountIdentity(t.Context(), scope.Partition, scope.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	update := account.PrimaryEmailUpdate{Scope: scope, Email: "verified@example.test", Status: "ACCEPTED"}
	if err := backends.Account.Update(t.Context(), func(tx account.Writer) error { return tx.PutPrimaryEmailUpdate(update) }); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("completion transaction failed")
	err = backends.Account.Update(t.Context(), func(tx account.Writer) error {
		if err := org.PutPrimaryEmail(tx.Context(), scope.Partition, scope.AccountID, update.Email); err != nil {
			return err
		}
		update.Status = "COMPLETED"
		if err := tx.PutPrimaryEmailUpdate(update); err != nil {
			return err
		}
		return rejected
	})
	if !errors.Is(err, rejected) {
		t.Fatal(err)
	}
	current, err := org.AccountIdentity(t.Context(), scope.Partition, scope.AccountID)
	if err != nil || current.Email != initial.Email {
		t.Fatal("failed completion changed registry email", err)
	}
	if err := backends.Account.View(t.Context(), func(tx account.Reader) error {
		current, found, err := tx.PrimaryEmailUpdate(scope)
		if !found || current.Status != "ACCEPTED" {
			t.Fatal("failed completion retained status write")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

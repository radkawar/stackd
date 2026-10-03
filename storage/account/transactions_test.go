package account_test

import (
	"errors"
	"testing"
	"time"

	"stackd/storage"
	"stackd/storage/account"
	"stackd/storage/iam"
	"stackd/storage/memory"
)

func TestRegionChangesJoinIAMAuthorityAndRollback(t *testing.T) {
	backends := storage.NewMemory()
	key := account.RegionKey{Partition: "aws", AccountID: "111111111111", Region: "af-south-1"}
	row := account.RegionRecord{Status: "ENABLING", Due: time.Unix(100, 0)}
	rejected := errors.New("credential publication failed")
	var escaped account.Writer
	err := backends.IAM.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := backends.Account.Update(tx.Context(), func(writer account.Writer) error {
			escaped = writer
			return writer.PutRegion(key, row)
		}); err != nil {
			return err
		}
		if err := backends.Account.View(tx.Context(), func(reader account.Reader) error {
			got, found, err := reader.Region(key)
			if err != nil {
				return err
			}
			if !found || got != row {
				t.Fatal("lost staged region transition", got)
			}
			return nil
		}); err != nil {
			return err
		}
		return rejected
	})
	if !errors.Is(err, rejected) {
		t.Fatal(err)
	}
	if err := escaped.PutRegion(key, row); !errors.Is(err, memory.ErrClosedTransaction) {
		t.Fatal("escaped writer", err)
	}
	if err := backends.Account.View(t.Context(), func(reader account.Reader) error {
		_, found, err := reader.Region(key)
		if found {
			t.Fatal("region change survived failed IAM authority")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

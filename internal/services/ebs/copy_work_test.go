package ebs

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// A recipient's admitted copy must pin the owner's inherited sparse bytes even
// after both public source layers disappear. Pinning only live snapshots or
// only destinations in the source account/Region silently truncates the copy.
func TestPendingSnapshotCopyRetainsDeletedAncestorLayers(t *testing.T) {
	repository := NewMemoryRepository(nil)
	owner := Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	recipient := Scope{Partition: "aws", AccountID: "222222222222", Region: "us-west-2"}
	parent := SnapshotRecord{Key: SnapshotKey{Scope: owner, ID: "snap-parent"}, Deleted: true}
	source := SnapshotRecord{Key: SnapshotKey{Scope: owner, ID: "snap-source"}, ParentID: parent.Key.ID, Deleted: true}
	destination := SnapshotRecord{Key: SnapshotKey{Scope: recipient, ID: "snap-copy"}, Copy: &SnapshotCopy{
		Source: source.Key, WorkAt: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
	}}
	inherited := BlockRecord{BlockInfo: BlockInfo{Key: BlockKey{Snapshot: parent.Key, Index: 1}}, Data: []byte("inherited source block")}
	changed := BlockRecord{BlockInfo: BlockInfo{Key: BlockKey{Snapshot: source.Key, Index: 9}}, Data: []byte("child source block")}
	err := repository.Update(t.Context(), func(tx Transaction) error {
		for _, snapshot := range []SnapshotRecord{parent, source, destination} {
			if err := tx.PutSnapshot(snapshot); err != nil {
				return err
			}
		}
		for _, block := range []BlockRecord{inherited, changed} {
			if err := tx.PutBlock(block); err != nil {
				return err
			}
		}
		return pruneLayers(tx, owner)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = repository.View(t.Context(), func(r Reader) error {
		blocks, err := resolvedBlocks(r, source)
		if err != nil {
			return err
		}
		for _, expected := range []BlockRecord{inherited, changed} {
			info, exists := blocks[expected.Key.Index]
			if !exists {
				t.Fatalf("pending recipient copy lost source index %d", expected.Key.Index)
			}
			actual, err := r.Block(info.Key)
			if err != nil {
				return err
			}
			if !bytes.Equal(actual.Data, expected.Data) {
				t.Fatalf("pending recipient copy changed source index %d", expected.Key.Index)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = repository.Update(t.Context(), func(tx Transaction) error {
		destination.Copy.WorkAt = time.Time{}
		if err := tx.PutSnapshot(destination); err != nil {
			return err
		}
		return pruneLayers(tx, owner)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(r Reader) error {
		for _, key := range []BlockKey{inherited.Key, changed.Key} {
			if _, err := r.Block(key); !errors.Is(err, ErrNotFound) {
				t.Fatalf("finished copy retained deleted source block %+v: %v", key, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

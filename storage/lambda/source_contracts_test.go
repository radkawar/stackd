package lambda_test

import (
	"errors"
	"testing"

	"stackd/storage/lambda"
)

func TestFunctionSourceTransitionsPreserveSnapshotQuota(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		latest := deployment()
		latest.CodeSize = 5
		copyLayer := lambda.LayerVersionKey{LayerKey: lambda.LayerKey{Scope: latest.Key.Scope, Name: "copy"}, Version: 1}
		referenceLayer := copyLayer
		referenceLayer.Name = "reference"
		source := lambda.S3ObjectReference{Bucket: "code", Key: "function.zip", VersionID: "resolved-version"}
		update := func(fn func(lambda.Transaction) error) {
			t.Helper()
			if err := repo.Update(t.Context(), fn); err != nil {
				t.Fatal(err)
			}
		}
		usage := func(size, count, reserved int64) {
			t.Helper()
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				got, err := r.AccountUsage(latest.Key.Scope)
				if err != nil {
					return err
				}
				if got.TotalCodeSize != size || got.FunctionCount != count || got.ReservedConcurrency != reserved {
					t.Fatalf("snapshot quota = %+v, want size=%d count=%d reserved=%d", got, size, count, reserved)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		publish := func(tx lambda.Transaction, v lambda.FunctionRecord) error {
			var err error
			v.Version, err = tx.AllocateFunctionVersion(v.Key)
			if err != nil {
				return err
			}
			return tx.PutFunctionVersion(v)
		}
		update(func(tx lambda.Transaction) error {
			if err := tx.PutLayerVersion(lambda.LayerVersionRecord{Key: copyLayer, CodeSize: 11}); err != nil {
				return err
			}
			if err := tx.PutLayerVersion(lambda.LayerVersionRecord{Key: referenceLayer, CodeSize: 23, Reference: &source}); err != nil {
				return err
			}
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
			if err := tx.PutFunctionConcurrency(latest.Key, 7); err != nil {
				return err
			}
			return publish(tx, latest)
		})
		usage(21, 1, 7) // Current COPY + published COPY + live COPY layer.

		pending := latest
		pending.CodeSize = 31
		pending.Reference = &lambda.S3ObjectReference{Bucket: source.Bucket, Key: source.Key, VersionID: source.VersionID}
		update(func(tx lambda.Transaction) error { return tx.PutPendingFunction(pending) })
		pending.Reference.VersionID = "caller mutation"
		for range 2 {
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				candidate, err := r.PendingFunction(latest.Key)
				if err != nil || candidate.Reference == nil || *candidate.Reference != source {
					t.Fatalf("pending source escaped snapshot ownership: %+v, %v", candidate, err)
				}
				candidate.Reference.VersionID = "reader mutation"
				current, err := r.Function(latest.Key)
				if err != nil || current.Reference != nil {
					t.Fatalf("pending source replaced current COPY: %+v, %v", current, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		usage(21, 1, 7)
		pending.Reference = nil
		update(func(tx lambda.Transaction) error { return tx.PutPendingFunction(pending) })
		usage(21, 1, 7) // Pending COPY also stays outside account storage.
		update(func(tx lambda.Transaction) error {
			candidate, err := tx.PendingFunction(latest.Key)
			if err != nil || candidate.Reference != nil {
				t.Fatalf("pending COPY retained the old source: %+v, %v", candidate, err)
			}
			candidate.Reference = &source
			return tx.PutPendingFunction(candidate)
		})
		usage(21, 1, 7) // Pending code never consumes account storage.
		update(func(tx lambda.Transaction) error {
			candidate, err := tx.PendingFunction(latest.Key)
			if err != nil {
				return err
			}
			if err := tx.PutFunction(candidate); err != nil {
				return err
			}
			if err := publish(tx, candidate); err != nil {
				return err
			}
			return tx.DeletePendingFunction(latest.Key)
		})
		usage(16, 1, 7) // Activation releases current COPY, not published COPY.
		update(func(tx lambda.Transaction) error {
			current, err := tx.Function(latest.Key)
			if err != nil || current.Reference == nil || *current.Reference != source {
				t.Fatalf("activation lost the resolved source: %+v, %v", current, err)
			}
			current.Reference = nil
			current.CodeSize = 7
			if err := tx.PutFunction(current); err != nil {
				return err
			}
			return publish(tx, current)
		})
		usage(30, 1, 7) // Both retained COPY versions count; REFERENCE never does.
		update(func(tx lambda.Transaction) error {
			version := lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 2}
			published, err := tx.FunctionVersion(version)
			if err != nil || published.Reference == nil || *published.Reference != source {
				t.Fatalf("COPY update changed immutable source: %+v, %v", published, err)
			}
			published.Reference = nil
			if err := tx.PutFunctionVersion(published); err == nil {
				t.Fatal("overwrote immutable source mode")
			}
			versions, err := tx.FunctionVersions(latest.Key)
			if err != nil {
				return err
			}
			if len(versions) != 3 || versions[0].Reference != nil || versions[1].Reference == nil || *versions[1].Reference != source || versions[2].Reference != nil {
				t.Fatalf("publication source identities merged: %+v", versions)
			}
			current, err := tx.Function(latest.Key)
			if err != nil || current.Reference != nil {
				t.Fatalf("current COPY retained reference identity: %+v, %v", current, err)
			}
			if _, err := tx.PendingFunction(latest.Key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("activated pending snapshot remains: %v", err)
			}
			return tx.DeleteFunctionVersion(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 1})
		})
		usage(25, 1, 7)
		update(func(tx lambda.Transaction) error {
			return tx.DeleteFunctionVersion(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 2})
		})
		usage(25, 1, 7) // Deleting a REFERENCE version cannot release COPY bytes.
		update(func(tx lambda.Transaction) error {
			latest.Reference = &source
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
			return tx.PutPendingFunction(latest)
		})
		usage(18, 1, 7)
		update(func(tx lambda.Transaction) error { return tx.DeleteFunction(latest.Key) })
		usage(11, 0, 0) // Function deletion leaves the independent layer catalog.
		latest.Reference = nil
		update(func(tx lambda.Transaction) error {
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
			if err := tx.PutPendingFunction(latest); err != nil {
				return err
			}
			current, err := tx.Function(latest.Key)
			if err != nil || current.Reference != nil {
				t.Fatalf("recreation inherited deleted current source: %+v, %v", current, err)
			}
			candidate, err := tx.PendingFunction(latest.Key)
			if err != nil || candidate.Reference != nil {
				t.Fatalf("recreation inherited deleted pending source: %+v, %v", candidate, err)
			}
			return nil
		})
		usage(16, 1, 0)
	})
}

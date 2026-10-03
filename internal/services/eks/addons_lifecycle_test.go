package eks

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	native "stackd/compute/eks"
)

// Fault injection supplies only observed native failure/pending outcomes. It does
// not implement successful workloads; the executable probe owns native readiness.
type addonFailureRuntime struct {
	native.Runtime
	failure error
	mutated bool
}

func (r *addonFailureRuntime) ReconcileAddon(context.Context, native.AddonSpecification) (native.AddonObservation, error) {
	return native.AddonObservation{Configuration: `{"replicaCount":1}`, Mutated: r.mutated}, r.failure
}
func TestAddonPendingPreservesIntentThenNativeUnschedulableDegrades(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/eks/depth_native_health.json")
	if err != nil {
		t.Fatal(err)
	}
	type observedAddon struct {
		AddonName, Status string
		Health            struct {
			Issues []struct{ Code, Message string }
		}
	}
	var fixture struct {
		Addons []observedAddon
		Calls  []struct {
			Operation string
			Output    struct{ Addon observedAddon }
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var created, unhealthy observedAddon
	for _, call := range fixture.Calls {
		if call.Operation == "create-addon" && call.Output.Addon.AddonName == "coredns" {
			created = call.Output.Addon
		}
	}
	for _, addon := range fixture.Addons {
		if addon.AddonName == "coredns" {
			unhealthy = addon
		}
	}
	if created.Status == "" || unhealthy.Status == "" || len(unhealthy.Health.Issues) != 1 {
		t.Fatal("native add-on transition fixture is incomplete")
	}
	epoch := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	source := clock.NewManual(epoch)
	runtime := &addonFailureRuntime{failure: &native.AddonPending{Message: "Kubernetes rollout not ready"}}
	repository := NewMemoryRepository(nil)
	s := New(Config{Repository: repository, Clock: source, Runtime: runtime})
	t.Cleanup(func() { _ = s.Close() })
	c := Cluster{Key: Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "native-addon"}, ID: "cluster-id", Status: "ACTIVE"}
	a := Addon{Key: c.Key, ID: "addon-id", Name: "coredns", Version: native.CoreDNSVersion, Status: created.Status, Operation: "create", Generation: 1, Created: epoch, Modified: epoch, Due: epoch}
	if err = repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutCluster(c); err != nil {
			return err
		}
		return tx.PutAddon(a)
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcileAddon(t.Context(), c, a); err != nil {
		t.Fatal(err)
	}
	if err = repository.View(t.Context(), func(tx Reader) error { var err error; a, err = tx.Addon(c.Key, a.Name); return err }); err != nil {
		t.Fatal(err)
	}
	if a.Status != created.Status || a.Operation != "create" || !a.Modified.Equal(epoch) || !a.Due.After(epoch) {
		t.Fatalf("pending effect lost durable admission: %+v", a)
	}
	issue := unhealthy.Health.Issues[0]
	runtime.failure = &native.AddonError{Code: issue.Code, Message: issue.Message}
	if err = source.Advance(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcileAddon(t.Context(), c, a); err != nil {
		t.Fatal(err)
	}
	if err = repository.View(t.Context(), func(tx Reader) error {
		current, err := tx.Addon(c.Key, a.Name)
		if err != nil {
			return err
		}
		if current.Status != unhealthy.Status || current.ErrorCode != issue.Code || current.Operation != "" || current.Due.IsZero() || current.AppliedVersion != native.CoreDNSVersion {
			t.Fatalf("native unhealthy installation was treated as failed creation: %+v", current)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAddonRollbackFailureTerminatesUpdate(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "rejected"
		if pending {
			name = "readiness-deadline"
		}
		t.Run(name, func(t *testing.T) {
			epoch := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
			source := clock.NewManual(epoch)
			rollbackMessage := "restored deployment cannot become ready"
			runtime := &addonFailureRuntime{failure: &native.AddonError{Code: "InsufficientNumberOfReplicas", Message: rollbackMessage}}
			if pending {
				runtime.failure = &native.AddonPending{Message: rollbackMessage}
			}
			repository := NewMemoryRepository(nil)
			service := New(Config{Repository: repository, Clock: source, Runtime: runtime})
			t.Cleanup(func() { _ = service.Close() })
			c := Cluster{Key: Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "rollback"}, ID: "cluster-id", Status: "ACTIVE"}
			a := Addon{Key: c.Key, ID: "addon-id", Name: "coredns", Version: "v1.12.1-eksbuild.2", AppliedVersion: native.CoreDNSVersion, Configuration: `{"replicaCount":2}`, AppliedConfiguration: `{"replicaCount":1}`, Status: "UPDATING", Operation: "rollback", UpdateID: "update-id", Error: "requested deployment failed", ErrorCode: "InsufficientNumberOfReplicas", Generation: 1, Created: epoch, Modified: epoch, Due: epoch}
			if err := repository.Update(t.Context(), func(tx Transaction) error {
				if err := tx.PutCluster(c); err != nil {
					return err
				}
				if err := tx.PutClusterUpdate(Update{Key: c.Key, ID: a.UpdateID, Type: "AddonUpdate", ResourceType: "addon", ResourceName: a.Name, Status: "InProgress"}); err != nil {
					return err
				}
				return tx.PutAddon(a)
			}); err != nil {
				t.Fatal(err)
			}
			if err := service.reconcileAddon(t.Context(), c, a); err != nil {
				t.Fatal(err)
			}
			if pending {
				if err := repository.View(t.Context(), func(tx Reader) error {
					var err error
					a, err = tx.Addon(c.Key, a.Name)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if a.Operation != "rollback" || !a.Modified.Equal(epoch) {
					t.Fatalf("rollback lost its original deadline: %+v", a)
				}
				if err := source.Advance(5 * time.Minute); err != nil {
					t.Fatal(err)
				}
				if err := service.reconcileAddon(t.Context(), c, a); err != nil {
					t.Fatal(err)
				}
			}
			if err := repository.View(t.Context(), func(tx Reader) error {
				current, err := tx.Addon(c.Key, a.Name)
				if err != nil {
					return err
				}
				update, err := tx.ClusterUpdate(c.Key, a.UpdateID)
				if err != nil {
					return err
				}
				health, result := addonAPI(current), updateAPI(update)
				if value(health.Status) != "UPDATE_FAILED" || current.Operation != "" || !current.Due.IsZero() || value(result.Status) != "Failed" {
					t.Fatalf("rollback remained in progress: addon=%+v update=%+v", current, update)
				}
				if current.Version != a.Version || current.Configuration != a.Configuration {
					t.Fatal("failed rollback claimed the previous deployment was restored")
				}
				if len(health.Health.Issues) != 1 || len(result.Errors) != 1 || !strings.Contains(value(health.Health.Issues[0].Message), rollbackMessage) || !strings.Contains(value(result.Errors[0].ErrorMessage), a.Error) || !strings.Contains(value(result.Errors[0].ErrorMessage), rollbackMessage) {
					t.Fatalf("terminal responses omitted the original or rollback failure: addon=%+v update=%+v", current, update)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAddonConflictDoesNotForceRollbackOverUserFields(t *testing.T) {
	epoch := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository, Clock: clock.NewManual(epoch), Runtime: &addonFailureRuntime{mutated: true, failure: &native.AddonError{Code: "ConfigurationConflict", Message: "user owns Corefile"}}})
	t.Cleanup(func() { _ = service.Close() })
	c := Cluster{Key: Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "conflict"}, ID: "cluster-id", Status: "ACTIVE"}
	a := Addon{Key: c.Key, ID: "addon-id", Name: "coredns", Version: native.CoreDNSVersion, AppliedVersion: native.CoreDNSVersion, Status: "UPDATING", Operation: "update", Generation: 1, Modified: epoch}
	if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutAddon(a) }); err != nil {
		t.Fatal(err)
	}
	if err := service.reconcileAddon(t.Context(), c, a); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(tx Reader) error {
		current, err := tx.Addon(c.Key, a.Name)
		if err == nil && (current.Operation != "" || current.Status != "UPDATE_FAILED" || current.ErrorCode != "ConfigurationConflict") {
			t.Fatalf("conflict queued a destructive rollback: %+v", current)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

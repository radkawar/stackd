package integrations

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/services/lambda"
)

type managedAdvancingClock struct{ *clock.Manual }

func (c managedAdvancingClock) Now() time.Time {
	if err := c.Manual.Advance(time.Nanosecond); err != nil {
		panic(err)
	}
	return c.Manual.Now()
}

func TestManagedCapacityInitialReconciliationDoesNotStarveAdvancingClock(t *testing.T) {
	sourceClock := managedAdvancingClock{clock.NewManual(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))}
	repository := lambda.NewMemoryRepository(nil)
	key := lambda.CapacityProviderKey{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "awaiting-deletion"}
	if err := repository.Update(t.Context(), func(tx lambda.Transaction) error {
		return tx.PutCapacityProvider(lambda.CapacityProviderRecord{Key: key, Generation: "retained-generation", State: "Deleting"})
	}); err != nil {
		t.Fatal(err)
	}
	// The actual adapter is intentionally unconfigured: deleting a provider with
	// no functions or guests needs no EC2 effects, but must finish reconciliation.
	service := lambda.New(lambda.Config{Repository: repository, Clock: sourceClock, Capacity: &LambdaCapacity{}})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	result, err := service.JobDriver().RunDue(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		err = repository.View(t.Context(), func(r lambda.Reader) error { _, err := r.CapacityProvider(key); return err })
		if errors.Is(err, lambda.ErrNotFound) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-deadline.Done():
			t.Fatalf("provider deletion never reconciled while time advanced during selection: drain=%+v", result)
		case <-tick.C:
		}
	}
}

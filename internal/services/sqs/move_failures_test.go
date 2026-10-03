package sqs

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"stackd/internal/awswire"
)

type cancellationRepository struct {
	Repository
	fail atomic.Bool
}

func (r *cancellationRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.Repository.Update(ctx, func(tx Transaction) error {
		return fn(cancellationTransaction{Transaction: tx, repository: r})
	})
}

type cancellationTransaction struct {
	Transaction
	repository *cancellationRepository
}

func (tx cancellationTransaction) PutMoveTask(task MoveTaskRecord) error {
	if err := tx.Transaction.PutMoveTask(task); err != nil {
		return err
	}
	if task.Status == moveCancelled && tx.repository.fail.Load() {
		return errors.New("injected cancellation commit failure")
	}
	return nil
}

func TestRedriveAcceptedCancellationRecoversAfterFailedCompletion(t *testing.T) {
	backend := &cancellationRepository{Repository: NewMemoryRepository(nil)}
	f := retainedRedrive(t, backend, 3, 1)
	advance(t, f.clock, time.Second)
	if _, err := f.s.jobs.RunDue(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	backend.fail.Store(true)
	out, err := f.c.CancelMessageMoveTask(t.Context(), &sdk.CancelMessageMoveTaskInput{TaskHandle: aws.String(f.handle)})
	if err != nil || out.ApproximateNumberOfMessagesMoved != 1 {
		t.Fatalf("cancel request: %v %v", out, err)
	}
	if _, err := f.s.jobs.RunDue(t.Context(), 1); err == nil {
		t.Fatal("failed cancellation commit succeeded")
	}
	f.reopen(t)
	if got := f.status(t); aws.ToString(got.Status) != moveCancelling || got.ApproximateNumberOfMessagesMoved != 1 {
		t.Fatalf("lost accepted cancellation: %v", got)
	}
	backend.fail.Store(false)
	if _, err := f.s.jobs.RunDue(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t); aws.ToString(got.Status) != moveCancelled || got.ApproximateNumberOfMessagesMoved != 1 {
		t.Fatalf("recovered cancellation: %v", got)
	}
	if attributes(t, f.c, f.dlq)["ApproximateNumberOfMessages"] != "2" || len(receive(t, f.c, f.destination, 10)) != 1 {
		t.Fatal("cancel rolled back previously moved messages or moved new work")
	}
}

type blockingRedriveKMS struct {
	testKMS
	entered, release chan struct{}
}

func (k *blockingRedriveKMS) GenerateDataKey(ctx context.Context, _ string, _ map[string]string) ([]byte, []byte, string, *awswire.Error) {
	close(k.entered)
	select {
	case <-ctx.Done():
	case <-k.release:
	}
	return nil, nil, "", &awswire.Error{Code: "DependencyUnavailable", Message: "interrupted encryption", StatusCode: 503}
}

func TestRedriveCloseCancelsPendingKeyPreparation(t *testing.T) {
	f := retainedRedrive(t, NewMemoryRepository(nil), 2, 1)
	if _, err := f.c.SetQueueAttributes(t.Context(), &sdk.SetQueueAttributesInput{QueueUrl: aws.String(f.destination), Attributes: map[string]string{"KmsMasterKeyId": "key"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	kms := &blockingRedriveKMS{entered: make(chan struct{}), release: make(chan struct{})}
	f.s = NewWithConfig(Config{Repository: f.backend, Clock: f.clock, KMS: kms})
	t.Cleanup(func() { _ = f.s.Close() })
	t.Cleanup(func() { close(kms.release) })
	advance(t, f.clock, time.Second)
	f.s.StartWorkers()
	select {
	case <-kms.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("redrive did not call encryption dependency")
	}
	closed := make(chan error, 1)
	go func() { closed <- f.s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel and join its key preparation")
	}
	if err := f.backend.View(t.Context(), func(r Reader) error {
		tasks, err := r.MoveTasks()
		if err != nil {
			return err
		}
		if len(tasks) != 1 || tasks[0].Status != moveRunning || tasks[0].Moved != 0 {
			t.Fatalf("shutdown changed accepted task: %v", tasks)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	requirePending(t, f.clock, 0)
}

func TestRedriveDeletedSourceCannotConsumeRecreatedQueue(t *testing.T) {
	f := retainedRedrive(t, NewMemoryRepository(nil), 2, 1)
	if _, err := f.c.DeleteQueue(t.Context(), &sdk.DeleteQueueInput{QueueUrl: aws.String(f.dlq)}); err != nil {
		t.Fatal(err)
	}
	advance(t, f.clock, time.Minute)
	newURL := create(t, f.c, "dead", nil)
	send(t, f.c, newURL, "new incarnation")
	if _, err := f.s.jobs.RunDue(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	out, err := f.c.ListMessageMoveTasks(t.Context(), &sdk.ListMessageMoveTasksInput{SourceArn: aws.String(f.arn)})
	if err != nil || len(out.Results) != 0 {
		t.Fatalf("old task leaked into recreated queue: %v %v", out, err)
	}
	if got := receive(t, f.c, newURL, 10); len(got) != 1 || aws.ToString(got[0].Body) != "new incarnation" {
		t.Fatalf("old task consumed recreated queue: %v", got)
	}
	if len(receive(t, f.c, f.destination, 10)) != 0 {
		t.Fatal("old task delivered from the recreated queue")
	}
	if err := f.backend.View(t.Context(), func(r Reader) error {
		tasks, err := r.MoveTasks()
		if err != nil {
			return err
		}
		if len(tasks) != 1 || tasks[0].Status != moveFailed || tasks[0].Moved != 0 {
			t.Fatalf("deleted source left outstanding work: %v", tasks)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

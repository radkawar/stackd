package iam

import (
	"context"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
)

type shutdownActivityUsage struct {
	service  *Service
	entered  chan struct{}
	recorded chan error
}

func (u shutdownActivityUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref ServiceLinkedRoleReference, _ func(context.Context, []ServiceLinkedRoleUsage) error) error {
	close(u.entered)
	<-ctx.Done()
	// A joined accepted attempt can finish after Close begins and its job
	// context is canceled. Reporting must stay open until this check exits.
	accepted := awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: ref.Scope.Partition, AccountID: ref.Scope.AccountID, Region: "eu-west-1", AccessKeyID: ref.Scope.AccountID, PrincipalID: ref.Scope.AccountID, PrincipalARN: "arn:" + ref.Scope.Partition + ":iam::" + ref.Scope.AccountID + ":root"})
	u.recorded <- u.service.RecordActivity(accepted, "s3", "HeadObject")
	return ctx.Err()
}

func TestCloseDrainsAcceptedChecksBeforeFinalActivityFlush(t *testing.T) {
	repository := NewMemoryRepository(nil)
	scope, _, _ := seedLinkedJob(t, repository, serviceLinkedNotStarted)
	start := time.Date(2035, 1, 2, 3, 4, 5, 123456789, time.UTC)
	service := NewWithConfig(Config{Repository: repository, Clock: clock.NewManual(start)})
	t.Cleanup(func() { _ = service.Close() })
	usage := shutdownActivityUsage{service: service, entered: make(chan struct{}), recorded: make(chan error, 1)}
	if err := service.RegisterServiceLinkedRole(autoScalingLinkedTemplate(t, service), usage); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := service.RunDueJobs(ctx, 1); err != nil {
		t.Fatal(err)
	}
	awaitLinked(t, ctx, usage.entered)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitLinked(t, ctx, usage.recorded); err != nil {
		t.Fatalf("shutdown rejected an already admitted attempt: %v", err)
	}
	if err := repository.View(t.Context(), func(tx ReadTx) error {
		rows, err := tx.PrincipalActivities(scope)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].ActionName != "HeadObject" || rows[0].Region != "eu-west-1" || !rows[0].LastAuthenticated.Equal(start) {
			t.Fatalf("final flush preceded accepted work: %+v", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

package scheduler_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/scheduler"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/scheduler"
	"stackd/storage/sqlite"
	sqlrepo "stackd/storage/sqlite/scheduler"
)

type deliveryAttempt struct {
	body string
	dlq  bool
}

type receiver struct {
	mu       sync.Mutex
	attempts []deliveryAttempt
	failure  *awswire.Error
}

func (*receiver) ValidateTarget(context.Context, service.ScheduleKey, service.TargetRecord) *awswire.Error {
	return nil
}

func (*receiver) ValidateRole(context.Context, service.ScheduleKey, string) *awswire.Error {
	return nil
}

func (r *receiver) Send(_ context.Context, _ service.DeliveryRecord, body string, dlq bool) *awswire.Error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts = append(r.attempts, deliveryAttempt{
		body,
		dlq,
	})
	if dlq {
		return nil
	}
	return r.failure
}

func (r *receiver) fail(e *awswire.Error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failure = e
}

func requestContext(t *testing.T, account string) context.Context {
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{
		Partition:    "aws",
		AccountID:    account,
		Region:       "us-east-1",
		PrincipalARN: "arn:aws:iam::" + account + ":root",
	})
}

func command(t *testing.T, s *service.Service, account, action string, in any) (any, *awswire.Error) {
	t.Helper()
	model, _ := awscatalog.LookupService("scheduler")
	op, _ := model.Operation(action)
	return s.ExecuteCommand(requestContext(t, account), awsapi.DecodedRequest{
		Operation: op,
		Protocol:  model.Protocol,
		Input:     in,
	})
}

func success(t *testing.T, s *service.Service, action string, in any) any {
	t.Helper()
	out, err := command(t, s, "123456789012", action, in)
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return out
}

func scheduleInput(name, expression string) *api.CreateScheduleInput {
	return &api.CreateScheduleInput{
		Name:               new(api.Name(name)),
		ScheduleExpression: new(api.ScheduleExpression(expression)),
		FlexibleTimeWindow: &api.FlexibleTimeWindow{Mode: new(api.FlexibleTimeWindowMode("OFF"))},
		Target: &api.Target{
			Arn:     new(api.TargetArn("arn:aws:sqs:us-east-1:123456789012:orders")),
			RoleArn: new(api.RoleArn("arn:aws:iam::123456789012:role/scheduler")),
			Input:   new(api.TargetInput("old <aws.scheduler.attempt-number> <aws.scheduler.execution-id>")),
			RetryPolicy: &api.RetryPolicy{
				MaximumRetryAttempts:     new(api.MaximumRetryAttempts(2)),
				MaximumEventAgeInSeconds: new(api.MaximumEventAgeInSeconds(60)),
			},
			DeadLetterConfig: &api.DeadLetterConfig{Arn: new(api.ResourceArn("arn:aws:sqs:us-east-1:123456789012:dead"))},
		},
	}
}

func TestPendingDeliverySurvivesReplacementAndRestart(t *testing.T) {
	for _, kind := range []string{
		"memory",
		"sqlite",
	} {
		t.Run(kind, func(t *testing.T) {
			var db *sql.DB
			var repo service.Repository
			path := filepath.Join(t.TempDir(), "scheduler.sqlite")
			reopen := func() {
				if kind == "memory" {
					if repo == nil {
						repo = service.NewMemoryRepository(nil)
					}
					return
				}
				if db != nil {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				db, err = sqlite.Open(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				repo = sqlrepo.New(db)
			}
			reopen()
			t.Cleanup(func() {
				if db != nil {
					_ = db.Close()
				}
			})
			now := time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC)
			c := clock.NewManual(now)
			r := &receiver{failure: &awswire.Error{
				Code:       "Unavailable",
				Message:    "retry",
				StatusCode: 503,
			}}
			s := service.NewWithConfig(service.Config{
				Repository: repo,
				Clock:      c,
				Delivery:   r,
				Roles:      r,
			})
			success(t, s, "CreateSchedule", scheduleInput("one", "at(2031-01-02T03:05:00)"))
			c.Advance(time.Minute)
			if _, err := s.JobDriver().RunDue(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			var pending service.DeliveryRecord
			if err := repo.View(t.Context(), func(view service.Reader) error {
				var found bool
				var err error
				pending, found, err = view.NextDelivery()
				if err == nil && (!found || pending.Attempts != 1 || pending.Target.Input != "old <aws.scheduler.attempt-number> <aws.scheduler.execution-id>" || !pending.Due.After(c.Now())) {
					t.Fatalf("unexpected retained retry: %#v", pending)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopen()
			s = service.NewWithConfig(service.Config{
				Repository: repo,
				Clock:      c,
				Delivery:   r,
				Roles:      r,
			})
			t.Cleanup(func() {
				_ = s.Close()
			})
			update := api.UpdateScheduleInput(*scheduleInput("one", "at(2031-01-02T04:00:00)"))
			update.Target.Input = new(api.TargetInput("new"))
			success(t, s, "UpdateSchedule", &update)
			r.fail(&awswire.Error{
				Code:       "AccessDenied",
				Message:    "policy changed",
				StatusCode: 403,
			})
			c.Advance(pending.Due.Sub(c.Now()))
			if _, err := s.JobDriver().RunDue(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			r.mu.Lock()
			attempts := append([]deliveryAttempt(nil), r.attempts...)
			r.mu.Unlock()
			if len(attempts) != 3 || !strings.HasPrefix(attempts[0].body, "old 1 ") || !strings.HasPrefix(attempts[1].body, "old 2 ") || attempts[2].body != attempts[1].body || !attempts[2].dlq {
				t.Fatalf("retry/DLQ transition: %#v", attempts)
			}
			if strings.TrimPrefix(attempts[0].body, "old 1 ") == strings.TrimPrefix(attempts[1].body, "old 2 ") {
				t.Fatal("different target attempts reused the same execution context ID")
			}
			if err := repo.View(t.Context(), func(view service.Reader) error {
				_, err := view.Delivery(pending.ID)
				if !errors.Is(err, service.ErrNotFound) {
					t.Fatalf("terminal delivery still retained: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGroupScopePaginationAndAtomicDelete(t *testing.T) {
	c := clock.NewManual(time.Date(2031, 1, 2, 0, 0, 0, 0, time.UTC))
	r := &receiver{}
	s := service.NewWithConfig(service.Config{
		Clock:    c,
		Delivery: r,
		Roles:    r,
	})
	defer s.Close()
	for _, name := range []string{
		"alpha",
		"beta",
	} {
		success(t, s, "CreateScheduleGroup", &api.CreateScheduleGroupInput{Name: new(api.ScheduleGroupName(name))})
	}
	first := success(t, s, "ListScheduleGroups", &api.ListScheduleGroupsInput{MaxResults: new(api.MaxResults(1))}).(*api.ListScheduleGroupsOutput)
	if first.NextToken == nil || string(*first.ScheduleGroups[0].Name) != "alpha" {
		t.Fatalf("unexpected first page: %#v", first)
	}
	if _, err := command(t, s, "222222222222", "ListScheduleGroups", &api.ListScheduleGroupsInput{NextToken: first.NextToken}); err == nil || err.Code != "ValidationException" {
		t.Fatalf("cross-account cursor: %v", err)
	}
	if _, err := command(t, s, "222222222222", "GetScheduleGroup", &api.GetScheduleGroupInput{Name: new(api.ScheduleGroupName("alpha"))}); err == nil || err.Code != "ResourceNotFoundException" {
		t.Fatalf("cross-account resource: %v", err)
	}
	in := scheduleInput("one", "rate(1 hour)")
	in.GroupName = new(api.ScheduleGroupName("alpha"))
	in.StartDate = new(c.Now().Add(time.Hour))
	success(t, s, "CreateSchedule", in)
	success(t, s, "DeleteScheduleGroup", &api.DeleteScheduleGroupInput{Name: in.GroupName})
	if _, err := command(t, s, "123456789012", "GetSchedule", &api.GetScheduleInput{
		Name:      in.Name,
		GroupName: in.GroupName,
	}); err == nil || err.Code != "ResourceNotFoundException" {
		t.Fatalf("cascade delete: %v", err)
	}
}

func TestSchedulerPaginationPreservesGroupTupleOrder(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repo service.Repository = service.NewMemoryRepository(nil)
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "scheduler.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo = sqlrepo.New(db)
			}
			c := clock.NewManual(time.Date(2031, 1, 2, 0, 0, 0, 0, time.UTC))
			target := &receiver{}
			s := service.NewWithConfig(service.Config{Repository: repo, Clock: c, Delivery: target, Roles: target})
			defer s.Close()
			for _, group := range []string{"a", "a-"} {
				success(t, s, "CreateScheduleGroup", &api.CreateScheduleGroupInput{Name: new(api.ScheduleGroupName(group))})
				in := scheduleInput("x", "rate(1 hour)")
				in.GroupName = new(api.ScheduleGroupName(group))
				in.State = new(api.ScheduleState("DISABLED"))
				success(t, s, "CreateSchedule", in)
			}
			first := success(t, s, "ListSchedules", &api.ListSchedulesInput{MaxResults: new(api.MaxResults(1))}).(*api.ListSchedulesOutput)
			if len(first.Schedules) != 1 || string(*first.Schedules[0].GroupName) != "a" || first.NextToken == nil {
				t.Fatalf("incorrect first page: %#v", first)
			}
			last := success(t, s, "ListSchedules", &api.ListSchedulesInput{MaxResults: new(api.MaxResults(1)), NextToken: first.NextToken}).(*api.ListSchedulesOutput)
			if len(last.Schedules) != 1 || string(*last.Schedules[0].GroupName) != "a-" || string(*last.Schedules[0].Name) != "x" || last.NextToken != nil {
				t.Fatalf("pagination lost the tuple-sorted second group: %#v", last)
			}
		})
	}
}

func TestAtIgnoresBoundsAndAutomaticDeletionRetainsRetry(t *testing.T) {
	now := time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC)
	c := clock.NewManual(now)
	r := &receiver{failure: &awswire.Error{
		Code:       "Unavailable",
		StatusCode: 503,
	}}
	repo := service.NewMemoryRepository(nil)
	s := service.NewWithConfig(service.Config{
		Clock:      c,
		Repository: repo,
		Delivery:   r,
		Roles:      r,
	})
	defer s.Close()
	in := scheduleInput("once", "at(2031-01-02T03:05:00)")
	in.StartDate = new(now.Add(24 * time.Hour))
	in.EndDate = new(now.Add(-24 * time.Hour))
	in.ActionAfterCompletion = new(api.ActionAfterCompletion("DELETE"))
	success(t, s, "CreateSchedule", in)
	c.Advance(time.Minute)
	if _, err := s.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := command(t, s, "123456789012", "GetSchedule", &api.GetScheduleInput{Name: in.Name}); err == nil || err.Code != "ResourceNotFoundException" {
		t.Fatalf("one-shot auto-delete: %v", err)
	}
	if err := repo.View(t.Context(), func(r service.Reader) error {
		d, ok, err := r.NextDelivery()
		if !ok || d.Attempts != 1 {
			t.Fatalf("auto-delete lost pending retry: %#v", d)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRateStartsImmediatelyAtFractionalClock(t *testing.T) {
	c := clock.NewManual(time.Date(2031, 1, 2, 0, 0, 0, 500000000, time.UTC))
	r := &receiver{}
	s := service.NewWithConfig(service.Config{
		Clock:    c,
		Delivery: r,
		Roles:    r,
	})
	defer s.Close()
	success(t, s, "CreateSchedule", scheduleInput("rate", "rate(1 hour)"))
	if _, err := s.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.attempts) != 1 {
		t.Fatalf("an omitted StartDate must start immediately, attempts=%d", len(r.attempts))
	}
}

func TestFlexibleWindowAgeAndGroupDeletionOfRetainedRetry(t *testing.T) {
	now := time.Date(2031, 1, 2, 0, 0, 0, 0, time.UTC)
	c := clock.NewManual(now)
	repo := service.NewMemoryRepository(nil)
	r := &receiver{failure: &awswire.Error{
		Code:       "Unavailable",
		StatusCode: 503,
	}}
	key := service.ScheduleKey{
		Group: service.GroupKey{
			Scope: service.Scope{
				Partition: "aws",
				Account:   "123456789012",
				Region:    "us-east-1",
			},
			Name: "flexible",
		},
		Name: "once",
	}
	if err := repo.Update(t.Context(), func(tx service.Transaction) error {
		if err := tx.PutGroup(service.GroupRecord{
			Key:      key.Group,
			Created:  now,
			Modified: now,
		}); err != nil {
			return err
		}
		return tx.PutSchedule(service.ScheduleRecord{
			Key:                   key,
			Created:               now,
			Modified:              now,
			Expression:            "at(2031-01-02T00:00:00)",
			Timezone:              "UTC",
			State:                 "ENABLED",
			ActionAfterCompletion: "DELETE",
			Next:                  &now,
			WindowMode:            "FLEXIBLE",
			WindowMinutes:         60,
			HasWindowMinutes:      true,
			Revision:              1,
			Target: service.TargetRecord{
				ARN:           "arn:aws:sqs:us-east-1:123456789012:orders",
				RoleARN:       "arn:aws:iam::123456789012:role/scheduler",
				Input:         "retained",
				HasInput:      true,
				MaxAgeSeconds: 60,
				MaxRetries:    2,
			},
		})
	}); err != nil {
		t.Fatal(err)
	}
	s := service.NewWithConfig(service.Config{
		Repository: repo,
		Clock:      c,
		Delivery:   r,
		Roles:      r,
	})
	defer s.Close()
	if _, err := s.JobDriver().RunDue(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	var pending service.DeliveryRecord
	if err := repo.View(t.Context(), func(view service.Reader) error {
		var found bool
		var err error
		pending, found, err = view.NextDelivery()
		if !found || pending.Due.Before(now) || !pending.Due.Before(now.Add(time.Hour)) || pending.Expires.Sub(pending.Due) != time.Minute {
			t.Fatalf("flexible delivery window or retry age invalid: %#v", pending)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	c.Advance(pending.Due.Sub(c.Now()))
	if _, err := s.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	success(t, s, "DeleteScheduleGroup", &api.DeleteScheduleGroupInput{Name: new(api.ScheduleGroupName(key.Group.Name))})
	if err := repo.View(t.Context(), func(view service.Reader) error {
		_, found, err := view.NextDelivery()
		if found {
			t.Fatal("deleted group retained retry work from an automatically deleted schedule")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

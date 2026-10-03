package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	runtime "stackd/compute/lambda"
	"stackd/internal/apievents"
	"stackd/internal/scheduler"
	"stackd/journal"
	"stackd/storage/memory"
)

// No dependency may manufacture a runtime or publish metrics while these tests
// drive the queue transaction directly. Calling an embedded nil interface fails.
type missingAliasDependencies struct {
	runtime.Executor
	RoleProvider
	MetricPublisher
}

func missingAliasFixture(t *testing.T) (*Service, context.Context, InvocationRecord, *clock.Manual, journal.Storage) {
	t.Helper()
	domain := memory.NewDomain()
	repository := NewMemoryRepository(domain)
	events := journal.NewMemory(domain)
	ctx, ref := aliasOwnerFixture(t, repository)
	manual := clock.NewManual(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	dependencies := missingAliasDependencies{}
	s := aliasOwnerService(t, Config{Repository: repository, Clock: manual, Executor: dependencies, Roles: dependencies, Metrics: dependencies, APIEvents: apievents.New(events)})
	// Drive jobs explicitly rather than starting the background scheduler.
	s.started.Store(true)
	v := InvocationRecord{
		ID: "accepted-event", Key: ref.FunctionKey, FunctionARN: ref.ARN(),
		RequestID: "accepted-request", ParentEventID: "accepted-parent", TraceHeader: "accepted-trace",
		Payload:  []byte(`{"customer":"payload","nested":{"number":7}}`),
		Accepted: manual.Now(), Due: manual.Now(), Version: 1, State: "queued",
		Settings: EventInvokeSettings{MaxAgeSeconds: 180, MaxRetries: 1, OnFailureARN: "arn:aws:sqs:us-east-1:111111111111:failure"},
		RoleARN:  "arn:aws:iam::111111111111:role/accepted",
	}
	missingAliasPut(t, ctx, repository, v)
	return s, ctx, v, manual, events
}

func missingAliasPut(t *testing.T, ctx context.Context, repository Repository, v InvocationRecord) {
	t.Helper()
	if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutInvocation(v) }); err != nil {
		t.Fatal(err)
	}
}

func missingAliasRead(t *testing.T, ctx context.Context, repository Repository, id string) InvocationRecord {
	t.Helper()
	var v InvocationRecord
	if err := repository.View(ctx, func(r Reader) error {
		var err error
		v, err = r.Invocation(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

func missingAliasRun(t *testing.T, ctx context.Context, s *Service) scheduler.Job {
	t.Helper()
	jobs := invocationJobs{s}
	job, found, err := jobs.Next(ctx)
	if err != nil || !found {
		t.Fatalf("missing runnable accepted event: found=%v err=%v", found, err)
	}
	if err := jobs.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	s.work.Wait()
	return job
}

func missingAliasAssertRetired(t *testing.T, ctx context.Context, s *Service, v InvocationRecord) {
	t.Helper()
	if err := s.repository.View(ctx, func(r Reader) error {
		if _, err := r.Invocation(v.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired missing alias retained an invocation: %v", err)
		}
		if job, found, err := r.NextOutcomeDelivery(); err != nil || found {
			t.Fatalf("expired missing alias fabricated a destination/DLQ: %+v %v", job, err)
		}
		for _, resource := range []string{"", v.Key.Name + ":" + v.Reference().Qualifier} {
			key := MetricPublicationKey{Function: v.Key, Resource: resource, Minute: s.clock.Now().Truncate(time.Minute)}
			samples, err := r.MetricSamples(key)
			if err != nil {
				return err
			}
			want := []MetricSample{{Name: metricAsyncDropped, Value: 1, SampleCount: 1}}
			if !reflect.DeepEqual(samples, want) {
				t.Fatalf("drop must be committed once without runtime metrics for %q: %+v", resource, samples)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMissingAliasAgeBoundaryClaimAndCompletion(t *testing.T) {
	for _, path := range []string{"claim", "completion"} {
		t.Run(path, func(t *testing.T) {
			s, ctx, accepted, manual, _ := missingAliasFixture(t)
			v := accepted
			v.SystemErrors = 9
			missingAliasPut(t, ctx, s.repository, v)
			if err := manual.Advance(180*time.Second - time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			missingAliasRun(t, ctx, s)
			v = missingAliasRead(t, ctx, s.repository, v.ID)
			deadline := accepted.Accepted.Add(180 * time.Second)
			if v.State != "queued" || v.InvokeCount != 0 || v.ResponseStatus != 0 || !v.Due.Equal(deadline) {
				t.Fatalf("missing lookup retired early or consumed a handler attempt: %+v", v)
			}
			if err := manual.Advance(time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			if path == "claim" {
				job := missingAliasRun(t, ctx, s)
				// A stale claim after retirement must not double-publish the drop.
				if err := (invocationJobs{s}).Run(ctx, job); err != nil {
					t.Fatal(err)
				}
			} else {
				v.State, v.Version = "in-flight", v.Version+1
				missingAliasPut(t, ctx, s.repository, v)
				s.runInvocation(v)
				if err := s.finishInvocation(ctx, v, nil, failure("ResourceNotFoundException", "missing alias", 404), false, true); err != nil {
					t.Fatal(err)
				}
			}
			missingAliasAssertRetired(t, ctx, s, accepted)
		})
	}
}

func TestMissingAliasLookupsPreserveRequestAndRefreshReplacement(t *testing.T) {
	s, ctx, accepted, manual, events := missingAliasFixture(t)
	for range 3 {
		missingAliasRun(t, ctx, s)
		v := missingAliasRead(t, ctx, s.repository, accepted.ID)
		if v.InvokeCount != 0 || v.ResponseStatus != 0 || v.ResponseError != "" || len(v.ResponsePayload) != 0 || v.State != "queued" {
			t.Fatalf("missing alias exhausted handler retry budget or invented a result: %+v", v)
		}
		if v.RequestID != accepted.RequestID || v.FunctionARN != accepted.FunctionARN || v.ParentEventID != accepted.ParentEventID || v.TraceHeader != accepted.TraceHeader || !v.Accepted.Equal(accepted.Accepted) || string(v.Payload) != string(accepted.Payload) {
			t.Fatalf("missing alias lost accepted request identity/payload: %+v", v)
		}
		if err := manual.Advance(v.Due.Sub(manual.Now())); err != nil {
			t.Fatal(err)
		}
	}
	calls, err := events.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range calls {
		if call.APICallCompleted != nil && call.APICallCompleted.EventName == "InvokeExecution" {
			t.Fatal("failed alias lookup invented a runtime execution audit")
		}
	}
	settings := EventInvokeSettings{MaxAgeSeconds: 240, MaxRetries: 2, OnSuccessARN: "arn:aws:sqs:us-east-1:111111111111:replacement"}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutFunctionVersion(FunctionRecord{Key: accepted.Key, Version: 3, Role: "arn:aws:iam::111111111111:role/replacement", DeadLetterARN: "arn:aws:sqs:us-east-1:111111111111:replacement-dlq"}); err != nil {
			return err
		}
		if err := tx.PutAlias(AliasRecord{Key: accepted.Reference(), FunctionVersion: 3}); err != nil {
			return err
		}
		return tx.PutEventInvokeConfig(EventInvokeConfig{Key: accepted.Reference(), Effective: settings})
	}); err != nil {
		t.Fatal(err)
	}
	v := missingAliasRead(t, ctx, s.repository, accepted.ID)
	if err := s.repository.View(ctx, func(r Reader) error {
		selected, err := selectInvocation(r, &v)
		if err != nil {
			return err
		}
		if selected.Version != 3 || v.RoleARN != "arn:aws:iam::111111111111:role/replacement" || v.DeadLetterARN != "arn:aws:sqs:us-east-1:111111111111:replacement-dlq" || v.Settings != settings || invocationCondition(v, manual.Now()) != "" {
			t.Fatalf("accepted logical alias did not adopt current replacement controls: selected=%+v event=%+v", selected, v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMissingAliasRecreatedBetweenLookupAndCompletion(t *testing.T) {
	s, ctx, v, _, _ := missingAliasFixture(t)
	v.State = "in-flight"
	missingAliasPut(t, ctx, s.repository, v)
	base := s.repository
	s.repository = &replacingAliasRepository{Repository: base, beforeUpdate: func() error {
		return base.Update(ctx, func(tx Transaction) error {
			return tx.PutAlias(AliasRecord{Key: v.Reference(), FunctionVersion: 2})
		})
	}}
	s.runInvocation(v)
	got := missingAliasRead(t, ctx, base, v.ID)
	if got.State != "queued" || got.InvokeCount != 0 || got.ResponseStatus != 0 {
		t.Fatalf("alias recreation turned a failed lookup into a handler attempt: %+v", got)
	}
}

func TestMissingAliasRetryZeroRetainsNativeTerminal(t *testing.T) {
	s, ctx, v, _, _ := missingAliasFixture(t)
	v.Settings.MaxRetries = 0
	missingAliasPut(t, ctx, s.repository, v)
	missingAliasRun(t, ctx, s)
	got := missingAliasRead(t, ctx, s.repository, v.ID)
	if got.State != "completed" || got.Completion != "RetriesExhausted" || got.InvokeCount != 1 || got.ResponseStatus != 404 || len(got.ResponsePayload) != 0 {
		t.Fatalf("retry-zero deleted alias lost captured terminal: %+v", got)
	}
	payload, err := got.DestinationPayload()
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		RequestContext struct {
			Count int `json:"approximateInvokeCount"`
		} `json:"requestContext"`
		ResponseContext struct {
			Status int `json:"statusCode"`
		} `json:"responseContext"`
		ResponsePayload json.RawMessage `json:"responsePayload"`
	}
	if err := json.Unmarshal(payload, &record); err != nil || record.RequestContext.Count != 1 || record.ResponseContext.Status != 404 || record.ResponsePayload != nil {
		t.Fatalf("retry-zero destination changed: %s %v", payload, err)
	}
}

func TestMissingAliasRuleDoesNotGeneralizeUnmeasuredTargets(t *testing.T) {
	for _, scopeChange := range []string{"whole-function", "partition", "account", "region", "fixed-version", "latest", "published", "prior-handler", "existing-alias"} {
		t.Run(scopeChange, func(t *testing.T) {
			s, ctx, v, _, _ := missingAliasFixture(t)
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				switch scopeChange {
				case "whole-function", "partition", "account", "region":
					if err := tx.DeleteFunction(v.Key); err != nil {
						return err
					}
					foreign := v.Key
					switch scopeChange {
					case "partition":
						foreign.Partition = "aws-cn"
					case "account":
						foreign.Account = "222222222222"
					case "region":
						foreign.Region = "us-west-2"
					default:
						return nil
					}
					return tx.PutFunction(FunctionRecord{Key: foreign})
				case "fixed-version":
					v.FunctionARN = v.Key.ARN() + ":99"
				case "latest":
					v.FunctionARN = v.Key.ARN() + ":$LATEST"
				case "published":
					v.FunctionARN = v.Key.ARN() + ":$LATEST.PUBLISHED"
				case "prior-handler":
					v.InvokeCount = 1
				case "existing-alias":
					return tx.PutAlias(AliasRecord{Key: v.Reference(), FunctionVersion: 1})
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				missing, err := missingAliasBeforeEntry(r, v)
				if err == nil && missing {
					t.Fatal("alias-only terminal rule escaped its measured target/scope")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

var errMissingAliasRollback = errors.New("reject invocation retirement")

type missingAliasRollbackRepository struct{ Repository }

type missingAliasRollbackTransaction struct{ Transaction }

func (r missingAliasRollbackRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.Repository.Update(ctx, func(tx Transaction) error { return fn(missingAliasRollbackTransaction{tx}) })
}

func (tx missingAliasRollbackTransaction) DeleteInvocation(id string) error {
	if err := tx.Transaction.DeleteInvocation(id); err != nil {
		return err
	}
	return errMissingAliasRollback
}

func TestMissingAliasRetirementAndDropMetricRollbackTogether(t *testing.T) {
	s, ctx, v, manual, _ := missingAliasFixture(t)
	if err := manual.Advance(180 * time.Second); err != nil {
		t.Fatal(err)
	}
	base := s.repository
	s.repository = missingAliasRollbackRepository{base}
	job := scheduler.Job{Key: v.ID, Version: v.Version, Due: v.Due}
	if err := (invocationJobs{s}).Run(ctx, job); !errors.Is(err, errMissingAliasRollback) {
		t.Fatalf("retirement failure was not propagated: %v", err)
	}
	got := missingAliasRead(t, ctx, base, v.ID)
	if !reflect.DeepEqual(got, v) {
		t.Fatalf("failed retirement consumed accepted event: %+v", got)
	}
	if err := base.View(ctx, func(r Reader) error {
		if _, err := r.NextMetricPublication(); !errors.Is(err, ErrNotFound) {
			t.Fatalf("failed retirement leaked drop metric: %v", err)
		}
		if _, found, err := r.NextOutcomeDelivery(); err != nil || found {
			t.Fatalf("failed retirement leaked destination: found=%v err=%v", found, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.repository = base
	if err := (invocationJobs{s}).Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	missingAliasAssertRetired(t, ctx, s, v)
}

func TestMissingAliasPreparationFailureCannotDropBeforeDeadline(t *testing.T) {
	s, ctx, v, manual, _ := missingAliasFixture(t)
	v.State, v.SystemErrors = "in-flight", 9
	missingAliasPut(t, ctx, s.repository, v)
	if err := manual.Advance(179 * time.Second); err != nil {
		t.Fatal(err)
	}
	// The alias vanished after another pre-entry failure. Its next backoff
	// crosses the age limit, but the accepted request still has one second.
	if err := s.finishInvocation(ctx, v, nil, failure("ServiceException", "pre-entry failure", 500), false, false); err != nil {
		t.Fatal(err)
	}
	got := missingAliasRead(t, ctx, s.repository, v.ID)
	if got.State != "queued" || !got.Due.Equal(v.Accepted.Add(180*time.Second)) || got.InvokeCount != 0 || got.Completion != "" {
		t.Fatalf("pre-entry failure retired missing alias before age: %+v", got)
	}
	if err := manual.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	missingAliasRun(t, ctx, s)
	missingAliasAssertRetired(t, ctx, s, v)
}

func TestMissingAliasDropPreservesIndependentLegacyDeadLetterRoute(t *testing.T) {
	s, ctx, v, manual, _ := missingAliasFixture(t)
	v.DeadLetterARN = "arn:aws:sqs:us-east-1:111111111111:legacy-dead-letter"
	missingAliasPut(t, ctx, s.repository, v)
	if err := manual.Advance(180 * time.Second); err != nil {
		t.Fatal(err)
	}
	missingAliasRun(t, ctx, s)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		retained, err := tx.Invocation(v.ID)
		if err != nil {
			return err
		}
		if retained.State != "completed" || retained.InvokeCount != 0 || retained.ResponseStatus != 0 || string(retained.Payload) != string(v.Payload) || retained.RequestID != v.RequestID {
			t.Fatalf("independent DLQ route lost accepted request or invented a response: %+v", retained)
		}
		job, found, err := tx.NextOutcomeDelivery()
		if err != nil || !found {
			t.Fatalf("legacy DLQ was silently suppressed: found=%v err=%v", found, err)
		}
		delivery, err := tx.OutcomeDelivery(job.Key)
		if err != nil {
			return err
		}
		if !delivery.DeadLetter || delivery.DestinationARN != v.DeadLetterARN || delivery.InvocationID != v.ID {
			t.Fatalf("missing alias fabricated OnFailure instead of retaining independent DLQ: %+v", delivery)
		}
		// Acknowledging the one legacy route must collect the event: there
		// must not be an additional fabricated OnFailure destination.
		if err := tx.DeleteOutcomeDelivery(delivery.ID); err != nil {
			return err
		}
		if _, err := tx.Invocation(v.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("OnFailure survived independent DLQ acknowledgement: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	missingAliasAssertRetired(t, ctx, s, v)
}

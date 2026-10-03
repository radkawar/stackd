package stackd_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
	orgstore "stackd/storage/organizations"
)

type publicationAppendFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (s *publicationAppendFailure) AppendEffectivePolicyChanged(ctx context.Context, envelope journal.Envelope, change journal.EffectivePolicyChanged) error {
	if err := s.Storage.AppendEffectivePolicyChanged(ctx, envelope, change); err != nil {
		return err
	}
	if s.fail.Load() {
		return errors.New("injected failure after staged effective policy event")
	}
	return nil
}

func TestOrganizationsPolicyPublicationRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "rollback.sqlite"))
			}
			state := &creationCommitFailure{Storage: backends.Organizations}
			history := &publicationAppendFailure{Storage: backends.Journal}
			backends.Organizations, backends.Journal = state, history
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			cloud, c, _ := creationEventCloud(t, backends, source)
			f := organizationFixture(t, c, source)
			if _, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeTagPolicy}); err != nil {
				t.Fatal(err)
			}
			policy := createTagPolicy(t, f, "rollback-publication", effectivePolicyDocument("cost", "before"), f.rootID)
			settleEffectivePolicies(t, cloud, source)
			read := func() *orgtypes.EffectivePolicy {
				t.Helper()
				out, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy})
				if err != nil {
					t.Fatal(err)
				}
				return out.EffectivePolicy
			}
			for index, mode := range []string{"commit", "cancellation", "append"} {
				t.Run(mode, func(t *testing.T) {
					before := read()
					updated, err := f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &policy, Content: aws.String(effectivePolicyDocument("cost", mode))})
					if err != nil {
						t.Fatal(err)
					}
					requestID, ok := awsmiddleware.GetRequestIDMetadata(updated.ResultMetadata)
					if !ok {
						t.Fatal("missing request ID")
					}
					events := lifecycleEvents(t, history)
					defer func() {
						state.mode.Store(0)
						history.fail.Store(false)
					}()
					if mode == "append" {
						history.fail.Store(true)
					} else {
						state.mode.Store(int32(index + 1))
					}
					source.Advance(time.Second)
					if _, err := cloud.RunDueJobs(t.Context(), 100); err == nil {
						t.Fatal("publication unexpectedly committed")
					}
					if after := read(); !reflect.DeepEqual(after, before) {
						t.Fatal("failed publication changed cached view", before, after)
					}
					if after := lifecycleEvents(t, history); !reflect.DeepEqual(after, events) {
						t.Fatal("failed publication leaked event", after)
					}
					stored, _, err := state.Load(t.Context(), "aws")
					if err != nil {
						t.Fatal(err)
					}
					p := stored.Organizations[0].EffectivePolicies[0]
					if p.Due == nil || p.RequestID != requestID {
						t.Fatal("failed publication lost pending intent", p)
					}
					state.mode.Store(0)
					history.fail.Store(false)
					if _, err := cloud.RunDueJobs(t.Context(), 100); err != nil {
						t.Fatal(err)
					}
					after := read()
					if !strings.Contains(*after.PolicyContent, `"`+mode+`"`) || !after.LastUpdatedTimestamp.Equal(source.Now()) {
						t.Fatal("retry did not publish latest state", after)
					}
					var last journal.Event
					for _, event := range lifecycleEvents(t, history) {
						if event.EffectivePolicyChanged.State != "" {
							last = event
						}
					}
					if last.EffectivePolicyChanged.State != journal.EffectivePolicyPublished || last.RequestID != requestID {
						t.Fatal("retry lost origin", last)
					}
				})
			}
		})
	}
}

// Pause the selected publication before it enters the native transaction. API
// mutations must remain possible; its stale revision must not publish afterwards.
type blockedPublication struct {
	orgstore.Storage
	block   atomic.Bool
	started chan struct{}
	release chan struct{}
}

func (s *blockedPublication) CompareAndSwap(ctx context.Context, partition string, revision uint64, record orgstore.PartitionRecord, commit func(context.Context) error) (bool, error) {
	for _, org := range record.Organizations {
		for _, p := range org.EffectivePolicies {
			if p.Due == nil && strings.Contains(p.Content, `"selected"`) && s.block.CompareAndSwap(true, false) {
				close(s.started)
				select {
				case <-ctx.Done():
					return false, ctx.Err()
				case <-s.release:
				}
			}
		}
	}
	return s.Storage.CompareAndSwap(ctx, partition, revision, record, commit)
}

func TestOrganizationsPolicyPublicationConcurrentUpdate(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "conflict.sqlite"))
			}
			state := &blockedPublication{Storage: backends.Organizations, started: make(chan struct{}), release: make(chan struct{})}
			backends.Organizations = state
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			cloud, c, _ := creationEventCloud(t, backends, source)
			f := organizationFixture(t, c, source)
			if _, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeTagPolicy}); err != nil {
				t.Fatal(err)
			}
			policy := createTagPolicy(t, f, "concurrent-publication", effectivePolicyDocument("cost", "before"), f.rootID)
			settleEffectivePolicies(t, cloud, source)
			selected, err := f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &policy, Content: aws.String(effectivePolicyDocument("cost", "selected"))})
			if err != nil {
				t.Fatal(err)
			}
			oldRequest, _ := awsmiddleware.GetRequestIDMetadata(selected.ResultMetadata)
			state.block.Store(true)
			source.Advance(time.Second)
			drained := make(chan error, 1)
			go func() { _, err := cloud.RunDueJobs(t.Context(), 100); drained <- err }()
			select {
			case <-state.started:
			case <-time.After(5 * time.Second):
				t.Fatal("publication was not selected")
			}
			// A timeout here also detects accidentally holding a repository lock
			// while calling the operation-owned merge or journal preparation.
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			latest, err := f.org.UpdatePolicy(ctx, &organizations.UpdatePolicyInput{PolicyId: &policy, Content: aws.String(effectivePolicyDocument("cost", "latest"))})
			close(state.release)
			if err != nil {
				t.Fatal(err)
			}
			requestID, _ := awsmiddleware.GetRequestIDMetadata(latest.ResultMetadata)
			if err := <-drained; err != nil {
				t.Fatal(err)
			}
			prior, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy})
			if err != nil || !strings.Contains(*prior.EffectivePolicy.PolicyContent, `"before"`) {
				t.Fatal("stale selection replaced published view", prior, err)
			}
			settleEffectivePolicies(t, cloud, source)
			out, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy})
			if err != nil || !strings.Contains(*out.EffectivePolicy.PolicyContent, `"latest"`) {
				t.Fatal("latest update lost", out, err)
			}
			var published []string
			for _, event := range lifecycleEvents(t, backends.Journal) {
				if event.EffectivePolicyChanged.State == journal.EffectivePolicyPublished {
					if event.RequestID == oldRequest {
						t.Fatal("stale selection committed an event")
					}
					published = append(published, event.RequestID)
				}
			}
			if len(published) == 0 || published[len(published)-1] != requestID {
				t.Fatal("latest request origin lost", published)
			}
		})
	}
}

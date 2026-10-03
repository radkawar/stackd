package organizations_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	provider "stackd/internal/services/organizations"
)

func TestPolicySnapshotCoherentAcrossConcurrentSDKMutation(t *testing.T) {
	s := organizationsOnly(nil)
	root := fixedClient(t, s, orgRoot(managementID, "aws"))
	createOrg(t, root)
	member := createAccount(t, root, "snapshot-member")
	allow := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	deny := `{"Statement":{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}}`
	created, err := root.CreatePolicy(t.Context(), &sdk.CreatePolicyInput{Name: aws.String("session-controls"), Description: aws.String("session snapshot"), Type: types.PolicyTypeServiceControlPolicy, Content: aws.String(allow)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.AttachPolicy(t.Context(), &sdk.AttachPolicyInput{PolicyId: created.Policy.PolicySummary.Id, TargetId: aws.String(member)}); err != nil {
		t.Fatal(err)
	}
	ctx := awsctx.WithMetadata(t.Context(), orgRoot(member, "aws"))
	authorizer := authorization.New(nil, orgControlSource{s})
	permission := authorization.Request{Action: "sts:AssumeRole", ResourceARN: "arn:aws:iam::" + member + ":role/target"}
	var escaped context.Context
	err = s.WithPolicySnapshot(ctx, func(snapshot context.Context) error {
		escaped = snapshot
		before, err := s.ServiceControlPolicies(snapshot, member)
		if err != nil {
			return err
		}
		found := false
		for _, level := range before {
			for _, p := range level.Documents {
				if p.Source == aws.ToString(created.Policy.PolicySummary.Arn) {
					found = true
					if level.TargetID != member || p.Document != allow || p.Version != "" {
						t.Fatalf("SCP source snapshot = %+v", level)
					}
				}
			}
		}
		if !found {
			t.Fatal("SCP snapshot lost its policy ARN")
		}
		if err := authorizer.Authorize(snapshot, permission); err != nil {
			return err
		}
		// This SDK call runs on a different handler goroutine while the snapshot
		// callback is active, proving that the callback holds no storage lock.
		updateCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if _, err := root.UpdatePolicy(updateCtx, &sdk.UpdatePolicyInput{PolicyId: created.Policy.PolicySummary.Id, Content: aws.String(deny)}); err != nil {
			return err
		}
		after, err := s.ServiceControlPolicies(snapshot, member)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatal("policy snapshot changed during one decision")
		}
		if err := authorizer.Authorize(snapshot, permission); err != nil {
			return err
		}
		if len(after) == 0 || len(after[0].Documents) == 0 {
			t.Fatal("expected hierarchy documents")
		}
		after[0].Documents[0].Document = "caller mutation"
		again, err := s.ServiceControlPolicies(snapshot, member)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before, again) {
			t.Fatal("policy snapshot exposed mutable documents")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ServiceControlPolicies(escaped, member); !errors.Is(err, context.Canceled) {
		t.Fatalf("escaped snapshot remains usable: %v", err)
	}
	if err := s.WithPolicySnapshot(ctx, func(next context.Context) error {
		if err := authorizer.Authorize(next, permission); err == nil {
			t.Fatal("next request ignored committed SCP deny")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicySnapshotAccountPartitionAndSourceIsolation(t *testing.T) {
	s := organizationsOnly(nil)
	root := fixedClient(t, s, orgRoot(managementID, "aws"))
	createOrg(t, root)
	member := createAccount(t, root, "scoped-member")
	ctx := awsctx.WithMetadata(t.Context(), orgRoot(member, "aws"))
	if err := s.WithPolicySnapshot(ctx, func(snapshot context.Context) error {
		levels, err := s.ServiceControlPolicies(snapshot, member)
		if err != nil {
			return err
		}
		if len(levels) == 0 {
			t.Fatal("member should have SCP hierarchy")
		}
		for _, meta := range []awsctx.Metadata{orgRoot(managementID, "aws"), orgRoot(member, "aws-us-gov")} {
			other := awsctx.WithMetadata(snapshot, meta)
			levels, err := s.ServiceControlPolicies(other, meta.AccountID)
			if err != nil {
				return err
			}
			if len(levels) != 0 {
				t.Fatalf("snapshot leaked across scope: %+v", meta)
			}
		}
		otherService := provider.New()
		levels, err = otherService.ServiceControlPolicies(snapshot, member)
		if err != nil {
			return err
		}
		if len(levels) != 0 {
			t.Fatal("snapshot leaked across service instances")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicySnapshotCancellationAndFailureLifetime(t *testing.T) {
	s := provider.New()
	ctx := awsctx.WithMetadata(t.Context(), orgRoot(managementID, "aws"))
	for _, mode := range []string{"before", "during", "callback failure"} {
		t.Run(mode, func(t *testing.T) {
			request, cancel := context.WithCancel(ctx)
			defer cancel()
			if mode == "before" {
				cancel()
			}
			called := false
			var escaped context.Context
			failure := errors.New("callback failure")
			err := s.WithPolicySnapshot(request, func(snapshot context.Context) error {
				called = true
				escaped = snapshot
				if mode == "callback failure" {
					return failure
				}
				cancel()
				return nil
			})
			want := error(context.Canceled)
			if mode == "callback failure" {
				want = failure
			}
			if !errors.Is(err, want) {
				t.Fatalf("error=%v, want %v", err, want)
			}
			if mode == "before" && called {
				t.Fatal("canceled request entered callback")
			}
			if escaped != nil && !errors.Is(escaped.Err(), context.Canceled) {
				t.Fatal("callback context did not expire")
			}
		})
	}
	if err := s.WithPolicySnapshot(ctx, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
	if err := s.WithPolicySnapshot(t.Context(), func(context.Context) error { t.Fatal("unscoped callback ran"); return nil }); err == nil {
		t.Fatal("missing scope accepted")
	}
}

type failingSnapshotLoad struct {
	provider.Storage
	failure error
}

func (s failingSnapshotLoad) Load(context.Context, string) (provider.PartitionRecord, uint64, error) {
	return provider.PartitionRecord{}, 0, s.failure
}

func TestPolicySnapshotStorageFailureDoesNotSkipControls(t *testing.T) {
	failure := errors.New("snapshot unavailable")
	s := provider.NewWithStorage(failingSnapshotLoad{Storage: provider.NewMemoryStorage(nil), failure: failure})
	ctx := awsctx.WithMetadata(t.Context(), orgRoot(managementID, "aws"))
	err := s.WithPolicySnapshot(ctx, func(context.Context) error { t.Fatal("failed read entered callback"); return nil })
	if !errors.Is(err, failure) {
		t.Fatalf("storage failure=%v", err)
	}
}

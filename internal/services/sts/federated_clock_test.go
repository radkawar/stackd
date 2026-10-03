package sts

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

type federationClockAuthority struct {
	role  RoleSnapshot
	clock *clock.Manual
	store *identity.Store
}

func (a federationClockAuthority) WithFederationSession(ctx context.Context, _ FederationProviderReference, _ string, fn func(context.Context, RoleSnapshot, FederatedCredentialIssuer) error) error {
	return fn(ctx, a.role, a.store.WithRepositoryAt(identity.NewMemoryRepository(), a.clock.Now()))
}
func (a federationClockAuthority) RoleForAssumption(context.Context, string) (RoleSnapshot, error) {
	return a.role, nil
}
func (a federationClockAuthority) ResolveManagedPolicyDocuments(context.Context, []string) ([]string, error) {
	return nil, a.clock.Advance(time.Hour)
}

type countedFederationClock struct {
	*clock.Manual
	reads atomic.Int32
}

func (c *countedFederationClock) Now() time.Time { c.reads.Add(1); return c.Manual.Now() }

func TestFederatedSTSClockCapturedAndFallbackInstants(t *testing.T) {
	for _, captured := range []bool{false, true} {
		for _, epoch := range []time.Time{time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC), {}} {
			t.Run(fmt.Sprintf("captured=%t/%s", captured, epoch.Format(time.RFC3339)), func(t *testing.T) {
				source := &countedFederationClock{Manual: clock.NewManual(epoch)}
				role := RoleSnapshot{ARN: "arn:aws:iam::123456789012:role/target", ID: "AROACLOCK", Name: "target", MaxSessionDuration: time.Hour}
				if captured {
					role.EvaluationTime = &epoch
				}
				provider := "arn:aws:iam::123456789012:oidc-provider/clock.example.test"
				role.TrustPolicy = fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"Federated":%q},"Action":["sts:AssumeRoleWithWebIdentity","sts:TagSession","sts:SetSourceIdentity"],"Condition":{"DateLessThan":{"aws:CurrentTime":%q}}}}`, provider, epoch.Add(time.Minute).Format(time.RFC3339))
				store := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: identity.NewMemoryRepository(), Clock: source.Manual})
				authority := federationClockAuthority{role: role, clock: source.Manual, store: store}
				s := NewWithDependencies(Dependencies{Credentials: store, Roles: authority, Federation: authority, Clock: source})
				ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012"})
				result, apiErr := issueFederatedRole(s, ctx, FederatedRoleRequest{Action: "sts:AssumeRoleWithWebIdentity", ProviderARN: provider, ProviderID: "AOIDC", ProviderVersion: "version", RoleARN: role.ARN, SessionName: "clock-session", Duration: time.Hour, NotAfter: epoch.Add(time.Minute), SourceIdentity: "clock-source", Tags: map[string]string{"team": "clock"}, PolicyARNs: stsapi.PolicyDescriptorListType{{Arn: ptr(stsapi.ArnType("arn:aws:iam::123456789012:policy/session"))}}, HasSessionPolicy: true}, func(result FederatedRoleResult) *FederatedRoleResult { return &result })
				if apiErr != nil {
					t.Fatal("clock advance during policy resolution split expiry/trust decision", apiErr)
				}
				if !result.Credential.Expiration.Equal(epoch.Add(time.Minute)) {
					t.Fatal("verified expiry cap ignored captured epoch")
				}
				wantReads := int32(1)
				if captured {
					wantReads = 0
				}
				if source.reads.Load() != wantReads {
					t.Fatalf("clock sampled %d times; want %d", source.reads.Load(), wantReads)
				}
			})
		}
	}
}

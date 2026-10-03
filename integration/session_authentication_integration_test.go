package stackd_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/storage"
	orgstore "stackd/storage/organizations"
)

type unavailableOrganizationStorage struct {
	orgstore.Storage
	unavailable atomic.Bool
	reads       atomic.Int32
}

func (s *unavailableOrganizationStorage) Load(ctx context.Context, partition string) (orgstore.PartitionRecord, uint64, error) {
	s.reads.Add(1)
	if s.unavailable.Load() {
		return orgstore.PartitionRecord{}, 0, errors.New("injected Organizations outage")
	}
	return s.Storage.Load(ctx, partition)
}

func TestSessionAuthenticationIsIndependentOfPermissionsAndOrganizations(t *testing.T) {
	backends := storage.NewMemory()
	organizations := &unavailableOrganizationStorage{Storage: backends.Organizations}
	backends.Organizations = organizations
	c := clockCloud(t, stackd.Config{Storage: backends})
	_, key, secret := c.user(t, "test", "authentication-only")
	putUserPolicy(t, c.iam("test", "test", ""), "authentication-only", `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`)
	organizations.unavailable.Store(true)
	reads := organizations.reads.Load()
	client := c.sts(key, secret, "")
	session, err := client.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal("authentication was coupled to permission evaluation:", err)
	}
	if organizations.reads.Load() != reads {
		t.Fatal("GetSessionToken read Organizations state")
	}
	if _, err := c.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatal("authentication did not produce usable credentials:", err)
	}
	federation, err := client.GetFederationToken(t.Context(), &sts.GetFederationTokenInput{Name: aws.String("requires-permissions")})
	assertAPIError(t, err, "InternalFailure")
	if federation != nil && federation.Credentials != nil {
		t.Fatal("permission-dependent issuance returned credentials during control-source failure")
	}
	if organizations.reads.Load() == reads {
		t.Fatal("permission-dependent issuance skipped Organizations controls")
	}
}

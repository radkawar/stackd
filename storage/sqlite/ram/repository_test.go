package ram_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	service "stackd/internal/services/ram"
	"stackd/storage/memory"
	domain "stackd/storage/ram"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/ram"
)

type owner struct{ resource service.ResourceIdentity }

func (o owner) ResolveResource(_ context.Context, arn string) (service.ResourceIdentity, error) {
	if arn != o.resource.ARN {
		return service.ResourceIdentity{}, service.ErrNotFound
	}
	return o.resource, nil
}
func ctx(account string) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", Region: "us-east-1", AccountID: account, PrincipalID: account, PrincipalARN: "arn:aws:iam::" + account + ":root"})
}
func command[O any](t *testing.T, s *service.Service, ctx context.Context, name string, input any) *O {
	t.Helper()
	model, _ := awscatalog.LookupService("ram")
	operation, _ := model.Operation(name)
	out, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: input})
	if rejected != nil {
		t.Fatalf("%s: %v", name, rejected)
	}
	v, ok := out.(*O)
	if !ok {
		t.Fatalf("%s response %T", name, out)
	}
	return v
}
func TestGrantStateAtomicityAndDeletionAcrossRestart(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var repo domain.Repository
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "ram.sqlite")
			open := func() {
				if db != nil {
					if e := db.Close(); e != nil {
						t.Fatal(e)
					}
				}
				var e error
				db, e = sqlite.Open(t.Context(), path)
				if e != nil {
					t.Fatal(e)
				}
				repo = backend.New(db)
			}
			if kind == "memory" {
				repo = domain.NewMemory(memory.NewDomain())
			} else {
				open()
				t.Cleanup(func() { _ = db.Close() })
			}
			at := clock.NewManual(time.Date(2033, 2, 3, 4, 5, 6, 0, time.UTC))
			resource := service.ResourceIdentity{ARN: "arn:aws:ssm:us-east-1:111111111111:parameter/retained", Partition: "aws", AccountID: "111111111111", Region: "us-east-1", ResourceType: "ssm:Parameter", SupportsIAMPrincipals: true}
			newService := func() *service.Service {
				return service.New(service.Config{Repository: repo, Clock: at, Resources: owner{resource}, ResourceTypes: []string{"ssm:Parameter"}})
			}
			s := newService()
			ownerCtx, recipient := ctx(resource.AccountID), ctx("222222222222")
			share := command[api.CreateResourceShareResponse](t, s, ownerCtx, "CreateResourceShare", &api.CreateResourceShareRequest{Name: new(api.String("retained")), ResourceArns: api.ResourceArnList{api.String(resource.ARN)}, Principals: api.PrincipalArnOrIdList{"222222222222"}, Tags: api.TagList{{Key: new(api.TagKey("team")), Value: new(api.TagValue("storage"))}}})
			invitations := command[api.GetResourceShareInvitationsResponse](t, s, recipient, "GetResourceShareInvitations", &api.GetResourceShareInvitationsRequest{})
			command[api.AcceptResourceShareInvitationResponse](t, s, recipient, "AcceptResourceShareInvitation", &api.AcceptResourceShareInvitationRequest{ResourceShareInvitationArn: invitations.ResourceShareInvitations[0].ResourceShareInvitationArn})
			grant := func(want bool) {
				t.Helper()
				allowed, e := s.ResourcePermission(recipient, service.PermissionQuery{ResourceARN: resource.ARN, AccountID: "222222222222", Action: "ssm:GetParameter"})
				if e != nil || allowed != want {
					t.Fatalf("grant=%v want=%v error=%v", allowed, want, e)
				}
			}
			grant(true)
			rejected := errors.New("owner deletion rejected")
			e := repo.Update(ownerCtx, func(tx domain.Transaction) error {
				if e := s.ResourceDeleted(tx.Context(), resource.ARN); e != nil {
					return e
				}
				return rejected
			})
			if !errors.Is(e, rejected) {
				t.Fatal(e)
			}
			if kind == "sqlite" {
				open()
				s = newService()
			}
			grant(true)
			if e = repo.View(ownerCtx, func(r domain.Reader) error {
				v, e := r.Share(string(*share.ResourceShare.ResourceShareArn))
				if e != nil {
					return e
				}
				v.Tags["team"] = "detached"
				v.Principals[0].Status = "DISASSOCIATED"
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			listed := command[api.GetResourceSharesResponse](t, s, ownerCtx, "GetResourceShares", &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerSELF), TagFilters: api.TagFilters{{TagKey: new(api.TagKey("team")), TagValues: api.TagValueList{"storage"}}}})
			if len(listed.ResourceShares) != 1 || *listed.ResourceShares[0].ResourceShareArn != *share.ResourceShare.ResourceShareArn {
				t.Fatalf("detached mutation altered stored tags: %#v", listed)
			}
			grant(true)
			if e = s.ResourceDeleted(ownerCtx, resource.ARN); e != nil {
				t.Fatal(e)
			}
			if kind == "sqlite" {
				open()
				s = newService()
			}
			grant(false)
			// The resource owner resolves a replacement at the same ARN. Only an explicit
			// new association can regrant it; restart never revives the removed grant.
			command[api.AssociateResourceShareResponse](t, s, ownerCtx, "AssociateResourceShare", &api.AssociateResourceShareRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, ResourceArns: api.ResourceArnList{api.String(resource.ARN)}})
			grant(true)
		})
	}
}

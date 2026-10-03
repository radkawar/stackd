package autoscaling_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	service "stackd/internal/services/autoscaling"
	iamservice "stackd/internal/services/iam"
	domain "stackd/storage/autoscaling"
	iamstore "stackd/storage/iam"
	"stackd/storage/sqlite"
	asgdb "stackd/storage/sqlite/autoscaling"
	iamdb "stackd/storage/sqlite/iam"
)

// A single SQLite connection makes loss of the owning read transaction
// deterministic: IAM cannot open a second transaction while ASG admission holds
// the only connection. Both services use their production typed repositories and
// the real current-policy evaluator; no transaction-context mock is involved.
func TestPreparedAutoScalingAdmissionBorrowsIAMReadTransaction(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "prepared-admission.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	groups := asgdb.New(db)
	identities := iamdb.New(db)
	group := fixtureGroup()
	if err = groups.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutGroup(group) }); err != nil {
		t.Fatal(err)
	}
	actor := iamstore.User{Path: "/", UserName: "refresh-operator", UserId: "AIDAREFRESHOPERATOR", Arn: "arn:aws:iam::111111111111:user/refresh-operator", CreateDate: group.ReconcileAt}
	iamScope := iamstore.Scope{Partition: group.Key.Partition, AccountID: group.Key.AccountID}
	source := clock.NewManual(group.ReconcileAt)
	iam := iamservice.NewWithRepository(nil, identities)
	asg := service.New(service.Config{Repository: groups, Clock: source, Authorizer: authorization.NewWithClock(iam, nil, source)})
	model, _ := awscatalog.LookupService("autoscaling")
	t.Cleanup(func() { asg.JobDriver().Close() })
	for _, effect := range []string{"Allow", "Deny"} {
		actor.IdentityPolicies = iamstore.IdentityPolicies{Inline: map[string]string{"current": `{"Version":"2012-10-17","Statement":[{"Effect":"` + effect + `","Action":"autoscaling:*","Resource":"*"}]}`}}
		if err = identities.Update(t.Context(), func(tx iamstore.WriteTx) error { return tx.PutUser(iamScope, actor) }); err != nil {
			t.Fatal(err)
		}
		for _, action := range []string{"StartInstanceRefresh", "UpdateAutoScalingGroup"} {
			t.Run(effect+"/"+action, func(t *testing.T) {
				var input any
				if action == "StartInstanceRefresh" {
					input = &api.StartInstanceRefreshInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, Strategy: new(api.RefreshStrategy("ReplaceRootVolume"))}
				} else {
					input = &api.UpdateAutoScalingGroupInput{AutoScalingGroupName: new(api.XmlStringMaxLen255("missing-group"))}
				}
				operation, ok := model.Operation(action)
				if !ok {
					t.Fatalf("missing operation %s", action)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: group.Key.Partition, AccountID: group.Key.AccountID, Region: group.Key.Region, PrincipalARN: actor.Arn, PrincipalID: actor.UserId})
				_, rejected := asg.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: input})
				want := "ValidationError"
				if effect == "Deny" {
					want = "AccessDenied"
				}
				if rejected == nil || rejected.Code != want {
					t.Fatalf("prepared admission did not honor current IAM policy within its read transaction: got %v want %s", rejected, want)
				}
				if ctx.Err() != nil {
					t.Fatalf("admission exhausted its deadline while borrowing IAM state: %v", ctx.Err())
				}
			})
		}
	}
}

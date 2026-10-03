package autoscaling_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/autoscaling"
	iamservice "stackd/internal/services/iam"
	domain "stackd/storage/autoscaling"
	iamstore "stackd/storage/iam"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/autoscaling"
	iamdb "stackd/storage/sqlite/iam"
	journaldb "stackd/storage/sqlite/journal"
)

func managedGroup() domain.GroupRecord {
	key := domain.GroupKey{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "managed-workers"}
	return domain.GroupRecord{
		Key: key, ID: "first", ScaleUpVersion: 3,
		Data: api.AutoScalingGroup{
			AutoScalingGroupName: new(api.XmlStringMaxLen255(key.Name)), AutoScalingGroupARN: new(api.ResourceName(key.ARN("first"))),
			MinSize: new(api.AutoScalingGroupMinSize(2)), MaxSize: new(api.AutoScalingGroupMaxSize(8)), DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(4)),
			LaunchTemplate:  &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-workers")), Version: new(api.XmlStringMaxLen255("1"))},
			HealthCheckType: new(api.XmlStringMaxLen32("EC2")),
		},
	}
}

func managedContext(ctx context.Context, group domain.GroupRecord) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: group.Key.Partition, AccountID: group.Key.AccountID, Region: group.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: group.Key.AccountID})
}

func requireScalingCode(t *testing.T, err error, code string) {
	t.Helper()
	var rejected *awswire.Error
	if !errors.As(err, &rejected) || rejected.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestManagedScalingCounterSurvivesReopenAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-scaling.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	group := managedGroup()
	ctx := managedContext(t.Context(), group)
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
	if err := repo.Update(ctx, func(tx domain.Transaction) error { return tx.PutGroup(group) }); err != nil {
		t.Fatal(err)
	}
	s := service.New(service.Config{Repository: repo, Clock: source, Recorder: apievents.New(journaldb.New(db))})
	// Exercise command commits without unrelated background capacity execution.
	s.JobDriver().Close()
	model, _ := awscatalog.LookupService("autoscaling")
	operation, _ := model.Operation("SetDesiredCapacity")
	increase := &api.SetDesiredCapacityInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(5))}
	if _, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: increase}); rejected != nil {
		t.Fatal(rejected)
	}
	s.JobDriver().Close()
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo = backend.New(db)
	s = service.New(service.Config{Repository: repo, Clock: source, Recorder: apievents.New(journaldb.New(db))})
	s.JobDriver().Close()
	arn := group.Key.ARN(group.ID)
	state, err := s.ManagedScaling(ctx, group.Key.Name, arn)
	if err != nil {
		t.Fatal(err)
	}
	if state.ScaleUpVersion != group.ScaleUpVersion+1 || *state.Group.DesiredCapacity != 5 {
		t.Fatalf("reopen lost atomic capacity ownership: %+v", state)
	}
	if err := s.UpdateManagedScaling(ctx, group.Key.Name, arn, group.ScaleUpVersion, 3, 7); !errors.Is(err, service.ErrManagedScaleUp) {
		t.Fatalf("reopened guard accepted stale scale-down: %v", err)
	}
	unchanged, err := s.ManagedScaling(ctx, group.Key.Name, arn)
	if err != nil || !reflect.DeepEqual(unchanged, state) {
		t.Fatalf("rejected stale reduction changed live capacity: %+v %v", unchanged, err)
	}
	if err := s.UpdateManagedScaling(ctx, group.Key.Name, arn, state.ScaleUpVersion, 4, 7); err != nil {
		t.Fatal(err)
	}
	completed, err := s.ManagedScaling(ctx, group.Key.Name, arn)
	if err != nil {
		t.Fatal(err)
	}
	if *completed.Group.MinSize != 2 || *completed.Group.MaxSize != 7 || *completed.Group.DesiredCapacity != 4 || completed.ScaleUpVersion != state.ScaleUpVersion {
		t.Fatalf("managed decrease changed minimum or scale-up ownership: %+v", completed)
	}
	abort := errors.New("abort enclosing transaction")
	err = repo.Update(ctx, func(tx domain.Transaction) error {
		if _, rejected := s.ExecuteCommand(tx.Context(), awsapi.DecodedRequest{Operation: operation, Input: increase}); rejected != nil {
			return rejected
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatalf("rollback result: %v", err)
	}
	after, err := s.ManagedScaling(ctx, group.Key.Name, arn)
	if err != nil || !reflect.DeepEqual(after, completed) {
		t.Fatalf("rolled-back increase escaped capacity transaction: %+v %v", after, err)
	}
	calls, err := journaldb.New(db).Read(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || calls[0].APICallCompleted.EventName != "SetDesiredCapacity" || calls[0].APICallCompleted.ErrorCode != "" || calls[1].APICallCompleted.EventName != "UpdateAutoScalingGroup" || calls[1].APICallCompleted.ErrorCode != "ResourceContentionFault" || calls[2].APICallCompleted.EventName != "UpdateAutoScalingGroup" || calls[2].APICallCompleted.ErrorCode != "" {
		t.Fatalf("recovery/rollback API outcomes diverged from committed capacity: %+v", calls)
	}
}

func TestManagedScalingUsesCurrentIAMAuthority(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "managed-authority.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	groups := backend.New(db)
	identities := iamdb.New(db)
	group := managedGroup()
	if err := groups.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutGroup(group) }); err != nil {
		t.Fatal(err)
	}
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
	actor := iamstore.User{Path: "/", UserName: "managed-operator", UserId: "AIDAMANAGEDOPERATOR", Arn: "arn:aws:iam::111111111111:user/managed-operator", CreateDate: source.Now()}
	iamScope := iamstore.Scope{Partition: group.Key.Partition, AccountID: group.Key.AccountID}
	iam := iamservice.NewWithRepository(nil, identities)
	s := service.New(service.Config{Repository: groups, Clock: source, Authorizer: authorization.NewWithClock(iam, nil, source)})
	s.JobDriver().Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: group.Key.Partition, AccountID: group.Key.AccountID, Region: group.Key.Region, PrincipalARN: actor.Arn, PrincipalID: actor.UserId})
	for _, effect := range []string{"Allow", "Deny"} {
		actor.IdentityPolicies = iamstore.IdentityPolicies{Inline: map[string]string{"current": `{"Version":"2012-10-17","Statement":[{"Effect":"` + effect + `","Action":"autoscaling:*","Resource":"*"}]}`}}
		if err := identities.Update(t.Context(), func(tx iamstore.WriteTx) error { return tx.PutUser(iamScope, actor) }); err != nil {
			t.Fatal(err)
		}
		_, err := s.ManagedScaling(ctx, group.Key.Name, group.Key.ARN(group.ID))
		if effect == "Deny" {
			requireScalingCode(t, err, "AccessDenied")
		} else if err != nil {
			t.Fatal(err)
		}
		err = s.UpdateManagedScaling(ctx, group.Key.Name, group.Key.ARN(group.ID), group.ScaleUpVersion, 3, 7)
		if effect == "Deny" {
			requireScalingCode(t, err, "AccessDenied")
			if errors.Is(err, service.ErrManagedScaleUp) {
				t.Fatal("revoked caller was mistaken for a capacity owner")
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if err := groups.View(t.Context(), func(tx domain.Reader) error {
		current, err := tx.Group(group.Key)
		if err == nil && (*current.Data.MinSize != 2 || *current.Data.MaxSize != 7 || *current.Data.DesiredCapacity != 3 || current.ScaleUpVersion != group.ScaleUpVersion) {
			t.Fatalf("revoked replay changed capacity or ownership: %+v", current)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

package identitycenter_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	account "stackd/storage/account"
	domain "stackd/storage/identitycenter"
	"stackd/storage/sqlite"
	sqlaccount "stackd/storage/sqlite/account"
	backend "stackd/storage/sqlite/identitycenter"
)

func database(t *testing.T) (func() *sql.DB, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.sqlite")
	var db *sql.DB
	open := func() *sql.DB {
		t.Helper()
		if db != nil {
			require(t, db.Close())
		}
		var err error
		db, err = sqlite.Open(t.Context(), path)
		require(t, err)
		return db
	}
	open()
	t.Cleanup(func() { require(t, db.Close()) })
	return open, db
}

func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func equal[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestPermissionRelationshipsAndReplacementSurviveRestart(t *testing.T) {
	reopen, db := database(t)
	repo := backend.New(db)
	ctx := t.Context()
	at := time.Date(2032, 4, 5, 6, 7, 8, 123456789, time.UTC)
	instance := domain.Instance{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, ARN: "arn:aws:sso:::instance/ssoins-0000000000000001", StoreID: "d-0000000001", Name: "workforce", ClientToken: "create-token", Created: at, Tags: map[string]string{"environment": "test", "owner": "identity"}}
	permission := domain.PermissionSet{InstanceARN: instance.ARN, ARN: "arn:aws:sso:::permissionSet/ssoins-0000000000000001/ps-0000000000000001", Name: "ReadOnly", Description: "read account resources", RelayState: "https://console.aws.amazon.com/", InlinePolicy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`, Duration: 2 * time.Hour, Created: at, ManagedPolicies: []string{"arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/SecurityAudit"}, CustomerManagedPolicies: []domain.PolicyReference{{Name: "TeamRead", Path: "/teams/"}, {Name: "AuditRead", Path: "/"}}, BoundaryARN: "arn:aws:iam::aws:policy/ReadOnlyAccess", Tags: map[string]string{"team": "platform"}}
	assignment := domain.Assignment{InstanceARN: instance.ARN, PermissionSetARN: permission.ARN, AccountID: "222222222222", PrincipalType: "USER", PrincipalID: "user-1"}
	group := assignment
	group.PrincipalType, group.PrincipalID = "GROUP", "group-1"
	provision := domain.Provisioning{InstanceARN: instance.ARN, PermissionSetARN: permission.ARN, AccountID: assignment.AccountID, RoleARN: "arn:aws:iam::222222222222:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnly_0123456789abcdef", RoleID: "AROACTUALIDENTITY", RoleName: "AWSReservedSSO_ReadOnly_0123456789abcdef"}
	operation := domain.Operation{InstanceARN: instance.ARN, ID: "operation-1", Kind: "CREATE", PermissionSetARN: permission.ARN, AccountID: assignment.AccountID, PrincipalType: assignment.PrincipalType, PrincipalID: assignment.PrincipalID, Created: at}
	require(t, repo.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutInstance(instance); err != nil {
			return err
		}
		if err := tx.PutPermissionSet(permission); err != nil {
			return err
		}
		if err := tx.PutAssignment(assignment); err != nil {
			return err
		}
		if err := tx.PutAssignment(group); err != nil {
			return err
		}
		if err := tx.PutAssignment(assignment); err != nil {
			return err
		}
		if err := tx.PutProvisioning(provision); err != nil {
			return err
		}
		return tx.PutOperation(operation)
	}))
	repo = backend.New(reopen())
	require(t, repo.View(ctx, func(r domain.Reader) error {
		got, err := r.Instance(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, got, instance)
		instances, err := r.Instances(instance.Scope)
		if err != nil {
			return err
		}
		equal(t, instances, []domain.Instance{instance})
		other := instance.Scope
		other.AccountID = "999999999999"
		instances, err = r.Instances(other)
		if err != nil {
			return err
		}
		equal(t, instances, []domain.Instance{})
		permissions, err := r.PermissionSets(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, permissions, []domain.PermissionSet{permission})
		assignments, err := r.Assignments(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, assignments, []domain.Assignment{group, assignment})
		provisions, err := r.Provisionings(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, provisions, []domain.Provisioning{provision})
		operations, err := r.Operations(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, operations, []domain.Operation{operation})
		gotOperation, err := r.Operation(operation.ID)
		if err != nil {
			return err
		}
		equal(t, gotOperation, operation)
		got.Tags["owner"] = "mutated"
		permissions[0].Tags["team"] = "mutated"
		permissions[0].ManagedPolicies[0] = "mutated"
		permissions[0].CustomerManagedPolicies[0].Path = "/mutated/"
		return nil
	}))
	require(t, repo.View(ctx, func(r domain.Reader) error {
		got, err := r.PermissionSet(permission.ARN)
		if err != nil {
			return err
		}
		equal(t, got, permission)
		gotInstance, err := r.Instance(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, gotInstance, instance)
		return nil
	}))
	permission.ManagedPolicies = []string{}
	permission.CustomerManagedPolicies = []domain.PolicyReference{{Name: "Replacement", Path: "/new/"}}
	permission.Tags = map[string]string{}
	permission.BoundaryARN = ""
	permission.Boundary = domain.PolicyReference{Name: "Boundary", Path: "/limits/"}
	instance.Tags = map[string]string{"owner": "new-owner"}
	require(t, repo.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutInstance(instance); err != nil {
			return err
		}
		if err := tx.PutPermissionSet(permission); err != nil {
			return err
		}
		return tx.DeleteAssignment(group)
	}))
	repo = backend.New(reopen())
	require(t, repo.View(ctx, func(r domain.Reader) error {
		got, err := r.PermissionSet(permission.ARN)
		if err != nil {
			return err
		}
		equal(t, got, permission)
		gotInstance, err := r.Instance(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, gotInstance, instance)
		assignments, err := r.Assignments(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, assignments, []domain.Assignment{assignment})
		provisions, err := r.Provisionings(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, provisions, []domain.Provisioning{provision})
		return nil
	}))
	require(t, repo.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.DeleteAssignment(assignment); err != nil {
			return err
		}
		if err := tx.DeleteProvisioning(provision); err != nil {
			return err
		}
		if err := tx.DeletePermissionSet(permission.ARN); err != nil {
			return err
		}
		return tx.DeleteInstance(instance.ARN)
	}))
	repo = backend.New(reopen())
	require(t, repo.View(ctx, func(r domain.Reader) error {
		_, err := r.PermissionSet(permission.ARN)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deleted permission: %v", err)
		}
		_, err = r.Instance(instance.ARN)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deleted instance: %v", err)
		}
		assignments, err := r.Assignments(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, assignments, []domain.Assignment{})
		provisions, err := r.Provisionings(instance.ARN)
		if err != nil {
			return err
		}
		equal(t, provisions, []domain.Provisioning{})
		retained, err := r.Operation(operation.ID)
		if err != nil {
			return err
		}
		equal(t, retained, operation)
		return nil
	}))
}

func TestDeviceSessionFamiliesAndSharedRollbackAcrossRestart(t *testing.T) {
	reopen, db := database(t)
	repo := backend.New(db)
	accounts := sqlaccount.New(db)
	ctx := t.Context()
	at := time.Date(2032, 4, 5, 6, 7, 8, 123456789, time.UTC)
	client := domain.Client{ID: "client-1", SecretHash: "sha256-client", Name: "aws-cli", Region: "us-east-1", Partition: "aws", Created: at, Expires: at.Add(90 * 24 * time.Hour), Scopes: []string{"sso:account:access"}, GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}}
	device := domain.Device{CodeHash: "sha256-device", UserCode: "ABCD-EFGH", ClientID: client.ID, InstanceARN: "instance-1", CSRF: "csrf-nonce", State: "pending", Created: at, Expires: at.Add(10 * time.Minute), Interval: 5}
	session := domain.Session{ID: "session-1", FamilyID: "family-1", ClientID: client.ID, InstanceARN: device.InstanceARN, UserID: "user-1", AccessHash: "sha256-access-1", RefreshHash: "sha256-refresh", Created: at, AccessExpires: at.Add(time.Hour), RefreshExpires: at.Add(8 * time.Hour)}
	otherSession := session
	otherSession.ID, otherSession.FamilyID, otherSession.AccessHash, otherSession.RefreshHash = "session-other", "family-other", "sha256-access-other", ""
	require(t, repo.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutClient(client); err != nil {
			return err
		}
		return tx.PutDevice(device)
	}))
	repo = backend.New(reopen())
	require(t, repo.View(ctx, func(r domain.Reader) error {
		got, err := r.DeviceByUserCode(device.UserCode)
		if err != nil {
			return err
		}
		equal(t, got, device)
		gotClient, err := r.Client(client.ID)
		if err != nil {
			return err
		}
		equal(t, gotClient, client)
		gotClient.Scopes[0], gotClient.GrantTypes[0] = "mutated", "mutated"
		return nil
	}))
	device.State, device.UserID, device.LastPoll, device.Interval = "consumed", session.UserID, at.Add(15*time.Second), 10
	require(t, repo.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutDevice(device); err != nil {
			return err
		}
		if err := tx.PutSession(otherSession); err != nil {
			return err
		}
		return tx.PutSession(session)
	}))
	db = reopen()
	repo, accounts = backend.New(db), sqlaccount.New(db)
	contactScope := account.Scope{Partition: "aws", AccountID: "111111111111"}
	rejected := errors.New("reject cross-service admission")
	rotated := session
	rotated.ID, rotated.AccessHash, rotated.Created = "session-2", "sha256-access-2", at.Add(30*time.Minute)
	rotated.AccessExpires = rotated.Created.Add(time.Hour)
	refresh := func(tx domain.Transaction) error {
		old, err := tx.SessionByRefresh(session.RefreshHash)
		if err != nil {
			return err
		}
		old.RefreshHash = ""
		if err := tx.PutSession(old); err != nil {
			return err
		}
		return tx.PutSession(rotated)
	}
	err := repo.Update(ctx, func(tx domain.Transaction) error {
		if err := refresh(tx); err != nil {
			return err
		}
		if err := accounts.Update(tx.Context(), func(a account.Writer) error {
			return a.PutContact(contactScope, account.ContactInformation{FullName: "must roll back"})
		}); err != nil {
			return err
		}
		return rejected
	})
	if !errors.Is(err, rejected) {
		t.Fatalf("rollback: %v", err)
	}
	db = reopen()
	repo, accounts = backend.New(db), sqlaccount.New(db)
	require(t, repo.View(ctx, func(r domain.Reader) error {
		got, err := r.Device(device.CodeHash)
		if err != nil {
			return err
		}
		equal(t, got, device)
		gotSession, err := r.SessionByRefresh(session.RefreshHash)
		if err != nil {
			return err
		}
		equal(t, gotSession, session)
		_, err = r.SessionByAccess(rotated.AccessHash)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("rolled-back token present: %v", err)
		}
		gotClient, err := r.Client(client.ID)
		if err != nil {
			return err
		}
		equal(t, gotClient, client)
		return accounts.View(r.Context(), func(a account.Reader) error {
			_, found, err := a.Contact(contactScope)
			if found {
				t.Fatal("cross-service contact committed")
			}
			return err
		})
	}))
	// A handled attempt rolls back both repositories, but leaves its parent able
	// to rotate the family and retain an independent account write.
	require(t, repo.Update(ctx, func(tx domain.Transaction) error {
		err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
			if err := refresh(child); err != nil {
				return err
			}
			if err := accounts.Update(child.Context(), func(a account.Writer) error {
				return a.PutContact(contactScope, account.ContactInformation{FullName: "attempt must roll back"})
			}); err != nil {
				return err
			}
			return rejected
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("attempt rejection: %v", err)
		}
		unchanged, err := tx.SessionByRefresh(session.RefreshHash)
		if err != nil {
			return err
		}
		equal(t, unchanged, session)
		if err := accounts.View(tx.Context(), func(a account.Reader) error {
			_, found, err := a.Contact(contactScope)
			if found {
				t.Fatal("attempt leaked account state")
			}
			return err
		}); err != nil {
			return err
		}
		if err := refresh(tx); err != nil {
			return err
		}
		return accounts.Update(tx.Context(), func(a account.Writer) error {
			return a.PutContact(contactScope, account.ContactInformation{FullName: "committed"})
		})
	}))
	db = reopen()
	repo, accounts = backend.New(db), sqlaccount.New(db)
	session.RefreshHash = ""
	require(t, repo.View(ctx, func(r domain.Reader) error {
		prior, err := r.SessionByAccess(session.AccessHash)
		if err != nil {
			return err
		}
		equal(t, prior, session)
		current, err := r.SessionByRefresh(rotated.RefreshHash)
		if err != nil {
			return err
		}
		equal(t, current, rotated)
		family, err := r.Sessions(session.FamilyID)
		if err != nil {
			return err
		}
		equal(t, family, []domain.Session{session, rotated})
		return accounts.View(r.Context(), func(a account.Reader) error {
			got, found, err := a.Contact(contactScope)
			if !found || got.FullName != "committed" {
				t.Fatalf("committed contact: %#v %v", got, found)
			}
			return err
		})
	}))
	require(t, repo.Update(ctx, func(tx domain.Transaction) error {
		family, err := tx.Sessions(session.FamilyID)
		if err != nil {
			return err
		}
		for _, member := range family {
			member.Revoked = true
			if err := tx.PutSession(member); err != nil {
				return err
			}
		}
		return nil
	}))
	repo = backend.New(reopen())
	session.Revoked, rotated.Revoked = true, true
	require(t, repo.View(ctx, func(r domain.Reader) error {
		family, err := r.Sessions(session.FamilyID)
		if err != nil {
			return err
		}
		equal(t, family, []domain.Session{session, rotated})
		other, err := r.SessionByAccess(otherSession.AccessHash)
		if err != nil {
			return err
		}
		equal(t, other, otherSession)
		return nil
	}))
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := repo.Update(canceled, func(tx domain.Transaction) error { return tx.PutDevice(domain.Device{CodeHash: "canceled"}) }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled update: %v", err)
	}
}

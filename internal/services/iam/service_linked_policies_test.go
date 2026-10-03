package iam

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"stackd/internal/awsctx"
	"stackd/journal"
)

type rejectingLinkedPolicyEvents struct{ err error }

func (r rejectingLinkedPolicyEvents) Record(context.Context, journal.Envelope, journal.APICallCompleted) error {
	return r.err
}

func TestServiceLinkedOwnedPolicyIsolationAndRollback(t *testing.T) {
	repository := NewMemoryRepository(nil)
	scope, role, _ := seedLinkedJob(t, repository, serviceLinkedNotStarted)
	s := NewWithRepository(nil, repository)
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, PrincipalARN: "arn:aws:iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID})
	owned := awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: role.ServiceLinkedService, Type: "AWSService"})
	name := "AWSServiceOwned-" + role.ServiceLinkedService + "-resource"
	const policy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::owned-bucket/list.txt"}]}`
	readPolicy := func() string {
		t.Helper()
		var result string
		if err := repository.View(ctx, func(tx ReadTx) error {
			current, err := tx.Role(scope, role.RoleName)
			result = current.Inline[name]
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if err := s.PutServiceLinkedRolePolicy(owned, scope, role.ServiceLinkedService, role.RoleName, name, policy); err != nil {
		t.Fatal(err)
	}
	if got := readPolicy(); got != policy {
		t.Fatalf("persisted policy = %q", got)
	}
	for _, action := range []string{"PutRolePolicy", "DeleteRolePolicy"} {
		form := url.Values{"Action": {action}, "Version": {"2010-05-08"}, "RoleName": {role.RoleName}, "PolicyName": {name}, "PolicyDocument": {policy}}
		req := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode())).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		s.ServeHTTP(response, req)
		if !strings.Contains(response.Body.String(), "UnmodifiableEntity") {
			t.Fatalf("ordinary %s = %d %s", action, response.Code, response.Body.String())
		}
	}
	if got := readPolicy(); got != policy {
		t.Fatal("ordinary APIs modified protected role")
	}
	wrong := awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "lambda.amazonaws.com", Type: "AWSService"})
	if err := s.DeleteServiceLinkedRolePolicy(wrong, scope, role.ServiceLinkedService, role.RoleName, name); err == nil {
		t.Fatal("wrong invoking service deleted policy")
	}
	if err := s.PutServiceLinkedRolePolicy(wrong, scope, "lambda.amazonaws.com", role.RoleName, "AWSServiceOwned-lambda.amazonaws.com-other", policy); err == nil {
		t.Fatal("wrong template adopted protected role")
	}
	if err := s.PutServiceLinkedRolePolicy(owned, scope, role.ServiceLinkedService, role.RoleName, "customer-policy", policy); err == nil {
		t.Fatal("trusted command adopted unreserved policy")
	}
	if err := s.PutServiceLinkedRolePolicy(owned, scope, role.ServiceLinkedService, role.RoleName, name, "not-json"); err == nil {
		t.Fatal("invalid policy accepted")
	}
	rollback := errors.New("enclosing resource transaction rejected")
	err := repository.Update(owned, func(tx WriteTx) error {
		borrowed := context.WithValue(tx.Context(), transactionKey{}, serviceTransaction{service: s, tx: tx, currentTime: time.Now()})
		if err := s.DeleteServiceLinkedRolePolicy(borrowed, scope, role.ServiceLinkedService, role.RoleName, name); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) || readPolicy() != policy {
		t.Fatalf("shared rollback = %v", err)
	}
	s.apiCallEvents = rejectingLinkedPolicyEvents{rollback}
	if err := s.DeleteServiceLinkedRolePolicy(owned, scope, role.ServiceLinkedService, role.RoleName, name); !errors.Is(err, rollback) {
		t.Fatalf("audit rejection = %v", err)
	}
	if readPolicy() != policy {
		t.Fatal("journal failure committed policy deletion")
	}
	s.apiCallEvents = nil
	if err := s.DeleteServiceLinkedRolePolicy(owned, scope, role.ServiceLinkedService, role.RoleName, name); err != nil {
		t.Fatal(err)
	}
	if readPolicy() != "" {
		t.Fatal("owned deletion retained policy")
	}
}

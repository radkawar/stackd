package iam

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

func autoScalingLinkedTemplate(t *testing.T, s *Service) ServiceLinkedRoleTemplate {
	t.Helper()
	template, err := s.serviceLinkedTemplate("aws", "autoscaling.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func seedLinkedJob(t *testing.T, repository Repository, status string) (Scope, Role, ServiceLinkedRoleDeletion) {
	t.Helper()
	scope := Scope{Partition: "aws", AccountID: "123456789012"}
	r := Role{Path: "/aws-service-role/autoscaling.amazonaws.com/", RoleName: "AWSServiceRoleForAutoScaling", RoleId: "AROASTABLE", Arn: "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", ServiceLinkedService: "autoscaling.amazonaws.com", IdentityPolicies: newIdentityPolicies()}
	job := ServiceLinkedRoleDeletion{ID: "task/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling/00000000-0000-4000-8000-000000000000", RoleID: r.RoleId, RoleARN: r.Arn, RoleName: r.RoleName, ServiceName: r.ServiceLinkedService, Status: status, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := repository.Update(context.Background(), func(tx WriteTx) error {
		if err := tx.PutRole(scope, r); err != nil {
			return err
		}
		return tx.PutServiceLinkedRoleDeletion(scope, job)
	}); err != nil {
		t.Fatal(err)
	}
	return scope, r, job
}

func readLinkedJob(t *testing.T, repository Repository, scope Scope, id string) ServiceLinkedRoleDeletion {
	t.Helper()
	var job ServiceLinkedRoleDeletion
	if err := repository.View(context.Background(), func(tx ReadTx) error { var err error; job, err = tx.ServiceLinkedRoleDeletion(scope, id); return err }); err != nil {
		t.Fatal(err)
	}
	return job
}

func waitPersistedLinkedStatus(t *testing.T, repository Repository, scope Scope, id, status string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if job := readLinkedJob(t, repository, scope, id); job.Status == status {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("job was not recovered: %+v", readLinkedJob(t, repository, scope, id))
}

func TestServiceLinkedWorkerRecoversWithoutStatusReads(t *testing.T) {
	for _, status := range []string{serviceLinkedNotStarted, serviceLinkedInProgress} {
		t.Run(status, func(t *testing.T) {
			repository := NewMemoryRepository(nil)
			scope, r, job := seedLinkedJob(t, repository, status)
			s := NewWithRepository(nil, repository)
			defer s.Close()
			s.StartWorkers()
			waitPersistedLinkedStatus(t, repository, scope, job.ID, serviceLinkedSucceeded)
			if err := repository.View(context.Background(), func(tx ReadTx) error { _, err := tx.Role(scope, r.RoleName); return err }); !errors.Is(err, ErrRecordNotFound) {
				t.Fatalf("worker did not remove role: %v", err)
			}
		})
	}
}

type cancelLinkedUsage struct {
	entered chan struct{}
	once    sync.Once
}

func (u *cancelLinkedUsage) WithServiceLinkedRoleUsage(ctx context.Context, _ ServiceLinkedRoleReference, _ func(context.Context, []ServiceLinkedRoleUsage) error) error {
	u.once.Do(func() { close(u.entered) })
	<-ctx.Done()
	return ctx.Err()
}

func TestServiceLinkedWorkerShutdownRetainsRecoverableJob(t *testing.T) {
	repository := NewMemoryRepository(nil)
	scope, _, job := seedLinkedJob(t, repository, serviceLinkedNotStarted)
	s := NewWithRepository(nil, repository)
	u := &cancelLinkedUsage{entered: make(chan struct{})}
	if err := s.RegisterServiceLinkedRole(autoScalingLinkedTemplate(t, s), u); err != nil {
		t.Fatal(err)
	}
	s.StartWorkers()
	select {
	case <-u.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not acquire usage boundary")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readLinkedJob(t, repository, scope, job.ID); got.Status != serviceLinkedInProgress {
		t.Fatalf("shutdown converted recoverable work into %s", got.Status)
	}
	next := NewWithRepository(nil, repository)
	defer next.Close()
	next.StartWorkers()
	waitPersistedLinkedStatus(t, repository, scope, job.ID, serviceLinkedSucceeded)
}

func TestServiceLinkedWorkerRejectsRecreatedRole(t *testing.T) {
	repository := NewMemoryRepository(nil)
	scope, r, job := seedLinkedJob(t, repository, serviceLinkedInProgress)
	r.RoleId = "AROARECREATED"
	if err := repository.Update(context.Background(), func(tx WriteTx) error { return tx.PutRole(scope, r) }); err != nil {
		t.Fatal(err)
	}
	s := NewWithRepository(nil, repository)
	defer s.Close()
	if err := s.processServiceLinkedRoleDeletion(context.Background(), scope, job.ID); err != nil {
		t.Fatal(err)
	}
	if got := readLinkedJob(t, repository, scope, job.ID); got.Status != serviceLinkedFailed {
		t.Fatalf("replacement role accepted by old task: %+v", got)
	}
	if err := repository.View(context.Background(), func(tx ReadTx) error {
		got, err := tx.Role(scope, r.RoleName)
		if got.RoleId != r.RoleId {
			t.Errorf("replacement role removed: %+v", got)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceLinkedWorkerRejectsActiveSessions(t *testing.T) {
	for _, active := range []bool{true, false} {
		t.Run(map[bool]string{true: "active", false: "expired"}[active], func(t *testing.T) {
			repository := NewMemoryRepository(nil)
			scope, r, job := seedLinkedJob(t, repository, serviceLinkedNotStarted)
			expires := time.Now().Add(-time.Hour)
			if active {
				expires = time.Now().Add(time.Hour)
			}
			credential := identity.Record{Status: identity.Active, Credential: identity.Credential{AccessKeyID: "ASIATEST", AccountID: scope.AccountID, PrincipalID: r.RoleId + ":session", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/" + r.RoleName + "/session", IssuerID: r.RoleId, IssuerARN: r.Arn, SessionToken: "token", Expiration: expires}}
			if err := repository.Update(context.Background(), func(tx WriteTx) error { return tx.PutCredential(credential) }); err != nil {
				t.Fatal(err)
			}
			s := NewWithRepository(nil, repository)
			defer s.Close()
			if err := s.processServiceLinkedRoleDeletion(context.Background(), scope, job.ID); err != nil {
				t.Fatal(err)
			}
			got := readLinkedJob(t, repository, scope, job.ID)
			if active {
				if got.Status != serviceLinkedFailed || !strings.Contains(got.FailureReason, "active sessions") {
					t.Fatalf("active role session ignored: %+v", got)
				}
			} else if got.Status != serviceLinkedSucceeded {
				t.Fatalf("expired role session blocks deletion: %+v", got)
			}
		})
	}
}

type unavailableLinkedUsage struct{ skipCallback bool }

func (u unavailableLinkedUsage) WithServiceLinkedRoleUsage(context.Context, ServiceLinkedRoleReference, func(context.Context, []ServiceLinkedRoleUsage) error) error {
	if u.skipCallback {
		return nil
	}
	return errors.New("linked service storage unavailable")
}

func TestServiceLinkedWorkerCannotDeleteWithoutUsageCheck(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(map[bool]string{false: "provider-error", true: "missing-callback"}[skip], func(t *testing.T) {
			repository := NewMemoryRepository(nil)
			scope, role, job := seedLinkedJob(t, repository, serviceLinkedNotStarted)
			s := NewWithRepository(nil, repository)
			defer s.Close()
			if err := s.RegisterServiceLinkedRole(autoScalingLinkedTemplate(t, s), unavailableLinkedUsage{skipCallback: skip}); err != nil {
				t.Fatal(err)
			}
			if err := s.processServiceLinkedRoleDeletion(context.Background(), scope, job.ID); err != nil {
				t.Fatal(err)
			}
			if got := readLinkedJob(t, repository, scope, job.ID); got.Status != serviceLinkedFailed || got.FailureReason == "" {
				t.Fatalf("missing usage verification did not fail closed: %+v", got)
			}
			if err := repository.View(context.Background(), func(tx ReadTx) error { _, err := tx.Role(scope, role.RoleName); return err }); err != nil {
				t.Fatalf("unverified role deleted: %v", err)
			}
		})
	}
}

type failedLinkedWriteRepository struct {
	Repository
	reject, rejectPending bool
}
type failedLinkedWriteTx struct {
	WriteTx
	reject, rejectPending bool
}

var errLinkedCommit = errors.New("injected terminal job write failure")

func (r *failedLinkedWriteRepository) Update(ctx context.Context, fn func(WriteTx) error) error {
	return r.Repository.Update(ctx, func(tx WriteTx) error { return fn(failedLinkedWriteTx{tx, r.reject, r.rejectPending}) })
}
func (t failedLinkedWriteTx) PutServiceLinkedRoleDeletion(scope Scope, job ServiceLinkedRoleDeletion) error {
	if (t.reject && job.Status == serviceLinkedSucceeded) || (t.rejectPending && job.Status == serviceLinkedNotStarted) {
		return errLinkedCommit
	}
	return t.WriteTx.PutServiceLinkedRoleDeletion(scope, job)
}

func TestServiceLinkedRequestRollbackDoesNotStartWorker(t *testing.T) {
	repository := &failedLinkedWriteRepository{Repository: NewMemoryRepository(nil)}
	scope, role, _ := seedLinkedJob(t, repository, serviceLinkedFailed)
	repository.rejectPending = true
	s := NewWithRepository(nil, repository)
	defer s.Close()
	q := url.Values{"Action": {"DeleteServiceLinkedRole"}, "RoleName": {role.RoleName}, "Version": {"2010-05-08"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(q.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(awsctx.WithMetadata(req.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID}))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 500 {
		t.Fatalf("failed task commit response = %d %s", w.Code, w.Body.String())
	}
	s.serviceLinked.mu.Lock()
	started := s.serviceLinked.started
	s.serviceLinked.mu.Unlock()
	if started {
		t.Fatal("rolled-back deletion request started the worker")
	}
	if err := repository.View(context.Background(), func(tx ReadTx) error {
		jobs, err := tx.ServiceLinkedRoleDeletions(scope)
		if err != nil {
			return err
		}
		if len(jobs) != 1 || jobs[0].Status != serviceLinkedFailed {
			t.Fatalf("rolled-back request published task: %+v", jobs)
		}
		_, err = tx.Role(scope, role.RoleName)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceLinkedRoleDeletionAndTerminalJobCommitAtomically(t *testing.T) {
	repository := &failedLinkedWriteRepository{Repository: NewMemoryRepository(nil)}
	scope, r, job := seedLinkedJob(t, repository, serviceLinkedNotStarted)
	s := NewWithRepository(nil, repository)
	defer s.Close()
	repository.reject = true
	if err := s.processServiceLinkedRoleDeletion(context.Background(), scope, job.ID); !errors.Is(err, errLinkedCommit) {
		t.Fatalf("injected commit failure lost: %v", err)
	}
	if got := readLinkedJob(t, repository, scope, job.ID); got.Status != serviceLinkedInProgress {
		t.Fatalf("failed commit changed job: %+v", got)
	}
	if err := repository.View(context.Background(), func(tx ReadTx) error { _, err := tx.Role(scope, r.RoleName); return err }); err != nil {
		t.Fatalf("failed job commit removed role: %v", err)
	}
	repository.reject = false
	if _, err := s.RunDueJobs(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	waitPersistedLinkedStatus(t, repository, scope, job.ID, serviceLinkedSucceeded)
}

func TestServiceLinkedRoleDeletionRepositoryDetachmentAndScope(t *testing.T) {
	repository := NewMemoryRepository(nil)
	scope, _, job := seedLinkedJob(t, repository, serviceLinkedFailed)
	job.Usage = []ServiceLinkedRoleUsage{{Region: "eu-west-1", ResourceARNs: []string{"arn:original"}}}
	if err := repository.Update(context.Background(), func(tx WriteTx) error {
		if err := tx.PutServiceLinkedRoleDeletion(scope, job); err != nil {
			return err
		}
		job.Usage[0].ResourceARNs[0] = "arn:mutated"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := readLinkedJob(t, repository, scope, job.ID)
	if got.Usage[0].ResourceARNs[0] != "arn:original" {
		t.Fatal("repository retained caller-owned usage list")
	}
	got.Usage[0].ResourceARNs[0] = "arn:read-mutated"
	if next := readLinkedJob(t, repository, scope, job.ID); next.Usage[0].ResourceARNs[0] != "arn:original" {
		t.Fatal("repository returned aliased usage list")
	}
	if err := repository.View(context.Background(), func(tx ReadTx) error {
		if _, err := tx.ServiceLinkedRoleDeletion(Scope{Partition: "aws-us-gov", AccountID: scope.AccountID}, job.ID); !errors.Is(err, ErrRecordNotFound) {
			t.Errorf("partition leaked: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceLinkedRoleTemplatesAndQuota(t *testing.T) {
	s := New()
	defer s.Close()
	for _, template := range s.ServiceLinkedRoleTemplates() {
		if err := validateServiceLinkedTemplate(template); err != nil {
			t.Fatalf("invalid captured template %s: %v", template.ServiceName, err)
		}
	}
	templates := s.ServiceLinkedRoleTemplates()
	templates[0].ManagedPolicyARNs[0] = "mutated"
	if next := s.ServiceLinkedRoleTemplates(); next[0].ManagedPolicyARNs[0] == "mutated" {
		t.Fatal("template catalogue exposes aliased policy list")
	}
	scope := Scope{Partition: "aws", AccountID: "123456789012"}
	if err := s.repository.Update(t.Context(), func(tx WriteTx) error {
		for i := range maxRoles {
			name := fmt.Sprintf("occupied-%d", i)
			if err := tx.PutRole(scope, Role{RoleName: name, RoleId: name, Path: "/", Arn: "arn:aws:iam::123456789012:role/" + name, IdentityPolicies: newIdentityPolicies()}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m := awsctx.Metadata{Partition: "aws", AccountID: scope.AccountID, Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.AccountID}
	q := url.Values{"Action": {"CreateServiceLinkedRole"}, "AWSServiceName": {"autoscaling.amazonaws.com"}}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(q.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	s.ServeHTTP(response, request.WithContext(awsctx.WithMetadata(request.Context(), m)))
	if response.Code != http.StatusOK {
		t.Fatalf("service-linked role cannot exceed ordinary role quota: %s", response.Body.String())
	}
	if err := s.repository.View(t.Context(), func(tx ReadTx) error {
		roles, err := tx.Roles(scope)
		if err == nil && len(roles) != maxRoles+1 {
			t.Fatalf("service-linked role not counted in usage: %d", len(roles))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Ownership is not inferred from a role's name or path.
	ordinary := Role{RoleName: "AWSServiceRoleForPretend", RoleId: "AROAPRETEND", Path: "/aws-service-role/pretend.amazonaws.com/", Arn: "arn:aws:iam::123456789012:role/aws-service-role/pretend.amazonaws.com/AWSServiceRoleForPretend", IdentityPolicies: newIdentityPolicies()}
	if err := s.repository.Update(t.Context(), func(tx WriteTx) error { return tx.PutRole(scope, ordinary) }); err != nil {
		t.Fatal(err)
	}
	q = url.Values{"Action": {"DeleteRole"}, "RoleName": {ordinary.RoleName}}
	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(q.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	s.ServeHTTP(response, request.WithContext(awsctx.WithMetadata(request.Context(), m)))
	if response.Code != http.StatusOK {
		t.Fatalf("path made ordinary role immutable: %s", response.Body.String())
	}
	before := readLinkedTemplateCount(s)
	s.StartWorkers()
	if err := s.RegisterServiceLinkedRole(autoScalingLinkedTemplate(t, s), absentServiceLinkedProvider{}); err == nil {
		t.Fatal("late service registration changed running worker dependencies")
	}
	if readLinkedTemplateCount(s) != before {
		t.Fatal("failed registration mutated registry")
	}
}

func readLinkedTemplateCount(s *Service) int { return len(s.ServiceLinkedRoleTemplates()) }

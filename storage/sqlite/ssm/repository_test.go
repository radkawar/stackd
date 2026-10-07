package ssm_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	journaldb "stackd/storage/sqlite/journal"
	backend "stackd/storage/sqlite/ssm"
	domain "stackd/storage/ssm"
)

type store struct {
	repo   domain.Repository
	events journal.Storage
	reopen func()
}

func stores(t *testing.T, check func(*testing.T, *store)) {
	t.Helper()
	for _, name := range []string{"memory", "sqlite"} {
		t.Run(name, func(t *testing.T) {
			s := &store{}
			if name == "memory" {
				d := memory.NewDomain()
				s.repo, s.events = domain.NewMemory(d), journal.NewMemory(d)
			} else {
				path := filepath.Join(t.TempDir(), "ssm.sqlite")
				var db *sql.DB
				s.reopen = func() {
					if db != nil {
						if err := db.Close(); err != nil {
							t.Fatal(err)
						}
					}
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					s.repo, s.events = backend.New(db), journaldb.New(db)
				}
				s.reopen()
				t.Cleanup(func() { _ = db.Close() })
			}
			check(t, s)
		})
	}
}
func retained() (domain.ParameterRecord, domain.VersionRecord, domain.ValidationJob) {
	at := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	key := domain.ParameterKey{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "/app/image"}
	p := domain.ParameterRecord{Key: key, ARN: "arn:aws:ssm:us-east-1:111111111111:parameter/app/image", Type: "SecureString", Tier: "Advanced", DataType: "aws:ec2:image", Description: "retained metadata", AllowedPattern: "ami-.*", CurrentVersion: 0, Tags: map[string]string{"team": "compute"}, Policies: []domain.ParameterPolicy{{Type: "Expiration", Version: "1.0", Attributes: map[string]string{"Timestamp": at.Format(time.RFC3339Nano)}, Due: at.Add(time.Hour)}}, ResourcePolicies: []domain.ResourcePolicy{{ID: "policy-one", Hash: "hash-one", Policy: authorization.BoundPolicy{Document: `{"Version":"2012-10-17","Statement":[]}`, PrincipalIDs: map[string]string{"arn:aws:iam::111111111111:role/reader": "AROAIMMUTABLE"}}, CloudFormationOwner: "stack-resource:incarnation"}}}
	v := domain.VersionRecord{Key: domain.VersionKey{Parameter: key, Version: 1}, Type: p.Type, Tier: p.Tier, DataType: p.DataType, Description: p.Description, AllowedPattern: p.AllowedPattern, KeyID: "alias/ssm", KeyARN: "arn:aws:kms:us-east-1:111111111111:key/key-one", ModifiedUser: "arn:aws:iam::111111111111:role/writer", Value: []byte{0, 1, 2, 255}, WrappedKey: []byte{9, 8, 7}, Modified: at, Labels: []string{"production", "stable"}, Policies: []domain.ParameterPolicy{{Type: "NoChangeNotification", Version: "1.0", Attributes: map[string]string{"After": "1", "Unit": "Days"}, Due: at.Add(-time.Hour), Fired: true}}}
	j := domain.ValidationJob{Key: v.Key, Due: at, Caller: awsctx.Metadata{
		AccountID: key.AccountID, Region: key.Region, Partition: key.Partition, AccessKeyID: "ASIAEXAMPLE", RequestID: "accepted-request", ParentEventID: "parent-event", TraceHeader: "Root=1-00000000-000000000000000000000000", PrincipalARN: "arn:aws:sts::111111111111:assumed-role/writer/session", PrincipalID: "role:session", UserName: "writer", SessionType: "AssumedRole", IssuerARN: "arn:aws:iam::111111111111:role/writer", IssuerID: "role-id",
		SessionPolicies: []string{`{"Statement":[]}`}, SessionPolicyARNs: []string{"arn:aws:iam::111111111111:policy/validate"}, HasSessionPolicy: true, SessionContext: map[string][]string{"claim": {"first", "second"}, "empty": {}, "nil": nil}, FederatedProvider: "oidc.example", SessionTags: map[string]string{"team": "compute"}, TransitiveTagKeys: []string{"team"}, SourceIdentity: "caller", MFAPresent: true, MFAAuthenticatedAt: at.Add(-time.Minute), TokenIssueTime: at.Add(-time.Hour), CalledVia: []string{"ssm.amazonaws.com", "ec2.amazonaws.com"}, TransportKnown: true, SourceIP: "192.0.2.5", SecureTransport: true, UserAgent: "owned-client", SignatureVersion: "SigV4", AuthenticationMethod: "AuthHeader", ServicePrincipal: awsctx.ServicePrincipal{Name: "ssm.amazonaws.com", SourceARN: p.ARN, Type: "AWSService", Aliases: []string{"ssm.us-east-1.amazonaws.com"}}, InvokedBy: "ssm.amazonaws.com", InScopeOf: journal.APIIdentityScope{IssuerType: "AWS::EC2::Instance", CredentialsIssuedTo: "arn:aws:ec2:us-east-1:111111111111:instance/i-owned"},
	}}
	return p, v, j
}
func putAll(tx domain.Transaction, p domain.ParameterRecord, v domain.VersionRecord, j domain.ValidationJob) error {
	if err := tx.PutParameter(p); err != nil {
		return err
	}
	if err := tx.PutVersion(v); err != nil {
		return err
	}
	return tx.PutValidationJob(j)
}
func same[T any](t *testing.T, label string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s changed: got %#v want %#v", label, got, want)
	}
}
func TestValuesJobsAuthorityAndScopeRemainDetachedAcrossRestart(t *testing.T) {
	stores(t, func(t *testing.T, s *store) {
		p, v, j := retained()
		scopes := []domain.Scope{p.Key.Scope, {Partition: "aws-cn", AccountID: p.Key.AccountID, Region: p.Key.Region}, {Partition: p.Key.Partition, AccountID: "222222222222", Region: p.Key.Region}, {Partition: p.Key.Partition, AccountID: p.Key.AccountID, Region: "us-west-2"}}
		for _, scope := range scopes {
			p, v, j := retained()
			p.Key.Scope = scope
			v.Key.Parameter, j.Key.Parameter = p.Key, p.Key
			if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error { return putAll(tx, p, v, j) }); err != nil {
				t.Fatal(err)
			}
			p.Tags["team"] = "input-mutation"
			p.Policies[0].Attributes["Timestamp"] = "input-mutation"
			p.ResourcePolicies[0].Policy.PrincipalIDs["arn:aws:iam::111111111111:role/reader"] = "input-mutation"
			v.Value[0], v.WrappedKey[0] = 100, 100
			v.Labels[0] = "input-mutation"
			v.Policies[0].Attributes["After"] = "100"
			j.Caller.SessionContext["claim"][0] = "input-mutation"
			j.Caller.SessionTags["team"] = "input-mutation"
			j.Caller.CalledVia[0] = "input-mutation"
		}
		if s.reopen != nil {
			s.reopen()
		}
		for _, scope := range scopes {
			p, v, j := retained()
			p.Key.Scope = scope
			v.Key.Parameter, j.Key.Parameter = p.Key, p.Key
			if err := s.repo.View(t.Context(), func(r domain.Reader) error {
				got, err := r.Parameter(p.Key)
				if err != nil {
					return err
				}
				same(t, "parameter", got, p)
				version, err := r.Version(v.Key)
				if err != nil {
					return err
				}
				same(t, "value and history", version, v)
				job, err := r.ValidationJob(j.Key)
				if err != nil {
					return err
				}
				same(t, "caller authority", job, j)
				job.Caller.SessionContext["claim"][0] = "read-mutation"
				got.Tags["team"] = "read-mutation"
				got.Policies[0].Attributes["Timestamp"] = "read-mutation"
				got.ResourcePolicies[0].Policy.PrincipalIDs["arn:aws:iam::111111111111:role/reader"] = "read-mutation"
				version.Value[0] = 100
				version.Labels[0] = "read-mutation"
				again, err := r.Parameter(p.Key)
				if err != nil {
					return err
				}
				same(t, "detached metadata", again, p)
				next, err := r.Version(v.Key)
				if err != nil {
					return err
				}
				same(t, "detached value", next, v)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		// Replacing current metadata and caller collections must not alter historical policy bytes.
		p.Tags = map[string]string{}
		p.Policies = nil
		p.ResourcePolicies = []domain.ResourcePolicy{}
		j.Caller.SessionContext = map[string][]string{"claim": {}, "nil": nil}
		j.Caller.SessionPolicies = nil
		j.Caller.SessionPolicyARNs = []string{}
		j.Caller.SessionTags = map[string]string{}
		j.Caller.CalledVia = nil
		j.Caller.ServicePrincipal.Aliases = []string{}
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutParameter(p); err != nil {
				return err
			}
			return tx.PutValidationJob(j)
		}); err != nil {
			t.Fatal(err)
		}
		if s.reopen != nil {
			s.reopen()
		}
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			got, err := r.Parameter(p.Key)
			if err != nil {
				return err
			}
			same(t, "replacement metadata", got, p)
			history, err := r.Version(v.Key)
			if err != nil {
				return err
			}
			same(t, "historical policy", history, v)
			job, err := r.ValidationJob(j.Key)
			if err != nil {
				return err
			}
			same(t, "replacement authority", job, j)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPolicyDeadlineOrderingAndDeletionCascade(t *testing.T) {
	stores(t, func(t *testing.T, s *store) {
		p, v, j := retained()
		later := p
		later.Key.Name = "/later"
		later.Policies = []domain.ParameterPolicy{{Due: j.Due.Add(time.Hour)}}
		first := p
		first.Key.AccountID = "000000000000"
		first.Policies = []domain.ParameterPolicy{{Due: j.Due.Add(-time.Hour), Fired: true}, {}, {Due: j.Due}}
		tied := first
		tied.Key.AccountID = "999999999999"
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := putAll(tx, p, v, j); err != nil {
				return err
			}
			for _, item := range []domain.ParameterRecord{later, tied, first} {
				if err := tx.PutParameter(item); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			got, err := r.NextPolicy()
			if err != nil {
				return err
			}
			same(t, "earliest unfired deadline", got.Key, first.Key)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			for _, item := range []domain.ParameterRecord{p, later, tied, first} {
				if err := tx.DeleteParameter(item.Key); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if s.reopen != nil {
			s.reopen()
		}
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			if _, err := r.Version(v.Key); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("deleted version remains: %v", err)
			}
			versions, err := r.Versions(p.Key)
			if err != nil {
				return err
			}
			same(t, "deleted versions", versions, []domain.VersionRecord{})
			if _, err := r.NextValidationJob(); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("deleted validation job remains: %v", err)
			}
			if _, err := r.NextPolicy(); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("deleted policy remains: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRelatedJournalRollbackAndSavepointIsolation(t *testing.T) {
	stores(t, func(t *testing.T, s *store) {
		p, v, j := retained()
		appendEvent := func(ctx context.Context, id string) error {
			return s.events.AppendAPICallCompleted(ctx, journal.Envelope{At: j.Due, Partition: p.Key.Partition, AccountID: p.Key.AccountID, Region: p.Key.Region, RequestID: id}, journal.APICallCompleted{EventID: id, EventSource: "ssm.amazonaws.com", EventName: "PutParameter", Category: journal.CategoryManagement})
		}
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error { return putAll(tx, p, v, j) }); err != nil {
			t.Fatal(err)
		}
		rejected := errors.New("reject resource transition")
		err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.DeleteParameter(p.Key); err != nil {
				return err
			}
			if err := appendEvent(tx.Context(), "rolled-back"); err != nil {
				return err
			}
			return rejected
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("rollback result: %v", err)
		}
		// Ordinary nested errors poison the owner even when handled by its callback.
		err = s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			err := s.repo.Update(tx.Context(), func(child domain.Transaction) error {
				if err := child.DeleteParameter(p.Key); err != nil {
					return err
				}
				if err := appendEvent(child.Context(), "nested-abort"); err != nil {
					return err
				}
				return rejected
			})
			if !errors.Is(err, rejected) {
				return err
			}
			return nil
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("nested rejection did not abort owner: %v", err)
		}
		setting := domain.SettingRecord{Scope: p.Key.Scope, ID: "/ssm/parameter-store/default-parameter-tier", Value: "Advanced", ModifiedUser: "caller", Modified: j.Due}
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			err := s.repo.Attempt(tx.Context(), func(child domain.Transaction) error {
				if err := child.DeleteParameter(p.Key); err != nil {
					return err
				}
				if err := appendEvent(child.Context(), "attempt-abort"); err != nil {
					return err
				}
				return rejected
			})
			if !errors.Is(err, rejected) {
				return err
			}
			if err := tx.PutSetting(setting); err != nil {
				return err
			}
			return appendEvent(tx.Context(), "committed-owner")
		}); err != nil {
			t.Fatal(err)
		}
		if s.reopen != nil {
			s.reopen()
		}
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			got, err := r.Parameter(p.Key)
			if err != nil {
				return err
			}
			same(t, "rolled-back parameter", got, p)
			version, err := r.Version(v.Key)
			if err != nil {
				return err
			}
			same(t, "rolled-back version", version, v)
			job, err := r.NextValidationJob()
			if err != nil {
				return err
			}
			same(t, "rolled-back validation", job, j)
			settings, err := r.Settings(p.Key.Scope)
			if err != nil {
				return err
			}
			same(t, "committed setting", settings, []domain.SettingRecord{setting})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		events, err := s.events.Read(t.Context(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(events))
		for _, event := range events {
			ids = append(ids, event.APICallCompleted.EventID)
		}
		same(t, "atomic journal outcomes", ids, []string{"committed-owner"})
	})
}

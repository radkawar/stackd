package guardduty_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/guardduty"
	domain "stackd/storage/guardduty"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/guardduty"
)

func repository(t *testing.T, kind string) (domain.Repository, func() domain.Repository) {
	t.Helper()
	if kind == "memory" {
		repo := domain.NewMemory(memory.NewDomain())
		return repo, func() domain.Repository { return repo }
	}
	path := filepath.Join(t.TempDir(), "guardduty.sqlite")
	var db *sql.DB
	open := func() domain.Repository {
		var err error
		db, err = sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		return backend.New(db)
	}
	repo := open()
	t.Cleanup(func() { _ = db.Close() })
	return repo, func() domain.Repository {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		return open()
	}
}

func records(scope domain.Scope) (domain.Detector, domain.Finding, domain.Filter) {
	now := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	arn := fmt.Sprintf("arn:%s:guardduty:%s:%s:detector/detector", scope.Partition, scope.Region, scope.AccountID)
	detector := domain.Detector{CFNOwnership: domain.CloudFormationOwnership{Owner: "detector-owner", Token: "detector-incarnation"}, Scope: scope, ID: "detector", ARN: arn, Status: "ENABLED", Frequency: "SIX_HOURS", ServiceRole: "role", ClientToken: "detector-token", Created: now, Updated: now.Add(time.Minute), Tags: map[string]string{"owner": "security"}, Features: []domain.Feature{
		{Name: "RUNTIME_MONITORING", Status: "DISABLED", Updated: now, Additional: []domain.AdditionalFeature{{Name: "EKS_ADDON_MANAGEMENT", Status: "DISABLED", Updated: now}}},
		{Name: "S3_DATA_EVENTS", Status: "ENABLED", Updated: now, Additional: []domain.AdditionalFeature{}},
	}}
	finding := domain.Finding{Scope: scope, DetectorID: detector.ID, ID: "finding", SampleType: "Recon:EC2/PortProbeUnprotectedPort", SampleRevision: "immutable-corpus-v1", Created: now, Updated: now.Add(time.Hour), Count: 9, Archived: true, Feedback: "USEFUL"}
	longMin, longMax, zeroLong := api.Long(math.MinInt64), api.Long(math.MaxInt64), api.Long(0)
	intMin, intMax, zeroInt := api.Integer(math.MinInt32), api.Integer(math.MaxInt32), api.Integer(0)
	filter := domain.Filter{CFNOwnership: domain.CloudFormationOwnership{Owner: "filter-owner", Token: "filter-incarnation"}, Scope: scope, DetectorID: detector.ID, Name: "triage", ARN: arn + "/filter/triage", Action: "ARCHIVE", Description: "retained criteria", DescriptionSet: true, ClientToken: "filter-token", Rank: 4, Version: 8, Created: now, Updated: now.Add(time.Hour), Tags: map[string]string{"owner": "analyst"}, Criteria: api.FindingCriteria{Criterion: api.Criterion{
		"all-operators":    {Eq: api.Eq{"second", "first", "second"}, Equals: api.Equals{"equal"}, Neq: api.Neq{"neq"}, NotEquals: api.NotEquals{"not-equal"}, Matches: api.Matches{"prefix*", "*suffix"}, NotMatches: api.NotMatches{"excluded*"}, GreaterThan: &longMin, GreaterThanOrEqual: &zeroLong, LessThan: &longMax, LessThanOrEqual: &zeroLong, Gt: &intMin, Gte: &zeroInt, Lt: &intMax, Lte: &zeroInt},
		"empty-lists":      {Eq: api.Eq{}, Equals: api.Equals{}, Neq: api.Neq{}, NotEquals: api.NotEquals{}, Matches: api.Matches{}, NotMatches: api.NotMatches{}},
		"absent-operators": {},
	}}}
	return detector, finding, filter
}

func TestObservedFindingsRoundtripRollbackAndIsolation(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, reopen := repository(t, kind)
			scopes := []domain.Scope{
				{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"},
				{Partition: "aws-cn", AccountID: "111111111111", Region: "us-east-1"},
				{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"},
				{Partition: "aws", AccountID: "111111111111", Region: "us-west-2"},
			}
			observed := func(sc domain.Scope) domain.Finding {
				_, v, _ := records(sc)
				v.ID = "observed"
				v.SampleType, v.SampleRevision = "", ""
				v.Observation = domain.Observation{
					Type:  "Stealth:IAMUser/CloudTrailLoggingDisabled",
					Title: "CloudTrail logging disabled", Description: "Observed successful StopLogging API call",
					Severity: 8.5, EventID: "event-" + sc.Partition + sc.AccountID + sc.Region,
					AccessKeyID: "AKIAEXAMPLE", PrincipalID: "principal", UserName: "analyst",
					UserType: "IAMUser", API: "StopLogging", ServiceName: "cloudtrail.amazonaws.com",
					SourceIP: "192.0.2.10", ErrorCode: "retained-error", ResourceType: "AccessKey", ResourceName: "trail",
					FeatureName: "Management",
				}
				v.LastPublished = v.Created.Add(time.Minute)
				v.PublishDue = v.Updated.Add(time.Hour)
				v.Suppressed = true
				return v
			}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				for _, sc := range scopes {
					d, sample, _ := records(sc)
					if err := tx.PutDetector(d); err != nil {
						return err
					}
					if err := tx.PutFinding(sample); err != nil {
						return err
					}
					if err := tx.PutFinding(observed(sc)); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			assertScope := func(sc domain.Scope, want domain.Finding) {
				t.Helper()
				if err := repo.View(t.Context(), func(r domain.Reader) error {
					got, err := r.Finding(sc, want.DetectorID, want.ID)
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("observed finding = %#v, want %#v", got, want)
					}
					_, sample, _ := records(sc)
					all, err := r.Findings(sc, want.DetectorID)
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(all, []domain.Finding{sample, want}) {
						t.Fatalf("sample and observation list = %#v", all)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			repo = reopen()
			for _, sc := range scopes {
				assertScope(sc, observed(sc))
			}
			scope := scopes[0]
			want := observed(scope)
			rejected := errors.New("reject observation transaction")
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				changed := want
				changed.Observation.EventID = "rolled-back-event"
				changed.Observation.Severity = 1
				if err := tx.PutFinding(changed); err != nil {
					return err
				}
				if err := tx.DeleteDetector(scope, want.DetectorID); err != nil {
					return err
				}
				return rejected
			}); !errors.Is(err, rejected) {
				t.Fatalf("rollback error = %v", err)
			}
			repo = reopen()
			assertScope(scope, want)
			want.Observation.EventID = "committed-event"
			want.Observation.SourceIP = "2001:db8::1"
			want.Count++
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutFinding(want) }); err != nil {
				t.Fatal(err)
			}
			repo = reopen()
			assertScope(scope, want)
			want.Observation = domain.Observation{}
			want.SampleType, want.SampleRevision = "sample-replacement", "immutable-corpus-v1"
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutFinding(want) }); err != nil {
				t.Fatal(err)
			}
			repo = reopen()
			assertScope(scope, want)
			// Removing the sample revision must not resurrect the replaced observation.
			want.SampleType, want.SampleRevision = "", ""
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutFinding(want) }); err != nil {
				t.Fatal(err)
			}
			assertScope(scope, want)
			for _, deleteDetector := range []bool{false, true} {
				if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
					if err := tx.PutFinding(observed(scope)); err != nil {
						return err
					}
					if deleteDetector {
						return tx.DeleteDetector(scope, want.DetectorID)
					}
					return tx.DeleteFinding(scope, want.DetectorID, want.ID)
				}); err != nil {
					t.Fatal(err)
				}
				repo = reopen()
				if err := repo.View(t.Context(), func(r domain.Reader) error {
					_, err := r.Finding(scope, want.DetectorID, want.ID)
					if !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("deleted observation finding: %v", err)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			for _, sc := range scopes[1:] {
				assertScope(sc, observed(sc))
			}
		})
	}
}
func putRecords(tx domain.Transaction, detector domain.Detector, finding domain.Finding, filter domain.Filter) error {
	if err := tx.PutDetector(detector); err != nil {
		return err
	}
	if err := tx.PutFinding(finding); err != nil {
		return err
	}
	return tx.PutFilter(filter)
}
func assertRecords(t *testing.T, repo domain.Repository, detector domain.Detector, finding domain.Finding, filter domain.Filter) {
	t.Helper()
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		d, err := r.Detector(detector.Scope, detector.ID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(d, detector) {
			t.Fatalf("detector state changed: got %#v, want %#v", d, detector)
		}
		f, err := r.Finding(finding.Scope, finding.DetectorID, finding.ID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(f, finding) {
			t.Fatalf("finding state changed: got %#v, want %#v", f, finding)
		}
		filterGot, err := r.Filter(filter.Scope, filter.DetectorID, filter.Name)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(filterGot, filter) {
			t.Fatalf("filter state changed: got %#v, want %#v", filterGot, filter)
		}
		findings, err := r.Findings(finding.Scope, finding.DetectorID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(findings, []domain.Finding{finding}) {
			t.Fatalf("scoped findings = %#v", findings)
		}
		filters, err := r.Filters(filter.Scope, filter.DetectorID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(filters, []domain.Filter{filter}) {
			t.Fatalf("scoped filters = %#v", filters)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedStateRollbackScopeIsolationAndCascade(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, reopen := repository(t, kind)
			scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			detector, finding, filter := records(scope)
			others := []domain.Scope{
				{Partition: "aws-cn", AccountID: scope.AccountID, Region: scope.Region},
				{Partition: scope.Partition, AccountID: "222222222222", Region: scope.Region},
				{Partition: scope.Partition, AccountID: scope.AccountID, Region: "us-west-2"},
			}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				for _, sc := range others {
					d, f, v := records(sc)
					if err := putRecords(tx, d, f, v); err != nil {
						return err
					}
				}
				d, f, v := records(scope)
				if err := putRecords(tx, d, f, v); err != nil {
					return err
				}
				// Inputs become caller-owned again immediately after Put.
				d.Tags["owner"] = "changed"
				d.Features[0].Additional[0].Status = "ENABLED"
				c := v.Criteria.Criterion["all-operators"]
				c.Eq[0] = "changed"
				*c.GreaterThan = 55
				v.Tags["owner"] = "changed"
				delete(v.Criteria.Criterion, "absent-operators")
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			assertRecords(t, repo, detector, finding, filter)
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				d, err := r.Detector(scope, detector.ID)
				if err != nil {
					return err
				}
				d.Tags["owner"] = "read mutation"
				d.Features[0].Additional[0].Status = "read mutation"
				all, err := r.AllDetectors()
				if err != nil {
					return err
				}
				for _, v := range all {
					v.Tags["owner"] = "list mutation"
				}
				fs, err := r.Filters(scope, detector.ID)
				if err != nil {
					return err
				}
				fs[0].Tags["owner"] = "list mutation"
				c := fs[0].Criteria.Criterion["all-operators"]
				c.NotMatches[0] = "list mutation"
				*c.Lt = 4
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			rejected := errors.New("event rejected")
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				f := finding
				f.Count++
				f.Archived = false
				f.Feedback = "NOT_USEFUL"
				if err := tx.PutFinding(f); err != nil {
					return err
				}
				if err := tx.DeleteDetector(scope, detector.ID); err != nil {
					return err
				}
				return rejected
			}); !errors.Is(err, rejected) {
				t.Fatalf("rollback error = %v", err)
			}
			repo = reopen()
			assertRecords(t, repo, detector, finding, filter)
			for _, sc := range others {
				d, f, v := records(sc)
				assertRecords(t, repo, d, f, v)
			}
			// A replacement must remove stale normalized children, retaining empty versus nil intent.
			detector.Features = []domain.Feature{}
			detector.Tags = nil
			filter.Criteria.Criterion = api.Criterion{"replacement": {Equals: api.Equals{"new"}}}
			filter.Tags = map[string]string{}
			finding.Count++
			finding.Archived = false
			finding.Feedback = "NOT_USEFUL"
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return putRecords(tx, detector, finding, filter) }); err != nil {
				t.Fatal(err)
			}
			repo = reopen()
			assertRecords(t, repo, detector, finding, filter)
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteDetector(scope, detector.ID) }); err != nil {
				t.Fatal(err)
			}
			repo = reopen()
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				if _, err := r.Detector(scope, detector.ID); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("deleted detector: %v", err)
				}
				if _, err := r.Finding(scope, detector.ID, finding.ID); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("finding cascade: %v", err)
				}
				if _, err := r.Filter(scope, detector.ID, filter.Name); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("filter cascade: %v", err)
				}
				findings, err := r.Findings(scope, detector.ID)
				if err != nil {
					return err
				}
				filters, err := r.Filters(scope, detector.ID)
				if err != nil {
					return err
				}
				if len(findings) != 0 || len(filters) != 0 {
					t.Fatalf("cascade left findings=%#v filters=%#v", findings, filters)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, sc := range others {
				d, f, v := records(sc)
				assertRecords(t, repo, d, f, v)
			}
			// Reusing the deleted identity cannot resurrect tags, features, or criteria.
			detector.Features = nil
			filter.Criteria.Criterion = nil
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return putRecords(tx, detector, finding, filter) }); err != nil {
				t.Fatal(err)
			}
			assertRecords(t, repo, detector, finding, filter)
		})
	}
}

func TestAttemptSavepointsAndMissingParent(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, _ := repository(t, kind)
			scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			detector, finding, filter := records(scope)
			for _, put := range []func(domain.Transaction) error{
				func(tx domain.Transaction) error { return tx.PutFinding(finding) },
				func(tx domain.Transaction) error { return tx.PutFilter(filter) },
			} {
				if err := repo.Update(t.Context(), put); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("missing parent: %v", err)
				}
			}
			rejected := errors.New("rejected child attempt")
			ownerRejected := errors.New("owner failed")
			write := func(ctx context.Context) error {
				return repo.Update(ctx, func(tx domain.Transaction) error {
					if err := tx.PutDetector(detector); err != nil {
						return err
					}
					err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
						if err := child.PutFinding(finding); err != nil {
							return err
						}
						if err := child.PutFilter(filter); err != nil {
							return err
						}
						return rejected
					})
					if !errors.Is(err, rejected) {
						t.Fatalf("attempt error = %v", err)
					}
					if _, err := tx.Finding(scope, detector.ID, finding.ID); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("failed attempt leaked finding: %v", err)
					}
					if _, err := tx.Filter(scope, detector.ID, filter.Name); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("failed attempt leaked filter: %v", err)
					}
					return repo.Attempt(tx.Context(), func(child domain.Transaction) error {
						if err := child.PutFinding(finding); err != nil {
							return err
						}
						return child.PutFilter(filter)
					})
				})
			}
			if err := write(t.Context()); err != nil {
				t.Fatal(err)
			}
			assertRecords(t, repo, detector, finding, filter)
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := repo.Attempt(tx.Context(), func(child domain.Transaction) error { return child.DeleteDetector(scope, detector.ID) }); err != nil {
					return err
				}
				return ownerRejected
			}); !errors.Is(err, ownerRejected) {
				t.Fatalf("owner error = %v", err)
			}
			assertRecords(t, repo, detector, finding, filter)
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.DeleteFinding(scope, detector.ID, finding.ID); err != nil {
					return err
				}
				return tx.DeleteFilter(scope, detector.ID, filter.Name)
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				if _, err := r.Detector(scope, detector.ID); err != nil {
					return err
				}
				if _, err := r.Finding(scope, detector.ID, finding.ID); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("deleted finding = %v", err)
				}
				if _, err := r.Filter(scope, detector.ID, filter.Name); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("deleted filter = %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

package ssmcommands_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	journaldb "stackd/storage/sqlite/journal"
	backend "stackd/storage/sqlite/ssmcommands"
	domain "stackd/storage/ssmcommands"
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
				path := filepath.Join(t.TempDir(), "commands.sqlite")
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
func retained() (domain.Node, domain.Command, domain.Invocation) {
	at := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	n := domain.Node{Key: domain.Key{Scope: scope, ID: "i-agent"}, AgentVersion: "3.3.100", AgentName: "amazon-ssm-agent", PlatformType: "Linux", PlatformName: "Ubuntu", PlatformVersion: "24.04", ComputerName: "guest", RegisteredAt: at.Add(-time.Hour), LastPing: at}
	c := domain.Command{Key: domain.Key{Scope: scope, ID: "command-one"}, DocumentName: "OwnedDocument", DocumentVersion: "3", DocumentHash: "snapshot-hash", Content: `{"schemaVersion":"2.2","mainSteps":[]}`, Comment: "requested", Parameters: map[string][]string{"commands": {"printf hello", "exit 7"}, "empty": {}, "nil": nil}, InstanceIDs: []string{"i-agent", "i-other"}, Targets: []domain.Target{{Key: "tag:team", Values: []string{"compute", "storage"}}, {Key: "empty", Values: []string{}}, {Key: "nil"}}, RequestedAt: at, DeliveryDeadline: at.Add(time.Hour), TimeoutSeconds: 60, MaxConcurrency: "50%", MaxErrors: "10%", Concurrency: 2, ErrorBudget: 1, OutputBucket: "results", OutputPrefix: "owned/", OutputRegion: "us-east-1", LogGroup: "commands", CloudWatchEnabled: true, Status: "InProgress", StatusDetails: "In Progress", ParentEventID: "admission-event"}
	i := domain.Invocation{Key: domain.InvocationKey{Command: c.Key, NodeID: n.Key.ID}, InstanceName: "guest", Status: "InProgress", StatusDetails: "In Progress", Trace: "agent trace", DeliveryID: "delivery-stable", CancelID: "cancel-stable", CancelJobID: "cancel-job-stable", DeliveredAt: at.Add(time.Second), StartedAt: at.Add(2 * time.Second), RetryAt: at.Add(time.Minute), DeliveryAcknowledged: true, CancelAcknowledged: true, Plugins: []domain.Plugin{{Name: "step-one", Action: "aws:runShellScript", Status: "Failed", StatusDetails: "Failed", Code: 7, Output: "hello\nerror\n", StandardOutput: "hello\n", StandardError: "error\n", StartedAt: at.Add(2 * time.Second), FinishedAt: at.Add(3 * time.Second), OutputBucket: "results", OutputPrefix: "owned/step-one/"}, {Name: "step-two", Action: "aws:runShellScript", Status: "Pending", Code: -1}}, ReplyIDs: []string{"reply-progress", "reply-step"}}
	return n, c, i
}
func putAll(tx domain.Transaction, n domain.Node, c domain.Command, i domain.Invocation) error {
	if err := tx.PutNode(n); err != nil {
		return err
	}
	if err := tx.PutCommand(c); err != nil {
		return err
	}
	return tx.PutInvocation(i)
}
func same[T any](t *testing.T, label string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %#v, want %#v", label, got, want)
	}
}
func TestInputsOutputsAndMessageFencesRemainDetachedAcrossRestart(t *testing.T) {
	stores(t, func(t *testing.T, s *store) {
		n, c, i := retained()
		scopes := []domain.Scope{n.Key.Scope, {Partition: "aws-cn", AccountID: n.Key.AccountID, Region: n.Key.Region}, {Partition: "aws", AccountID: "222222222222", Region: n.Key.Region}, {Partition: "aws", AccountID: n.Key.AccountID, Region: "us-west-2"}}
		for _, scope := range scopes {
			n, c, i := retained()
			n.Key.Scope, c.Key.Scope, i.Key.Command.Scope = scope, scope, scope
			if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error { return putAll(tx, n, c, i) }); err != nil {
				t.Fatal(err)
			}
			c.Parameters["commands"][0], c.InstanceIDs[0], c.Targets[0].Values[0] = "mutated", "mutated", "mutated"
			i.Plugins[0].StandardOutput, i.ReplyIDs[0] = "mutated", "mutated"
		}
		if s.reopen != nil {
			s.reopen()
		}
		for _, scope := range scopes {
			n, c, i := retained()
			n.Key.Scope, c.Key.Scope, i.Key.Command.Scope = scope, scope, scope
			if err := s.repo.View(t.Context(), func(r domain.Reader) error {
				nodes, err := r.Nodes(scope)
				if err != nil {
					return err
				}
				same(t, "scoped observations", nodes, []domain.Node{n})
				commands, err := r.Commands(scope)
				if err != nil {
					return err
				}
				same(t, "scoped inputs", commands, []domain.Command{c})
				invocations, err := r.NodeInvocations(n.Key)
				if err != nil {
					return err
				}
				same(t, "scoped fences and output", invocations, []domain.Invocation{i})
				commands[0].Parameters["commands"][0], commands[0].InstanceIDs[0], commands[0].Targets[0].Values[0] = "read mutation", "read mutation", "read mutation"
				invocations[0].Plugins[0].Output, invocations[0].ReplyIDs[0] = "read mutation", "read mutation"
				got, err := r.Command(c.Key)
				if err != nil {
					return err
				}
				same(t, "detached command", got, c)
				inv, err := r.Invocation(i.Key)
				if err != nil {
					return err
				}
				same(t, "detached invocation", inv, i)
				got.Parameters["commands"][0], inv.Plugins[0].StandardError = "point read mutation", "point read mutation"
				again, err := r.Command(c.Key)
				if err != nil {
					return err
				}
				same(t, "detached point read", again, c)
				all, err := r.Invocations(c.Key)
				if err != nil {
					return err
				}
				same(t, "detached plugin", all, []domain.Invocation{i})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		// Replacing child collections removes stale rows without replacing an invocation's identity.
		c.Parameters, c.InstanceIDs, c.Targets = map[string][]string{"commands": {}, "nil": nil}, nil, []domain.Target{}
		i.Plugins, i.ReplyIDs = []domain.Plugin{}, nil
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error { return putAll(tx, n, c, i) }); err != nil {
			t.Fatal(err)
		}
		if s.reopen != nil {
			s.reopen()
		}
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			got, err := r.Command(c.Key)
			if err != nil {
				return err
			}
			same(t, "replaced inputs", got, c)
			inv, err := r.Invocation(i.Key)
			if err != nil {
				return err
			}
			same(t, "replaced output with retained fences", inv, i)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStateAndJournalRollbackWithIsolatedAttempt(t *testing.T) {
	stores(t, func(t *testing.T, s *store) {
		n, c, i := retained()
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error { return putAll(tx, n, c, i) }); err != nil {
			t.Fatal(err)
		}
		rejected := errors.New("reject command transition")
		appendEvent := func(ctx context.Context, id string) error {
			return s.events.AppendAPICallCompleted(ctx, journal.Envelope{At: c.RequestedAt, Partition: c.Key.Partition, AccountID: c.Key.AccountID, Region: c.Key.Region, RequestID: id}, journal.APICallCompleted{EventID: id, EventSource: "ssm.amazonaws.com", EventName: "CancelCommand", Category: journal.CategoryManagement})
		}
		change := func(tx domain.Transaction) error {
			inv, err := tx.Invocation(i.Key)
			if err != nil {
				return err
			}
			inv.DeliveryID, inv.CancelJobID, inv.ReplyIDs[0], inv.Plugins[0].Output = "rejected delivery", "rejected cancellation", "rejected reply", "rejected output"
			if err := tx.PutInvocation(inv); err != nil {
				return err
			}
			cmd, err := tx.Command(c.Key)
			if err != nil {
				return err
			}
			cmd.Parameters["commands"][0] = "rejected input"
			if err := tx.PutCommand(cmd); err != nil {
				return err
			}
			if err := appendEvent(tx.Context(), "rejected-event"); err != nil {
				return err
			}
			return rejected
		}
		if err := s.repo.Update(t.Context(), change); !errors.Is(err, rejected) {
			t.Fatalf("rollback error: %v", err)
		}
		err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := s.repo.Update(tx.Context(), change); !errors.Is(err, rejected) {
				t.Fatalf("nested error: %v", err)
			}
			return nil
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("handled nested update did not abort owner: %v", err)
		}
		n.LastPing = n.LastPing.Add(time.Minute)
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := s.repo.Attempt(tx.Context(), change); !errors.Is(err, rejected) {
				t.Fatalf("attempt error: %v", err)
			}
			if err := tx.PutNode(n); err != nil {
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
			got, err := r.Command(c.Key)
			if err != nil {
				return err
			}
			same(t, "rolled back command", got, c)
			inv, err := r.Invocation(i.Key)
			if err != nil {
				return err
			}
			same(t, "rolled back output and fences", inv, i)
			node, err := r.Node(n.Key)
			if err != nil {
				return err
			}
			same(t, "committed owner observation", node, n)
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
		same(t, "atomic events", ids, []string{"committed-owner"})
	})
}

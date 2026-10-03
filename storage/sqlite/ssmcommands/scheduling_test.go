package ssmcommands_test

import (
	"errors"
	"testing"
	"time"

	domain "stackd/storage/ssmcommands"
)

func TestDeadlineIncludesAcknowledgedWorkUntilTerminal(t *testing.T) {
	stores(t, func(t *testing.T, s *store) {
		n, baseline, inv := retained()
		// Acknowledged commands still need a total delivery/execution deadline.
		cases := []struct {
			id, commandStatus, invocationStatus string
			acknowledged, omitInvocation        bool
			deadline                            time.Duration
		}{
			{"terminal-command", "Success", "Pending", false, false, -time.Hour},
			{"terminal-invocation", "InProgress", "Failed", false, false, -time.Hour},
			{"no-invocations", "Pending", "", false, true, -time.Hour},
			{"pending", "Pending", "Pending", false, false, time.Hour},
			{"delayed", "InProgress", "Delayed", false, false, 2 * time.Hour},
			{"acknowledged", "InProgress", "InProgress", true, false, 0},
			{"cancelling", "Cancelling", "Cancelling", true, false, 0},
		}
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			for _, tc := range cases {
				c, i := baseline, inv
				c.Key.ID, c.Status, c.DeliveryDeadline = tc.id, tc.commandStatus, baseline.DeliveryDeadline.Add(tc.deadline)
				if err := tx.PutCommand(c); err != nil {
					return err
				}
				if tc.omitInvocation {
					continue
				}
				i.Key.Command, i.Status, i.DeliveryAcknowledged = c.Key, tc.invocationStatus, tc.acknowledged
				if err := tx.PutInvocation(i); err != nil {
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
		for _, want := range []string{"acknowledged", "cancelling", "pending", "delayed"} {
			if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
				c, err := tx.NextDeadline()
				if err != nil {
					return err
				}
				same(t, "earliest nonterminal deadline", c.Key.ID, want)
				c.Parameters["commands"][0] = "detached deadline read"
				stored, err := tx.Command(c.Key)
				if err != nil {
					return err
				}
				same(t, "deadline inputs remain detached", stored.Parameters, baseline.Parameters)
				i, err := tx.Invocation(domain.InvocationKey{Command: c.Key, NodeID: n.Key.ID})
				if err != nil {
					return err
				}
				i.Status, i.StatusDetails, i.FinishedAt = "TimedOut", "Delivery Timed Out", c.DeliveryDeadline
				return tx.PutInvocation(i)
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			_, err := r.NextDeadline()
			if !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("terminal work scheduled: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestEmptyTargetReadinessSharesDurableDeadlineOrdering(t *testing.T) {
	stores(t, func(t *testing.T, s *store) {
		_, baseline, inv := retained()
		ready := baseline.RequestedAt.Add(time.Second)
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			for _, id := range []string{"empty-z", "empty-a", "cancelled", "completed"} {
				c := baseline
				c.Key.ID, c.Status, c.StatusDetails = id, "Pending", "Pending"
				c.InstanceIDs = []string{}
				c.EmptyTargetReadyAt = ready
				switch id {
				case "cancelled":
					c.Status, c.StatusDetails = "Cancelled", "Cancelled"
				case "completed":
					c.Status, c.StatusDetails = "Success", "NoInstancesInTag"
				}
				if err := tx.PutCommand(c); err != nil {
					return err
				}
			}
			c := baseline
			c.Key.ID, c.Status = "ordinary", "Pending"
			c.DeliveryDeadline = ready.Add(time.Second)
			if err := tx.PutCommand(c); err != nil {
				return err
			}
			inv.Key.Command, inv.Status = c.Key, "Pending"
			return tx.PutInvocation(inv)
		}); err != nil {
			t.Fatal(err)
		}
		if s.reopen != nil {
			s.reopen()
		}
		for _, want := range []string{"empty-a", "empty-z", "ordinary"} {
			if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
				c, err := tx.NextDeadline()
				if err != nil {
					return err
				}
				same(t, "ready job precedes later invocation deadline", c.Key.ID, want)
				if want != "ordinary" {
					same(t, "ready timestamp survives reopen", c.EmptyTargetReadyAt, ready)
					same(t, "public expiry remains independent", c.DeliveryDeadline, baseline.DeliveryDeadline)
				}
				c.Status, c.StatusDetails, c.EmptyTargetReadyAt = "Success", "NoInstancesInTag", time.Time{}
				return tx.PutCommand(c)
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			_, err := r.NextDeadline()
			if !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("terminal commands retained deadline jobs: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestScopedListsHaveDeterministicOrder(t *testing.T) {
	stores(t, func(t *testing.T, s *store) {
		n, c, i := retained()
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			for _, id := range []string{"i-z", "i-a", "i-m"} {
				node := n
				node.Key.ID = id
				if err := tx.PutNode(node); err != nil {
					return err
				}
			}
			for index, id := range []string{"command-z", "command-a", "command-m"} {
				cmd := c
				cmd.Key.ID = id
				cmd.RequestedAt = c.RequestedAt.Add(time.Duration(index) * time.Second)
				if err := tx.PutCommand(cmd); err != nil {
					return err
				}
				for _, nodeID := range []string{"i-z", "i-a", "i-m"} {
					inv := i
					inv.Key = domain.InvocationKey{Command: cmd.Key, NodeID: nodeID}
					if err := tx.PutInvocation(inv); err != nil {
						return err
					}
				}
			}
			// Equal instance IDs in another region must not leak into the node's poll.
			c.Key.Region = "us-west-2"
			i.Key.Command = c.Key
			i.Key.NodeID = "i-a"
			n.Key.Region = c.Key.Region
			return putAll(tx, n, c, i)
		}); err != nil {
			t.Fatal(err)
		}
		if s.reopen != nil {
			s.reopen()
		}
		n, c, _ = retained()
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			nodes, err := r.Nodes(n.Key.Scope)
			if err != nil {
				return err
			}
			nodeIDs := make([]string, 0, len(nodes))
			for _, n := range nodes {
				nodeIDs = append(nodeIDs, n.Key.ID)
			}
			same(t, "node ordering", nodeIDs, []string{"i-a", "i-m", "i-z"})
			commands, err := r.Commands(c.Key.Scope)
			if err != nil {
				return err
			}
			commandIDs := make([]string, 0, len(commands))
			for _, c := range commands {
				commandIDs = append(commandIDs, c.Key.ID)
			}
			same(t, "command ordering", commandIDs, []string{"command-a", "command-m", "command-z"})
			c.Key.ID = "command-a"
			invocations, err := r.Invocations(c.Key)
			if err != nil {
				return err
			}
			nodeIDs = nodeIDs[:0]
			for _, i := range invocations {
				nodeIDs = append(nodeIDs, i.Key.NodeID)
			}
			same(t, "invocation node ordering", nodeIDs, []string{"i-a", "i-m", "i-z"})
			n.Key.ID = "i-a"
			invocations, err = r.NodeInvocations(n.Key)
			if err != nil {
				return err
			}
			commandIDs = commandIDs[:0]
			for _, i := range invocations {
				commandIDs = append(commandIDs, i.Key.Command.ID)
			}
			same(t, "node request-time ordering and scope", commandIDs, []string{"command-z", "command-a", "command-m"})
			c.Key.ID = "missing"
			if _, err := r.Command(c.Key); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("missing command: %v", err)
			}
			invocations, err = r.Invocations(c.Key)
			if err != nil {
				return err
			}
			same(t, "missing command invocations", invocations, []domain.Invocation{})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

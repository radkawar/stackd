package ssmcommands_test

import (
	"fmt"
	"slices"
	"testing"

	domain "stackd/storage/ssmcommands"
)

func TestConcurrentRepliesDoNotLoseCommittedFences(t *testing.T) {
	stores(t, func(t *testing.T, s *store) {
		n, c, i := retained()
		i.ReplyIDs = nil
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error { return putAll(tx, n, c, i) }); err != nil {
			t.Fatal(err)
		}
		const writers = 12
		results := make(chan error, writers)
		want := make([]string, 0, writers)
		for index := range writers {
			id := fmt.Sprintf("reply-%02d", index)
			want = append(want, id)
			go func() {
				results <- s.repo.Update(t.Context(), func(tx domain.Transaction) error {
					inv, err := tx.Invocation(i.Key)
					if err != nil {
						return err
					}
					inv.ReplyIDs = append(inv.ReplyIDs, id)
					return tx.PutInvocation(inv)
				})
			}()
		}
		for range writers {
			if err := <-results; err != nil {
				t.Error(err)
			}
		}
		if t.Failed() {
			return
		}
		if s.reopen != nil {
			s.reopen()
		}
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			inv, err := r.Invocation(i.Key)
			if err != nil {
				return err
			}
			slices.Sort(inv.ReplyIDs)
			same(t, "all committed replies", inv.ReplyIDs, want)
			inv.ReplyIDs = nil
			same(t, "delivery identity and plugin results", inv, i)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

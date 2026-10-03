package memory

import (
	"context"
	"errors"
	"math"

	"golang.org/x/sync/semaphore"
)

// Domain coordinates stores whose typed state must commit together. A write
// holds exclusive access until every participating store has committed; readers
// can run concurrently. Callbacks borrow the domain through their context and
// must not perform external effects or use that context concurrently. Construct
// domains with NewDomain; a Domain must not be copied after construction.
type Domain struct{ lock *semaphore.Weighted }

func NewDomain() *Domain { return &Domain{lock: semaphore.NewWeighted(math.MaxInt64)} }

// View supplies one read snapshot to related typed stores. Callbacks must pass
// the supplied context to those stores and finish before performing writes.
func (d *Domain) View(ctx context.Context, fn func(context.Context) error) error {
	return d.run(ctx, false, func(ctx context.Context, _ *domainTransaction) error {
		return fn(ctx)
	})
}

type domainKey struct{ domain *Domain }

type domainTransaction struct {
	writable bool
	// Each entry is a pointer to one Store's typed staging value, not an
	// untyped resource record. Adapters retain ownership of schemas and copies.
	states  map[any]stagedState
	parent  *domainTransaction
	failure error
}

type stagedState interface {
	commit()
	merge(stagedState)
}

var errAborted = errors.New("memory transaction aborted")

func (d *Domain) run(ctx context.Context, write bool, fn func(context.Context, *domainTransaction) error) error {
	if current, ok := ctx.Value(domainKey{d}).(*domainTransaction); ok {
		return current.call(ctx, write, fn)
	}
	weight := int64(1)
	if write {
		weight = math.MaxInt64
	}
	if err := d.lock.Acquire(ctx, weight); err != nil {
		return err
	}
	defer d.lock.Release(weight)
	current := &domainTransaction{writable: write}
	if write {
		current.states = make(map[any]stagedState)
	}
	callbackCtx, cancel := context.WithCancel(context.WithValue(ctx, domainKey{d}, current))
	defer cancel()
	if err := current.call(callbackCtx, write, fn); err != nil {
		return err
	}
	for _, state := range current.states {
		state.commit()
	}
	return nil
}

// attempt is an explicit command savepoint. Ordinary nested Update calls keep
// their abort-on-error contract; only a command boundary may recover a failure.
func (d *Domain) attempt(ctx context.Context, fn func(context.Context, *domainTransaction) error) error {
	parent, nested := ctx.Value(domainKey{d}).(*domainTransaction)
	if !nested {
		return d.run(ctx, true, fn)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if parent.failure != nil {
		return parent.failure
	}
	if !parent.writable {
		return ErrClosedTransaction
	}
	child := &domainTransaction{writable: true, parent: parent, states: make(map[any]stagedState)}
	borrowed, cancel := context.WithCancel(context.WithValue(ctx, domainKey{d}, child))
	defer cancel()
	if err := child.call(borrowed, true, fn); err != nil {
		return err
	}
	for store, state := range child.states {
		if previous, exists := parent.states[store]; exists {
			// Existing parent adapters retain a pointer to their staging value.
			// Merge in place so they observe the accepted command's changes.
			previous.merge(state)
		} else {
			parent.states[store] = state
		}
	}
	return nil
}

// A failed nested write aborts the whole transaction, even if its caller catches
// the error or panic. There are no implicit savepoints or partial commits.
func (t *domainTransaction) call(ctx context.Context, write bool, fn func(context.Context, *domainTransaction) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.failure != nil {
		return t.failure
	}
	if write && !t.writable {
		return ErrClosedTransaction
	}
	completed := false
	defer func() {
		if write {
			if !completed {
				t.failure = errAborted
			} else if err != nil {
				t.failure = err
			}
		}
	}()
	err = fn(ctx, t)
	completed = true
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = t.failure
	}
	return err
}

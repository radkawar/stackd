package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"
)

// ErrOutcomeGroupClosed rejects work submitted after shutdown starts.
var ErrOutcomeGroupClosed = errors.New("SQLite API outcome group is closed")

// OutcomeGroup synchronously commits bounded groups of independent read-only API
// outcomes. Its callbacks must contain the complete event sink, use their supplied
// context, and perform no external effects. Mutations must not use this queue.
// A context already carrying this database's transaction executes inline instead.
// The database remains owned by the caller and must outlive Close.
type OutcomeGroup struct {
	db        *sql.DB
	queue     chan *outcomeRequest
	slots     chan struct{}
	stopping  chan struct{}
	done      chan struct{}
	batchSize int
	delay     time.Duration

	mu     sync.Mutex
	closed bool
	inline sync.WaitGroup
}

type outcomeRequest struct {
	ctx        context.Context
	fn         func(context.Context) error
	result     chan error
	err        error
	panicValue any
	panicked   bool
}

// NewOutcomeGroup uses at most 128 queued callbacks and 32 callbacks per native
// FULL commit, collecting a batch for at most one millisecond. Backpressure is
// cancellable before acceptance. Accepted calls wait for their native commit or
// rollback even when canceled; cancellation still reaches their own attempt.
func NewOutcomeGroup(db *sql.DB) *OutcomeGroup {
	return newOutcomeGroup(db, 128, 32, time.Millisecond)
}

func newOutcomeGroup(db *sql.DB, queueSize, batchSize int, delay time.Duration) *OutcomeGroup {
	g := &OutcomeGroup{
		db: db, queue: make(chan *outcomeRequest, queueSize),
		slots: make(chan struct{}, queueSize), stopping: make(chan struct{}),
		done: make(chan struct{}), batchSize: batchSize, delay: delay,
	}
	for range queueSize {
		g.slots <- struct{}{}
	}
	go g.run()
	return g
}

// Do acknowledges a successful callback only after its group's native commit.
// Callback errors roll back only that member's SAVEPOINT. A failed group commit
// fails every otherwise successful member. Callers retain ownership of their
// callback's inputs and must snapshot mutable data before calling Do.
func (g *OutcomeGroup) Do(ctx context.Context, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, borrowed := ctx.Value(transactionKey{g.db}).(*transactionScope); borrowed {
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			return ErrOutcomeGroupClosed
		}
		g.inline.Add(1)
		g.mu.Unlock()
		defer g.inline.Done()
		return fn(ctx)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.stopping:
		return ErrOutcomeGroupClosed
	case <-g.slots:
	}
	request := &outcomeRequest{ctx: ctx, fn: fn, result: make(chan error, 1)}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		g.slots <- struct{}{}
		return ErrOutcomeGroupClosed
	}
	if err := ctx.Err(); err != nil {
		g.mu.Unlock()
		g.slots <- struct{}{}
		return err
	}
	// A reserved slot guarantees that this send cannot block while holding mu.
	// Closing the queue uses the same lock, so no accepted send races with Close.
	g.queue <- request
	g.mu.Unlock()
	err := <-request.result
	if request.panicked {
		panic(request.panicValue)
	}
	return err
}

// Close rejects new calls, drains all accepted callbacks and joins the worker.
// Concurrent Close calls are safe. Call Close only outside a Do callback, after
// stopping producers, and before closing the database. Results belong to callers;
// there are no unobserved asynchronous persistence failures to report here.
func (g *OutcomeGroup) Close() error {
	g.mu.Lock()
	if !g.closed {
		g.closed = true
		close(g.stopping)
		close(g.queue)
	}
	g.mu.Unlock()
	<-g.done
	g.inline.Wait()
	return nil
}

func (g *OutcomeGroup) run() {
	defer close(g.done)
	batch := make([]*outcomeRequest, 0, g.batchSize)
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for first := range g.queue {
		g.slots <- struct{}{}
		batch = append(batch[:0], first)
		timer.Reset(g.delay)
	collect:
		for len(batch) < g.batchSize {
			select {
			case request, ok := <-g.queue:
				if !ok {
					break collect
				}
				g.slots <- struct{}{}
				batch = append(batch, request)
			case <-timer.C:
				break collect
			}
		}
		timer.Stop()
		g.commit(batch)
		clear(batch)
	}
}

func (g *OutcomeGroup) commit(batch []*outcomeRequest) {
	// No individual caller owns the batch transaction's lifetime. Only the
	// SAVEPOINT context carries that caller's values, deadline and cancellation.
	err := TransactOwned(context.Background(), g.db, false, func(group context.Context, _ *sql.Tx) error {
		parent := group.Value(transactionKey{g.db}).(*transactionScope)
		for _, request := range batch {
			ctx := context.WithValue(request.ctx, transactionKey{g.db}, parent)
			request.err = Attempt(ctx, g.db, func(ctx context.Context, _ *sql.Tx) error {
				return request.call(ctx)
			})
		}
		return nil
	})
	for _, request := range batch {
		if request.err == nil {
			request.err = err
		}
		request.result <- request.err
	}
}

func (r *outcomeRequest) call(ctx context.Context) (err error) {
	completed := false
	defer func() {
		if !completed {
			// Preserve the synchronous caller's recovery boundary, but first let
			// Attempt roll back its writes and finish the other group members.
			r.panicValue, r.panicked = recover(), true
			err = errAborted
		}
	}()
	err = r.fn(ctx)
	completed = true
	return err
}

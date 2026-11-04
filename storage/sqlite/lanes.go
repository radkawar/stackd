package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
)

const snapshotReaders = 8

var errDatabaseClosed = errors.New("SQLite database is closed")

// laneDriver belongs to one sql.DB, not to the process-wide driver registry.
// Keeping it on the connector preserves the DB identity used by SQLC statements
// and lets DB.Close stop admission and join the transactions it already owns.
// The embedded native driver still opens every physical connection normally.
type laneDriver struct {
	driver.Driver
	readers chan struct{}
	writer  chan struct{}
	done    chan struct{}
	mu      sync.Mutex
	closed  bool
	active  sync.WaitGroup
}

type laneConnector struct {
	driver.Connector
	owner *laneDriver
}

func openLaneDB(connector driver.Connector) *sql.DB {
	owner := &laneDriver{
		Driver:  connector.Driver(),
		readers: make(chan struct{}, snapshotReaders),
		writer:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	db := sql.OpenDB(&laneConnector{Connector: connector, owner: owner})
	// Every admitted callback can lease a connection without a queued writer
	// taking a reader's slot. Keep the bounded pool warm for prepared queries.
	db.SetMaxOpenConns(snapshotReaders + 1)
	db.SetMaxIdleConns(snapshotReaders + 1)
	return db
}

func (c *laneConnector) Driver() driver.Driver { return c.owner }

func (c *laneConnector) Close() error {
	c.owner.mu.Lock()
	if !c.owner.closed {
		c.owner.closed = true
		close(c.owner.done)
	}
	c.owner.mu.Unlock()
	// Add is protected by mu and forbidden after closed becomes true, so no
	// new owner can race this Wait. Owners release only after conn.Close joins
	// database/sql's cancellation-triggered native rollback.
	c.owner.active.Wait()
	if closer, ok := c.Connector.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (d *laneDriver) permit(readOnly bool) chan struct{} {
	if readOnly {
		return d.readers
	}
	return d.writer
}

func (d *laneDriver) acquire(ctx context.Context, readOnly bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	permit := d.permit(readOnly)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		return errDatabaseClosed
	case permit <- struct{}{}:
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		<-permit
		return err
	}
	if d.closed {
		<-permit
		return errDatabaseClosed
	}
	d.active.Add(1)
	return nil
}

func (d *laneDriver) release(readOnly bool) {
	<-d.permit(readOnly)
	d.active.Done()
}

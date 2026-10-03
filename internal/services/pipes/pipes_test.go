package pipes

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestInputTemplateDecodesSourceBodyAndPreservesMissingFields(t *testing.T) {
	p := PipeRecord{Key: Key{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "orders"}}
	template, err := compileTemplate(`{"body":<$.body>,"id":"<$.body.id>","absent":<$.body.absent>,"name":<aws.pipes.pipe-name>}`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := template.apply([]byte(`{"body":"{\"id\":\"one\",\"amount\":3}"}`), p, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Body   map[string]any `json:"body"`
		ID     string         `json:"id"`
		Absent string         `json:"absent"`
		Name   string         `json:"name"`
	}
	if err = json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid transformation %s: %v", out, err)
	}
	if got.Body["amount"] != float64(3) || got.ID != "one" || got.Absent != "" || got.Name != "orders" {
		t.Fatalf("unexpected transformation: %s", out)
	}
	matched, err := matches([]string{`{"body":{"amount":[{"numeric":[">",2]}]}}`}, []byte(`{"body":"{\"amount\":3}"}`))
	if err != nil || !matched {
		t.Fatalf("implicit filter match=%v error=%v", matched, err)
	}
	matched, err = matches([]string{`{"body":{"amount":[3]}}`}, []byte(`{"body":"not-json"}`))
	if err != nil || matched {
		t.Fatalf("non-JSON body matched object filter: %v %v", matched, err)
	}
}

func TestStreamFailureBlocksCheckpointAndSplitsRetriedBatch(t *testing.T) {
	now := time.Unix(100, 0)
	p := PipeRecord{Source: SourceSettings{Kind: "kinesis", BatchSize: 4, Parallelism: 1}}
	work := []Work{
		{ID: "one", RecordID: "one", ShardID: "a", Ordinal: 1, Phase: "ready", Attempts: 1, Due: now.Add(time.Second), BatchLimit: 1},
		{ID: "two", RecordID: "two", ShardID: "a", Ordinal: 2, Phase: "ready", Due: now},
		{ID: "three", RecordID: "three", ShardID: "b", Ordinal: 3, Phase: "ready", Due: now},
	}
	batch := selectBatch(p, work, now)
	if len(batch) != 1 || batch[0].ID != "three" {
		t.Fatalf("retrying shard did not fence later records: %#v", batch)
	}
	batch = selectBatch(p, work, now.Add(time.Second))
	if len(batch) != 1 || batch[0].ID != "one" {
		t.Fatalf("bisected batch ignored retained limit: %#v", batch)
	}
	work[1].Phase = "ack"
	work[2].Phase = "ack"
	ack := acknowledgeable(p, work, now)
	if len(ack) != 1 || ack[0].ID != "three" {
		t.Fatalf("checkpoint advanced across failure: %#v", ack)
	}
	work[0].Phase = "ack"
	work[0].Due = now
	ack = acknowledgeable(p, work, now)
	if len(ack) != 3 {
		t.Fatalf("completed contiguous prefix was not acknowledged: %#v", ack)
	}
}

func TestAcceptedWorkRollsBackWithCheckpoint(t *testing.T) {
	repository := NewMemoryRepository(nil)
	key := Key{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "orders"}
	err := repository.Update(context.Background(), func(tx Transaction) error {
		return tx.PutPipe(PipeRecord{Key: key, ID: "pipe"})
	})
	if err != nil {
		t.Fatal(err)
	}
	abort := errors.New("abort after checkpoint")
	err = repository.Update(context.Background(), func(tx Transaction) error {
		if err := tx.PutWork(Work{ID: "work", PipeID: "pipe", Event: []byte(`{"id":1}`)}); err != nil {
			return err
		}
		if err := tx.PutCheckpoint(Checkpoint{PipeID: "pipe", ShardID: "shard", Sequence: "123"}); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	err = repository.View(context.Background(), func(r Reader) error {
		work, err := r.Work("pipe")
		if err != nil {
			return err
		}
		checkpoints, err := r.Checkpoints("pipe")
		if err != nil {
			return err
		}
		if len(work) != 0 || len(checkpoints) != 0 {
			t.Fatalf("partial accepted transaction: %v %v", work, checkpoints)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFIFOQueueRedriveDoesNotBlockSuccessor(t *testing.T) {
	repository := NewMemoryRepository(nil)
	p := PipeRecord{
		Key: Key{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "fifo"},
		ID:  "pipe", SourceARN: "arn:aws:sqs:us-east-1:123456789012:orders.fifo",
		State: "RUNNING", Source: SourceSettings{Kind: "sqs", BatchSize: 1},
	}
	old := Work{ID: "old", PipeID: p.ID, RecordID: "old", GroupID: "group", Phase: "waiting", Ordinal: 1}
	other := Work{ID: "other", PipeID: p.ID, RecordID: "other", GroupID: "other", Phase: "waiting", Ordinal: 2}
	if err := repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutPipe(p); err != nil {
			return err
		}
		if err := tx.PutWork(old); err != nil {
			return err
		}
		return tx.PutWork(other)
	}); err != nil {
		t.Fatal(err)
	}
	service := NewWithConfig(Config{Repository: repository})
	defer service.Close()
	next := Work{ID: "next", PipeID: p.ID, RecordID: "next", GroupID: "group", Phase: "ready", Ordinal: 3}
	if err := service.retain(t.Context(), p, []Work{next}, nil); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(reader Reader) error {
		work, err := reader.Work(p.ID)
		if err != nil {
			return err
		}
		batch := selectBatch(p, work, time.Now())
		if len(work) != 2 || len(batch) != 1 || batch[0].ID != next.ID {
			t.Fatalf("redriven receipt fenced its FIFO successor: %#v", work)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

package lambda

import (
	"bytes"
	"cmp"
	"errors"
	"math"
	"slices"

	"stackd/storage/memory"
)

func (r memoryReader) DurableExecution(arn string) (v DurableExecutionRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.durable.View(r.Context(), func(rows *map[string]DurableExecutionRecord, _ *memory.Transaction) error {
		row, ok := (*rows)[arn]
		if !ok {
			return ErrNotFound
		}
		v = cloneDurableExecution(row)
		return nil
	})
	return
}

func (r memoryReader) DurableExecutions() (out []DurableExecutionRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.durable.View(r.Context(), func(rows *map[string]DurableExecutionRecord, _ *memory.Transaction) error {
		out = make([]DurableExecutionRecord, 0, len(*rows))
		for _, v := range *rows {
			out = append(out, cloneDurableExecution(v))
		}
		return nil
	})
	slices.SortFunc(out, func(a, b DurableExecutionRecord) int { return cmp.Compare(a.ARN, b.ARN) })
	return
}

func (w memoryWriter) PutDurableExecution(v DurableExecutionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if v.Function.Version > math.MaxInt64 {
		return errors.New("invalid durable function version")
	}
	return w.repository.durable.Update(w.Context(), func(rows *map[string]DurableExecutionRecord, _ *memory.Transaction) error {
		if old, ok := (*rows)[v.ARN]; ok && (old.Function != v.Function || old.ID != v.ID || old.Name != v.Name || !old.StartedAt.Equal(v.StartedAt) || old.KeyARN != v.KeyARN || old.Encrypted != v.Encrypted || !bytes.Equal(old.WrappedKey, v.WrappedKey)) {
			return errors.New("durable execution identity cannot be changed")
		}
		(*rows)[v.ARN] = cloneDurableExecution(v)
		return nil
	})
}

func (w memoryWriter) DeleteDurableExecution(arn string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.durable.Update(w.Context(), func(rows *map[string]DurableExecutionRecord, _ *memory.Transaction) error {
		delete(*rows, arn)
		return nil
	})
}

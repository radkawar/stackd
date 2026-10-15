package ec2

import (
	"errors"
	"slices"
	api "stackd/internal/awsapi/ec2"
	"strings"
)

func cloneFlowLog(v FlowLogRecord) FlowLogRecord { v.Tags = api.CloneTagList(v.Tags); return v }
func cloneFlowLogToken(v FlowLogTokenRecord) FlowLogTokenRecord {
	v.Results = slices.Clone(v.Results)
	return v
}
func cloneFlowLogDelivery(v FlowLogDeliveryRecord) FlowLogDeliveryRecord {
	v.Lines = slices.Clone(v.Lines)
	return v
}
func (r memoryReader) FlowLog(k ResourceKey) (FlowLogRecord, error) {
	return getRecord(r.tx, r.s.flowLogs, k, cloneFlowLog)
}
func (r memoryReader) FlowLogs(scope Scope) ([]FlowLogRecord, error) {
	return listRecords(r.tx, r.s.flowLogs, scope, cloneFlowLog)
}
func (r memoryReader) InternalFlowLogs() ([]FlowLogRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]FlowLogRecord, 0, len(r.s.flowLogs))
	for _, v := range r.s.flowLogs {
		out = append(out, cloneFlowLog(v))
	}
	slices.SortFunc(out, func(a, b FlowLogRecord) int { return strings.Compare(flowLogKeyString(a.Key), flowLogKeyString(b.Key)) })
	return out, nil
}
func (w memoryWriter) PutFlowLog(v FlowLogRecord) error {
	return putRecord(w.tx, w.s.flowLogs, v.Key, v, cloneFlowLog)
}
func (w memoryWriter) DeleteFlowLog(k ResourceKey) error {
	if err := deleteRecord(w.tx, w.s.flowLogs, k); err != nil {
		return err
	}
	for id := range w.s.flowLogAggregates {
		if id.FlowLogKey == k {
			delete(w.s.flowLogAggregates, id)
		}
	}
	for id, v := range w.s.flowLogDeliveries {
		if v.FlowLogKey == k {
			delete(w.s.flowLogDeliveries, id)
		}
	}
	return nil
}
func (r memoryReader) FlowLogToken(k FlowLogTokenKey) (FlowLogTokenRecord, error) {
	return getRecord(r.tx, r.s.flowLogTokens, k, cloneFlowLogToken)
}
func (w memoryWriter) PutFlowLogToken(v FlowLogTokenRecord) error {
	return putRecord(w.tx, w.s.flowLogTokens, v.Key, v, cloneFlowLogToken)
}
func (r memoryReader) FlowLogCaptureState() (FlowLogCaptureState, error) {
	if err := r.tx.Check(false); err != nil {
		return FlowLogCaptureState{}, err
	}
	if r.s.flowLogCapture == nil {
		return FlowLogCaptureState{}, ErrNotFound
	}
	return *r.s.flowLogCapture, nil
}
func (w memoryWriter) PutFlowLogCaptureState(v FlowLogCaptureState) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.flowLogCapture = &v
	return nil
}
func (r memoryReader) FlowLogAggregates(k ResourceKey) ([]FlowLogAggregateRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []FlowLogAggregateRecord{}
	for _, v := range r.s.flowLogAggregates {
		if v.Key.FlowLogKey == k {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b FlowLogAggregateRecord) int { return strings.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (w memoryWriter) PutFlowLogAggregate(v FlowLogAggregateRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.flowLogs[v.Key.FlowLogKey]; !ok {
		return ErrNotFound
	}
	return putRecord(w.tx, w.s.flowLogAggregates, v.Key, v, func(v FlowLogAggregateRecord) FlowLogAggregateRecord { return v })
}
func (w memoryWriter) DeleteFlowLogAggregate(k FlowLogAggregateKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.flowLogAggregates[k]; !ok {
		return ErrNotFound
	}
	delete(w.s.flowLogAggregates, k)
	return nil
}
func (r memoryReader) FlowLogDeliveries() ([]FlowLogDeliveryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []FlowLogDeliveryRecord{}
	for _, v := range r.s.flowLogDeliveries {
		out = append(out, cloneFlowLogDelivery(v))
	}
	slices.SortFunc(out, func(a, b FlowLogDeliveryRecord) int {
		return strings.Compare(flowLogKeyString(a.Key), flowLogKeyString(b.Key))
	})
	return out, nil
}
func (w memoryWriter) PutFlowLogDelivery(v FlowLogDeliveryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if v.Key.Scope != v.FlowLogKey.Scope {
		return errors.New("ec2: flow log delivery scope differs from subscription scope")
	}
	if _, ok := w.s.flowLogs[v.FlowLogKey]; !ok {
		return ErrNotFound
	}
	if old, ok := w.s.flowLogDeliveries[v.Key]; ok {
		old.Due, old.Version = v.Due, v.Version
		v = old
	}
	return putRecord(w.tx, w.s.flowLogDeliveries, v.Key, v, cloneFlowLogDelivery)
}
func (w memoryWriter) DeleteFlowLogDelivery(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.flowLogDeliveries, k)
}
func flowLogKeyString(k ResourceKey) string {
	return k.Scope.Partition + "\x00" + k.Scope.AccountID + "\x00" + k.Scope.Region + "\x00" + k.ID
}

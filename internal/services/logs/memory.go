package logs

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"stackd/storage/memory"
)

type memoryState struct {
	groups        map[GroupKey]GroupRecord
	streams       map[StreamKey]StreamRecord
	events        map[string]*eventNode
	policies      map[PolicyKey]PolicyRecord
	subscriptions map[SubscriptionKey]SubscriptionRecord
	deliveries    map[string]SubscriptionDelivery
	metricFilters map[MetricFilterKey]MetricFilterRecord
	destinations  map[DestinationKey]DestinationRecord
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	initial := memoryState{groups: map[GroupKey]GroupRecord{}, streams: map[StreamKey]StreamRecord{}, events: map[string]*eventNode{}, policies: map[PolicyKey]PolicyRecord{}, subscriptions: map[SubscriptionKey]SubscriptionRecord{}, deliveries: map[string]SubscriptionDelivery{}, metricFilters: map[MetricFilterKey]MetricFilterRecord{}, destinations: map[DestinationKey]DestinationRecord{}}
	return &MemoryRepository{memory.New(d, initial, func(s memoryState) memoryState {
		return memoryState{maps.Clone(s.groups), maps.Clone(s.streams), maps.Clone(s.events), maps.Clone(s.policies), maps.Clone(s.subscriptions), maps.Clone(s.deliveries), maps.Clone(s.metricFilters), maps.Clone(s.destinations)}
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryReader{s, t}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, t}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, t}}) })
}

type memoryReader struct {
	state *memoryState
	tx    *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func cloneGroup(g GroupRecord) GroupRecord      { g.Tags = maps.Clone(g.Tags); return g }
func (r memoryReader) Group(k GroupKey) (GroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return GroupRecord{}, err
	}
	g, ok := r.state.groups[k]
	if !ok {
		return g, ErrNotFound
	}
	return cloneGroup(g), nil
}
func (r memoryReader) Groups(q GroupQuery) ([]GroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []GroupRecord{}
	for k, g := range r.state.groups {
		if k.Scope == q.Scope && k.Name > q.After && strings.HasPrefix(k.Name, q.Prefix) && strings.Contains(k.Name, q.Contains) && (q.Class == "" || q.Class == "STANDARD") {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b GroupRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	for i := range out {
		out[i] = cloneGroup(out[i])
	}
	return out, nil
}
func (r memoryReader) Stream(k StreamKey) (StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return StreamRecord{}, err
	}
	v, ok := r.state.streams[k]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func compareStream(a, b StreamRecord, byTime bool) int {
	if byTime {
		if n := cmp.Compare(a.LastEvent, b.LastEvent); n != 0 {
			return n
		}
	}
	return cmp.Compare(a.Key.Name, b.Key.Name)
}
func (r memoryReader) Streams(q StreamQuery) ([]StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []StreamRecord{}
	for k, v := range r.state.streams {
		if k.GroupID != q.GroupID || !strings.HasPrefix(k.Name, q.Prefix) {
			continue
		}
		if q.After != "" {
			n := compareStream(v, StreamRecord{Key: StreamKey{Name: q.After}, LastEvent: q.AfterTime}, q.ByTime)
			if !q.Descending && n <= 0 || q.Descending && n >= 0 {
				continue
			}
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b StreamRecord) int {
		n := compareStream(a, b, q.ByTime)
		if q.Descending {
			return -n
		}
		return n
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (r memoryReader) Events(q EventQuery) ([]EventRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]EventRecord, 0, min(q.Limit, 128))
	root := r.state.events[q.GroupID]
	if q.StreamID != "" {
		root = r.state.events[q.StreamID]
	}
	var walk func(*eventNode)
	walk = func(n *eventNode) {
		if n == nil || len(out) >= q.Limit {
			return
		}
		v := n.event
		c := 0
		if q.HasCursor {
			c = compareCursor(v.EventCursor, q.Cursor)
		}
		if v.Timestamp < q.Start || q.HasCursor && !q.Backward && c <= 0 {
			walk(n.right)
			return
		}
		if v.Timestamp >= q.End || q.HasCursor && q.Backward && c >= 0 {
			walk(n.left)
			return
		}
		first, last := n.left, n.right
		if q.Backward {
			first, last = last, first
		}
		walk(first)
		if len(out) >= q.Limit {
			return
		}
		stream, live := r.state.streams[StreamKey{v.GroupID, v.StreamName}]
		if live && stream.ID == v.StreamID {
			out = append(out, v)
		}
		walk(last)
	}
	walk(root)
	return out, nil
}
func (w memoryWriter) PutGroup(g GroupRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if old, ok := w.state.groups[g.Key]; ok && old.ID != g.ID {
		return errors.New("log group identity is immutable")
	}
	w.state.groups[g.Key] = cloneGroup(g)
	return nil
}
func (w memoryWriter) DeleteGroup(k GroupKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	g, ok := w.state.groups[k]
	if !ok {
		return nil
	}
	delete(w.state.groups, k)
	delete(w.state.events, g.ID)
	for key := range w.state.subscriptions {
		if key.GroupID == g.ID {
			if err := w.DeleteSubscription(key); err != nil {
				return err
			}
		}
	}
	for key := range w.state.metricFilters {
		if key.GroupID == g.ID {
			delete(w.state.metricFilters, key)
		}
	}
	for key, policy := range w.state.policies {
		if policy.GroupID == g.ID {
			delete(w.state.policies, key)
		}
	}
	for k, v := range w.state.streams {
		if k.GroupID == g.ID {
			delete(w.state.streams, k)
			delete(w.state.events, v.ID)
		}
	}
	return nil
}
func (w memoryWriter) PutStream(v StreamRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	found := false
	for _, g := range w.state.groups {
		if g.ID == v.Key.GroupID {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	if old, ok := w.state.streams[v.Key]; ok && old.ID != v.ID {
		return errors.New("log stream identity is immutable")
	}
	w.state.streams[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteStream(k StreamKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v, ok := w.state.streams[k]
	if !ok {
		return nil
	}
	root := w.state.events[k.GroupID]
	var remove func(*eventNode)
	remove = func(n *eventNode) {
		if n == nil {
			return
		}
		remove(n.left)
		remove(n.right)
		root = deleteEvent(root, n.event.EventCursor)
	}
	remove(w.state.events[v.ID])
	w.state.events[k.GroupID] = root
	delete(w.state.streams, k)
	delete(w.state.events, v.ID)
	return nil
}
func (w memoryWriter) AppendEvent(v EventRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	stream, ok := w.state.streams[StreamKey{v.GroupID, v.StreamName}]
	if !ok || stream.ID != v.StreamID {
		return ErrNotFound
	}
	w.state.events[v.GroupID] = insertEvent(w.state.events[v.GroupID], v)
	w.state.events[v.StreamID] = insertEvent(w.state.events[v.StreamID], v)
	return nil
}

// Persistent AVL roots make a transaction copy only its changed search paths,
// never the retained history. Event messages remain immutable strings.
type eventNode struct {
	event       EventRecord
	left, right *eventNode
	height      int
	bytes       int64
}

func height(n *eventNode) int {
	if n == nil {
		return 0
	}
	return n.height
}
func eventBytes(n *eventNode) int64 {
	if n == nil {
		return 0
	}
	return n.bytes
}
func retainedBytes(n *eventNode, start int64) int64 {
	if n == nil {
		return 0
	}
	if n.event.Timestamp < start {
		return retainedBytes(n.right, start)
	}
	return int64(len(n.event.Message)) + eventBytes(n.right) + retainedBytes(n.left, start)
}
func (r memoryReader) StoredBytes(groupID string, start int64) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	return retainedBytes(r.state.events[groupID], start), nil
}
func node(v EventRecord, l, r *eventNode) *eventNode {
	return &eventNode{v, l, r, 1 + max(height(l), height(r)), int64(len(v.Message)) + eventBytes(l) + eventBytes(r)}
}
func compareCursor(a, b EventCursor) int {
	if n := cmp.Compare(a.Timestamp, b.Timestamp); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Ingestion, b.Ingestion); n != 0 {
		return n
	}
	return cmp.Compare(a.Sequence, b.Sequence)
}
func rotateLeft(n *eventNode) *eventNode {
	r := n.right
	return node(r.event, node(n.event, n.left, r.left), r.right)
}
func rotateRight(n *eventNode) *eventNode {
	l := n.left
	return node(l.event, l.left, node(n.event, l.right, n.right))
}
func insertEvent(n *eventNode, v EventRecord) *eventNode {
	if n == nil {
		return node(v, nil, nil)
	}
	c := compareCursor(v.EventCursor, n.event.EventCursor)
	if c < 0 {
		n = node(n.event, insertEvent(n.left, v), n.right)
	} else if c > 0 {
		n = node(n.event, n.left, insertEvent(n.right, v))
	} else {
		return n
	}
	return balanceNode(n)
}
func balanceNode(n *eventNode) *eventNode {
	balance := height(n.left) - height(n.right)
	if balance > 1 {
		if height(n.left.left) < height(n.left.right) {
			n = node(n.event, rotateLeft(n.left), n.right)
		}
		return rotateRight(n)
	}
	if balance < -1 {
		if height(n.right.right) < height(n.right.left) {
			n = node(n.event, n.left, rotateRight(n.right))
		}
		return rotateLeft(n)
	}
	return n
}
func deleteEvent(n *eventNode, cursor EventCursor) *eventNode {
	if n == nil {
		return nil
	}
	c := compareCursor(cursor, n.event.EventCursor)
	if c < 0 {
		return balanceNode(node(n.event, deleteEvent(n.left, cursor), n.right))
	}
	if c > 0 {
		return balanceNode(node(n.event, n.left, deleteEvent(n.right, cursor)))
	}
	if n.left == nil {
		return n.right
	}
	if n.right == nil {
		return n.left
	}
	next := n.right
	for next.left != nil {
		next = next.left
	}
	return balanceNode(node(next.event, n.left, deleteEvent(n.right, next.event.EventCursor)))
}

var _ Repository = (*MemoryRepository)(nil)

func (r memoryReader) ResourcePolicy(k PolicyKey) (PolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PolicyRecord{}, err
	}
	v, ok := r.state.policies[k]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) ResourcePolicies(q PolicyQuery) ([]PolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []PolicyRecord{}
	for k, v := range r.state.policies {
		if k.Scope == q.Scope && k.PolicyScope == q.PolicyScope && k.Name > q.After && (q.ResourceARN == "" || k.Name == q.ResourceARN) {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b PolicyRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (w memoryWriter) PutResourcePolicy(v PolicyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if v.Key.PolicyScope == PolicyScopeResource {
		k := GroupKey{Scope: v.Key.Scope}
		k.Name = strings.TrimPrefix(v.Key.Name, k.ARN())
		g, found := w.state.groups[k]
		if !found || g.ID != v.GroupID || k.ARN() != v.Key.Name {
			return ErrNotFound
		}
	}
	w.state.policies[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteResourcePolicy(k PolicyKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.policies, k)
	return nil
}

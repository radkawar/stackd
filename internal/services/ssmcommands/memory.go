package ssmcommands

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type memoryState struct {
	nodes         map[Key]Node
	commands      map[Key]Command
	invocations   map[InvocationKey]Invocation
	notifications map[string]Notification
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{nodes: map[Key]Node{}, commands: map[Key]Command{}, invocations: map[InvocationKey]Invocation{}}
	initial.notifications = map[string]Notification{}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		s.nodes = maps.Clone(s.nodes)
		s.commands = maps.Clone(s.commands)
		s.invocations = maps.Clone(s.invocations)
		s.notifications = maps.Clone(s.notifications)
		return s
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func cloneCommand(v Command) Command {
	if v.Alarm != nil {
		alarm := *v.Alarm
		v.Alarm = &alarm
	}
	v.Parameters = maps.Clone(v.Parameters)
	for k, values := range v.Parameters {
		v.Parameters[k] = slices.Clone(values)
	}
	v.InstanceIDs = slices.Clone(v.InstanceIDs)
	v.NotificationEvents = slices.Clone(v.NotificationEvents)
	v.Targets = slices.Clone(v.Targets)
	for i := range v.Targets {
		v.Targets[i].Values = slices.Clone(v.Targets[i].Values)
	}
	return v
}
func cloneInvocation(v Invocation) Invocation {
	v.Plugins = slices.Clone(v.Plugins)
	v.ReplyIDs = slices.Clone(v.ReplyIDs)
	return v
}
func compareKeys(a, b Key) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.ID, b.ID))
}
func (r memoryReader) Node(k Key) (Node, error) {
	if err := r.tx.Check(false); err != nil {
		return Node{}, err
	}
	v, ok := r.s.nodes[k]
	if !ok {
		return Node{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Nodes(scope Scope) ([]Node, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]Node, 0)
	for k, v := range r.s.nodes {
		if k.Scope == scope {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Node) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (r memoryReader) Command(k Key) (Command, error) {
	if err := r.tx.Check(false); err != nil {
		return Command{}, err
	}
	v, ok := r.s.commands[k]
	if !ok {
		return Command{}, ErrNotFound
	}
	return cloneCommand(v), nil
}
func (r memoryReader) Commands(scope Scope) ([]Command, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]Command, 0)
	for k, v := range r.s.commands {
		if k.Scope == scope {
			out = append(out, cloneCommand(v))
		}
	}
	slices.SortFunc(out, func(a, b Command) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (r memoryReader) Invocation(k InvocationKey) (Invocation, error) {
	if err := r.tx.Check(false); err != nil {
		return Invocation{}, err
	}
	v, ok := r.s.invocations[k]
	if !ok {
		return Invocation{}, ErrNotFound
	}
	return cloneInvocation(v), nil
}
func (r memoryReader) Invocations(k Key) ([]Invocation, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]Invocation, 0)
	for key, v := range r.s.invocations {
		if key.Command == k {
			out = append(out, cloneInvocation(v))
		}
	}
	slices.SortFunc(out, func(a, b Invocation) int { return cmp.Compare(a.Key.NodeID, b.Key.NodeID) })
	return out, nil
}
func (r memoryReader) NodeInvocations(k Key) ([]Invocation, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]Invocation, 0)
	for key, v := range r.s.invocations {
		if key.Command.Scope == k.Scope && key.NodeID == k.ID {
			out = append(out, cloneInvocation(v))
		}
	}
	slices.SortFunc(out, func(a, b Invocation) int {
		return cmp.Or(r.s.commands[a.Key.Command].RequestedAt.Compare(r.s.commands[b.Key.Command].RequestedAt), cmp.Compare(a.Key.Command.ID, b.Key.Command.ID))
	})
	return out, nil
}
func (r memoryReader) NextDeadline() (Command, error) {
	if err := r.tx.Check(false); err != nil {
		return Command{}, err
	}
	var next Command
	found := false
	for _, command := range r.s.commands {
		if command.EmptyTargetReadyAt.IsZero() || terminal(command.Status) {
			continue
		}
		if !found || cmp.Or(commandDeadline(command).Compare(commandDeadline(next)), compareKeys(command.Key, next.Key)) < 0 {
			next, found = command, true
		}
	}
	for key, invocation := range r.s.invocations {
		switch invocation.Status {
		case "Pending", "Delayed", "InProgress", "Cancelling":
		default:
			continue
		}
		command, ok := r.s.commands[key.Command]
		if !ok {
			continue
		}
		switch command.Status {
		case "Pending", "InProgress", "Cancelling":
		default:
			continue
		}
		if !found || cmp.Or(commandDeadline(command).Compare(commandDeadline(next)), compareKeys(command.Key, next.Key)) < 0 {
			next, found = command, true
		}
	}
	if !found {
		return Command{}, ErrNotFound
	}
	return cloneCommand(next), nil
}

func (r memoryReader) NextAlarmPoll() (Command, error) {
	if err := r.tx.Check(false); err != nil {
		return Command{}, err
	}
	var next Command
	found := false
	for _, cmd := range r.s.commands {
		if cmd.Alarm == nil || cmd.AlarmPoll.Due.IsZero() || terminal(cmd.Status) || cmd.Status == "Cancelling" {
			continue
		}
		if !found || cmp.Or(cmd.AlarmPoll.Due.Compare(next.AlarmPoll.Due), compareKeys(cmd.Key, next.Key)) < 0 {
			next, found = cmd, true
		}
	}
	if !found {
		return Command{}, ErrNotFound
	}
	return cloneCommand(next), nil
}

func (r memoryReader) AlarmRegions(partition, account string) ([]string, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var regions []string
	for _, cmd := range r.s.commands {
		if cmd.Key.Partition == partition && cmd.Key.AccountID == account && cmd.Alarm != nil && !terminal(cmd.Status) {
			regions = append(regions, cmd.Key.Region)
		}
	}
	slices.Sort(regions)
	return slices.Compact(regions), nil
}
func (w memoryWriter) PutNode(v Node) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.nodes[v.Key] = v
	return nil
}
func (w memoryWriter) PutCommand(v Command) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.commands[v.Key] = cloneCommand(v)
	return nil
}
func (w memoryWriter) PutInvocation(v Invocation) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.commands[v.Key.Command]; !ok {
		return ErrNotFound
	}
	w.s.invocations[v.Key] = cloneInvocation(v)
	return nil
}

func (r memoryReader) Notification(id string) (Notification, error) {
	if err := r.tx.Check(false); err != nil {
		return Notification{}, err
	}
	v, ok := r.s.notifications[id]
	if !ok {
		return Notification{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) NextNotification() (Notification, error) {
	if err := r.tx.Check(false); err != nil {
		return Notification{}, err
	}
	var next Notification
	found := false
	for _, v := range r.s.notifications {
		if v.MessageID != "" {
			continue
		}
		if !found || cmp.Or(v.Due.Compare(next.Due), cmp.Compare(v.ID, next.ID)) < 0 {
			next, found = v, true
		}
	}
	if !found {
		return Notification{}, ErrNotFound
	}
	return next, nil
}
func (w memoryWriter) PutNotification(v Notification) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.commands[v.Command]; !ok {
		return ErrNotFound
	}
	w.s.notifications[v.ID] = v
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}

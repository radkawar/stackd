package sqs

import (
	"net/http"
	"slices"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// moveDelivery selects the permissions used by an accepted redrive step.
// It is an internal command, not an additional AWS operation.
const moveDelivery = "MoveMessage"

const (
	moveRunning    = "RUNNING"
	moveCancelling = "CANCELLING"
	moveCancelled  = "CANCELLED"
	moveCompleted  = "COMPLETED"
	moveFailed     = "FAILED"
)

func (s *Service) registerMoves() {
	register(s, "StartMessageMoveTask", true, s.startMove)
	register(s, "ListMessageMoveTasks", true, s.listMoves)
	register(s, "CancelMessageMoveTask", true, s.cancelMove)
}
func (s *Service) moveSource(r *http.Request, arn string) (*queue, *awswire.Error) {
	key, ok := parseQueueARN(arn)
	scope := requestKey(r, "")
	if !ok {
		return nil, failure("InvalidAddress", "Invalid source queue ARN.")
	}
	if key.partition != scope.partition || key.region != scope.region || key.account != scope.account {
		return nil, failure("ResourceNotFoundException", "The source queue does not exist in this account and region.")
	}
	q := s.lookupQueue(key)
	if q == nil {
		return nil, failure("ResourceNotFoundException", "The source queue does not exist.")
	}
	s.loadMessages(q)
	s.prune(q, s.now())
	return q, nil
}
func (s *Service) movePermissions(r *http.Request, action, source, destination string) ([]authorization.Request, *awswire.Error) {
	q, err := s.moveSource(r, source)
	if err != nil {
		return nil, err
	}
	messages := q.messages
	if action == moveDelivery {
		available := q.availableMessages(s.now())
		if len(available) == 0 {
			// Waiting or completing an empty task does not perform a receive.
			// Rechecking this snapshot at commit also catches newly eligible work.
			return nil, nil
		}
		messages = available[:1]
	}
	var out []authorization.Request
	if action != moveDelivery {
		out = append(out, queuePermission(q, action))
	}
	out = append(out, queuePermission(q, "GetQueueAttributes"))
	if action == "ListMessageMoveTasks" {
		return out, nil
	}
	out = append(out, queuePermission(q, "ReceiveMessage"), queuePermission(q, "DeleteMessage"))
	if action == "CancelMessageMoveTask" {
		return out, nil
	}
	targets := make(map[queueKey]bool)
	if destination != "" {
		key, ok := parseQueueARN(destination)
		if !ok {
			return nil, failure("InvalidAddress", "Invalid destination queue ARN.")
		}
		targets[key] = true
	} else {
		for _, m := range messages {
			if key, ok := parseQueueARN(m.sourceARN); ok {
				targets[key] = true
			}
		}
	}
	keys := make([]queueKey, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b queueKey) int { return compareARN(a, b) })
	for _, key := range keys {
		target := s.lookupQueue(key)
		if target == nil {
			return nil, failure("ResourceNotFoundException", "The destination queue does not exist.")
		}
		if key.partition != q.key.partition || key.account != q.key.account || key.region != q.key.region || target.config.fifo != q.config.fifo || key == q.key {
			return nil, failure("UnsupportedOperation", "The destination must be another queue of the same type in this account and region.")
		}
		out = append(out, queuePermission(target, "SendMessage"))
	}
	return out, nil
}
func compareARN(a, b queueKey) int {
	if a.arn() < b.arn() {
		return -1
	}
	if a == b {
		return 0
	}
	return 1
}
func (s *Service) startMove(r *http.Request, in *api.StartMessageMoveTaskInput) (*api.StartMessageMoveTaskOutput, *awswire.Error) {
	q, err := s.moveSource(r, value(in.SourceArn))
	if err != nil {
		return nil, err
	}
	isDLQ := false
	for _, candidate := range s.allQueues() {
		if candidate.config.redrive != nil && candidate.config.redrive.DeadLetterTargetARN == q.key.arn() {
			isDLQ = true
			break
		}
	}
	if !isDLQ {
		return nil, failure("UnsupportedOperation", "The source must be a dead-letter queue configured for another SQS queue.")
	}
	active := 0
	for _, task := range s.tasks {
		if task.Status == moveRunning || task.Status == moveCancelling {
			if task.Source == publicKey(q.key) && task.SourceID == q.id {
				return nil, failure("UnsupportedOperation", "A message move task is already active for this queue.")
			}
			if task.Source.Account == q.key.account && task.Source.Partition == q.key.partition {
				active++
			}
		}
	}
	if active >= 100 {
		return nil, failure("UnsupportedOperation", "This account already has 100 active message move tasks.")
	}
	rate := 500
	if in.MaxNumberOfMessagesPerSecond != nil {
		rate = int(*in.MaxNumberOfMessagesPerSecond)
		if rate < 1 || rate > 500 {
			return nil, failure("InvalidParameterValue", "MaxNumberOfMessagesPerSecond must be between 1 and 500.")
		}
	}
	s.nextMove++
	task := &MoveTaskRecord{Sequence: s.nextMove, Caller: awsctx.FromContext(r.Context()), Handle: identifier() + identifier(), Source: publicKey(q.key), SourceID: q.id, Destination: value(in.DestinationArn), Status: moveRunning, Started: s.now(), Due: s.now().Add(time.Second / time.Duration(rate)), Rate: rate, CustomRate: in.MaxNumberOfMessagesPerSecond != nil, ToMove: int64(len(q.messages))}
	s.tasks[task.Handle] = task
	s.jobsChanged = true

	return &api.StartMessageMoveTaskOutput{TaskHandle: str(task.Handle)}, nil
}
func (s *Service) listMoves(r *http.Request, in *api.ListMessageMoveTasksInput) (*api.ListMessageMoveTasksOutput, *awswire.Error) {
	q, err := s.moveSource(r, value(in.SourceArn))
	if err != nil {
		return nil, err
	}
	max := 1
	if in.MaxResults != nil {
		max = int(*in.MaxResults)
	}
	if max < 1 || max > 10 {
		return nil, failure("InvalidParameterValue", "MaxResults must be between 1 and 10.")
	}
	tasks := make([]*MoveTaskRecord, 0)
	for _, task := range s.tasks {
		if task.Source == publicKey(q.key) && task.SourceID == q.id {
			tasks = append(tasks, task)
		}
	}
	slices.SortFunc(tasks, func(a, b *MoveTaskRecord) int {
		if a.Sequence > b.Sequence {
			return -1
		}
		if a.Sequence < b.Sequence {
			return 1
		}
		return 0
	})
	if len(tasks) > max {
		tasks = tasks[:max]
	}
	out := &api.ListMessageMoveTasksOutput{Results: api.ListMessageMoveTasksResultEntryList{}}
	for _, task := range tasks {
		entry := api.ListMessageMoveTasksResultEntry{SourceArn: str(privateKey(task.Source).arn()), Status: str(task.Status), StartedTimestamp: ptr(api.Long(task.Started.UnixMilli())), ApproximateNumberOfMessagesMoved: ptr(api.Long(task.Moved)), ApproximateNumberOfMessagesToMove: ptr(api.NullableLong(task.ToMove))}
		if task.Status == moveRunning {
			entry.TaskHandle = str(task.Handle)
		}
		if task.Destination != "" {
			entry.DestinationArn = str(task.Destination)
		}
		if task.CustomRate {
			entry.MaxNumberOfMessagesPerSecond = ptr(api.NullableInteger(task.Rate))
		}
		if task.Failure != "" {
			entry.FailureReason = str(task.Failure)
		}
		out.Results = append(out.Results, entry)
	}
	return out, nil
}
func (s *Service) cancelMove(_ *http.Request, in *api.CancelMessageMoveTaskInput) (*api.CancelMessageMoveTaskOutput, *awswire.Error) {
	task := s.tasks[value(in.TaskHandle)]
	if task == nil {
		return nil, failure("ResourceNotFoundException", "The specified message move task does not exist.")
	}
	if task.Status != moveRunning {
		return nil, failure("UnsupportedOperation", "Only a RUNNING message move task can be cancelled.")
	}
	task.Status = moveCancelling
	task.Due = s.now()
	s.jobsChanged = true

	return &api.CancelMessageMoveTaskOutput{ApproximateNumberOfMessagesMoved: ptr(api.Long(task.Moved))}, nil
}
func (s *Service) moveOne(r *http.Request, source, target *queue, m *message) (bool, *awswire.Error) {
	p, err := s.open(r.Context(), source, m)
	if err != nil {
		return false, err
	}
	s.loadMessages(target)
	now := s.now()
	s.prune(target, now)
	if target.config.fifo {
		if _, duplicate := target.dedup[target.dedupKey(m.group, m.id)]; duplicate {
			source.remove(m)
			return false, nil
		}
	}
	data, err := s.seal(r.Context(), target, p)
	if err != nil {
		return false, err
	}
	moved := *m
	moved.id = identifier()
	moved.data = data.data
	moved.encrypted = data.encrypted
	moved.keyARN = data.keyARN
	moved.dataKey = data.dataKey
	moved.sent = now
	moved.retentionStarted = now
	moved.available = now.Add(time.Duration(target.config.delay) * time.Second)
	moved.firstReceived = time.Time{}
	moved.lastReceived = time.Time{}
	moved.receives = 0
	moved.receipt = ""
	moved.sourceARN = ""
	moved.generation = 0
	moved.sender = awsctx.FromContext(r.Context()).PrincipalID
	if target.config.fifo {
		moved.dedup = m.id
	}
	source.remove(m)
	target.appendMessage(&moved, now)
	return true, nil
}

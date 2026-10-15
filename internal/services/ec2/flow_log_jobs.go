package ec2

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type flowLogJobs struct{ service *Service }

func flowLogAggregateJob(a FlowLogAggregateRecord) string {
	return "flow-aggregate:" + flowLogKeyString(a.Key.FlowLogKey) + ":" + a.Key.ID
}
func flowLogDeliveryJob(d FlowLogDeliveryRecord) string {
	return "flow-delivery:" + flowLogKeyString(d.Key)
}
func (j flowLogJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	s := j.service
	s.flowLogEffects.mu.Lock()
	available, retryAt := !s.flowLogEffects.active && !s.flowLogEffects.closed, s.flowLogEffects.retryAt
	s.flowLogEffects.mu.Unlock()
	if !available {
		return scheduler.Job{}, false, nil
	}
	var next scheduler.Job
	found := false
	consider := func(job scheduler.Job) {
		if !found || job.Due.Before(next.Due) || (job.Due.Equal(next.Due) && job.Key < next.Key) {
			next, found = job, true
		}
	}
	err := j.service.repository.View(ctx, func(tx Reader) error {
		state, e := tx.FlowLogCaptureState()
		if e == nil {
			consider(scheduler.Job{Key: "flow-capture", Version: state.Version, Due: state.Due})
		} else if !errors.Is(e, ErrNotFound) {
			return e
		}
		logs, e := tx.InternalFlowLogs()
		if e != nil {
			return e
		}
		for _, r := range logs {
			rows, e := tx.FlowLogAggregates(r.Key)
			if e != nil {
				return e
			}
			for _, a := range rows {
				consider(scheduler.Job{Key: flowLogAggregateJob(a), Version: uint64(a.Due.UnixNano()), Due: a.Due})
			}
		}
		deliveries, e := tx.FlowLogDeliveries()
		if e != nil {
			return e
		}
		for _, d := range deliveries {
			consider(scheduler.Job{Key: flowLogDeliveryJob(d), Version: d.Version, Due: d.Due})
		}
		return nil
	})
	if found && next.Due.Before(retryAt) {
		next.Due = retryAt
	}
	return next, found, err
}
func (j flowLogJobs) Run(ctx context.Context, job scheduler.Job) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s := j.service
	s.flowLogEffects.mu.Lock()
	defer s.flowLogEffects.mu.Unlock()
	if s.flowLogEffects.closed || s.flowLogEffects.active {
		return nil
	}
	if s.flowLogEffects.ctx == nil {
		s.flowLogEffects.ctx, s.flowLogEffects.cancel = context.WithCancel(context.Background())
	}
	s.flowLogEffects.active = true
	s.flowLogEffects.work.Go(func() {
		ctx := s.flowLogEffects.ctx
		// Reload the durable job, whose original Due may precede an in-memory
		// failure backoff; never replace its persistent fencing deadline.
		selected, ok, err := s.nextFlowLogPersistedJob(ctx, job.Key)
		if err == nil && ok && selected.Version == job.Version {
			s.flowLogMu.Lock()
			switch {
			case selected.Key == "flow-capture":
				err = s.captureFlowLogs(ctx, selected)
			case strings.HasPrefix(selected.Key, "flow-delivery:"):
				err = s.deliverFlowLogs(ctx, selected)
			default:
				err = s.sealFlowLogs(ctx, selected)
			}
			s.flowLogMu.Unlock()
		}
		if err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "EC2 flow-log reconciliation failed", "error", err)
		}
		s.flowLogEffects.mu.Lock()
		s.flowLogEffects.active = false
		s.flowLogEffects.retryAt = time.Time{}
		if err != nil && ctx.Err() == nil {
			s.flowLogEffects.retryAt = s.clock.Now().Add(time.Second)
		}
		closed := s.flowLogEffects.closed
		s.flowLogEffects.mu.Unlock()
		if !closed {
			s.jobs.Wake()
		}
	})
	return nil
}
func (s *Service) nextFlowLogPersistedJob(ctx context.Context, key string) (scheduler.Job, bool, error) {
	var out scheduler.Job
	found := false
	err := s.repository.View(ctx, func(tx Reader) error {
		if key == "flow-capture" {
			state, e := tx.FlowLogCaptureState()
			if errors.Is(e, ErrNotFound) {
				return nil
			}
			if e != nil {
				return e
			}
			out = scheduler.Job{Key: key, Version: state.Version, Due: state.Due}
			found = !state.Due.After(s.clock.Now())
			return nil
		}
		if strings.HasPrefix(key, "flow-delivery:") {
			rows, e := tx.FlowLogDeliveries()
			if e != nil {
				return e
			}
			for _, d := range rows {
				if flowLogDeliveryJob(d) == key {
					out = scheduler.Job{Key: key, Version: d.Version, Due: d.Due}
					found = !d.Due.After(s.clock.Now())
					break
				}
			}
			return nil
		}
		logs, e := tx.InternalFlowLogs()
		if e != nil {
			return e
		}
		for _, r := range logs {
			rows, e := tx.FlowLogAggregates(r.Key)
			if e != nil {
				return e
			}
			for _, a := range rows {
				if flowLogAggregateJob(a) == key {
					out = scheduler.Job{Key: key, Version: uint64(a.Due.UnixNano()), Due: a.Due}
					found = !a.Due.After(s.clock.Now())
					return nil
				}
			}
		}
		return nil
	})
	return out, found, err
}
func flowLogMatches(r FlowLogRecord, i FlowLogInterface) bool {
	if r.Key.Scope.Partition != i.Key.Scope.Partition || r.Key.Scope.Region != i.Key.Scope.Region {
		return false
	}
	switch r.ResourceType {
	case "VPC":
		return r.ResourceID == i.VPCID && i.NetworkID == resourceARN(r.Key.Scope, "vpc", i.VPCID)
	case "Subnet":
		return r.ResourceID == i.SubnetID && i.NetworkID == resourceARN(r.Key.Scope, "vpc", i.VPCID)
	case "NetworkInterface":
		return r.Key.Scope == i.Key.Scope && r.ResourceID == i.Key.ID
	}
	return false
}
func flowLogBindings(tx Reader, logs []FlowLogRecord) ([]FlowLogInterface, error) {
	scopes := map[Scope]bool{}
	seen := map[ResourceKey]bool{}
	var out []FlowLogInterface
	for _, r := range logs {
		if scopes[r.Key.Scope] {
			continue
		}
		scopes[r.Key.Scope] = true
		enis, e := tx.RegionalNetworkInterfaces(r.Key.Scope)
		if e != nil {
			return nil, e
		}
		for _, eni := range enis {
			// Native identity always comes from the repository; packet contents never
			// select an account, interface, subnet, VPC, instance, or AZ.
			if eni.Key.Scope.Partition != r.Key.Scope.Partition || eni.Key.Scope.Region != r.Key.Scope.Region || str(eni.Data.OwnerId) != eni.Key.Scope.AccountID {
				continue
			}
			subnet, e := interfaceSubnet(tx, eni)
			if errors.Is(e, ErrNotFound) {
				continue
			}
			if e != nil {
				return nil, e
			}
			i := FlowLogInterface{Key: eni.Key, Incarnation: eni.Key.ID, NetworkID: resourceARN(subnet.Key.Scope, "vpc", str(eni.Data.VpcId)), Address: str(eni.Data.PrivateIpAddress), VPCID: str(eni.Data.VpcId), SubnetID: str(eni.Data.SubnetId), AvailabilityZoneID: str(eni.Data.AvailabilityZoneId)}
			if eni.Data.Attachment != nil && !boolValue(eni.Data.RequesterManaged) {
				i.InstanceID = str(eni.Data.Attachment.InstanceId)
			}
			matched := false
			for _, log := range logs {
				if flowLogMatches(log, i) {
					matched = true
					break
				}
			}
			if matched && !seen[i.Key] {
				out = append(out, i)
				seen[i.Key] = true
			}
		}
	}
	slices.SortFunc(out, func(a, b FlowLogInterface) int {
		return strings.Compare(flowLogKeyString(a.Key), flowLogKeyString(b.Key))
	})
	return out, nil
}
func flowLogScopedContext(ctx context.Context, k ResourceKey) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ServicePrincipal: awsctx.ServicePrincipal{Name: "vpc-flow-logs.amazonaws.com", SourceARN: resourceARN(k.Scope, "vpc-flow-log", k.ID)}})
}
func sameFlowLogJob(state FlowLogCaptureState, job scheduler.Job) bool {
	return state.Version == job.Version && state.Due.Equal(job.Due)
}

// TODO: Comeback retain continuous per-ENI idle coverage before emitting NODATA; an empty read alone does not prove an idle aggregation window.
func (s *Service) captureFlowLogs(ctx context.Context, job scheduler.Job) error {
	var state FlowLogCaptureState
	var bindings []FlowLogInterface
	eligible := false
	err := s.repository.View(ctx, func(tx Reader) error {
		var e error
		state, e = tx.FlowLogCaptureState()
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if !sameFlowLogJob(state, job) || state.Due.After(s.clock.Now()) {
			return nil
		}
		logs, e := tx.InternalFlowLogs()
		if e != nil {
			return e
		}
		bindings, e = flowLogBindings(tx, logs)
		eligible = e == nil
		return e
	})
	if err != nil || !eligible {
		return err
	}
	var batch FlowLogCaptureBatch
	var captureErr error
	if s.flowLogCapture == nil {
		captureErr = errors.New("native flow capture is unavailable")
	} else {
		// Reclaim a checkpoint whose previous process committed but did not Ack.
		if state.Cursor != "" {
			captureErr = s.flowLogCapture.Acknowledge(ctx, state.Cursor)
		}
		if captureErr == nil {
			batch, captureErr = s.flowLogCapture.Read(ctx, bindings, state.Cursor)
		}
		if captureErr == nil && len(batch.Observations) > 0 && (batch.Cursor == "" || batch.Cursor == state.Cursor) {
			captureErr = errors.New("native flow capture returned observations without a new durable cursor")
		}
	}
	committed := false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.FlowLogCaptureState()
		if e != nil {
			return e
		}
		if !sameFlowLogJob(current, job) {
			return nil
		}
		logs, e := tx.InternalFlowLogs()
		if e != nil {
			return e
		}
		currentBindings, e := flowLogBindings(tx, logs)
		if e != nil {
			return e
		}
		byKey := map[ResourceKey]FlowLogInterface{}
		for _, i := range currentBindings {
			byKey[i.Key] = i
		}
		observations := batch.Observations
		if captureErr != nil {
			observations = []FlowLogObservation{{Lost: true, Start: s.clock.Now(), End: s.clock.Now()}}
		}
		for _, r := range logs {
			rows, e := tx.FlowLogAggregates(r.Key)
			if e != nil {
				return e
			}
			aggregates := make(map[FlowLogAggregateKey]FlowLogAggregateRecord, len(rows))
			for _, row := range rows {
				aggregates[row.Key] = row
			}
			for _, o := range observations {
				if !o.Lost && o.End.Before(r.CreatedAt) {
					continue
				}
				i, ok := byKey[o.InterfaceKey]
				// Unknown/incarnation-retired packets cannot be attributed. Preserve an
				// explicit gap, never a forged record for a replacement interface.
				if o.Lost || !ok || i.Incarnation != o.Incarnation {
					candidates := currentBindings
					if ok {
						candidates = []FlowLogInterface{i}
					} else {
						for _, old := range bindings {
							if old.Key == o.InterfaceKey {
								candidates = []FlowLogInterface{old}
								break
							}
						}
						if r.ResourceType == "NetworkInterface" && o.InterfaceKey.Scope == r.Key.Scope && o.InterfaceKey.ID == r.ResourceID {
							candidates = []FlowLogInterface{{Key: o.InterfaceKey, Incarnation: o.Incarnation}}
						}
					}
					for _, binding := range candidates {
						if o.InterfaceKey.Scope != (Scope{}) && o.InterfaceKey.Scope != binding.Key.Scope {
							continue
						}
						if flowLogMatches(r, binding) {
							loss := o
							loss.Lost = true
							if loss.Start.IsZero() {
								loss.Start = s.clock.Now()
							}
							if loss.End.IsZero() || loss.End.Before(loss.Start) {
								loss.End = loss.Start
							}
							if e = s.mergeFlowLogObservation(tx, r, binding, loss, aggregates); e != nil {
								return e
							}
						}
					}
					continue
				}
				if !flowLogMatches(r, i) || (r.TrafficType != "ALL" && r.TrafficType != o.Action) {
					continue
				}
				src, se := netip.ParseAddr(o.SourceAddress)
				dst, de := netip.ParseAddr(o.DestinationAddress)
				if se != nil || de != nil || src.Is4() != dst.Is4() || (o.Action != "ACCEPT" && o.Action != "REJECT") || (o.Direction != "ingress" && o.Direction != "egress") || o.Start.IsZero() || o.End.Before(o.Start) {
					loss := o
					loss.Lost = true
					if loss.Start.IsZero() {
						loss.Start = s.clock.Now()
					}
					if loss.End.IsZero() || loss.End.Before(loss.Start) {
						loss.End = loss.Start
					}
					if e = s.mergeFlowLogObservation(tx, r, i, loss, aggregates); e != nil {
						return e
					}
					continue
				}
				if e = s.mergeFlowLogObservation(tx, r, i, o, aggregates); e != nil {
					return e
				}
			}
			r.CaptureError = batch.CoverageError
			if captureErr != nil {
				r.CaptureError = captureErr.Error()
			}
			reconcileFlowLogStatus(&r)
			r.Version++
			if e = tx.PutFlowLog(r); e != nil {
				return e
			}
		}
		if captureErr == nil {
			current.Cursor = batch.Cursor
		}
		current.Due = s.clock.Now().Add(10 * time.Second)
		if captureErr == nil && batch.More {
			current.Due = s.clock.Now()
		}
		current.Version++
		if e = tx.PutFlowLogCaptureState(current); e != nil {
			return e
		}
		committed = true
		return nil
	})
	if err != nil {
		return err
	}
	if committed && captureErr == nil && batch.Cursor != "" {
		return s.flowLogCapture.Acknowledge(ctx, batch.Cursor)
	}
	return nil
}
func (s *Service) mergeFlowLogObservation(tx Transaction, r FlowLogRecord, i FlowLogInterface, o FlowLogObservation, aggregates map[FlowLogAggregateKey]FlowLogAggregateRecord) error {
	interval := time.Duration(r.AggregationSeconds) * time.Second
	window := o.Start.Unix() / int64(r.AggregationSeconds)
	identity := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%s\x00%s\x00%d\x00%t", flowLogKeyString(i.Key), o.SourceAddress, o.DestinationAddress, o.SourcePort, o.DestinationPort, o.Protocol, o.Action, o.Direction, window, o.Lost)
	if o.Lost {
		identity = fmt.Sprintf("%s\x00loss\x00%d", flowLogKeyString(i.Key), s.clock.Now().Unix()/int64(r.AggregationSeconds))
	}
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(identity)))
	a := FlowLogAggregateRecord{Key: FlowLogAggregateKey{FlowLogKey: r.Key, ID: id}, Incarnation: r.Incarnation, Interface: i, SourceAddress: o.SourceAddress, DestinationAddress: o.DestinationAddress, SourcePort: o.SourcePort, DestinationPort: o.DestinationPort, Protocol: o.Protocol, Action: o.Action, Direction: o.Direction, Start: o.Start, End: o.End, Due: s.clock.Now().Truncate(interval).Add(interval), Lost: o.Lost}
	if old, exists := aggregates[a.Key]; exists {
		a = old
	}
	if o.Start.Before(a.Start) {
		a.Start = o.Start
	}
	if o.End.After(a.End) {
		a.End = o.End
	}
	if o.Protocol == 6 {
		flags := o.TCPFlags & 7
		if o.TCPFlags&18 == 18 {
			flags |= 16
		}
		a.TCPFlags |= flags
	}
	if math.MaxUint64-a.Packets < o.Packets || math.MaxUint64-a.Bytes < o.Bytes {
		a.Lost = true
	} else {
		a.Packets += o.Packets
		a.Bytes += o.Bytes
	}
	if err := tx.PutFlowLogAggregate(a); err != nil {
		return err
	}
	aggregates[a.Key] = a
	return nil
}
func (s *Service) sealFlowLogs(ctx context.Context, job scheduler.Job) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		logs, err := tx.InternalFlowLogs()
		if err != nil {
			return err
		}
		now := s.clock.Now()
		for _, record := range logs {
			rows, err := tx.FlowLogAggregates(record.Key)
			if err != nil {
				return err
			}
			for _, aggregate := range rows {
				if flowLogAggregateJob(aggregate) != job.Key || !aggregate.Due.Equal(job.Due) || aggregate.Due.After(now) {
					continue
				}
				if aggregate.Incarnation != record.Incarnation {
					return tx.DeleteFlowLogAggregate(aggregate.Key)
				}
				return sealFlowLogBatches(tx, record, rows, now)
			}
		}
		return nil
	})
}

func sealFlowLogBatches(tx Transaction, record FlowLogRecord, rows []FlowLogAggregateRecord, now time.Time) error {
	groups := make(map[time.Time][]int)
	for index := range rows {
		aggregate := &rows[index]
		if aggregate.Due.After(now) {
			continue
		}
		if aggregate.Incarnation != record.Incarnation {
			if err := tx.DeleteFlowLogAggregate(aggregate.Key); err != nil {
				return err
			}
			continue
		}
		window := aggregate.End.UTC().Truncate(5 * time.Minute)
		groups[window] = append(groups[window], index)
	}
	windows := make([]time.Time, 0, len(groups))
	for window := range groups {
		windows = append(windows, window)
	}
	slices.SortFunc(windows, func(a, b time.Time) int { return a.Compare(b) })
	due := now
	if record.DestinationType == "s3" {
		due = due.Truncate(5 * time.Minute).Add(5 * time.Minute)
	}
	header := flowLogHeader(record.LogFormat)
	for _, window := range windows {
		indexes := groups[window]
		for len(indexes) != 0 {
			count := min(len(indexes), 1024)
			// A late native read can recreate a closed tuple/window aggregate.
			// Allocate a new committed batch identity rather than colliding with
			// its earlier immutable delivery or overwriting that S3 object.
			id, err := tx.NextID(record.Key.Scope, "flow-delivery")
			if err != nil {
				return err
			}
			lines := make([]FlowLogLine, 0, count)
			for _, index := range indexes[:count] {
				aggregate := rows[index]
				lines = append(lines, FlowLogLine{Start: aggregate.Start, InterfaceID: aggregate.Interface.Key.ID, Message: formatFlowLog(record, aggregate)})
			}
			batch := FlowLogDeliveryRecord{
				Key: ResourceKey{Scope: record.Key.Scope, ID: id}, FlowLogKey: record.Key, Incarnation: record.Incarnation,
				DestinationType: record.DestinationType, Destination: record.Destination, LogGroupName: record.LogGroupName, PermissionARN: record.PermissionARN,
				HivePartitions: record.HivePartitions, HourPartitions: record.HourPartitions,
				Header: header, Lines: lines, WindowStart: window, Due: due, Version: 1,
			}
			if err := tx.PutFlowLogDelivery(batch); err != nil {
				return err
			}
			for _, index := range indexes[:count] {
				if err := tx.DeleteFlowLogAggregate(rows[index].Key); err != nil {
					return err
				}
			}
			indexes = indexes[count:]
		}
	}
	return nil
}
func (s *Service) deliverFlowLogs(ctx context.Context, job scheduler.Job) error {
	var delivery FlowLogDeliveryRecord
	var log FlowLogRecord
	found := false
	load := func(tx Reader) error {
		rows, e := tx.FlowLogDeliveries()
		if e != nil {
			return e
		}
		for _, d := range rows {
			if flowLogDeliveryJob(d) == job.Key && d.Version == job.Version && d.Due.Equal(job.Due) && !d.Due.After(s.clock.Now()) {
				r, e := tx.FlowLog(d.FlowLogKey)
				if errors.Is(e, ErrNotFound) {
					return nil
				}
				if e != nil {
					return e
				}
				if r.Incarnation == d.Incarnation {
					delivery, log, found = d, r, true
				}
				break
			}
		}
		return nil
	}
	if e := s.repository.View(ctx, load); e != nil || !found {
		return e
	}
	var rejected *awswire.Error
	if s.flowLogDestination == nil {
		rejected = &awswire.Error{Code: "ServiceUnavailable", Message: "Flow-log destination adapter is unavailable.", StatusCode: 503}
	} else {
		rejected = s.flowLogDestination.Write(flowLogScopedContext(ctx, log.Key), delivery, delivery.Lines)
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, e := tx.FlowLogDeliveries()
		if e != nil {
			return e
		}
		for _, current := range rows {
			if current.Key != delivery.Key {
				continue
			}
			if current.Version != delivery.Version || !current.Due.Equal(delivery.Due) {
				return nil
			}
			r, e := tx.FlowLog(current.FlowLogKey)
			if errors.Is(e, ErrNotFound) {
				return nil
			}
			if e != nil {
				return e
			}
			if r.Incarnation != delivery.Incarnation {
				return nil
			}
			if rejected == nil {
				if e = tx.DeleteFlowLogDelivery(current.Key); e != nil {
					return e
				}
				r.DeliveryError = ""
			} else {
				current.Due = s.clock.Now().Add(time.Minute)
				current.Version++
				if e = tx.PutFlowLogDelivery(current); e != nil {
					return e
				}
				r.DeliveryError = rejected.Message
			}
			reconcileFlowLogStatus(&r)
			r.Version++
			return tx.PutFlowLog(r)
		}
		return nil
	})
}

// Admission checks actual collector readiness without acknowledging or
// consuming its observations. The sole durable capture checkpoint is still
// advanced only by captureFlowLogs with all aggregate changes atomically.
func (s *Service) flowLogReadiness(ctx context.Context, candidates []FlowLogRecord) error {
	if len(candidates) == 0 {
		return nil
	}
	if s.flowLogCapture == nil {
		return errors.New("native flow capture is unavailable")
	}
	s.flowLogMu.Lock()
	defer s.flowLogMu.Unlock()
	var cursor string
	var bindings []FlowLogInterface
	err := s.repository.View(ctx, func(tx Reader) error {
		state, err := tx.FlowLogCaptureState()
		if err == nil {
			cursor = state.Cursor
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		logs, err := tx.InternalFlowLogs()
		if err != nil {
			return err
		}
		logs = append(logs, candidates...)
		bindings, err = flowLogBindings(tx, logs)
		return err
	})
	if err != nil {
		return err
	}
	batch, err := s.flowLogCapture.Read(ctx, bindings, cursor)
	if err != nil {
		return err
	}
	if batch.CoverageError != "" {
		return errors.New(batch.CoverageError)
	}
	return nil
}

func reconcileFlowLogStatus(record *FlowLogRecord) {
	record.Status = "ACTIVE"
	record.DeliveryStatus = "SUCCESS"
	if record.CaptureError != "" || record.DeliveryError != "" {
		record.DeliveryStatus = "FAILED"
	}
}

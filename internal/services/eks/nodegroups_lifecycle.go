package eks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	native "stackd/compute/eks"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

func (s *Service) startNodegroups(tx Transaction) error {
	all, e := tx.AllNodegroups()
	if e != nil {
		return e
	}
	for _, n := range all {
		if n.Status == "CREATE_FAILED" || (n.Status == "DEGRADED" && n.Due.IsZero()) {
			continue
		}
		n.Due = s.clock.Now()
		n.Generation++
		if e = tx.PutNodegroup(n); e != nil {
			return e
		}
	}
	return nil
}
func nodegroupJobKey(n Nodegroup) string { return "eks-nodegroup:" + n.Key.ARN(n.ID) }
func (s *Service) nodegroupNext(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	e := s.repository.View(ctx, func(r Reader) error {
		all, e := r.AllNodegroups()
		if e != nil {
			return e
		}
		s.effects.mu.Lock()
		defer s.effects.mu.Unlock()
		if s.effects.closed {
			return nil
		}
		for _, n := range all {
			if _, active := s.effects.nodegroups[n.Key]; active || n.Due.IsZero() {
				continue
			}
			candidate := scheduler.Job{Key: nodegroupJobKey(n), Version: uint64(n.Generation), Due: n.Due}
			if !found || scheduler.Compare(candidate, next) < 0 {
				next = candidate
				found = true
			}
		}
		return nil
	})
	return next, found, e
}
func (s *Service) runNodegroupJob(ctx context.Context, job scheduler.Job) error {
	var n Nodegroup
	var c Cluster
	found := false
	e := s.repository.View(ctx, func(r Reader) error {
		all, e := r.AllNodegroups()
		if e != nil {
			return e
		}
		for _, v := range all {
			if nodegroupJobKey(v) == job.Key {
				n = v
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		c, e = r.Cluster(n.Key.Cluster)
		return e
	})
	if e != nil || !found {
		return e
	}
	if uint64(n.Generation) != job.Version || !n.Due.Equal(job.Due) || n.Due.After(s.clock.Now()) {
		return nil
	}
	s.effects.mu.Lock()
	defer s.effects.mu.Unlock()
	if s.effects.closed {
		return nil
	}
	if _, active := s.effects.nodegroups[n.Key]; active {
		return nil
	}
	s.effects.nodegroups[n.Key] = struct{}{}
	s.effects.work.Go(func() {
		ctx := awsctx.WithMetadata(s.effects.ctx, awsctx.Metadata{Partition: c.Key.Partition, AccountID: c.Key.AccountID, Region: c.Key.Region, InvokedBy: "eks-nodegroup.amazonaws.com", ServicePrincipal: awsctx.ServicePrincipal{Name: "eks-nodegroup.amazonaws.com", SourceARN: n.Key.ARN(n.ID), Type: "AWSService"}})
		if err := s.runNodegroup(ctx, c, n); err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "EKS nodegroup completion failed", "nodegroup", n.Key.ARN(n.ID), "error", err)
		}
		s.effects.mu.Lock()
		delete(s.effects.nodegroups, n.Key)
		s.effects.mu.Unlock()
		s.jobs.Wake()
	})
	return nil
}
func (s *Service) runNodegroup(ctx context.Context, c Cluster, admitted Nodegroup) error {
	n := cloneNodegroup(admitted)
	done := false
	var effectErr error
	runtime, ok := s.runtime.(native.WorkerRuntime)
	if !ok || s.nodegroups == nil {
		effectErr = errors.New("managed EC2 worker owners are unavailable")
	} else if c.ID != n.ClusterID {
		effectErr = errors.New("parent cluster incarnation changed")
	} else {
		done, effectErr = s.reconcileNodegroup(ctx, runtime, c, &n)
	}
	if errors.Is(effectErr, errStaleNodegroup) {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var deadlineCode string
	var deadlineErr error
	if !done {
		deadlineCode, deadlineErr = nodegroupDeadlineFailure(n, s.clock.Now())
		effectErr = errors.Join(effectErr, deadlineErr)
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Nodegroup(n.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != admitted.ID || current.Generation != admitted.Generation {
			return nil
		}
		if done && admitted.Operation == "delete" {
			return tx.DeleteNodegroup(n.Key)
		}
		n.Generation++
		n.Modified = s.clock.Now()
		n.Due = n.Modified.Add(5 * time.Second)
		if effectErr != nil {
			n.ErrorCode = "NodeCreationFailure"
			if slices.ContainsFunc(n.Workers, func(w NodegroupWorker) bool { return !w.DrainStarted.IsZero() }) {
				n.ErrorCode = "PodEvictionFailure"
			}
			if deadlineCode != "" {
				n.ErrorCode = deadlineCode
			}
			n.ErrorMessage = effectErr.Error()
			if n.Operation == "delete" {
				n.Status = "DELETE_FAILED"
				n.Due = n.Modified.Add(30 * time.Second)
			} else if deadlineErr != nil {
				if n.UpdateID != "" {
					update, err := tx.NodegroupUpdate(n.Key, n.UpdateID)
					if err != nil {
						return err
					}
					update.Status, update.ErrorCode, update.ErrorMessage = "Failed", n.ErrorCode, n.ErrorMessage
					if err = tx.PutNodegroupUpdate(update); err != nil {
						return err
					}
					n.Status = "DEGRADED"
				} else {
					n.Status = "CREATE_FAILED"
				}
				n.Operation, n.UpdateID = "", ""
				n.Deadline, n.Due = time.Time{}, time.Time{}
				// A failed drain must not silently reduce the surge and bypass the PDB.
				// An explicit version retry (optionally force) or deletion resumes effects.
			}
		} else {
			n.ErrorCode, n.ErrorMessage = "", ""
			if done {
				if n.UpdateID != "" {
					update, err := tx.NodegroupUpdate(n.Key, n.UpdateID)
					if err != nil {
						return err
					}
					update.Status = "Successful"
					if err = tx.PutNodegroupUpdate(update); err != nil {
						return err
					}
				}
				n.Status, n.Operation, n.UpdateID = "ACTIVE", "", ""
				n.Deadline = time.Time{}
			}
		}
		return tx.PutNodegroup(n)
	})
}
func (s *Service) reconcileNodegroup(ctx context.Context, runtime native.WorkerRuntime, c Cluster, n *Nodegroup) (bool, error) {
	before, err := s.nodegroups.Observe(ctx, *n)
	if err != nil {
		return false, err
	}
	if nodegroupYieldScaleDown(n, before) {
		return true, nil
	}
	nodes, err := runtime.ObserveWorkers(ctx, c.ID)
	if err != nil {
		return false, err
	}
	if n.Operation == "" && before.GroupARN != "" {
		n.MinSize, n.MaxSize, n.DesiredSize = before.MinSize, before.MaxSize, before.DesiredSize
	}
	deleting := n.Operation == "delete"
	if deleting {
		// ASG records desired zero and retains real instances behind our termination
		// hook. Its own lifecycle, not a second EC2 terminator, owns their removal.
		if _, err = s.nodegroups.Delete(ctx, *n); err != nil {
			return false, err
		}
	} else {
		bootstrap, err := runtime.WorkerBootstrap(ctx, c.ID)
		if err != nil {
			return false, err
		}
		capacity, scaleDown := nodegroupRolloutCapacity(*n, before, nodes)
		if before.DesiredSize < capacity && n.Deadline.IsZero() {
			n.Deadline = s.clock.Now().Add(15 * time.Minute)
		}
		if scaleDown && !n.ScaleDownStarted {
			n.ScaleDownStarted, n.ScaleDownScaleUpVersion = true, before.ScaleUpVersion
			// Retain the owner fence before the first reduction. Recovery must not
			// recapture a scale-up that raced or followed this capacity effect.
			if err = s.checkpointNodegroup(ctx, *n); err != nil {
				return false, err
			}
		}
		observed, err := s.nodegroups.Reconcile(ctx, c, *n, bootstrap, capacity)
		if err != nil {
			return false, err
		}
		before = observed
		n.ManagedTemplateID, n.ManagedTemplateVersion, n.GroupARN = observed.ManagedTemplateID, observed.ManagedTemplateVersion, observed.GroupARN
		n.AppliedTemplateGeneration = n.TemplateGeneration
		if nodegroupYieldScaleDown(n, observed) {
			return true, nil
		}
		if n.Operation == "" {
			n.MinSize, n.MaxSize, n.DesiredSize = observed.MinSize, observed.MaxSize, observed.DesiredSize
		}
	}
	// Native stale-node cleanup is fenced by the old Kubernetes UID and absence
	// from current ASG/EC2 inventory. A recreated node name is never deleted.
	for _, old := range n.Workers {
		if old.NodeUID != "" && !slices.ContainsFunc(before.Workers, func(w NodegroupWorker) bool { return w.InstanceID == old.InstanceID }) {
			if err = runtime.DeleteWorker(ctx, c.ID, old.NodeName, old.NodeUID); err != nil {
				return false, err
			}
		}
	}
	previous := n.Workers
	n.Workers = before.Workers
	var allocated int32
	for i := range n.Workers {
		w := &n.Workers[i]
		if !strings.HasPrefix(w.LifecycleState, "Terminating") {
			allocated++
		}
		if !n.Deadline.IsZero() {
			required := n.Deadline.Add(-15 * time.Minute)
			if w.BootstrapStarted.IsZero() || required.Before(w.BootstrapStarted) {
				w.BootstrapStarted = required
			}
		}
		for _, old := range previous {
			if old.InstanceID == w.InstanceID {
				if !old.BootstrapStarted.IsZero() {
					w.BootstrapStarted = old.BootstrapStarted
				}
				w.DrainStarted, w.DrainCompleted = old.DrainStarted, old.DrainCompleted
				// A pending drain belongs to the exact node incarnation it selected.
				if !old.DrainStarted.IsZero() {
					w.NodeName, w.NodeUID = old.NodeName, old.NodeUID
				}
				break
			}
		}
	}
	// This clock covers capacity not yet allocated by ASG. Once an instance
	// exists, its retained bootstrap clock owns joining; scale-down has no
	// bootstrap deadline and cannot fail an already Ready replacement.
	if deleting || allocated >= before.DesiredSize {
		n.Deadline = time.Time{}
	} else if n.Deadline.IsZero() {
		n.Deadline = s.clock.Now().Add(15 * time.Minute)
	}
	peers := make([]native.WorkerPeer, 0, len(n.Workers))
	var ready, targetReady int32
	oldCount := 0
	minimal := n.Operation == "VersionUpdate" && n.UpdateStrategy == "MINIMAL"
	for i := range n.Workers {
		w := &n.Workers[i]
		for _, node := range nodes {
			if nodegroupWorkerMatchesNode(w, &node) {
				if !w.DrainStarted.IsZero() && w.NodeUID != "" && w.NodeUID != node.UID {
					return false, errors.New("refusing to drain a replaced Kubernetes node incarnation")
				}
				w.NodeName, w.NodeUID, w.KubeletVersion, w.Ready, w.Unschedulable = node.Name, node.UID, node.Version, node.Ready, node.Unschedulable
				break
			}
		}
		if w.NodeUID != "" {
			peers = append(peers, native.WorkerPeer{InstanceARN: "arn:" + c.Key.Partition + ":ec2:" + c.Key.Region + ":" + c.Key.AccountID + ":instance/" + w.InstanceID, Address: w.PrivateIP})
		}
		currentTemplate := w.TemplateID == n.ManagedTemplateID && w.TemplateVersion == n.ManagedTemplateVersion
		if !currentTemplate {
			oldCount++
		}
		if nodegroupWorkerAvailable(*w, minimal) {
			ready++
			if (currentTemplate || n.Operation != "VersionUpdate") && strings.HasPrefix(strings.TrimPrefix(w.KubeletVersion, "v"), n.Version+".") {
				targetReady++
			}
		}
		if w.NodeUID != "" && !deleting {
			if err = runtime.ConfigureWorker(ctx, c.ID, native.WorkerConfiguration{Name: w.NodeName, UID: w.NodeUID, Nodegroup: n.Key.Name, Labels: n.Labels, Taints: n.Taints}); err != nil {
				return false, err
			}
			if minimal && !currentTemplate {
				if err = runtime.CordonWorker(ctx, c.ID, w.NodeName, w.NodeUID); err != nil {
					return false, err
				}
				w.Unschedulable = true
			}
		}
	}
	if err = runtime.ReconcileWorkerNetwork(ctx, c.ID, n.ID, peers); err != nil {
		return false, err
	}
	selectNodegroupDrains(n, s.clock.Now(), before.DesiredSize)
	// Reserve the entire eviction batch before draining any node. Lost completions
	// and controller restart must resume these same slots.
	if err = s.checkpointNodegroup(ctx, *n); err != nil {
		return false, err
	}
	var drainErr error
	pending := false
	for i := range n.Workers {
		w := &n.Workers[i]
		if w.DrainStarted.IsZero() {
			continue
		}
		pending = true
		if strings.HasPrefix(w.LifecycleState, "Terminating") && w.LifecycleState != "Terminating:Wait" {
			continue
		}
		drained := true
		if w.NodeUID != "" {
			drained, err = runtime.DrainWorker(ctx, c.ID, w.NodeName, w.NodeUID, n.Force || deleting || n.Operation != "VersionUpdate")
			if err != nil {
				drainErr = errors.Join(drainErr, err)
				continue
			}
		}
		if !drained {
			w.DrainCompleted = time.Time{}
			continue
		}
		if w.DrainCompleted.IsZero() {
			w.DrainCompleted = s.clock.Now()
			continue
		}
		if n.Operation == "VersionUpdate" && s.clock.Now().Sub(w.DrainCompleted) < 60*time.Second {
			continue
		}
		if err = s.checkpointNodegroup(ctx, *n); err != nil {
			return false, err
		}
		if w.LifecycleState == "Terminating:Wait" {
			err = s.nodegroups.CompleteTermination(ctx, *n, w.InstanceID)
		} else if !deleting {
			// Keep the replacement target stable for the whole batch. Reducing
			// it per termination lets a retry scale down unrelated members.
			err = s.nodegroups.Terminate(ctx, *n, w.InstanceID, n.Operation != "VersionUpdate")
			if err == nil && n.Operation == "VersionUpdate" && n.Deadline.IsZero() {
				n.Deadline = s.clock.Now().Add(15 * time.Minute)
			}
		}
		drainErr = errors.Join(drainErr, err)
	}
	if pending {
		return false, drainErr
	}
	if deleting {
		if len(n.Workers) > 0 {
			return false, nil
		}
		return s.nodegroups.Delete(ctx, *n)
	}
	complete := ready == n.DesiredSize && targetReady == n.DesiredSize && int32(len(n.Workers)) == n.DesiredSize && (n.Operation != "VersionUpdate" || oldCount == 0)
	return complete, nil
}

func nodegroupDeadlineFailure(n Nodegroup, now time.Time) (string, error) {
	if n.Operation == "" || n.Operation == "delete" {
		return "", nil
	}
	for _, w := range n.Workers {
		if !w.DrainStarted.IsZero() && w.DrainCompleted.IsZero() && now.Sub(w.DrainStarted) >= 15*time.Minute {
			return "PodEvictionFailure", fmt.Errorf("pods on %s could not be evicted within 15 minutes", w.InstanceID)
		}
	}
	if !n.Deadline.IsZero() && !now.Before(n.Deadline) {
		return "NodeCreationFailure", errors.New("required worker capacity was not allocated within 15 minutes")
	}
	for _, w := range n.Workers {
		if !w.DrainStarted.IsZero() || strings.HasPrefix(w.LifecycleState, "Terminating") {
			continue
		}
		if n.Operation == "VersionUpdate" && (w.TemplateID != n.ManagedTemplateID || w.TemplateVersion != n.ManagedTemplateVersion) {
			continue
		}
		if w.Ready && strings.HasPrefix(strings.TrimPrefix(w.KubeletVersion, "v"), n.Version+".") {
			continue
		}
		if !w.BootstrapStarted.IsZero() && now.Sub(w.BootstrapStarted) >= 15*time.Minute {
			return "NodeCreationFailure", fmt.Errorf("worker %s did not join Kubernetes as Ready within 15 minutes", w.InstanceID)
		}
	}
	return "", nil
}

// A scale-up during DEFAULT scale-down hands capacity back to the ASG owner.
// Finish before worker readiness or new drain reservations: its new capacity
// need not have joined yet. The ordinary idle owner resumes any existing hooks.
func nodegroupYieldScaleDown(n *Nodegroup, observed NodegroupObservation) bool {
	if n.Operation != "VersionUpdate" || n.UpdateStrategy == "MINIMAL" || !n.ScaleDownStarted || observed.ScaleUpVersion <= n.ScaleDownScaleUpVersion {
		return false
	}
	n.MinSize, n.MaxSize, n.DesiredSize = observed.MinSize, observed.MaxSize, observed.DesiredSize
	return true
}

// DEFAULT keeps its surge until every remaining member is Ready, then restores
// one ASG slot at a time. Template replacement alone does not prove that the
// instances left behind by scale-down can serve the original capacity.
// The second result permits entry to the durable scale-down phase.
func nodegroupRolloutCapacity(n Nodegroup, observed NodegroupObservation, nodes []native.Worker) (int32, bool) {
	if n.Operation != "VersionUpdate" || n.UpdateStrategy == "MINIMAL" || n.DesiredSize == 0 {
		return n.DesiredSize, false
	}
	replacementNeeded := n.AppliedTemplateGeneration != n.TemplateGeneration || slices.ContainsFunc(observed.Workers, func(w NodegroupWorker) bool {
		return w.TemplateID != n.ManagedTemplateID || w.TemplateVersion != n.ManagedTemplateVersion
	})
	if replacementNeeded {
		return n.DesiredSize + max(nodegroupUnavailableBudget(n), 2*observed.AvailabilityZoneCount), false
	}
	capacity := max(n.DesiredSize, observed.DesiredSize)
	if capacity == n.DesiredSize || int32(len(observed.Workers)) != observed.DesiredSize {
		return capacity, false
	}
	for _, w := range observed.Workers {
		if w.LifecycleState != "InService" || !slices.ContainsFunc(nodes, func(node native.Worker) bool {
			return nodegroupWorkerMatchesNode(&w, &node) && node.Ready && !node.Unschedulable && strings.HasPrefix(strings.TrimPrefix(node.Version, "v"), n.Version+".")
		}) {
			return capacity, false
		}
	}
	return capacity - 1, true
}

func nodegroupWorkerMatchesNode(w *NodegroupWorker, node *native.Worker) bool {
	return node.Name == w.InstanceID && node.InternalIP == w.PrivateIP && node.ProviderID == "aws:///"+w.AvailabilityZone+"/"+w.InstanceID
}

// Percentages round up so every nonempty group can make progress, and the API
// limits either form to at most 100 concurrent replacements.
func nodegroupUnavailableBudget(n Nodegroup) int32 {
	budget := n.MaxUnavailable
	if n.MaxUnavailablePercentage > 0 {
		budget = int32(min(int64(100), (int64(n.DesiredSize)*int64(n.MaxUnavailablePercentage)+99)/100))
	}
	return min(max(budget, 1), max(n.DesiredSize, 1))
}

func nodegroupWorkerAvailable(w NodegroupWorker, allowCordoned bool) bool {
	return w.Ready && (allowCordoned || !w.Unschedulable) && w.LifecycleState == "InService" && w.DrainStarted.IsZero()
}

func selectNodegroupDrains(n *Nodegroup, now time.Time, capacity int32) {
	budget := nodegroupUnavailableBudget(*n)
	minimal := n.Operation == "VersionUpdate" && n.UpdateStrategy == "MINIMAL"
	var active, available int32
	for _, w := range n.Workers {
		if !w.DrainStarted.IsZero() {
			active++
		}
		if nodegroupWorkerAvailable(w, minimal) {
			available++
		}
	}
	slots := max(int32(0), budget-active)
	// ASG health replacements and scale-down already consume availability.
	// A blocked PDB on one member must not prevent draining the other slots.
	for i := range n.Workers {
		w := &n.Workers[i]
		if slots > 0 && w.DrainStarted.IsZero() && w.LifecycleState == "Terminating:Wait" {
			w.DrainStarted = now
			slots--
		}
	}
	if n.Operation != "VersionUpdate" {
		return
	}
	if !minimal {
		if int32(len(n.Workers)) < capacity {
			return
		}
		for _, w := range n.Workers {
			if w.TemplateID == n.ManagedTemplateID && w.TemplateVersion == n.ManagedTemplateVersion && !nodegroupWorkerAvailable(w, false) {
				return
			}
			if w.TemplateID != n.ManagedTemplateID || w.TemplateVersion != n.ManagedTemplateVersion {
				if !slices.ContainsFunc(n.Workers, func(replacement NodegroupWorker) bool {
					return replacement.AvailabilityZone == w.AvailabilityZone && replacement.TemplateID == n.ManagedTemplateID && replacement.TemplateVersion == n.ManagedTemplateVersion && nodegroupWorkerAvailable(replacement, false)
				}) {
					return
				}
			}
		}
	}
	floor := n.DesiredSize
	if minimal {
		floor = max(int32(0), floor-budget)
	}
	for i := range n.Workers {
		w := &n.Workers[i]
		if slots == 0 {
			break
		}
		if !w.DrainStarted.IsZero() || w.LifecycleState != "InService" {
			continue
		}
		if w.TemplateID == n.ManagedTemplateID && w.TemplateVersion == n.ManagedTemplateVersion {
			continue
		}
		if nodegroupWorkerAvailable(*w, minimal) {
			if available <= floor {
				continue
			}
			available--
		}
		w.DrainStarted = now
		slots--
	}
}

var errStaleNodegroup = errors.New("nodegroup generation changed")

func (s *Service) checkpointNodegroup(ctx context.Context, n Nodegroup) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Nodegroup(n.Key)
		if errors.Is(err, ErrNotFound) {
			return errStaleNodegroup
		}
		if err != nil {
			return err
		}
		if current.ID != n.ID || current.Generation != n.Generation {
			return errStaleNodegroup
		}
		return tx.PutNodegroup(n)
	})
}

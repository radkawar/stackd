package eks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"stackd/clock"
	native "stackd/compute/eks"
	api "stackd/internal/awsapi/eks"
)

func rolloutWorkers(count int, version string) []NodegroupWorker {
	workers := make([]NodegroupWorker, count)
	for i := range workers {
		workers[i] = NodegroupWorker{InstanceID: fmt.Sprintf("i-%s-%03d", version, i), TemplateID: "lt-owned", TemplateVersion: version, LifecycleState: "InService", Ready: true}
	}
	return workers
}

func retiringWorkers(n Nodegroup) []string {
	var ids []string
	for _, w := range n.Workers {
		if !w.DrainStarted.IsZero() {
			ids = append(ids, w.InstanceID)
		}
	}
	return ids
}

// These are rollout decisions over retained owner observations, not a fake
// successful worker runtime. The executable smoke owns native drain/ASG proof.
func TestNodegroupRolloutBudgetBoundaries(t *testing.T) {
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                         string
		desired, maximum, percentage int32
		strategy                     string
		surge, unavailable, want     int
	}{
		{name: "absolute parallel default", desired: 5, maximum: 3, strategy: "DEFAULT", surge: 3, want: 3},
		{name: "absolute minimal", desired: 5, maximum: 3, strategy: "MINIMAL", want: 3},
		{name: "percentage rounds up", desired: 5, percentage: 25, strategy: "MINIMAL", want: 2},
		{name: "percentage capped at hundred", desired: 250, percentage: 100, strategy: "MINIMAL", want: 100},
		{name: "absolute bounded by membership", desired: 3, maximum: 100, strategy: "MINIMAL", want: 3},
		{name: "external unavailability consumes slots", desired: 5, maximum: 2, strategy: "MINIMAL", unavailable: 1, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := Nodegroup{DesiredSize: tc.desired, Operation: "VersionUpdate", ManagedTemplateID: "lt-owned", ManagedTemplateVersion: "new", Workers: rolloutWorkers(int(tc.desired), "old")}
			config := &api.NodegroupUpdateConfig{UpdateStrategy: new(api.NodegroupUpdateStrategies(tc.strategy))}
			if tc.percentage > 0 {
				config.MaxUnavailablePercentage = new(api.PercentCapacity(tc.percentage))
			} else {
				config.MaxUnavailable = new(api.NonZeroInteger(tc.maximum))
			}
			if err := mergeNodegroupUpdateConfig(&n, config); err != nil {
				t.Fatal(err)
			}
			for i := range tc.unavailable {
				n.Workers[len(n.Workers)-1-i].Ready = false
			}
			n.Workers = append(n.Workers, rolloutWorkers(tc.surge, "new")...)
			selectNodegroupDrains(&n, now, tc.desired+int32(tc.surge))
			selected := retiringWorkers(n)
			if len(selected) != tc.want {
				t.Fatalf("selected %v; budget requires %d concurrent drains", selected, tc.want)
			}
			// PDB retries and force never create additional availability slots.
			n.Force = true
			selectNodegroupDrains(&n, now.Add(time.Minute), tc.desired+int32(tc.surge))
			if got := retiringWorkers(n); !slices.Equal(got, selected) {
				t.Fatalf("retry expanded pending batch: %v -> %v", selected, got)
			}
		})
	}
}

func TestNodegroupDrainReservationsSurviveRecoveryAndFenceStaleSelection(t *testing.T) {
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := NewMemoryRepository(nil)
	s := New(Config{Repository: repo, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = s.Close() })
	n := Nodegroup{Key: NodegroupKey{Cluster: Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "control"}, Name: "workers"}, ID: "group-incarnation", Generation: 7, Status: "UPDATING", Operation: "VersionUpdate", Due: now, DesiredSize: 3, MaxUnavailable: 2, UpdateStrategy: "MINIMAL", ManagedTemplateID: "lt-owned", ManagedTemplateVersion: "new", Workers: rolloutWorkers(3, "old")}
	for i := range n.Workers {
		n.Workers[i].Unschedulable = true
	}
	if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutNodegroup(n) }); err != nil {
		t.Fatal(err)
	}
	selectNodegroupDrains(&n, now, n.DesiredSize)
	selected := retiringWorkers(n)
	if err := s.checkpointNodegroup(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	// Model process loss after cordoning, before the normal completion commit.
	if err := repo.Update(t.Context(), s.startNodegroups); err != nil {
		t.Fatal(err)
	}
	if err := s.checkpointNodegroup(t.Context(), n); !errors.Is(err, errStaleNodegroup) {
		t.Fatalf("old generation overwrote recovered intent: %v", err)
	}
	if err := repo.View(t.Context(), func(r Reader) error { var err error; n, err = r.Nodegroup(n.Key); return err }); err != nil {
		t.Fatal(err)
	}
	selectNodegroupDrains(&n, now.Add(time.Minute), n.DesiredSize)
	if got := retiringWorkers(n); !slices.Equal(got, selected) || len(got) != 2 {
		t.Fatalf("recovery lost the pending batch: %v", got)
	}
	// One drained member has left the ASG, but its replacement is not Ready.
	// The other drain still consumes a slot even if its cordon is not observed.
	n.Workers = n.Workers[1:]
	replacement := rolloutWorkers(1, "new")[0]
	replacement.Ready = false
	n.Workers = append(n.Workers, replacement)
	selectNodegroupDrains(&n, now.Add(2*time.Minute), n.DesiredSize)
	if got := retiringWorkers(n); !slices.Equal(got, selected[1:]) {
		t.Fatalf("unready replacement incorrectly released an availability slot: %v", got)
	}
	n.Workers[len(n.Workers)-1].Ready = true
	selectNodegroupDrains(&n, now.Add(3*time.Minute), n.DesiredSize)
	if got := retiringWorkers(n); len(got) != 2 || !slices.Contains(got, selected[1]) {
		t.Fatalf("Ready replacement did not release exactly one slot: %v", got)
	}
}

func TestNodegroupDefaultScaleDownPreservesReadyCapacity(t *testing.T) {
	n := Nodegroup{Operation: "VersionUpdate", UpdateStrategy: "DEFAULT", DesiredSize: 3, MaxUnavailable: 2, Version: "1.33", ManagedTemplateID: "lt-owned", ManagedTemplateVersion: "new"}
	observed := NodegroupObservation{DesiredSize: 5, Workers: rolloutWorkers(5, "new")}
	var nodes []native.Worker
	for i := range observed.Workers {
		observed.Workers[i].PrivateIP = fmt.Sprintf("10.0.0.%d", i+10)
		observed.Workers[i].AvailabilityZone = "us-east-1a"
	}
	for _, worker := range observed.Workers[:4] {
		nodes = append(nodes, native.Worker{Name: worker.InstanceID, UID: worker.InstanceID + "-uid", InternalIP: worker.PrivateIP, ProviderID: "aws:///" + worker.AvailabilityZone + "/" + worker.InstanceID, Version: "v1.33.4+k3s1", Ready: true})
	}
	if got, scaleDown := nodegroupRolloutCapacity(n, observed, nodes); got != 5 || scaleDown {
		t.Fatalf("scale-down removed Ready surge before the final replacement joined: %d", got)
	}
	last := observed.Workers[4]
	nodes = append(nodes, native.Worker{Name: last.InstanceID, UID: last.InstanceID + "-uid", InternalIP: last.PrivateIP, ProviderID: "aws:///" + last.AvailabilityZone + "/" + last.InstanceID, Version: "v1.33.4+k3s1"})
	if got, scaleDown := nodegroupRolloutCapacity(n, observed, nodes); got != 5 || scaleDown {
		t.Fatalf("a registered but unready replacement released scale-down: %d", got)
	}
	nodes[4].Ready = true
	nodes[4].ProviderID = "aws:///us-east-1b/" + last.InstanceID
	if got, scaleDown := nodegroupRolloutCapacity(n, observed, nodes); got != 5 || scaleDown {
		t.Fatalf("an unbound Ready node released owned ASG capacity: %d", got)
	}
	nodes[4].ProviderID = "aws:///" + last.AvailabilityZone + "/" + last.InstanceID
	if got, scaleDown := nodegroupRolloutCapacity(n, observed, nodes); got != 4 || !scaleDown {
		t.Fatalf("Ready surge must restore one ASG slot, not the entire surplus: %d", got)
	}
	observed.DesiredSize = 4
	observed.Workers[0].LifecycleState = "Terminating:Wait"
	if got, scaleDown := nodegroupRolloutCapacity(n, observed, nodes); got != 4 || scaleDown {
		t.Fatalf("scale-down raced the unfinished prior termination: %d", got)
	}
	observed.Workers = observed.Workers[1:]
	if got, scaleDown := nodegroupRolloutCapacity(n, observed, nodes); got != 3 || !scaleDown {
		t.Fatalf("completed termination did not release the next scale-down step: %d", got)
	}
}

func TestNodegroupDefaultSurgeCoversAvailabilityZones(t *testing.T) {
	n := Nodegroup{Operation: "VersionUpdate", UpdateStrategy: "DEFAULT", DesiredSize: 3, MaxUnavailable: 2, ManagedTemplateID: "lt-owned", ManagedTemplateVersion: "new"}
	observed := NodegroupObservation{DesiredSize: 9, AvailabilityZoneCount: 2, Workers: rolloutWorkers(3, "old")}
	if got, scaleDown := nodegroupRolloutCapacity(n, observed, nil); got != 7 || scaleDown {
		t.Fatalf("two AZs require four surge slots above the live baseline: %d", got)
	}
	n.DesiredSize, n.MaxUnavailable = 20, 12
	observed.AvailabilityZoneCount = 5
	if got, scaleDown := nodegroupRolloutCapacity(n, observed, nil); got != 32 || scaleDown {
		t.Fatalf("maxUnavailable must dominate the smaller AZ surge: %d", got)
	}
}

func TestNodegroupDefaultWaitsForReadySurgeInEveryOccupiedZone(t *testing.T) {
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, boundary := range []string{"unallocated surge", "unready surge", "missing occupied zone", "ready in every zone"} {
		t.Run(boundary, func(t *testing.T) {
			n := Nodegroup{Operation: "VersionUpdate", UpdateStrategy: "DEFAULT", DesiredSize: 3, MaxUnavailable: 2, ManagedTemplateID: "lt-owned", ManagedTemplateVersion: "new", Workers: rolloutWorkers(3, "old")}
			n.Workers = append(n.Workers, rolloutWorkers(4, "new")...)
			for i := range n.Workers {
				n.Workers[i].AvailabilityZone = "us-east-1a"
			}
			n.Workers[1].AvailabilityZone = "us-east-1b"
			n.Workers[6].AvailabilityZone = "us-east-1b"
			switch boundary {
			case "unallocated surge":
				n.Workers[3] = n.Workers[6]
				n.Workers = n.Workers[:6]
			case "unready surge":
				n.Workers[3].Ready = false
			case "missing occupied zone":
				n.Workers[6].AvailabilityZone = "us-east-1a"
			}
			selectNodegroupDrains(&n, now, 7)
			want := 0
			if boundary == "ready in every zone" {
				want = 2
			}
			if got := retiringWorkers(n); len(got) != want {
				t.Fatalf("selected %v with incomplete surge boundary %q; want %d drains", got, boundary, want)
			}
		})
	}
}

func TestNodegroupPhaseDeadlineBoundaries(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/eks/nodegroup_deadlines.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Now   time.Time
		Cases []struct {
			Name      string
			Nodegroup Nodegroup
			Code      string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Cases {
		t.Run(row.Name, func(t *testing.T) {
			code, err := nodegroupDeadlineFailure(row.Nodegroup, fixture.Now)
			if code != row.Code || (err != nil) != (row.Code != "") {
				t.Fatalf("deadline failure = %q, %v; want %q", code, err, row.Code)
			}
		})
	}
}

// These owner snapshots stop at the first native configuration effect. They
// exercise phase decisions and durable update outcomes, not native worker effects.
type scaleDownCompute struct {
	NodegroupCompute
	observed  NodegroupObservation
	reconcile func(context.Context, Nodegroup, int32) (NodegroupObservation, error)
}

func (o scaleDownCompute) Observe(context.Context, Nodegroup) (NodegroupObservation, error) {
	observed := o.observed
	observed.Workers = slices.Clone(observed.Workers)
	return observed, nil
}

func (o scaleDownCompute) Reconcile(ctx context.Context, _ Cluster, n Nodegroup, _ native.WorkerBootstrap, capacity int32) (NodegroupObservation, error) {
	return o.reconcile(ctx, n, capacity)
}

type scaleDownRuntime struct {
	native.Runtime
	native.WorkerRuntime
	nodes      []native.Worker
	observeErr error
	effectErr  error
}

func (r scaleDownRuntime) ObserveWorkers(context.Context, string) ([]native.Worker, error) {
	return r.nodes, r.observeErr
}

func (r scaleDownRuntime) WorkerBootstrap(context.Context, string) (native.WorkerBootstrap, error) {
	return native.WorkerBootstrap{}, nil
}

func (r scaleDownRuntime) ConfigureWorker(context.Context, string, native.WorkerConfiguration) error {
	return r.effectErr
}

func scaleDownObservation(desired int32, version uint64) (NodegroupObservation, []native.Worker) {
	observed := NodegroupObservation{GroupARN: "asg-owned", ManagedTemplateID: "lt-owned", ManagedTemplateVersion: "new", MinSize: 1, MaxSize: desired + 1, DesiredSize: desired, ScaleUpVersion: version, Workers: rolloutWorkers(int(desired), "new")}
	nodes := make([]native.Worker, len(observed.Workers))
	for i := range observed.Workers {
		w := &observed.Workers[i]
		w.PrivateIP, w.AvailabilityZone = fmt.Sprintf("10.0.0.%d", i+10), "us-east-1a"
		w.NodeName, w.NodeUID = w.InstanceID, w.InstanceID+"-uid"
		nodes[i] = native.Worker{Name: w.NodeName, UID: w.NodeUID, InternalIP: w.PrivateIP, ProviderID: "aws:///" + w.AvailabilityZone + "/" + w.InstanceID, Version: "v1.33.4+k3s1", Ready: true}
	}
	return observed, nodes
}

func TestNodegroupDefaultScaleDownOwnerTransitions(t *testing.T) {
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, row := range []struct {
		name                            string
		strategy                        string
		started, restart, pending, done bool
		initialDesired, returnedDesired int32
		initialVersion, returnedVersion uint64
		capacity                        int32
	}{
		{name: "increase before first effect", started: true, done: true, initialDesired: 6, initialVersion: 8, capacity: -1},
		{name: "increase after a step with outstanding hook", started: true, pending: true, done: true, initialDesired: 5, initialVersion: 8, capacity: -1},
		{name: "increase racing first effect", done: true, initialDesired: 5, initialVersion: 7, returnedDesired: 6, returnedVersion: 8, capacity: 4},
		{name: "recovery retains original counter", started: true, restart: true, done: true, initialDesired: 6, initialVersion: 8, capacity: -1},
		{name: "first decrease checkpoints phase", initialDesired: 5, initialVersion: 7, returnedDesired: 4, returnedVersion: 7, capacity: 4},
		{name: "normal decrease is not scale-up", started: true, initialDesired: 4, initialVersion: 7, returnedDesired: 3, returnedVersion: 7, capacity: 3},
		{name: "minimal ignores scale-up exit", strategy: "MINIMAL", initialDesired: 3, initialVersion: 8, returnedDesired: 3, returnedVersion: 8, capacity: 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			before, nodes := scaleDownObservation(row.initialDesired, row.initialVersion)
			before.MinSize = 2
			n := Nodegroup{Key: NodegroupKey{Cluster: Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "control"}, Name: "workers"}, ID: "group-incarnation", ClusterID: "control-incarnation", Generation: 7, Status: "UPDATING", Operation: "VersionUpdate", UpdateID: "version-update", Due: now, MinSize: 1, MaxSize: 3, DesiredSize: 3, MaxUnavailable: 2, Version: "1.33", UpdateStrategy: "DEFAULT", ManagedTemplateID: "lt-owned", ManagedTemplateVersion: "new", ScaleDownStarted: row.started, ScaleDownScaleUpVersion: 7, Workers: slices.Clone(before.Workers)}
			if row.strategy != "" {
				n.UpdateStrategy = row.strategy
			}
			if row.pending {
				n.Workers[0].LifecycleState = "Terminating:Wait"
				n.Workers[0].DrainStarted = now.Add(-time.Minute)
				before.Workers[0].LifecycleState = "Terminating:Wait"
			}
			if row.done {
				// External capacity is not yet allocated and must not run out the
				// previous update's bootstrap clock before its successful exit.
				n.Deadline = now.Add(-time.Second)
			}
			repo := NewMemoryRepository(nil)
			if err := repo.Update(t.Context(), func(tx Transaction) error {
				if err := tx.PutNodegroup(n); err != nil {
					return err
				}
				return tx.PutNodegroupUpdate(NodegroupUpdate{Key: n.Key, ID: n.UpdateID, Type: "VersionUpdate", Status: "InProgress"})
			}); err != nil {
				t.Fatal(err)
			}
			effectErr := errors.New("native worker effect boundary")
			runtime := scaleDownRuntime{nodes: nodes, effectErr: effectErr}
			if row.capacity < 0 {
				runtime.observeErr = errors.New("external capacity is still joining")
			}
			owner := scaleDownCompute{observed: before}
			after := before
			owner.reconcile = func(ctx context.Context, candidate Nodegroup, capacity int32) (NodegroupObservation, error) {
				if capacity != row.capacity {
					t.Fatalf("capacity = %d, want %d", capacity, row.capacity)
				}
				if candidate.UpdateStrategy != "MINIMAL" {
					if err := repo.View(ctx, func(r Reader) error {
						checkpoint, err := r.Nodegroup(n.Key)
						if err == nil && (!checkpoint.ScaleDownStarted || checkpoint.ScaleDownScaleUpVersion != 7) {
							t.Fatalf("first capacity effect lacks durable owner fence: %#v", checkpoint)
						}
						return err
					}); err != nil {
						t.Fatal(err)
					}
				}
				after.DesiredSize, after.MaxSize, after.ScaleUpVersion = row.returnedDesired, row.returnedDesired+1, row.returnedVersion
				return after, nil
			}
			s := New(Config{Repository: repo, Clock: clock.NewManual(now), Runtime: runtime, Nodegroups: owner})
			t.Cleanup(func() { _ = s.Close() })
			if row.restart {
				stale := n
				if err := repo.Update(t.Context(), s.startNodegroups); err != nil {
					t.Fatal(err)
				}
				if err := s.checkpointNodegroup(t.Context(), stale); !errors.Is(err, errStaleNodegroup) {
					t.Fatalf("pre-restart phase overwrote recovery: %v", err)
				}
				if err := repo.View(t.Context(), func(r Reader) error { var err error; n, err = r.Nodegroup(n.Key); return err }); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.runNodegroup(t.Context(), Cluster{ID: n.ClusterID}, n); err != nil {
				t.Fatal(err)
			}
			if err := repo.View(t.Context(), func(r Reader) error {
				retained, err := r.Nodegroup(n.Key)
				if err != nil {
					return err
				}
				update, err := r.NodegroupUpdate(n.Key, n.UpdateID)
				if err != nil {
					return err
				}
				if row.done {
					if update.Status != "Successful" || retained.Status != "ACTIVE" || retained.Operation != "" || !retained.Deadline.IsZero() {
						t.Fatalf("scale-up did not finish immediately: group=%#v update=%#v", retained, update)
					}
					if retained.MinSize != after.MinSize || retained.MaxSize != after.MaxSize || retained.DesiredSize != after.DesiredSize || retained.Due.IsZero() {
						t.Fatalf("scale-up lost live scaling or idle recovery: %#v", retained)
					}
					if !slices.Equal(retiringWorkers(retained), retiringWorkers(n)) {
						t.Fatal("scale-up exit changed pending drain reservations")
					}
					// An ASG hook not reserved before the exit is still selected by
					// the ordinary idle owner, despite the retained phase marker.
					retained.Workers = slices.Clone(before.Workers)
					retained.Workers[0].LifecycleState = "Terminating:Wait"
					selectNodegroupDrains(&retained, now, retained.DesiredSize)
					if retained.Workers[0].DrainStarted.IsZero() {
						t.Fatal("idle recovery stranded a termination hook")
					}
				} else {
					if update.Status != "InProgress" || retained.Operation != "VersionUpdate" || retained.DesiredSize != 3 || retained.ErrorMessage != effectErr.Error() {
						t.Fatalf("ordinary rollout unexpectedly exited: group=%#v update=%#v", retained, update)
					}
				}
				if retained.ScaleDownStarted != (row.started || row.strategy != "MINIMAL") || retained.ScaleDownScaleUpVersion != 7 {
					t.Fatalf("owner phase was recaptured or lost: %#v", retained)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodegroupLaterUpdateCapturesNewScaleDownCounter(t *testing.T) {
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := NewMemoryRepository(nil)
	// The preceding exit adopted the owner's live baseline of five. Its old
	// phase must neither stop the next rollout nor be reused by that rollout.
	n := Nodegroup{Key: NodegroupKey{Cluster: Key{Name: "control"}, Name: "workers"}, ID: "group", Status: "ACTIVE", Version: "1.33", MinSize: 1, MaxSize: 6, DesiredSize: 5, UpdateStrategy: "DEFAULT", MaxUnavailable: 2, ManagedTemplateID: "lt-owned", ManagedTemplateVersion: "new", ScaleDownStarted: true, ScaleDownScaleUpVersion: 7}
	s := New(Config{Repository: repo, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = s.Close() })
	if err := repo.Update(t.Context(), func(tx Transaction) error {
		_, err := s.admitNodegroupUpdate(tx, n, "VersionUpdate", "later-request", "later-hash", nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(t.Context(), func(r Reader) error { var err error; n, err = r.Nodegroup(n.Key); return err }); err != nil {
		t.Fatal(err)
	}
	if n.ScaleDownStarted || n.ScaleDownScaleUpVersion != 0 {
		t.Fatalf("later admission retained the previous phase: %#v", n)
	}
	before, nodes := scaleDownObservation(7, 12)
	effectErr := errors.New("stop at guarded capacity effect")
	s.nodegroups = scaleDownCompute{observed: before, reconcile: func(_ context.Context, _ Nodegroup, capacity int32) (NodegroupObservation, error) {
		if capacity != 6 {
			t.Fatalf("later update used stale baseline: capacity %d", capacity)
		}
		return NodegroupObservation{}, effectErr
	}}
	if done, err := s.reconcileNodegroup(t.Context(), scaleDownRuntime{nodes: nodes}, Cluster{}, &n); done || !errors.Is(err, effectErr) {
		t.Fatalf("later scale-down did not reach its first guarded reduction: %v, %v", done, err)
	}
	if err := repo.View(t.Context(), func(r Reader) error {
		retained, err := r.Nodegroup(n.Key)
		if err == nil && (!retained.ScaleDownStarted || retained.ScaleDownScaleUpVersion != 12 || retained.DesiredSize != 5) {
			t.Fatalf("later phase failed to retain its own owner baseline: %#v", retained)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

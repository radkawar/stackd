package ebs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	blockapi "stackd/internal/awsapi/ebs"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// Block before entering the repository, not while holding its transaction. This
// models slow native hydration without making metadata reads slow by construction.
type blockedNativeRepository struct {
	Repository
	mu       sync.Mutex
	views    int
	blockAt  int
	entered  chan struct{}
	release  chan struct{}
	putCount map[VolumeBlockKey]int
}

func (r *blockedNativeRepository) View(ctx context.Context, fn func(Reader) error) error {
	if awsctx.FromContext(ctx).InvokedBy == "ec2.amazonaws.com" {
		r.mu.Lock()
		r.views++
		block := r.views == r.blockAt
		r.mu.Unlock()
		if block {
			close(r.entered)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-r.release:
			}
		}
	}
	return r.Repository.View(ctx, fn)
}

func (r *blockedNativeRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.Repository.Update(ctx, func(tx Transaction) error {
		return fn(countNativeBlocks{Transaction: tx, owner: r})
	})
}

type countNativeBlocks struct {
	Transaction
	owner *blockedNativeRepository
}

func (tx countNativeBlocks) PutVolumeBlock(block VolumeBlockRecord) error {
	if err := tx.Transaction.PutVolumeBlock(block); err != nil {
		return err
	}
	tx.owner.mu.Lock()
	tx.owner.putCount[block.Key]++
	tx.owner.mu.Unlock()
	return nil
}

// This is an independent joined metadata source, not an EBS native backend.
type otherMetadataJob struct {
	mu      sync.Mutex
	pending bool
	due     time.Time
	ran     chan struct{}
}

func (j *otherMetadataJob) Next(context.Context) (scheduler.Job, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return scheduler.Job{Key: "other-service-metadata", Due: j.due}, j.pending, nil
}

func (j *otherMetadataJob) Run(context.Context, scheduler.Job) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.pending {
		j.pending = false
		close(j.ran)
	}
	return nil
}

func awaitNativeSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("native lifecycle did not make bounded progress")
	}
}

func awaitNativeError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("native lifecycle did not return after cancellation")
		return nil
	}
}

func drainNativeJobs(t *testing.T, driver *scheduler.Driver) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if result, err := driver.RunDue(ctx, 256); err != nil || result.More {
		t.Fatalf("shared drain did not finish: result=%+v error=%v", result, err)
	}
}

func nativeHydrationFixture(t *testing.T, blockAt int) (*blockedNativeRepository, VolumeRecord, SnapshotRecord, map[int32][]byte, *clock.Manual) {
	t.Helper()
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	scope := Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	source := SnapshotRecord{Key: SnapshotKey{Scope: scope, ID: "snap-source"}, Created: now,
		Status: blockapi.StatusCOMPLETED, Sealed: true, Readable: true, VolumeSize: 1, LineageID: "source-lineage"}
	volume := VolumeRecord{Key: VolumeKey{Scope: scope, ID: "vol-hydrating"}, Created: now,
		Status: api.VolumeStateCreating, TransitionAt: now, RequestID: "create-volume", LineageID: "volume-lineage",
		Configuration: VolumeConfiguration{Size: 1, Type: "gp3", Iops: 3000, Throughput: 125},
		ZoneName:      "us-east-1a", ZoneID: "use1-az1", SnapshotID: source.Key.ID,
		Creation: &VolumeCreation{Source: source.Key}}
	metadata := SnapshotRecord{Key: SnapshotKey{Scope: scope, ID: "snap-metadata"}, Created: now,
		Status: blockapi.StatusPENDING, Sealed: true, CompleteAt: now.Add(time.Second), ReadableAt: now.Add(2 * time.Second), VolumeSize: 1}
	payloads := map[int32][]byte{1: bytes.Repeat([]byte{0, 0xff, 0x13, 0x7f}, BlockSize/4), 9: bytes.Repeat([]byte{0x42, 0, 0xfe, 0x2b}, BlockSize/4)}
	repository := NewMemoryRepository(nil)
	if err := repository.Update(t.Context(), func(tx Transaction) error {
		for _, snapshot := range []SnapshotRecord{source, metadata} {
			if err := tx.PutSnapshot(snapshot); err != nil {
				return err
			}
		}
		if err := tx.PutVolume(volume); err != nil {
			return err
		}
		for index, data := range payloads {
			if err := tx.PutBlock(BlockRecord{BlockInfo: BlockInfo{Key: BlockKey{Snapshot: source.Key, Index: index}, Checksum: sha256.Sum256(data), WrittenSnapshotID: source.Key.ID}, Data: data}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return &blockedNativeRepository{Repository: repository, blockAt: blockAt, entered: make(chan struct{}), release: make(chan struct{}), putCount: map[VolumeBlockKey]int{}}, volume, metadata, payloads, clock.NewManual(now)
}

func TestNativeHydrationDoesNotHoldSharedDrainAndRecoversAfterClose(t *testing.T) {
	// The first block is committed before the second block read is suspended.
	repository, volume, metadata, payloads, source := nativeHydrationFixture(t, 4)
	s := New(Config{Repository: repository, Clock: source})
	t.Cleanup(func() { _ = s.Close() })
	other := &otherMetadataJob{ran: make(chan struct{})}
	driver, err := scheduler.Join(nil, s.JobDriver(), scheduler.New(source, other))
	if err != nil {
		t.Fatal(err)
	}
	drainNativeJobs(t, driver)
	awaitNativeSignal(t, repository.entered)
	for range 10 {
		drainNativeJobs(t, driver)
		if err := (snapshotJobs{s}).Run(t.Context(), scheduler.Job{}); err != nil {
			t.Fatal(err)
		}
	}
	repository.mu.Lock()
	views, writes := repository.views, len(repository.putCount)
	repository.mu.Unlock()
	if views != 4 || writes != 1 {
		t.Fatalf("native flight was repeated or lost its recovery cursor: views=%d writes=%d", views, writes)
	}

	readCtx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: volume.Key.Partition, AccountID: volume.Key.AccountID, Region: volume.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", RequestID: "describe-while-hydrating"})
	readCtx, cancelRead := context.WithTimeout(readCtx, 2*time.Second)
	defer cancelRead()
	response, err := s.DescribeVolumes(readCtx, &api.DescribeVolumesRequest{})
	if err != nil || len(response.Volumes) != 1 || value(response.Volumes[0].State) != string(api.VolumeStateCreating) {
		t.Fatalf("control read during native work: response=%+v error=%v", response, err)
	}

	source.Advance(time.Second)
	other.mu.Lock()
	other.pending, other.due = true, source.Now()
	other.mu.Unlock()
	drainNativeJobs(t, driver)
	awaitNativeSignal(t, other.ran)
	if err := repository.Repository.View(t.Context(), func(r Reader) error {
		current, err := r.Snapshot(metadata.Key)
		if err == nil && (current.Status != blockapi.StatusCOMPLETED || current.Readable) {
			t.Errorf("completion deadline changed: %+v", current)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	source.Advance(time.Second)
	drainNativeJobs(t, driver)
	if err := repository.Repository.View(t.Context(), func(r Reader) error {
		current, err := r.Snapshot(metadata.Key)
		if err == nil && !current.Readable {
			t.Error("readability deadline remained behind blocked native work")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// EC2 closes before EBS. Its PrepareInstanceVolumes waiter must leave on
	// its own cancellation, before this dependency's native flight is canceled.
	prepareCtx, cancelPrepare := context.WithCancel(t.Context())
	observed := &observedNativeContext{Context: prepareCtx, entered: make(chan struct{})}
	prepared := make(chan error, 1)
	go func() { _, err := s.PrepareInstanceVolumes(observed, api.Instance{}); prepared <- err }()
	awaitNativeSignal(t, observed.entered)
	cancelPrepare()
	if err := awaitNativeError(t, prepared); !errors.Is(err, context.Canceled) {
		t.Fatalf("consumer shutdown waited for dependency work: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	if err := awaitNativeError(t, closed); err != nil {
		t.Fatal(err)
	}
	if err := repository.Repository.View(t.Context(), func(r Reader) error {
		current, err := r.Volume(volume.Key)
		if err != nil {
			return err
		}
		blocks, err := r.VolumeBlocks(volume.Key)
		if current.Status != api.VolumeStateCreating || current.Creation == nil || len(blocks) != 1 {
			t.Errorf("shutdown lost retained work: volume=%+v blocks=%d", current, len(blocks))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}

	reopened := New(Config{Repository: repository, Clock: source})
	t.Cleanup(func() { _ = reopened.Close() })
	drainNativeJobs(t, reopened.JobDriver())
	done := make(chan struct{})
	go func() { reopened.native.work.Wait(); close(done) }()
	awaitNativeSignal(t, done)
	if err := repository.Repository.View(t.Context(), func(r Reader) error {
		current, err := r.Volume(volume.Key)
		if err != nil {
			return err
		}
		if current.Status != api.VolumeStateAvailable || current.Creation != nil {
			t.Errorf("reopened work did not finish: %+v", current)
		}
		for index, expected := range payloads {
			block, err := r.VolumeBlock(VolumeBlockKey{Volume: volume.Key, Index: index})
			if err != nil {
				return err
			}
			if !bytes.Equal(block.Data, expected) || block.Checksum != sha256.Sum256(expected) {
				t.Errorf("reopened hydration changed block %d", index)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for key, count := range repository.putCount {
		if count != 1 {
			t.Errorf("committed block was repeated after reopen: key=%+v writes=%d", key, count)
		}
	}
	if len(repository.putCount) != len(payloads) {
		t.Errorf("reopened hydration did not write each source block exactly once: %v", repository.putCount)
	}
}

func TestNativeHydrationDoesNotPublishIntoReplacement(t *testing.T) {
	repository, volume, _, _, source := nativeHydrationFixture(t, 3)
	s := New(Config{Repository: repository, Clock: source})
	t.Cleanup(func() { _ = s.Close() })
	drainNativeJobs(t, s.JobDriver())
	awaitNativeSignal(t, repository.entered)
	replacement := volume
	replacement.Created = volume.Created.Add(time.Hour)
	replacement.RequestID, replacement.LineageID = "replacement-request", "replacement-lineage"
	replacement.Status, replacement.Creation, replacement.TransitionAt = api.VolumeStateAvailable, nil, time.Time{}
	replacement.Tags = map[string]string{"generation": "replacement"}
	if err := repository.Repository.Update(t.Context(), func(tx Transaction) error { return tx.PutVolume(replacement) }); err != nil {
		t.Fatal(err)
	}
	close(repository.release)
	done := make(chan struct{})
	go func() { s.native.work.Wait(); close(done) }()
	awaitNativeSignal(t, done)
	if err := repository.Repository.View(t.Context(), func(r Reader) error {
		current, err := r.Volume(volume.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, replacement) {
			t.Errorf("stale hydration changed replacement metadata: %+v", current)
		}
		blocks, err := r.VolumeBlocks(volume.Key)
		if len(blocks) != 0 {
			t.Errorf("stale hydration wrote replacement bytes: %d blocks", len(blocks))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if len(repository.putCount) != 0 {
		t.Fatalf("stale hydration attempted native writes: %v", repository.putCount)
	}
}

// Observing Done proves that an acquisition reached its cancellation-aware wait
// while the existing owner still holds the gate. No timing sleep is required.
type observedNativeContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
}

func (c *observedNativeContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestNativeWorkMutexCanceledWaiterKeepsOwnership(t *testing.T) {
	var gate nativeWorkMutex
	if err := gate.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	allocated := gate.gate
	ctx, cancel := context.WithCancel(t.Context())
	observed := &observedNativeContext{Context: ctx, entered: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- gate.Lock(observed) }()
	awaitNativeSignal(t, observed.entered)
	cancel()
	if err := awaitNativeError(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter acquired an owned gate: %v", err)
	}
	if len(gate.gate) != 1 {
		t.Fatal("canceled waiter released a gate it did not acquire")
	}
	gate.Unlock()
	following, cancelFollowing := context.WithTimeout(t.Context(), time.Second)
	defer cancelFollowing()
	if err := gate.Lock(following); err != nil {
		t.Fatalf("following acquisition failed: %v", err)
	}
	gate.Unlock()
	if gate.gate != allocated {
		t.Fatal("gate was allocated more than once")
	}
	alreadyCanceled, cancelAlready := context.WithCancel(t.Context())
	cancelAlready()
	if err := gate.Lock(alreadyCanceled); !errors.Is(err, context.Canceled) || len(gate.gate) != 0 {
		t.Fatalf("pre-canceled acquisition changed ownership: error=%v occupied=%d", err, len(gate.gate))
	}
	if err := gate.Lock(following); err != nil {
		t.Fatalf("acquisition after pre-canceled waiter failed: %v", err)
	}
	gate.Unlock()
}

func TestNativeWorkMutexConcurrentFirstAcquisition(t *testing.T) {
	var gate nativeWorkMutex
	start := make(chan struct{})
	done := make(chan struct{})
	var work sync.WaitGroup
	allocations := map[chan struct{}]bool{}
	admitted := 0
	for range 32 {
		work.Go(func() {
			<-start
			if err := gate.Lock(t.Context()); err != nil {
				t.Error(err)
				return
			}
			defer gate.Unlock()
			allocations[gate.gate] = true
			admitted++
		})
	}
	close(start)
	go func() { work.Wait(); close(done) }()
	awaitNativeSignal(t, done)
	if admitted != 32 || len(allocations) != 1 || len(gate.gate) != 0 {
		t.Fatalf("concurrent first acquisition changed gate ownership: admitted=%d allocations=%d occupied=%d", admitted, len(allocations), len(gate.gate))
	}
}

package eks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

// DefaultStorageReserveGiB is the creation-time native Docker worker reserve.
const DefaultStorageReserveGiB int64 = 64

const storageGiB int64 = 1 << 30

// nativeStoragePolicy is immutable creation policy, not an AWS EKS API field.
// A nil policy identifies a retained cluster using its original native defaults.
type nativeStoragePolicy struct {
	ReserveGiB           int64
	CapacityBytes        int64
	ImageGCHighThreshold int
	ImageGCLowThreshold  int
}

func validateStorageReserve(reserveGiB int64) error {
	if reserveGiB <= 0 || reserveGiB > math.MaxInt64/(2*storageGiB) {
		return errors.New("eks: storage reserve must be positive GiB with a representable twice-reserve recovery target")
	}
	return nil
}

func storagePolicy(capacityBytes, reserveGiB int64) (nativeStoragePolicy, error) {
	if err := validateStorageReserve(reserveGiB); err != nil {
		return nativeStoragePolicy{}, err
	}
	reserveBytes := reserveGiB * storageGiB
	if capacityBytes <= 2*reserveBytes {
		return nativeStoragePolicy{}, errors.New("eks: Docker backing filesystem capacity must exceed twice the native storage reserve")
	}
	// Floor used-space percentages, so integer rounding starts GC no later and
	// reclaims no less than the requested free-space watermarks. Mul64 avoids
	// overflowing on a large daemon filesystem before division by capacity.
	percent := func(used int64) int {
		hi, lo := bits.Mul64(uint64(used), 100)
		q, _ := bits.Div64(hi, lo, uint64(capacityBytes))
		return int(q)
	}
	high := percent(capacityBytes - reserveBytes - reserveBytes/2)
	low := percent(capacityBytes - 2*reserveBytes)
	if low >= high {
		// Native GC requires distinct integer thresholds. On large volumes one
		// percent can exceed half a reserve; reclaim more, never shrink R.
		low = high - 1
	}
	if low < 0 || high <= low || high >= 100 {
		return nativeStoragePolicy{}, errors.New("eks: native storage reserve cannot produce valid distinct image GC percentages")
	}
	return nativeStoragePolicy{ReserveGiB: reserveGiB, CapacityBytes: capacityBytes, ImageGCHighThreshold: high, ImageGCLowThreshold: low}, nil
}

func dockerFilesystemCapacity(output []byte) (int64, error) {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		return 0, errors.New("eks: Docker storage probe must report one df -Pk filesystem")
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 6 || fields[5] != "/" {
		return 0, errors.New("eks: invalid Docker storage probe filesystem")
	}
	kib, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || kib <= 0 || kib > math.MaxInt64/1024 {
		return 0, errors.New("eks: invalid or overflowing Docker filesystem capacity")
	}
	return kib * 1024, nil
}

func (k *K3d) prepareStoragePolicy(ctx context.Context, state *diskState, dir string) error {
	if state.StoragePolicy != nil {
		_, err := state.StoragePolicy.kubeletArguments()
		return err
	}
	// The probe runs on the explicitly selected daemon, not the controller's
	// filesystem (which can be on another host or outside Docker Desktop's VM).
	out, err := k.command(ctx, "docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only", "--label", ownerLabel+"="+state.Token, "--label", idLabel+"="+state.ID, "--entrypoint", "df", "ghcr.io/k3d-io/k3d-tools:5.8.3", "-Pk", "/")
	if err != nil {
		return err
	}
	capacity, err := dockerFilesystemCapacity(out)
	if err != nil {
		return err
	}
	policy, err := storagePolicy(capacity, k.config.StorageReserveGiB)
	if err != nil {
		return err
	}
	state.StoragePolicy = &policy
	// Persist before any worker is created; retries and future Fargate workers
	// must not reinterpret a changed controller flag or filesystem capacity.
	return saveState(dir, *state)
}

func (p *nativeStoragePolicy) kubeletArguments() ([]string, error) {
	if p == nil {
		return nil, nil
	}
	want, err := storagePolicy(p.CapacityBytes, p.ReserveGiB)
	if err != nil {
		return nil, err
	}
	if *p != want {
		return nil, errors.New("eks: invalid retained native storage policy")
	}
	reserve := strconv.FormatInt(p.ReserveGiB, 10) + "Gi"
	return []string{
		"eviction-hard=memory.available<100Mi,nodefs.available<" + reserve + ",imagefs.available<" + reserve + ",nodefs.inodesFree<5%,imagefs.inodesFree<5%",
		"eviction-minimum-reclaim=nodefs.available=" + reserve + ",imagefs.available=" + reserve,
		fmt.Sprintf("image-gc-high-threshold=%d", p.ImageGCHighThreshold),
		fmt.Sprintf("image-gc-low-threshold=%d", p.ImageGCLowThreshold),
	}, nil
}

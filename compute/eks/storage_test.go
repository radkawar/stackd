package eks

import (
	"math"
	"slices"
	"strings"
	"testing"
)

func TestNativeStoragePolicy(t *testing.T) {
	for _, tc := range []struct {
		name              string
		capacity, reserve int64
		high, low         int
		invalid           bool
	}{
		{name: "synthetic non-power-of-two capacity", capacity: 640 * storageGiB, reserve: 64, high: 85, low: 80},
		{name: "fractional percentages round conservatively", capacity: 256 * storageGiB, reserve: 64, high: 62, low: 50},
		{name: "just enough capacity", capacity: 128*storageGiB + 1, reserve: 64, high: 25, low: 0},
		{name: "sub-percent gap stays distinct", capacity: 1 << 62, reserve: 1, high: 99, low: 98},
		{name: "maximum capacity multiplication", capacity: math.MaxInt64, reserve: 64, high: 99, low: 98},
		{name: "maximum representable recovery target", capacity: math.MaxInt64, reserve: math.MaxInt64 / (2 * storageGiB), high: 25, low: 0},
		{name: "zero reserve", capacity: 256 * storageGiB, invalid: true},
		{name: "negative reserve", capacity: 256 * storageGiB, reserve: -1, invalid: true},
		{name: "recovery overflow", capacity: math.MaxInt64, reserve: math.MaxInt64/(2*storageGiB) + 1, invalid: true},
		{name: "reserve overflow", capacity: math.MaxInt64, reserve: math.MaxInt64, invalid: true},
		{name: "zero capacity", reserve: 64, invalid: true},
		{name: "negative capacity", capacity: -1, reserve: 64, invalid: true},
		{name: "insufficient capacity", capacity: 127 * storageGiB, reserve: 64, invalid: true},
		{name: "no room above recovery", capacity: 128 * storageGiB, reserve: 64, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := storagePolicy(tc.capacity, tc.reserve)
			if tc.invalid {
				if err == nil {
					t.Fatalf("accepted invalid policy: %+v", policy)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if policy.ReserveGiB != tc.reserve || policy.CapacityBytes != tc.capacity || policy.ImageGCHighThreshold != tc.high || policy.ImageGCLowThreshold != tc.low {
				t.Fatalf("policy=%+v; want reserve=%d capacity=%d high=%d low=%d", policy, tc.reserve, tc.capacity, tc.high, tc.low)
			}
			if policy.ImageGCLowThreshold < 0 || policy.ImageGCLowThreshold >= policy.ImageGCHighThreshold || policy.ImageGCHighThreshold >= 100 {
				t.Fatalf("invalid native percentages: %+v", policy)
			}
		})
	}
}

func TestNativeStorageProbeCapacity(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		capacity     int64
	}{
		{name: "synthetic daemon df", output: "Filesystem 1024-blocks Used Available Capacity Mounted on\noverlay 671088640 100 200 1% /\n", capacity: 640 * storageGiB},
		{name: "empty"},
		{name: "missing filesystem", output: "Filesystem 1024-blocks Used Available Capacity Mounted on\n"},
		{name: "multiple filesystems", output: "header\noverlay 100 1 99 1% /\nother 100 1 99 1% /other\n"},
		{name: "wrong mount", output: "header\noverlay 100 1 99 1% /data\n"},
		{name: "nonnumeric", output: "header\noverlay invalid 1 99 1% /\n"},
		{name: "zero", output: "header\noverlay 0 1 99 1% /\n"},
		{name: "negative", output: "header\noverlay -1 1 99 1% /\n"},
		{name: "KiB conversion overflow", output: "header\noverlay 9007199254740992 1 99 1% /\n"},
		{name: "integer overflow", output: "header\noverlay 9223372036854775808 1 99 1% /\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capacity, err := dockerFilesystemCapacity([]byte(tc.output))
			if tc.capacity == 0 {
				if err == nil {
					t.Fatalf("accepted invalid probe: %d", capacity)
				}
			} else if err != nil || capacity != tc.capacity {
				t.Fatalf("capacity=%d error=%v; want %d", capacity, err, tc.capacity)
			}
		})
	}
}

func TestNativeStorageWorkerArguments(t *testing.T) {
	policy, err := storagePolicy(256*storageGiB, 64)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"eviction-hard=memory.available<100Mi,nodefs.available<64Gi,imagefs.available<64Gi,nodefs.inodesFree<5%,imagefs.inodesFree<5%",
		"eviction-minimum-reclaim=nodefs.available=64Gi,imagefs.available=64Gi",
		"image-gc-high-threshold=62",
		"image-gc-low-threshold=50",
	}
	args, err := policy.kubeletArguments()
	if err != nil || !slices.Equal(args, want) {
		t.Fatalf("kubelet arguments=%q error=%v", args, err)
	}
	k := &K3d{}
	args, err = k.workerArguments(diskState{StoragePolicy: &policy}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range want {
		if !slices.Contains(args, "--kubelet-arg="+arg+"@agent:0") {
			t.Fatalf("missing bootstrap kubelet argument %q in %q", arg, args)
		}
	}
	legacyArgs, err := k.workerArguments(diskState{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range legacyArgs {
		if strings.Contains(arg, "eviction-") || strings.Contains(arg, "image-gc-") {
			t.Fatalf("rewrote legacy creation policy: %q", legacyArgs)
		}
	}
	policy.ImageGCLowThreshold = policy.ImageGCHighThreshold
	if _, err := policy.kubeletArguments(); err == nil {
		t.Fatal("accepted invalid retained GC thresholds")
	}
}

func TestNativeStoragePolicyRetainedAcrossReopen(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "absolute"
		if legacy {
			name = "legacy defaults"
		}
		t.Run(name, func(t *testing.T) {
			config := Config{DataDir: t.TempDir(), DockerHost: "unix:///explicit-daemon.sock", ListenHost: "127.0.0.1", AdvertiseHost: "127.0.0.1", StorageReserveGiB: 64}
			k := &K3d{config: config}
			state, dir, err := k.loadOrPrepare("storage-retained")
			if err != nil {
				t.Fatal(err)
			}
			if !legacy {
				policy, err := storagePolicy(256*storageGiB, config.StorageReserveGiB)
				if err != nil {
					t.Fatal(err)
				}
				state.StoragePolicy = &policy
				if err := saveState(dir, state); err != nil {
					t.Fatal(err)
				}
			}
			config.StorageReserveGiB = 128
			reopened := &K3d{config: config}
			retained, _, err := reopened.loadOrPrepare(state.ID)
			if err != nil {
				t.Fatal(err)
			}
			if legacy {
				if retained.StoragePolicy != nil {
					t.Fatal("silently replaced legacy native storage defaults")
				}
			} else {
				if retained.StoragePolicy == nil || *retained.StoragePolicy != *state.StoragePolicy {
					t.Fatalf("creation policy changed: %+v", retained.StoragePolicy)
				}
				// A persisted policy needs no live daemon probe on retries, even
				// when the configured reserve would not fit that filesystem.
				if err := reopened.prepareStoragePolicy(t.Context(), &retained, dir); err != nil {
					t.Fatal(err)
				}
			}
			if retained.Token != state.Token || retained.Name != state.Name || retained.DockerHost != state.DockerHost {
				t.Fatal("storage policy changed native ownership")
			}
		})
	}
}

func TestNativeStorageConfigRejectsInvalidReserve(t *testing.T) {
	for _, reserve := range []int64{-1, math.MaxInt64/(2*storageGiB) + 1, math.MaxInt64} {
		if _, err := NewK3d(Config{StorageReserveGiB: reserve}); err == nil || !strings.Contains(err.Error(), "storage reserve") {
			t.Fatalf("reserve=%d: expected reserve validation before native commands; got %v", reserve, err)
		}
	}
}

//go:build !linux

package ec2

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

func TestNonLinuxQEMURejectsNativeEffects(t *testing.T) {
	state := t.TempDir()
	assertUnavailable := func(err error) {
		t.Helper()
		var capability *CapabilityError
		if !errors.As(err, &capability) {
			t.Fatalf("native operation returned success or a non-capability error: %v", err)
		}
	}
	driver, err := NewQEMU(Config{StateDirectory: state})
	assertUnavailable(err)
	if driver != nil {
		t.Fatal("non-Linux constructor exposed an executable backend")
	}
	// Even a manually constructed zero value must never perform an effect or
	// invoke a disk callback that could publish fictional native data.
	driver = &QEMU{}
	called := false
	assertUnavailable(driver.WriteDisk(t.Context(), Disk{}, func(io.WriterAt) error { called = true; return nil }))
	assertUnavailable(driver.ReadDisk(t.Context(), Disk{}, func(io.ReaderAt) error { called = true; return nil }))
	if called {
		t.Fatal("unsupported disk operation invoked its native callback")
	}
	for _, operation := range []func(context.Context, Disk) error{
		driver.DeleteDisk,
		func(ctx context.Context, disk Disk) error { return driver.CreateDisk(ctx, disk, 1) },
		func(ctx context.Context, disk Disk) error { return driver.ImportDisk(ctx, disk, DiskSource{}, 1) },
		func(ctx context.Context, disk Disk) error { return driver.CheckResizeDisk(ctx, disk, 1) },
		func(ctx context.Context, disk Disk) error { return driver.ResizeDisk(ctx, disk, 1) },
	} {
		assertUnavailable(operation(t.Context(), Disk{}))
	}
	instance, err := driver.Prepare(t.Context(), Specification{})
	assertUnavailable(err)
	if instance != nil {
		t.Fatal("unsupported Prepare produced a guest")
	}
	instance, err = driver.Reopen(t.Context(), Specification{})
	assertUnavailable(err)
	if instance != nil {
		t.Fatal("unsupported Reopen produced a guest")
	}
	assertUnavailable(driver.Remove(t.Context(), Specification{}))
	extents, err := driver.Allocated(t.Context(), Disk{})
	assertUnavailable(err)
	if extents != nil {
		t.Fatal("unsupported allocation query published disk data")
	}
	backup, err := driver.Backup(t.Context(), Disk{}, Disk{})
	assertUnavailable(err)
	if backup.ExtentsKnown || backup.Extents != nil {
		t.Fatal("unsupported backup published an allocation observation")
	}
	backups, err := driver.BackupDisks(t.Context(), nil, nil)
	assertUnavailable(err)
	if backups != nil {
		t.Fatal("unsupported group backup published disk results")
	}
	files, err := os.ReadDir(state)
	if err != nil || len(files) != 0 {
		t.Fatalf("unsupported native execution mutated state: %v %v", files, err)
	}
}

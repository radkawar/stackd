//go:build !linux

package ec2

import (
	"context"
	"io"
)

// QEMU is unavailable on non-Linux controllers. Its method set keeps portable
// service contracts usable without substituting containers or simulated guests.
type QEMU struct{}

func unsupportedQEMU() error {
	return &CapabilityError{Feature: "guest and native disk execution requires a local Linux controller"}
}

func NewQEMU(Config) (*QEMU, error) { return nil, unsupportedQEMU() }

func (*QEMU) Prepare(context.Context, Specification) (Instance, error) {
	return nil, unsupportedQEMU()
}
func (*QEMU) Reopen(context.Context, Specification) (Instance, error) {
	return nil, unsupportedQEMU()
}
func (*QEMU) Remove(context.Context, Specification) error               { return unsupportedQEMU() }
func (*QEMU) CreateDisk(context.Context, Disk, int64) error             { return unsupportedQEMU() }
func (*QEMU) ImportDisk(context.Context, Disk, DiskSource, int64) error { return unsupportedQEMU() }
func (*QEMU) DeleteDisk(context.Context, Disk) error                    { return unsupportedQEMU() }
func (*QEMU) WriteDisk(context.Context, Disk, func(io.WriterAt) error) error {
	return unsupportedQEMU()
}
func (*QEMU) ReadDisk(context.Context, Disk, func(io.ReaderAt) error) error {
	return unsupportedQEMU()
}
func (*QEMU) Allocated(context.Context, Disk) ([]Extent, error) {
	return nil, unsupportedQEMU()
}
func (*QEMU) Backup(context.Context, Disk, Disk) (BackupResult, error) {
	return BackupResult{}, unsupportedQEMU()
}
func (*QEMU) BackupDisks(context.Context, []Disk, []Disk) ([]BackupResult, error) {
	return nil, unsupportedQEMU()
}
func (*QEMU) CheckResizeDisk(context.Context, Disk, int64) error { return unsupportedQEMU() }
func (*QEMU) ResizeDisk(context.Context, Disk, int64) error      { return unsupportedQEMU() }

var _ Executor = (*QEMU)(nil)

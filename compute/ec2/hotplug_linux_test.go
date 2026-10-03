package ec2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestQEMUUEFIDiskDiscovery(t *testing.T) {
	config := Config{StateDirectory: t.TempDir(), UEFICodePath: "/usr/share/OVMF/OVMF_CODE_4M.fd", UEFIVarsPath: "/usr/share/OVMF/OVMF_VARS_4M.fd"}
	for name, destination := range map[string]*string{"qemu-system-x86_64": &config.SystemBinary, "qemu-img": &config.ImageBinary} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("native UEFI regression requires %s: %v", name, err)
		}
		*destination = path
	}
	for _, path := range []string{config.UEFICodePath, config.UEFIVarsPath} {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			t.Skipf("native UEFI regression requires %s", path)
		} else if err != nil {
			t.Fatal(err)
		}
	}
	driver := &QEMU{config: config}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	disks := []Disk{
		{ID: "arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0", Path: filepath.Join(config.StateDirectory, "root.qcow2"), Root: true},
		{ID: "arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef1", Path: filepath.Join(config.StateDirectory, "extra.qcow2")},
	}
	for _, disk := range disks {
		if err := driver.CreateDisk(ctx, disk, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	directory := driver.directory("arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	vars := filepath.Join(directory, "nvram.fd")
	if err := copyIndependent(config.UEFIVarsPath, vars); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"-machine", "q35", "-nodefaults", "-display", "none", "-S", "-name", nativeName(directory),
		"-qmp", "unix:" + escapeOption(filepath.Join(directory, "qmp.sock")) + ",server=on,wait=off",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=" + escapeOption(config.UEFICodePath),
		"-drive", "if=pflash,format=raw,unit=1,file=" + escapeOption(vars),
	}
	for index, disk := range disks {
		options := diskOptions(disk)
		options["node-name"] = diskNode(disk)
		serial, err := volumeSerial(disk)
		if err != nil {
			t.Fatal(err)
		}
		device := fmt.Sprintf("nvme,id=nvme%d,drive=%s,serial=%s", index, diskNode(disk), serial)
		if disk.Root {
			device += ",bootindex=1"
		}
		args = append(args, "-blockdev", jsonOption(options), "-device", device)
	}
	startNativeTestQEMU(t, ctx, driver, directory, args)
	instance := &nativeInstance{driver: driver, directory: directory, spec: Specification{Disks: disks[:1]}}
	attached, err := instance.AttachedDisks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(attached) != len(disks) {
		t.Fatalf("attached disks include firmware or omit an unknown NVMe device: %+v", attached)
	}
	byNode := make(map[string]DiskStatus, len(attached))
	for _, disk := range attached {
		byNode[disk.NodeName] = disk
	}
	for index, disk := range disks {
		actual := byNode[diskNode(disk)]
		serial, err := volumeSerial(disk)
		if err != nil {
			t.Fatal(err)
		}
		wantID := ""
		if index == 0 {
			wantID = disk.ID
		}
		if actual.ID != wantID || actual.Path != disk.Path || actual.Serial != serial || actual.Root != disk.Root {
			t.Errorf("NVMe identity: got %+v, want disk %+v with resolved ID %q and serial %q", actual, disk, wantID, serial)
		}
	}
}

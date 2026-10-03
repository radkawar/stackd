package ec2

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestQEMUDiskHealth(t *testing.T) {
	config := Config{StateDirectory: t.TempDir()}
	for name, destination := range map[string]*string{"qemu-system-x86_64": &config.SystemBinary, "qemu-img": &config.ImageBinary, "qemu-io": &config.IOBinary} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("native disk health requires %s: %v", name, err)
		}
		*destination = path
	}
	driver := &QEMU{config: config}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	disk := Disk{ID: "arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0", Path: filepath.Join(config.StateDirectory, "root.qcow2"), Root: true}
	if err := driver.CreateDisk(ctx, disk, 1<<20); err != nil {
		t.Fatal(err)
	}
	spec := Specification{InstanceARN: "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0", Disks: []Disk{disk}}
	directory := driver.directory(spec.InstanceARN)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	options := diskOptions(disk)
	options["node-name"] = diskNode(disk)
	args := []string{
		"-machine", "q35", "-nodefaults", "-display", "none", "-S", "-name", nativeName(directory),
		"-qmp", "unix:" + escapeOption(filepath.Join(directory, "qmp.sock")) + ",server=on,wait=off",
		"-blockdev", jsonOption(options), "-device", "nvme,id=root,drive=" + diskNode(disk) + ",serial=vol0123456789abcdef0,bootindex=1",
		"-device", "pcie-root-port,id=health-port,chassis=1,slot=1",
	}
	startNativeTestQEMU(t, ctx, driver, directory, args)
	instance := &nativeInstance{driver: driver, directory: directory, spec: spec}
	if healthy, err := instance.checkDiskHealth(ctx); err != nil || !healthy {
		t.Fatalf("live root read: healthy=%v error=%v", healthy, err)
	}

	// QEMU itself injects a real NBD read error. An extra native attachment is
	// included even though the current EC2 specification does not resolve it.
	faultPath := filepath.Join(config.StateDirectory, "fault.raw")
	if err := os.WriteFile(faultPath, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := driver.existing(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	fault := map[string]any{
		"driver": "blkdebug", "node-name": "health-fault",
		"image":        map[string]any{"driver": "file", "filename": faultPath},
		"inject-error": []map[string]any{{"event": "none", "iotype": "read", "errno": 5, "immediately": true}},
	}
	if err := client.execute(ctx, "blockdev-add", fault, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.execute(ctx, "device_add", map[string]any{"driver": "nvme", "id": "fault", "bus": "health-port", "drive": "health-fault", "serial": "health-fault"}, nil); err != nil {
		t.Fatal(err)
	}
	client.close()
	if healthy, err := instance.checkDiskHealth(ctx); err != nil || healthy {
		t.Fatalf("native EIO: healthy=%v error=%v", healthy, err)
	}
	driver.config.IOBinary = filepath.Join(config.StateDirectory, "missing-qemu-io")
	if healthy, err := instance.checkDiskHealth(ctx); err == nil || healthy {
		t.Fatalf("missing observation tool must be unknown, not an observed impairment: healthy=%v error=%v", healthy, err)
	}
}

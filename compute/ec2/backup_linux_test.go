package ec2

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Exercise QMP's actual graph/job constraints and independent encrypted bytes,
// without requiring a guest image, KVM or host network privileges.
func TestQEMUGroupedBackupSnapshotBytes(t *testing.T) {
	config := Config{StateDirectory: t.TempDir()}
	for name, destination := range map[string]*string{
		"qemu-system-x86_64": &config.SystemBinary, "qemu-img": &config.ImageBinary,
		"qemu-nbd": &config.NBDBinary, "qemu-io": &config.IOBinary,
	} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("native disk regression requires %s: %v", name, err)
		}
		*destination = path
	}
	// This exercises only disk operations; no instance/network constructor is used.
	driver := &QEMU{config: config}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	sources := []Disk{
		{ID: "arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0", Path: filepath.Join(config.StateDirectory, "plain.qcow2")},
		{ID: "arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef1", Path: filepath.Join(config.StateDirectory, "encrypted.qcow2"), Encrypted: true, Key: bytes.Repeat([]byte{42}, 64)},
	}
	destinations := []Disk{
		{ID: "arn:aws:ec2:us-east-1::snapshot/snap-0123456789abcdef0:123456789012", Path: filepath.Join(config.StateDirectory, "snapshot-plain.qcow2")},
		{ID: "arn:aws:ec2:us-east-1::snapshot/snap-0123456789abcdef1:123456789012", Path: filepath.Join(config.StateDirectory, "snapshot-encrypted.qcow2"), Encrypted: true, Key: sources[1].Key},
	}
	for index, disk := range sources {
		if err := driver.CreateDisk(ctx, disk, 1<<20); err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{byte(index + 41)}, 4096)
		if err := driver.WriteDisk(ctx, disk, func(writer io.WriterAt) error {
			_, err := writer.WriteAt(payload, 524288)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	directory := driver.directory("arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "qmp.sock")
	args := []string{"-machine", "none", "-nodefaults", "-display", "none", "-S", "-name", nativeName(directory), "-qmp", "unix:" + escapeOption(socket) + ",server=on,wait=off"}
	for _, disk := range sources {
		if disk.Encrypted {
			args = append(args, "-object", "secret,id="+secretNode(disk)+",data="+base64.StdEncoding.EncodeToString(disk.Key))
		}
		options := diskOptions(disk)
		options["node-name"] = diskNode(disk)
		args = append(args, "-blockdev", jsonOption(options))
	}
	stop := startNativeTestQEMU(t, ctx, driver, directory, args)
	if _, err := driver.BackupDisks(ctx, sources, destinations); err != nil {
		t.Fatal(err)
	}
	stop()
	for _, disk := range sources {
		if err := driver.DeleteDisk(ctx, disk); err != nil {
			t.Fatal(err)
		}
	}
	for index, disk := range destinations {
		if err := driver.ReadDisk(ctx, disk, func(reader io.ReaderAt) error {
			actual := make([]byte, 8192)
			if _, err := reader.ReadAt(actual, 524288); err != nil {
				return err
			}
			want := append(bytes.Repeat([]byte{byte(index + 41)}, 4096), make([]byte, 4096)...)
			if !bytes.Equal(actual, want) {
				t.Errorf("snapshot %d did not retain its source payload and sparse bytes", index)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func startNativeTestQEMU(t *testing.T, ctx context.Context, driver *QEMU, directory string, args []string) func() {
	t.Helper()
	command := exec.CommandContext(ctx, driver.config.SystemBinary, args...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			_ = command.Process.Kill()
			_ = command.Wait()
			stopped = true
		}
	}
	t.Cleanup(stop)
	for {
		client, err := driver.existing(ctx, directory)
		if err == nil {
			client.close()
			break
		}
		if err := waitTick(ctx); err != nil {
			stop()
			t.Fatalf("native process readiness: %v: %s", err, stderr.String())
		}
	}
	return stop
}

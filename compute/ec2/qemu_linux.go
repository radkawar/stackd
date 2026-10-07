package ec2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"stackd/compute/network"
)

type QEMU struct{ config Config }

type nativeInstance struct {
	driver     *QEMU
	spec       Specification
	directory  string
	attachment GuestAttachment
	closeOnce  sync.Once
	closeErr   error
	// Protected by the driver's native-operation lock; a new controller handle
	// always reapplies its policy to the surviving process.
	quota    CPUQuota
	quotaPID int
}

func NewQEMU(config Config) (*QEMU, error) {
	for label, path := range map[string]string{"system binary": config.SystemBinary, "image binary": config.ImageBinary, "NBD binary": config.NBDBinary, "I/O binary": config.IOBinary} {
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("explicit absolute QEMU %s required", label)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return nil, fmt.Errorf("QEMU %s is not executable", label)
		}
	}
	if !filepath.IsAbs(config.StateDirectory) {
		return nil, errors.New("explicit absolute QEMU state directory required")
	}
	driver := &QEMU{config: config}
	// Every instance has the same digest width. QMP and disk-export sockets
	// must be dialable before any native state or guest can be created.
	socketBytes := len(filepath.Join(driver.directory(""), "qmp.sock"))
	const maxSocketBytes = len(unix.RawSockaddrUnix{}.Path) - 1
	if socketBytes > maxSocketBytes {
		return nil, fmt.Errorf("QEMU state directory %q produces %d-byte native socket paths; Linux supports at most %d bytes: select a shorter state directory", config.StateDirectory, socketBytes, maxSocketBytes)
	}
	if config.Networks == nil {
		return nil, errors.New("QEMU guest network owner required")
	}
	if err := os.MkdirAll(config.StateDirectory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(config.StateDirectory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("QEMU state directory must be a private directory (0700)")
	}
	return driver, nil
}

func identifier(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:12])
}
func diskNode(disk Disk) string   { return "disk-" + identifier(disk.ID) }
func fileNode(disk Disk) string   { return "file-" + identifier(disk.ID) }
func secretNode(disk Disk) string { return "key-" + identifier(disk.ID) }
func (q *QEMU) directory(arn string) string {
	return filepath.Join(q.config.StateDirectory, "vm-"+identifier(arn))
}
func nativeName(directory string) string { return "stackd-" + filepath.Base(directory) }

// A native-operation lock also covers other controller processes using this
// explicitly selected state directory. It prevents graph/export teardown racing
// reattachment, resize, backup or deletion; it contains no resource metadata.
func (q *QEMU) lock(ctx context.Context) (func(), error) {
	file, err := os.OpenFile(filepath.Join(q.config.StateDirectory, "control.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN); _ = file.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			file.Close()
			return nil, err
		}
		if err = waitTick(ctx); err != nil {
			file.Close()
			return nil, err
		}
	}
}

func (q *QEMU) Prepare(ctx context.Context, spec Specification) (Instance, error) {
	return q.open(ctx, spec, true)
}
func (q *QEMU) Reopen(ctx context.Context, spec Specification) (Instance, error) {
	return q.open(ctx, spec, false)
}

func (q *QEMU) open(ctx context.Context, spec Specification, create bool) (Instance, error) {
	if spec.InstanceARN == "" {
		return nil, errors.New("instance ARN required")
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	directory := q.directory(spec.InstanceARN)
	client, err := q.existing(ctx, directory)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, ErrNotFound) && !create {
		return nil, ErrNotFound
	}
	if client != nil {
		defer client.close()
	}
	if err := q.validate(spec, client == nil); err != nil {
		return nil, err
	}
	if client != nil {
		if err := verifyDisks(ctx, client, spec.Disks); err != nil {
			return nil, err
		}
	}
	attachment, err := q.config.Networks.Prepare(ctx, spec.InstanceARN, spec.Network, spec.Metadata)
	if err != nil {
		return nil, err
	}
	if attachment == nil || attachment.TAPName() == "" {
		if attachment != nil {
			_ = attachment.Close()
		}
		return nil, errors.New("network owner returned no TAP attachment")
	}
	instance := &nativeInstance{driver: q, spec: spec, directory: directory, attachment: attachment}
	if err := attachment.Configure(ctx, spec.Network); err != nil {
		_ = attachment.Close()
		return nil, err
	}
	if client == nil {
		if err := q.launch(ctx, instance); err != nil {
			_ = attachment.Close()
			return nil, err
		}
	}
	// Reconnection needs disk identities, never another retained copy of the
	// launch key slices supplied by the KMS owner.
	instance.spec.Disks = append([]Disk(nil), spec.Disks...)
	for index := range instance.spec.Disks {
		instance.spec.Disks[index].Key = nil
	}
	return instance, nil
}

func (q *QEMU) validate(spec Specification, starting bool) error {
	if spec.Architecture != "x86_64" {
		return &CapabilityError{Feature: "architecture " + spec.Architecture}
	}
	if spec.BootMode != "legacy-bios" && spec.BootMode != "uefi" {
		return &CapabilityError{Feature: "boot mode " + spec.BootMode}
	}
	if spec.CPU.Sockets < 1 || spec.CPU.Cores < 1 || spec.CPU.Threads < 1 || spec.MemoryBytes < 64<<20 || spec.MemoryBytes%(1<<20) != 0 {
		return &CapabilityError{Feature: "CPU topology or MiB-aligned memory"}
	}
	if len(spec.Disks) > 28 {
		return &CapabilityError{Feature: "more than 28 NVMe disks"}
	}
	roots := 0
	seen := map[string]bool{}
	for _, disk := range spec.Disks {
		if err := validateDisk(disk); err != nil {
			return err
		}
		relative, err := filepath.Rel(q.directory(spec.InstanceARN), disk.Path)
		if err != nil {
			return err
		}
		if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("EBS disk must be outside the instance runtime directory")
		}
		if seen[disk.ID] {
			return errors.New("duplicate native disk ID")
		}
		seen[disk.ID] = true
		if disk.Root {
			roots++
		}
		if starting && disk.Encrypted && len(disk.Key) == 0 {
			return fmt.Errorf("native disk %s requires unwrapped KMS material to start", disk.ID)
		}
	}
	if roots != 1 {
		return errors.New("one root volume required")
	}
	if !starting {
		return nil
	}
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return &CapabilityError{Feature: "KVM: " + err.Error()}
	}
	_ = kvm.Close()
	paths := []string{q.config.BIOSPath}
	if spec.BootMode == "uefi" {
		paths = []string{q.config.UEFICodePath, q.config.UEFIVarsPath}
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return &CapabilityError{Feature: "explicit installed firmware for " + spec.BootMode}
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return &CapabilityError{Feature: "installed firmware " + path}
		}
	}
	return nil
}

func (q *QEMU) existing(ctx context.Context, directory string) (*qmpClient, error) {
	socket := filepath.Join(directory, "qmp.sock")
	client, err := connectQMP(ctx, socket)
	if err == nil {
		owned, e := processOwns(client.pid, nativeName(directory), socket)
		if e != nil || !owned {
			client.close()
			return nil, errors.Join(e, errors.New("QMP peer is not the owned native process"))
		}
		return client, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	pid, readErr := readPID(directory)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	if pid != 0 {
		owned, e := processOwns(pid, nativeName(directory), socket)
		if e != nil {
			return nil, e
		}
		if owned {
			return nil, fmt.Errorf("owned QEMU process is alive but QMP is unavailable: %w", err)
		}
	}
	return nil, ErrNotFound
}

func readPID(directory string) (int, error) {
	data, err := os.ReadFile(filepath.Join(directory, "qemu.pid"))
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, errors.New("invalid native QEMU pid file")
	}
	return pid, nil
}

func (q *QEMU) launch(ctx context.Context, instance *nativeInstance) error {
	spec := instance.spec
	directory := instance.directory
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	for _, name := range []string{"qmp.sock", "qga.sock", "qemu.pid", "read.nbd"} {
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	args := []string{"-name", nativeName(directory), "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", fmt.Sprintf("sockets=%d,cores=%d,threads=%d", spec.CPU.Sockets, spec.CPU.Cores, spec.CPU.Threads), "-m", strconv.FormatInt(spec.MemoryBytes>>20, 10), "-S", "-no-shutdown", "-display", "none", "-no-user-config", "-nodefaults", "-pidfile", filepath.Join(directory, "qemu.pid"), "-qmp", "unix:" + escapeOption(filepath.Join(directory, "qmp.sock")) + ",server=on,wait=off", "-chardev", "file,id=console,path=" + escapeOption(filepath.Join(directory, "console.log")) + ",append=on", "-serial", "chardev:console"}
	// Headless display suppresses a host window, not the guest framebuffer.
	// Standard VGA supports both SeaBIOS and OVMF; q35's built-in i8042
	// keyboard remains available for the screenshot WakeUp keystroke.
	args = append(args, "-device", "VGA,id=console-video,bus=pcie.0,addr=0x1")
	// HVM guests use the documented EC2 UUID prefix to select their ordinary
	// EC2 datasource. Keep it stable across this instance's VMM replacements.
	// This supplies platform identity, not an Amazon NVMe/ENA hardware claim.
	systemID := sha256.Sum256([]byte(spec.InstanceARN))
	systemID[0], systemID[1] = 0xec, 0x20|(systemID[1]&0x0f)
	args = append(args, "-uuid", fmt.Sprintf("%x-%x-%x-%x-%x", systemID[:4], systemID[4:6], systemID[6:8], systemID[8:10], systemID[10:16]),
		"-smbios", "type=2,asset="+escapeOption(spec.InstanceARN[strings.LastIndexByte(spec.InstanceARN, '/')+1:]))
	if spec.BootMode == "legacy-bios" {
		args = append(args, "-bios", q.config.BIOSPath)
	} else {
		vars := filepath.Join(directory, "nvram.fd")
		if _, err := os.Stat(vars); errors.Is(err, os.ErrNotExist) {
			if err := copyIndependent(q.config.UEFIVarsPath, vars); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		args = append(args, "-drive", "if=pflash,format=raw,unit=0,readonly=on,file="+escapeOption(q.config.UEFICodePath), "-drive", "if=pflash,format=raw,unit=1,file="+escapeOption(vars))
	}
	var descriptors []*os.File
	defer func() {
		for _, file := range descriptors {
			_ = file.Close()
		}
	}()
	// Pack the disk root ports into multifunction slots. One slot per port
	// exhausts q35's root bus once the console, NIC and guest agent are present.
	for index := range 28 {
		args = append(args, "-device", fmt.Sprintf("pcie-root-port,id=port%d,chassis=%d,slot=%d,bus=pcie.0,addr=%x.%x,multifunction=on", index, index+1, index+1, 2+index/8, index%8))
	}
	for index, disk := range spec.Disks {
		if disk.Encrypted {
			file, err := keyDescriptor(disk.Key)
			if err != nil {
				return err
			}
			descriptors = append(descriptors, file)
			args = append(args, "-object", fmt.Sprintf("secret,id=%s,file=/proc/self/fd/%d", secretNode(disk), 2+len(descriptors)))
		}
		node := diskOptions(disk)
		node["node-name"] = diskNode(disk)
		args = append(args, "-blockdev", jsonOption(node))
		port := fmt.Sprintf("port%d", index)
		serial, err := volumeSerial(disk)
		if err != nil {
			return err
		}
		device := fmt.Sprintf("nvme,id=nvme%d,bus=%s,drive=%s,serial=%s", index, port, diskNode(disk), serial)
		if disk.Root {
			device += ",bootindex=1"
		}
		args = append(args, "-device", device)
	}
	if spec.Hibernation {
		args = append(args, "-device", "virtio-serial-pci,id=guest-agent",
			"-chardev", "socket,id=guest-agent,path="+escapeOption(filepath.Join(directory, "qga.sock"))+",server=on,wait=off",
			"-device", "virtserialport,chardev=guest-agent,name=org.qemu.guest_agent.0")
	}
	args = append(args, "-netdev", "tap,id=primary,ifname="+escapeOption(instance.attachment.TAPName())+",script=no,downscript=no", "-device", "virtio-net-pci,netdev=primary,mac="+escapeOption(spec.Network.MAC))
	log, err := os.OpenFile(filepath.Join(directory, "vmm.log"), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	command := exec.Command(q.config.SystemBinary, args...)
	command.ExtraFiles = descriptors
	command.Stdout = log
	command.Stderr = log
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	for {
		client, e := q.existing(ctx, directory)
		if e == nil {
			var status struct {
				Status string `json:"status"`
			}
			e = client.execute(ctx, "query-status", nil, &status)
			client.close()
			if e == nil && status.Status == "prelaunch" {
				return nil
			}
			if e == nil {
				e = fmt.Errorf("prepared QEMU has unexpected runstate %s", status.Status)
			}
		}
		select {
		case err := <-finished:
			info, readErr := log.Stat()
			if readErr != nil {
				return fmt.Errorf("QEMU exited during preparation: %w", errors.Join(err, readErr))
			}
			diagnostic := make([]byte, min(info.Size(), 8192))
			_, readErr = log.ReadAt(diagnostic, info.Size()-int64(len(diagnostic)))
			return fmt.Errorf("QEMU exited during preparation: %w: %s", errors.Join(err, readErr, errors.New("guest not prepared")), bytes.TrimSpace(diagnostic))
		default:
		}
		if err := waitTick(ctx); err != nil {
			_ = command.Process.Kill()
			<-finished
			return errors.Join(err, e)
		}
	}
}

func (i *nativeInstance) Close() error {
	i.closeOnce.Do(func() { i.closeErr = i.attachment.Close() })
	return i.closeErr
}
func (i *nativeInstance) SetNetwork(ctx context.Context, spec network.Specification) error {
	return i.attachment.Configure(ctx, spec)
}

func (i *nativeInstance) Inspect(ctx context.Context) (Status, error) {
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	client, err := i.driver.existing(ctx, i.directory)
	if errors.Is(err, ErrNotFound) {
		return Status{State: Exited, NativeState: "exited"}, nil
	}
	if err != nil {
		return Status{State: Error, Error: err.Error()}, err
	}
	defer client.close()
	var native struct {
		Status  string `json:"status"`
		Running bool   `json:"running"`
	}
	if err := client.execute(ctx, "query-status", nil, &native); err != nil {
		return Status{State: Error, PID: client.pid, Error: err.Error()}, err
	}
	startTime, err := processStartTime(client.pid)
	if err != nil {
		return Status{State: Error, PID: client.pid, Error: err.Error()}, err
	}
	status := Status{PID: client.pid, StartTimeTicks: startTime, NativeState: native.Status}
	switch native.Status {
	case "running":
		status.State = Running
	case "paused", "prelaunch":
		status.State = Paused
	case "shutdown":
		status.State = Shutdown
	default:
		status.State = Error
		status.Error = "native runstate: " + native.Status
	}
	return status, nil
}

func (i *nativeInstance) command(ctx context.Context, name string) error {
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	client, err := i.driver.existing(ctx, i.directory)
	if err != nil {
		return err
	}
	defer client.close()
	if name == "cont" {
		var status struct {
			Status string `json:"status"`
		}
		if err := client.execute(ctx, "query-status", nil, &status); err != nil {
			return err
		}
		if status.Status == "shutdown" {
			return errors.New("shutdown VMM must be stopped before restarting")
		}
	}
	return client.execute(ctx, name, nil, nil)
}
func (i *nativeInstance) Start(ctx context.Context) error { return i.command(ctx, "cont") }
func (i *nativeInstance) Pause(ctx context.Context) error { return i.command(ctx, "stop") }
func (i *nativeInstance) Powerdown(ctx context.Context) error {
	return i.command(ctx, "system_powerdown")
}
func (i *nativeInstance) Reset(ctx context.Context) error { return i.command(ctx, "system_reset") }
func (i *nativeInstance) Stop(ctx context.Context) error {
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := i.driver.stop(ctx, i.directory); err != nil {
		return err
	}
	if i.driver.config.CPULimits != nil {
		return i.driver.config.CPULimits.Remove(ctx, i.spec.InstanceARN)
	}
	return nil
}

func (q *QEMU) stop(ctx context.Context, directory string) error {
	client, err := q.existing(ctx, directory)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	var pid int
	if err == nil {
		pid = client.pid
		_ = client.execute(ctx, "quit", nil, nil)
		_ = client.close()
	} else {
		pid, err = readPID(directory)
		if err != nil {
			return err
		}
		owned, e := processOwns(pid, nativeName(directory), filepath.Join(directory, "qmp.sock"))
		if e != nil || !owned {
			return errors.Join(e, errors.New("cannot stop unowned native process"))
		}
		// A forced native stop is also usable when the QMP server has failed.
		fd, e := unix.PidfdOpen(pid, 0)
		if e != nil {
			return e
		}
		defer unix.Close(fd)
		owned, e = processOwns(pid, nativeName(directory), filepath.Join(directory, "qmp.sock"))
		if e != nil || !owned {
			return errors.Join(e, errors.New("native process ownership changed"))
		}
		if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return err
		}
	}
	for {
		owned, err := processOwns(pid, nativeName(directory), filepath.Join(directory, "qmp.sock"))
		if err != nil {
			return err
		}
		if !owned {
			return nil
		}
		if err := waitTick(ctx); err != nil {
			return err
		}
	}
}

func (q *QEMU) Remove(ctx context.Context, spec Specification) error {
	if spec.InstanceARN == "" {
		return errors.New("instance ARN required")
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	directory := q.directory(spec.InstanceARN)
	if err := q.stop(ctx, directory); err != nil {
		return err
	}
	if err := q.config.Networks.Remove(ctx, spec.InstanceARN, spec.Network); err != nil {
		return err
	}
	if q.config.CPULimits != nil {
		if err := q.config.CPULimits.Remove(ctx, spec.InstanceARN); err != nil {
			return err
		}
	}
	// Remove only named runtime artifacts, never recursively delete a caller's
	// EBS file accidentally placed beneath this directory.
	for _, name := range []string{"qmp.sock", "qga.sock", "qemu.pid", "read.nbd", "console.log", "vmm.log", "nvram.fd"} {
		path := filepath.Join(directory, name)
		for _, disk := range spec.Disks {
			if filepath.Clean(disk.Path) == path {
				return errors.New("EBS disk overlaps a native runtime artifact")
			}
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	err = os.Remove(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (i *nativeInstance) Console(ctx context.Context, offset int64, maximum int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if offset < 0 || maximum < 0 || maximum > 16<<20 {
		return nil, errors.New("invalid console range")
	}
	file, err := os.Open(filepath.Join(i.directory, "console.log"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make([]byte, maximum)
	n, err := file.ReadAt(result, offset)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return result[:n], err
}

var _ Executor = (*QEMU)(nil)
var _ Instance = (*nativeInstance)(nil)

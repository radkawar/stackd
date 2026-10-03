package ec2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type nativeBlock struct {
	NodeName string `json:"node-name"`
	File     string `json:"file"`
	Driver   string `json:"drv"`
	Image    struct {
		Filename    string `json:"filename"`
		VirtualSize int64  `json:"virtual-size"`
		Encrypted   bool   `json:"encrypted"`
	} `json:"image"`
}

func blockPath(node nativeBlock) (string, error) {
	filename := node.File
	if strings.HasPrefix(filename, "json:") {
		var options struct {
			File struct {
				Filename string `json:"filename"`
			} `json:"file"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(filename, "json:")), &options); err != nil {
			return "", err
		}
		filename = options.File.Filename
	}
	return filepath.Clean(filename), nil
}

func findBlock(ctx context.Context, client *qmpClient, disk Disk) (*nativeBlock, error) {
	var nodes []nativeBlock
	if err := client.execute(ctx, "query-named-block-nodes", nil, &nodes); err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if node.NodeName != diskNode(disk) {
			continue
		}
		filename, err := blockPath(node)
		if err != nil {
			return nil, err
		}
		if filename != filepath.Clean(disk.Path) || node.Driver != "qcow2" || node.Image.Encrypted != disk.Encrypted {
			return nil, errors.New("attached disk native identity mismatch")
		}
		return &node, nil
	}
	return nil, nil
}

func verifyDisks(ctx context.Context, client *qmpClient, disks []Disk) error {
	for _, disk := range disks {
		node, err := findBlock(ctx, client, disk)
		if err != nil {
			return err
		}
		if node == nil {
			if disk.Root {
				return fmt.Errorf("surviving guest lacks root volume %s", disk.ID)
			}
			continue
		}
		device, err := guestDevice(ctx, client, disk)
		if err != nil {
			return err
		}
		if device == "" {
			if disk.Root {
				return fmt.Errorf("root volume %s has no native guest device", disk.ID)
			}
			continue
		}
		path := "/machine/peripheral/" + device
		var serial string
		if err := client.execute(ctx, "qom-get", map[string]any{"path": path, "property": "serial"}, &serial); err != nil {
			return err
		}
		expected, err := volumeSerial(disk)
		if err != nil {
			return err
		}
		if serial != expected {
			return fmt.Errorf("surviving volume %s has mismatched NVMe serial", disk.ID)
		}
		if disk.Root {
			var bootindex int
			if err := client.execute(ctx, "qom-get", map[string]any{"path": path, "property": "bootindex"}, &bootindex); err != nil {
				return err
			}
			if bootindex != 1 {
				return fmt.Errorf("surviving root volume %s is not the native boot device", disk.ID)
			}
		}
	}
	return nil
}

func (q *QEMU) diskOwner(ctx context.Context, disk Disk) (*qmpClient, string, error) {
	entries, err := os.ReadDir(q.config.StateDirectory)
	if err != nil {
		return nil, "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "vm-") {
			continue
		}
		directory := filepath.Join(q.config.StateDirectory, entry.Name())
		client, err := q.existing(ctx, directory)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		node, err := findBlock(ctx, client, disk)
		if err != nil {
			client.close()
			return nil, "", err
		}
		if node != nil {
			return client, directory, nil
		}
		client.close()
	}
	return nil, "", nil
}

func (q *QEMU) withReader(ctx context.Context, disk Disk, read func(string, string) error) error {
	client, directory, err := q.diskOwner(ctx, disk)
	if err != nil {
		return err
	}
	if client != nil {
		defer client.close()
		return q.withExport(ctx, client, directory, diskNode(disk), read)
	}
	return q.withOfflineExport(ctx, disk, true, read)
}

func (q *QEMU) withExport(ctx context.Context, client *qmpClient, directory, node string, read func(string, string) error) (err error) {
	// No persistent NBD clients exist. Reconcile a prior interrupted temporary
	// export before creating this one; resize uses the same withdrawal path.
	if err := withdrawExports(ctx, client); err != nil {
		return err
	}
	socket := filepath.Join(directory, "read.nbd")
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := client.execute(ctx, "nbd-server-start", map[string]any{"addr": map[string]any{"type": "unix", "data": map[string]any{"path": socket}}}, nil); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = errors.Join(err, withdrawExports(cleanup, client))
		_ = os.Remove(socket)
	}()
	if err := client.execute(ctx, "block-export-add", map[string]any{"type": "nbd", "id": "stackd-read", "node-name": node, "name": "disk", "writable": false}, nil); err != nil {
		return err
	}
	return read(socket, "disk")
}

func withdrawExports(ctx context.Context, client *qmpClient) error {
	var exports []struct {
		ID string `json:"id"`
	}
	if err := client.execute(ctx, "query-block-exports", nil, &exports); err != nil {
		return err
	}
	for _, export := range exports {
		if export.ID != "stackd-read" {
			return errors.New("foreign native block export prevents exclusive operation")
		}
		if err := client.execute(ctx, "block-export-del", map[string]any{"id": export.ID, "mode": "hard"}, nil); err != nil {
			return err
		}
	}
	for len(exports) > 0 {
		if err := waitTick(ctx); err != nil {
			return err
		}
		if err := client.execute(ctx, "query-block-exports", nil, &exports); err != nil {
			return err
		}
	}
	// QMP explicitly reports an error when the NBD server was not started.
	// query-chardev does not expose NBD listeners, so only that precise native
	// absence is harmless; permission and other errors must propagate.
	err := client.execute(ctx, "nbd-server-stop", nil, nil)
	if err != nil && !strings.Contains(err.Error(), "NBD server not running") {
		return err
	}
	return nil
}

func (q *QEMU) withOfflineExport(ctx context.Context, disk Disk, readOnly bool, use func(string, string) error) (err error) {
	if _, err := q.info(ctx, disk); err != nil {
		return err
	}
	directory, err := os.MkdirTemp(q.config.StateDirectory, "export-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "nbd.sock")
	args := []string{"--persistent", "--shared=1", "--socket", socket, "--export-name", "disk"}
	if readOnly {
		args = append(args, "--read-only")
	}
	var files []*os.File
	args, files, err = addKeyArgs(args, files, disk)
	if err != nil {
		closeFiles(files)
		return err
	}
	defer closeFiles(files)
	args = append(args, "json:"+jsonOption(diskOptions(disk)))
	command := exec.Command(q.config.NBDBinary, args...)
	command.ExtraFiles = files
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	reaped := false
	defer func() {
		if !reaped {
			_ = command.Process.Kill()
			<-finished
		}
	}()
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case e := <-finished:
			reaped = true
			return fmt.Errorf("native NBD export: %w: %s", errors.Join(e, errors.New("export exited")), stderr.String())
		default:
		}
		if err := waitTick(ctx); err != nil {
			return err
		}
	}
	return use(socket, "disk")
}

// ReadDisk exposes bounded reads through one read-only native export. The
// callback must not retain the reader. Its reused memfd is anonymous RAM, not a
// plaintext disk mirror; EBS owns block sizes and the destination buffer.
func (q *QEMU) ReadDisk(ctx context.Context, disk Disk, consume func(io.ReaderAt) error) error {
	if err := validateDisk(disk); err != nil {
		return err
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return q.withReader(ctx, disk, func(socket, export string) error {
		file, err := memoryFile("stackd-range")
		if err != nil {
			return err
		}
		defer file.Close()
		reader := nativeDiskReader{
			ctx: ctx, driver: q, file: file,
			options: ",file.driver=nbd,file.server.type=unix,file.server.path=" + escapeOption(socket) + ",file.export=" + escapeOption(export),
		}
		return consume(&reader)
	})
}

type nativeDiskReader struct {
	ctx     context.Context
	driver  *QEMU
	file    *os.File
	options string
}

func (r *nativeDiskReader) ReadAt(destination []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("invalid native disk read offset")
	}
	if len(destination) == 0 {
		return 0, nil
	}
	options := "driver=raw,offset=" + strconv.FormatInt(offset, 10) + ",size=" + strconv.Itoa(len(destination)) + r.options
	args := []string{"dd", "--image-opts", "bs=" + strconv.Itoa(len(destination)), "count=1", "if=" + options, "of=/proc/self/fd/3"}
	if err := runNative(r.ctx, r.driver.config.ImageBinary, args, []*os.File{r.file}, io.Discard); err != nil {
		return 0, err
	}
	return r.file.ReadAt(destination, 0)
}

func (q *QEMU) Allocated(ctx context.Context, disk Disk) ([]Extent, error) {
	if err := validateDisk(disk); err != nil {
		return nil, err
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	var extents []Extent
	err = q.withReader(ctx, disk, func(socket, export string) error {
		var err error
		extents, err = q.mapExport(ctx, socket, export)
		return err
	})
	return extents, err
}

func (q *QEMU) mapExport(ctx context.Context, socket, export string) ([]Extent, error) {
	var output bytes.Buffer
	options := map[string]any{"driver": "nbd", "server": map[string]any{"type": "unix", "path": socket}, "export": export}
	if err := runNative(ctx, q.config.ImageBinary, []string{"map", "--output=json", "json:" + jsonOption(options)}, nil, &output); err != nil {
		return nil, err
	}
	var extents []Extent
	if err := json.Unmarshal(output.Bytes(), &extents); err != nil {
		return nil, err
	}
	return extents, nil
}

func (q *QEMU) ResizeDisk(ctx context.Context, disk Disk, size int64) error {
	if err := validateDisk(disk); err != nil {
		return err
	}
	if size <= 0 || size%512 != 0 {
		return errors.New("disk size must be positive and sector aligned")
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	client, _, err := q.diskOwner(ctx, disk)
	if err != nil {
		return err
	}
	if client == nil {
		return q.resizeOffline(ctx, disk, size)
	}
	defer client.close()
	node, err := findBlock(ctx, client, disk)
	if err != nil {
		return err
	}
	if size < node.Image.VirtualSize {
		return errors.New("native volume shrink is not supported")
	}
	if err := withdrawExports(ctx, client); err != nil {
		return err
	}
	return client.execute(ctx, "block_resize", map[string]any{"node-name": diskNode(disk), "size": size}, nil)
}

func (q *QEMU) resizeOffline(ctx context.Context, disk Disk, size int64) error {
	info, err := q.info(ctx, disk)
	if err != nil {
		return err
	}
	if size < info.VirtualSize {
		return errors.New("native volume shrink is not supported")
	}
	args := []string{"resize", "-q"}
	var files []*os.File
	args, files, err = addKeyArgs(args, files, disk)
	if err != nil {
		closeFiles(files)
		return err
	}
	defer closeFiles(files)
	args = append(args, "json:"+jsonOption(diskOptions(disk)), strconv.FormatInt(size, 10))
	return runNative(ctx, q.config.ImageBinary, args, files, io.Discard)
}

// releaseUnattachedDisk reconciles interrupted native image creation/backup.
// A guest block device is never hot-unplugged or deleted by this path.
func (q *QEMU) releaseUnattachedDisk(ctx context.Context, disk Disk) error {
	entries, err := os.ReadDir(q.config.StateDirectory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "vm-") {
			continue
		}
		client, err := q.existing(ctx, filepath.Join(q.config.StateDirectory, entry.Name()))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		err = releaseDiskNodes(ctx, client, disk)
		_ = client.close()
		if err != nil {
			return err
		}
	}
	return nil
}

func releaseDiskNodes(ctx context.Context, client *qmpClient, disk Disk) error {
	var nodes []nativeBlock
	if err := client.execute(ctx, "query-named-block-nodes", nil, &nodes); err != nil {
		return err
	}
	owned := map[string]bool{}
	for _, node := range nodes {
		if node.NodeName != diskNode(disk) && node.NodeName != fileNode(disk) {
			continue
		}
		path, err := blockPath(node)
		if err != nil {
			return err
		}
		if path != filepath.Clean(disk.Path) {
			return errors.New("native cleanup disk identity mismatch")
		}
		owned[node.NodeName] = true
	}
	var devices []struct {
		Inserted struct {
			NodeName string `json:"node-name"`
		} `json:"inserted"`
	}
	if err := client.execute(ctx, "query-block", nil, &devices); err != nil {
		return err
	}
	for _, device := range devices {
		if owned[device.Inserted.NodeName] {
			return errors.New("cannot delete a guest-attached native disk")
		}
	}
	for _, id := range []string{"create-" + identifier(disk.ID), "backup-" + identifier(disk.ID)} {
		if err := cancelJob(ctx, client, id); err != nil {
			return err
		}
	}
	var jobs []nativeJob
	if err := client.execute(ctx, "query-jobs", nil, &jobs); err != nil {
		return err
	}
	for _, job := range jobs {
		if strings.HasPrefix(job.ID, "group-") && strings.HasSuffix(job.ID, "-"+identifier(disk.ID)) {
			if err := cancelJob(ctx, client, job.ID); err != nil {
				return err
			}
		}
	}
	if len(owned) > 0 {
		if err := withdrawExports(ctx, client); err != nil {
			return err
		}
	}
	for _, name := range []string{diskNode(disk), fileNode(disk)} {
		if owned[name] {
			if err := client.execute(ctx, "blockdev-del", map[string]any{"node-name": name}, nil); err != nil {
				return err
			}
		}
	}
	var objects []struct {
		Name string `json:"name"`
	}
	if err := client.execute(ctx, "qom-list", map[string]any{"path": "/objects"}, &objects); err != nil {
		return err
	}
	for _, object := range objects {
		if object.Name == secretNode(disk) {
			if err := client.execute(ctx, "object-del", map[string]any{"id": object.Name}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

package ec2

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func validateDisk(disk Disk) error {
	if disk.ID == "" || !filepath.IsAbs(disk.Path) || strings.ContainsRune(disk.Path, '\x00') {
		return errors.New("native disk requires ID and absolute path")
	}
	return nil
}

func keyDescriptor(key []byte) (*os.File, error) {
	if len(key) == 0 {
		return nil, errors.New("unwrapped KMS key material required")
	}
	file, err := memoryFile("stackd-key")
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(key)))
	base64.StdEncoding.Encode(encoded, key)
	_, err = file.Write(encoded)
	clear(encoded)
	if err == nil {
		_, err = file.Seek(0, io.SeekStart)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func memoryFile(name string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func diskOptions(disk Disk) map[string]any {
	options := map[string]any{"driver": "qcow2", "file": map[string]any{"driver": "file", "filename": disk.Path}}
	if disk.Encrypted {
		options["encrypt"] = map[string]any{"format": "luks", "key-secret": secretNode(disk)}
	}
	return options
}

func runNative(ctx context.Context, binary string, args []string, files []*os.File, output io.Writer) error {
	command := exec.CommandContext(ctx, binary, args...)
	command.ExtraFiles = files
	command.Stdout = output
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", filepath.Base(binary), err, strings.TrimSpace(stderr.String()))
	}
	// qemu-img dd can report a failed range on stderr with exit status zero.
	if stderr.Len() != 0 {
		return fmt.Errorf("%s: %s", filepath.Base(binary), strings.TrimSpace(stderr.String()))
	}
	return nil
}

func addKeyArgs(args []string, files []*os.File, disk Disk) ([]string, []*os.File, error) {
	if !disk.Encrypted {
		return args, files, nil
	}
	file, err := keyDescriptor(disk.Key)
	if err != nil {
		return nil, files, err
	}
	files = append(files, file)
	args = append(args, "--object", fmt.Sprintf("secret,id=%s,file=/proc/self/fd/%d", secretNode(disk), 2+len(files)))
	return args, files, nil
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

type imageInformation struct {
	Format          string `json:"format"`
	VirtualSize     int64  `json:"virtual-size"`
	Encrypted       bool   `json:"encrypted"`
	BackingFilename string `json:"backing-filename"`
}

func (q *QEMU) info(ctx context.Context, disk Disk) (imageInformation, error) {
	var output bytes.Buffer
	err := runNative(ctx, q.config.ImageBinary, []string{"info", "--output=json", "-f", "qcow2", disk.Path}, nil, &output)
	if err != nil {
		return imageInformation{}, err
	}
	var info imageInformation
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		return info, err
	}
	if info.Format != "qcow2" || info.BackingFilename != "" || info.Encrypted != disk.Encrypted {
		return info, errors.New("native disk format, independence or encryption mismatch")
	}
	return info, nil
}

func reserveFile(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	return file.Close()
}

func (q *QEMU) CreateDisk(ctx context.Context, disk Disk, size int64) error {
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
	return q.createDisk(ctx, disk, size)
}

func (q *QEMU) createDisk(ctx context.Context, disk Disk, size int64) (err error) {
	args := []string{"create", "-q", "-f", "qcow2"}
	var files []*os.File
	args, files, err = addKeyArgs(args, files, disk)
	if err != nil {
		closeFiles(files)
		return err
	}
	defer closeFiles(files)
	if disk.Encrypted {
		args = append(args, "-o", "encrypt.format=luks,encrypt.key-secret="+secretNode(disk))
	}
	if err = reserveFile(disk.Path); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(disk.Path)
		}
	}()
	args = append(args, disk.Path, strconv.FormatInt(size, 10))
	return runNative(ctx, q.config.ImageBinary, args, files, io.Discard)
}

// ImportDisk performs a one-time native conversion from the owner's source.
// The destination is independent and becomes the only mutable byte authority.
func (q *QEMU) ImportDisk(ctx context.Context, destination Disk, source DiskSource, size int64) (err error) {
	if err := validateDisk(destination); err != nil {
		return err
	}
	if !filepath.IsAbs(source.Path) || source.Path == destination.Path || (source.Format != "raw" && source.Format != "qcow2") {
		return errors.New("import requires distinct absolute raw/qcow2 source")
	}
	if source.Encrypted && source.Format != "qcow2" {
		return &CapabilityError{Feature: "encrypted import format " + source.Format}
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	args := []string{"convert", "-q", "-O", "qcow2"}
	var files []*os.File
	args, files, err = addKeyArgs(args, files, destination)
	if err != nil {
		closeFiles(files)
		return err
	}
	sourceDisk := Disk{ID: "import-" + destination.ID, Path: source.Path, Encrypted: source.Encrypted, Key: source.Key}
	args, files, err = addKeyArgs(args, files, sourceDisk)
	defer closeFiles(files)
	if err != nil {
		return err
	}
	if destination.Encrypted {
		args = append(args, "-o", "encrypt.format=luks,encrypt.key-secret="+secretNode(destination))
	}
	options := diskOptions(sourceDisk)
	options["driver"] = source.Format
	if err = reserveFile(destination.Path); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(destination.Path)
		}
	}()
	args = append(args, "json:"+jsonOption(options), destination.Path)
	if err = runNative(ctx, q.config.ImageBinary, args, files, io.Discard); err != nil {
		return err
	}
	info, err := q.info(ctx, destination)
	if err != nil {
		return err
	}
	if size == 0 {
		return nil
	}
	if size < info.VirtualSize || size%512 != 0 {
		return errors.New("import size cannot shrink source and must be sector aligned")
	}
	if size > info.VirtualSize {
		return q.resizeOffline(ctx, destination, size)
	}
	return nil
}

// copyIndependent retains holes where the filesystem exposes SEEK_DATA/HOLE.
// It neither decrypts ciphertext nor creates a backing-file relationship.
func copyIndependent(source, destination string) (err error) {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("native copy source must be a regular file")
	}
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := out.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(destination)
		}
	}()
	if err = out.Truncate(info.Size()); err != nil {
		return err
	}
	for offset := int64(0); offset < info.Size(); {
		start, e := unix.Seek(int(in.Fd()), offset, unix.SEEK_DATA)
		if errors.Is(e, unix.ENXIO) {
			break
		}
		if errors.Is(e, unix.EINVAL) {
			_, err = io.Copy(out, io.NewSectionReader(in, 0, info.Size()))
			if err != nil {
				return err
			}
			break
		}
		if e != nil {
			return e
		}
		end, e := unix.Seek(int(in.Fd()), start, unix.SEEK_HOLE)
		if e != nil {
			return e
		}
		if end > info.Size() {
			end = info.Size()
		}
		if _, err = out.Seek(start, io.SeekStart); err != nil {
			return err
		}
		if _, err = io.CopyN(out, io.NewSectionReader(in, start, end-start), end-start); err != nil {
			return err
		}
		offset = end
	}
	return out.Sync()
}

// QEMU's native permission locks occupy bytes 100..199. Excluding those
// permission locks makes a raw ciphertext copy/delete fail while any native
// image user holds the file, including users outside this controller.
func exclusiveImage(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 100, Len: 100}
	if err := unix.FcntlFlock(file.Fd(), unix.F_OFD_SETLK, &lock); err != nil {
		file.Close()
		return nil, fmt.Errorf("native image is in use: %w", err)
	}
	return file, nil
}

func (q *QEMU) DeleteDisk(ctx context.Context, disk Disk) error {
	if err := validateDisk(disk); err != nil {
		return err
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := q.releaseUnattachedDisk(ctx, disk); err != nil {
		return err
	}
	info, err := os.Lstat(disk.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("native disk deletion requires a regular file")
	}
	file, err := exclusiveImage(disk.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	return os.Remove(disk.Path)
}

// WriteDisk hydrates an unbound native volume in one native disk session. The
// callback must not retain the writer. Blocks cross an anonymous memfd, never a
// plaintext disk mirror; encrypted disks are unlocked once, not once per block.
func (q *QEMU) WriteDisk(ctx context.Context, disk Disk, populate func(io.WriterAt) error) error {
	if err := validateDisk(disk); err != nil {
		return err
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	owner, _, err := q.diskOwner(ctx, disk)
	if err != nil {
		return err
	}
	if owner != nil {
		owner.close()
		return errors.New("cannot hydrate a VM-owned native disk")
	}
	return q.withOfflineExport(ctx, disk, false, func(socket, export string) error {
		input, err := memoryFile("stackd-hydrate")
		if err != nil {
			return err
		}
		defer input.Close()
		options := "driver=nbd,server.type=unix,server.path=" + escapeOption(socket) + ",export=" + escapeOption(export)
		writer := nativeDiskWriter{ctx: ctx, driver: q, input: input, options: options}
		if err := populate(&writer); err != nil {
			return err
		}
		return runNative(ctx, q.config.IOBinary, []string{"--image-opts", "-c", "flush", options}, nil, io.Discard)
	})
}

type nativeDiskWriter struct {
	ctx     context.Context
	driver  *QEMU
	input   *os.File
	options string
}

func (w *nativeDiskWriter) WriteAt(data []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("invalid native disk write offset")
	}
	if len(data) == 0 {
		return 0, nil
	}
	if _, err := w.input.WriteAt(data, 0); err != nil {
		return 0, err
	}
	command := fmt.Sprintf("write -s /proc/self/fd/3 %d %d", offset, len(data))
	if err := runNative(w.ctx, w.driver.config.IOBinary, []string{"--image-opts", "-c", command, w.options}, []*os.File{w.input}, io.Discard); err != nil {
		return 0, err
	}
	return len(data), nil
}

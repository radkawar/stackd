package lambda

import (
	"archive/tar"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func telemetryHelperArchive(ctx context.Context, filename, architecture string) (*os.File, error) {
	if !filepath.IsAbs(filename) {
		return nil, fmt.Errorf("lambda telemetry helper for %s requires an absolute local binary path", architecture)
	}
	binary, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening Lambda telemetry helper: %w", err)
	}
	defer binary.Close()
	info, err := binary.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("lambda telemetry helper is not a regular file")
	}
	image, err := elf.NewFile(binary)
	if err != nil {
		return nil, fmt.Errorf("lambda telemetry helper must be a static Linux ELF executable: %w", err)
	}
	machine := elf.EM_X86_64
	if architecture == "arm64" {
		machine = elf.EM_AARCH64
	}
	if image.Machine != machine || image.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("lambda telemetry helper does not match %s", architecture)
	}
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP {
			return nil, errors.New("lambda telemetry helper must be statically linked")
		}
	}
	file, err := os.CreateTemp("", "stackd-lambda-helper-*.tar")
	if err != nil {
		return nil, err
	}
	cleanup := func() { file.Close(); os.Remove(file.Name()) }
	archive := tar.NewWriter(file)
	if err := archive.WriteHeader(&tar.Header{Name: "telemetry-buffer", Mode: 0555, Size: info.Size(), Typeflag: tar.TypeReg}); err != nil {
		cleanup()
		return nil, err
	}
	if _, err := io.CopyN(archive, contextReader{ctx, binary}, info.Size()); err != nil {
		cleanup()
		return nil, err
	}
	if err := archive.Close(); err != nil {
		cleanup()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, err
	}
	return file, nil
}

package lambda

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const maxCodeBytes = 250 << 20

// ErrDeploymentTooLarge identifies Lambda's combined expanded package quota.
var ErrDeploymentTooLarge = errors.New("deployment exceeds expanded package quota")

// ValidateCode rejects unsafe and oversized expanded ZIP deployments.
// It checks actual decompressed bytes and CRCs, not just untrusted ZIP metadata.
func ValidateCode(code []byte) error {
	return walkCode(context.Background(), code, func(file *zip.File, body io.Reader) error {
		_, err := io.Copy(io.Discard, body)
		return err
	})
}

// ValidateDeploymentSize checks the combined expanded quota of already-validated
// function and layer archives without decompressing their content again.
func ValidateDeploymentSize(code []byte, layers [][]byte) error {
	var total uint64
	check := func(code []byte) error {
		archive, err := zip.NewReader(bytes.NewReader(code), int64(len(code)))
		if err != nil {
			return fmt.Errorf("invalid Lambda ZIP: %w", err)
		}
		for _, entry := range archive.File {
			if err := addExpandedSize(&total, entry.UncompressedSize64); err != nil {
				return err
			}
		}
		return nil
	}
	if err := check(code); err != nil {
		return err
	}
	for _, layer := range layers {
		if err := check(layer); err != nil {
			return err
		}
	}
	return nil
}

func addExpandedSize(total *uint64, size uint64) error {
	if size > maxCodeBytes || *total > maxCodeBytes-size {
		return ErrDeploymentTooLarge
	}
	*total += size
	return nil
}

func walkCode(ctx context.Context, code []byte, visit func(*zip.File, io.Reader) error) error {
	if len(code) == 0 {
		return fmt.Errorf("lambda ZIP cannot be empty")
	}
	zr, err := zip.NewReader(bytes.NewReader(code), int64(len(code)))
	if err != nil {
		return fmt.Errorf("invalid Lambda ZIP: %w", err)
	}
	if len(zr.File) == 0 || len(zr.File) > 100000 {
		return fmt.Errorf("lambda ZIP has invalid entry count")
	}
	var total uint64
	for _, file := range zr.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := strings.TrimSuffix(file.Name, "/")
		if name == "" || name == "." || strings.ContainsAny(name, "\\\x00:") || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("unsafe Lambda ZIP path %q", file.Name)
		}
		mode := file.Mode()
		if !mode.IsRegular() && !mode.IsDir() && mode&os.ModeSymlink == 0 {
			return fmt.Errorf("lambda ZIP entry %q is not a regular file, directory or symbolic link", file.Name)
		}
		if err := addExpandedSize(&total, file.UncompressedSize64); err != nil {
			return err
		}
		if mode.IsDir() {
			if file.UncompressedSize64 != 0 {
				return fmt.Errorf("lambda ZIP directory %q has content", file.Name)
			}
			if err := visit(file, strings.NewReader("")); err != nil {
				return err
			}
			continue
		}
		r, err := file.Open()
		if err != nil {
			return fmt.Errorf("opening Lambda ZIP entry %q: %w", name, err)
		}
		limited := &io.LimitedReader{R: contextReader{ctx, r}, N: int64(file.UncompressedSize64) + 1}
		err = visit(file, limited)
		closeErr := r.Close()
		if err != nil {
			return fmt.Errorf("reading Lambda ZIP entry %q: %w", name, err)
		}
		if limited.N != 1 {
			return fmt.Errorf("lambda ZIP entry %q has inconsistent expanded size", name)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func codeArchive(ctx context.Context, codes ...[]byte) (*os.File, error) {
	file, err := os.CreateTemp("", "stackd-lambda-*.tar")
	if err != nil {
		return nil, err
	}
	cleanup := func() { file.Close(); os.Remove(file.Name()) }
	tw := tar.NewWriter(file)
	writeEntry := func(entry *zip.File, body io.Reader) error {
		header := &tar.Header{Name: entry.Name, Mode: 0644, Size: int64(entry.UncompressedSize64), Typeflag: tar.TypeReg}
		if entry.Mode().IsDir() {
			header.Typeflag = tar.TypeDir
			header.Mode = 0755
		}
		if entry.Mode().Perm()&0111 != 0 {
			header.Mode = 0755
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			var target strings.Builder
			if _, err := io.Copy(&target, body); err != nil {
				return err
			}
			header.Typeflag, header.Size, header.Linkname = tar.TypeSymlink, 0, target.String()
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		_, err := io.Copy(tw, body)
		return err
	}
	for _, code := range codes {
		if err := walkCode(ctx, code, writeEntry); err != nil {
			cleanup()
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		cleanup()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, err
	}
	return file, nil
}

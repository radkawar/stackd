package codebuild

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

const maxArchiveBytes int64 = 512 << 20
const maxArchiveFiles = 100000

// Archive names are always relative to the isolated container workspace. Links
// are deliberately not followed, either when accepting source or returning output.
func workspacePath(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("invalid workspace path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("workspace path escapes source directory: %q", name)
		}
	}
	clean := path.Clean(name)
	if clean == "." {
		return "", fmt.Errorf("invalid workspace file %q", name)
	}
	return clean, nil
}

// Source entries share one workspace boundary whether supplied by S3 objects,
// a ZIP archive, or native Git. Directory entries preserve empty source folders.
func prepareSource(zip []byte, files []File) ([]File, error) {
	if files == nil {
		return unzipSource(zip)
	}
	if len(zip) != 0 {
		return nil, fmt.Errorf("source cannot contain both ZIP and folder files")
	}
	if len(files) > maxArchiveFiles {
		return nil, fmt.Errorf("source folder has too many entries")
	}
	directories := make(map[string]bool, len(files))
	var total int64
	for _, file := range files {
		name, err := workspacePath(file.Path)
		if err != nil {
			return nil, err
		}
		_, duplicate := directories[name]
		if name != file.Path || duplicate {
			return nil, fmt.Errorf("non-canonical or duplicate source path %q", file.Path)
		}
		mode := fs.FileMode(file.Mode)
		if mode.Type() != 0 && mode.Type() != fs.ModeDir {
			return nil, fmt.Errorf("source folder contains a special file %q", name)
		}
		if mode.IsDir() && len(file.Body) != 0 {
			return nil, fmt.Errorf("source directory contains file bytes %q", name)
		}
		directories[name] = mode.IsDir()
		total += int64(len(file.Body))
		if total > maxArchiveBytes {
			return nil, fmt.Errorf("source folder exceeds 512 MiB")
		}
	}
	for _, file := range files {
		for parent := path.Dir(file.Path); parent != "."; parent = path.Dir(parent) {
			if directory, exists := directories[parent]; exists && !directory {
				return nil, fmt.Errorf("source folder file/directory collision %q", parent)
			}
		}
	}
	return files, nil
}

func unzipSource(data []byte) ([]File, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if int64(len(data)) > maxArchiveBytes {
		return nil, fmt.Errorf("source archive exceeds 512 MiB")
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("reading ZIP: %w", err)
	}
	if len(r.File) > maxArchiveFiles {
		return nil, fmt.Errorf("ZIP has too many entries")
	}
	files := make([]File, 0, len(r.File))
	var total int64
	for _, entry := range r.File {
		name, err := workspacePath(entry.Name)
		if err != nil {
			return nil, err
		}
		if entry.Mode().IsDir() {
			if entry.UncompressedSize64 != 0 {
				return nil, fmt.Errorf("ZIP directory contains file bytes %q", name)
			}
			files = append(files, File{Path: name, Mode: uint32(entry.Mode())})
			continue
		}
		if !entry.Mode().IsRegular() {
			return nil, fmt.Errorf("ZIP links and special files are not supported: %q", name)
		}
		if entry.UncompressedSize64 > uint64(maxArchiveBytes-total) {
			return nil, fmt.Errorf("expanded ZIP exceeds 512 MiB")
		}
		src, err := entry.Open()
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(src, maxArchiveBytes-total+1))
		closeErr := src.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		total += int64(len(body))
		if total > maxArchiveBytes {
			return nil, fmt.Errorf("expanded ZIP exceeds 512 MiB")
		}
		files = append(files, File{Path: name, Body: body, Mode: uint32(entry.Mode().Perm())})
	}
	return prepareSource(nil, files)
}

func writeArchive(files []File) ([]byte, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	dirs := map[string]bool{}
	for _, file := range files {
		name, err := workspacePath(file.Path)
		if err != nil {
			return nil, err
		}
		var parents []string
		for dir := path.Dir(name); dir != "." && !dirs[dir]; dir = path.Dir(dir) {
			parents = append(parents, dir)
		}
		for i := len(parents) - 1; i >= 0; i-- {
			dir := parents[i]
			if err := writer.WriteHeader(&tar.Header{Name: dir + "/", Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
				return nil, err
			}
			dirs[dir] = true
		}
		mode := int64(file.Mode & 0777)
		if mode == 0 {
			mode = 0600
		}
		if fs.FileMode(file.Mode).IsDir() {
			if dirs[name] {
				continue
			}
			if err := writer.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: mode}); err != nil {
				return nil, err
			}
			dirs[name] = true
			continue
		}
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(file.Body))}); err != nil {
			return nil, err
		}
		if _, err := writer.Write(file.Body); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func readArchive(reader io.Reader, root string) ([]File, error) {
	return readSelectedArchive(reader, root, nil)
}

// A nil selection is strict source/control extraction. Output selection happens
// before inspecting entry types or reading bodies; unrelated links are never
// followed, while selected links and special files remain explicitly unsupported.
func readSelectedArchive(reader io.Reader, root string, selection *artifactSpec) ([]File, error) {
	tarReader := tar.NewReader(reader)
	var files []File
	var total int64
	count := 0
	var seen map[string]bool
	base := ""
	if selection != nil {
		seen = map[string]bool{}
		base = strings.TrimSuffix(strings.TrimPrefix(selection.BaseDirectory, "./"), "/")
		if base == "." {
			base = ""
		}
	}
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		count++
		if count > maxArchiveFiles {
			return nil, fmt.Errorf("workspace has too many files")
		}
		name := strings.TrimPrefix(header.Name, "./")
		if name == root || name == root+"/" {
			continue
		}
		if !strings.HasPrefix(name, root+"/") {
			return nil, fmt.Errorf("unexpected archive root %q", header.Name)
		}
		name, err = workspacePath(strings.TrimPrefix(name, root+"/"))
		if err != nil {
			return nil, err
		}
		if header.Typeflag == tar.TypeDir {
			if selection == nil && header.Size != 0 {
				return nil, fmt.Errorf("archive directory contains file bytes %q", name)
			}
			if selection == nil {
				files = append(files, File{Path: name, Mode: uint32(fs.ModeDir) | uint32(header.Mode&0777)})
			}
			continue
		}
		if selection != nil {
			var selected bool
			name, selected = selection.selectPath(name, base)
			if !selected {
				continue
			}
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("workspace links and special files are not supported: %q", name)
		}
		if selection != nil {
			if seen[name] {
				return nil, fmt.Errorf("artifact path collision %q", name)
			}
			seen[name] = true
		}
		if header.Size < 0 || header.Size > maxArchiveBytes-total {
			return nil, fmt.Errorf("workspace exceeds 512 MiB")
		}
		data, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, err
		}
		total += int64(len(data))
		files = append(files, File{Path: name, Body: data, Mode: uint32(header.Mode & 0777)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if selection == nil {
		return prepareSource(nil, files)
	}
	return files, nil
}

// matchGlob implements segment-aware '*'/'?' and recursive '**', unlike
// filepath.Match which cannot select nested artifact and cache paths.
func matchGlob(pattern, name string) bool {
	pattern = strings.TrimPrefix(pattern, "./")
	p, n := strings.Split(pattern, "/"), strings.Split(name, "/")
	var match func(int, int) bool
	match = func(i, j int) bool {
		if i == len(p) {
			return j == len(n)
		}
		if p[i] == "**" {
			for k := j; k <= len(n); k++ {
				if match(i+1, k) {
					return true
				}
			}
			return false
		}
		if j == len(n) {
			return false
		}
		ok, err := path.Match(p[i], n[j])
		return err == nil && ok && match(i+1, j+1)
	}
	return match(0, 0)
}

func (artifact artifactSpec) selectPath(name, base string) (string, bool) {
	if base != "" {
		found := false
		for i := strings.IndexByte(name, '/'); i >= 0; {
			if matchGlob(base, name[:i]) {
				name = name[i+1:]
				found = true
				break
			}
			next := strings.IndexByte(name[i+1:], '/')
			if next < 0 {
				break
			}
			i += next + 1
		}
		if !found {
			return "", false
		}
	}
	included := false
	for _, pattern := range artifact.Files {
		if matchGlob(pattern, name) {
			included = true
			break
		}
	}
	if !included {
		return "", false
	}
	for _, pattern := range artifact.ExcludePaths {
		if matchGlob(pattern, name) {
			return "", false
		}
	}
	if artifact.DiscardPaths {
		name = path.Base(name)
	}
	return name, true
}

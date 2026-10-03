package codebuild

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"testing"
)

func TestSourceZIPRejectsEscapesAndLinks(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		mode       fs.FileMode
	}{
		{"parent", "../outside", 0600}, {"absolute", "/outside", 0600}, {"nested-parent", "inside/../../outside", 0600},
		{"windows-separator", `inside\..\outside`, 0600}, {"symlink", "link", fs.ModeSymlink | 0777},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			writer := zip.NewWriter(&data)
			header := &zip.FileHeader{Name: tc.path}
			header.SetMode(tc.mode)
			entry, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = entry.Write([]byte("../../outside")); err != nil {
				t.Fatal(err)
			}
			if err = writer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = unzipSource(data.Bytes()); err == nil {
				t.Fatalf("accepted unsafe source %q", tc.path)
			}
		})
	}
}

func TestSourceZIPPreservesExecutableCommands(t *testing.T) {
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	header := &zip.FileHeader{Name: "scripts/build.sh"}
	header.SetMode(0755)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entry.Write([]byte("#!/bin/sh\nprintf built")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := unzipSource(data.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	archive, err := writeArchive(files)
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(bytes.NewReader(archive))
	if _, err = reader.Next(); err != nil {
		t.Fatal(err)
	}
	actual, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if actual.Name != "scripts/build.sh" || actual.Mode != 0755 {
		t.Fatalf("executable changed: %#v", actual)
	}
}

func TestContainerArchiveRejectsEscapingArtifactLink(t *testing.T) {
	var data bytes.Buffer
	writer := tar.NewWriter(&data)
	if err := writer.WriteHeader(&tar.Header{Name: "src/output", Typeflag: tar.TypeSymlink, Linkname: "/proc/1/environ", Mode: 0777}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readArchive(&data, "src"); err == nil {
		t.Fatal("followed artifact link outside workspace")
	}
}

func TestArtifactSelectionHonorsBaseExclusionsAndCollisions(t *testing.T) {
	source := []File{
		{Path: "src/dist/nested/result.txt", Body: []byte("actual output")},
		{Path: "src/dist/private/key.txt", Body: []byte("not published")},
		{Path: "src/elsewhere/result.txt", Body: []byte("unrelated")},
	}
	archive, err := writeArchive(source)
	if err != nil {
		t.Fatal(err)
	}
	files, err := readSelectedArchive(bytes.NewReader(archive), "src", &artifactSpec{BaseDirectory: "dist", Files: []string{"**/*.txt"}, ExcludePaths: []string{"private/**"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "nested/result.txt" || string(files[0].Body) != "actual output" {
		t.Fatalf("incorrect artifact selection: %#v", files)
	}
	_, err = readSelectedArchive(bytes.NewReader(archive), "src", &artifactSpec{Files: []string{"**/result.txt"}, DiscardPaths: true})
	if err == nil {
		t.Fatal("silently overwrote colliding artifact paths")
	}
}

func TestOutputSelectionSkipsOnlyUnselectedLinks(t *testing.T) {
	var data bytes.Buffer
	writer := tar.NewWriter(&data)
	for _, name := range []string{"src/node_modules/.bin/tool", "src/dist/private/link"} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: "/proc/1/environ", Mode: 0777}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.WriteHeader(&tar.Header{Name: "src/dist/result.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 6}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("result")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	selection := artifactSpec{BaseDirectory: "dist", Files: []string{"**/*"}, ExcludePaths: []string{"private/**"}}
	files, err := readSelectedArchive(bytes.NewReader(data.Bytes()), "src", &selection)
	if err != nil || len(files) != 1 || files[0].Path != "result.txt" || string(files[0].Body) != "result" {
		t.Fatalf("ordinary selected output was poisoned by unrelated links: %#v, %v", files, err)
	}
	selection.ExcludePaths = nil
	if _, err := readSelectedArchive(bytes.NewReader(data.Bytes()), "src", &selection); err == nil {
		t.Fatal("selected unsupported link was silently ignored or followed")
	}
	if _, err := readArchive(bytes.NewReader(data.Bytes()), "src"); err == nil {
		t.Fatal("output selection weakened strict source extraction")
	}
}

func TestSourceArchivesPreserveEmptyDirectories(t *testing.T) {
	for _, format := range []string{"zip", "tar"} {
		t.Run(format, func(t *testing.T) {
			var input bytes.Buffer
			var files []File
			var err error
			if format == "zip" {
				writer := zip.NewWriter(&input)
				for _, file := range []File{{Path: "nested/value", Body: []byte("source bytes"), Mode: 0600}, {Path: "empty/", Mode: uint32(fs.ModeDir | 0750)}, {Path: "nested/", Mode: uint32(fs.ModeDir | 0700)}} {
					header := &zip.FileHeader{Name: file.Path}
					header.SetMode(fs.FileMode(file.Mode))
					entry, e := writer.CreateHeader(header)
					if e != nil {
						t.Fatal(e)
					}
					if _, e = entry.Write(file.Body); e != nil {
						t.Fatal(e)
					}
				}
				if err = writer.Close(); err != nil {
					t.Fatal(err)
				}
				files, err = unzipSource(input.Bytes())
			} else {
				data, e := writeArchive([]File{{Path: "src/nested/value", Body: []byte("source bytes"), Mode: 0600}, {Path: "src/empty", Mode: uint32(fs.ModeDir | 0750)}})
				if e != nil {
					t.Fatal(e)
				}
				files, err = readArchive(bytes.NewReader(data), "src")
			}
			if err != nil {
				t.Fatal(err)
			}
			staged, err := writeArchive(files)
			if err != nil {
				t.Fatal(err)
			}
			reader := tar.NewReader(bytes.NewReader(staged))
			foundEmpty, foundBytes := false, false
			for {
				header, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if header.Name == "empty/" {
					foundEmpty = header.Typeflag == tar.TypeDir && header.Mode == 0750
				}
				if header.Name == "nested/value" {
					body, err := io.ReadAll(reader)
					if err != nil {
						t.Fatal(err)
					}
					foundBytes = string(body) == "source bytes"
				}
			}
			if !foundEmpty || !foundBytes {
				t.Fatalf("source staging lost directory or bytes: empty=%v bytes=%v", foundEmpty, foundBytes)
			}
		})
	}
}

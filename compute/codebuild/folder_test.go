package codebuild

import (
	"io/fs"
	"testing"
)

func TestFolderSourceWorkspaceBoundary(t *testing.T) {
	for _, test := range []struct {
		name  string
		files []File
	}{
		{"parent traversal", []File{{Path: "nested/../../control/buildspec.yml"}}},
		{"absolute", []File{{Path: "/codebuild/control/runner"}}},
		{"backslash", []File{{Path: `nested\escape`}}},
		{"nul", []File{{Path: "nested/\x00"}}},
		{"alias", []File{{Path: "nested/./value.txt"}}},
		{"duplicate", []File{{Path: "value.txt"}, {Path: "value.txt"}}},
		{"parent file", []File{{Path: "nested"}, {Path: "nested/value.txt"}}},
		{"symlink", []File{{Path: "link", Mode: uint32(fs.ModeSymlink | 0600)}}},
		{"duplicate directory", []File{{Path: "empty", Mode: uint32(fs.ModeDir | 0700)}, {Path: "empty", Mode: uint32(fs.ModeDir | 0700)}}},
		{"file and directory", []File{{Path: "same", Mode: 0600}, {Path: "same", Mode: uint32(fs.ModeDir | 0700)}}},
		{"file parent of directory", []File{{Path: "parent", Mode: 0600}, {Path: "parent/empty", Mode: uint32(fs.ModeDir | 0700)}}},
		{"directory traversal", []File{{Path: "nested/../../outside", Mode: uint32(fs.ModeDir | 0700)}}},
		{"directory payload", []File{{Path: "empty", Body: []byte("not a directory"), Mode: uint32(fs.ModeDir | 0700)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := prepareSource(nil, test.files); err == nil {
				t.Fatal("unsafe folder source accepted")
			}
		})
	}
}

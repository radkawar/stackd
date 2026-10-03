package lambda

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/fsnotify/fsnotify"
)

// HotReloadDirectories overrides $LATEST's /var/task and merged /opt trees for
// local development. Empty fields preserve the uploaded deployment contents.
// Published versions always use their retained archives, not these directories.
// Paths must be absolute, readable by UID 993, and visible at the same resolved
// paths to both stackd and Docker. Host files are mounted read-only, not copied.
// Filesystem notifications require a local filesystem with native watch support.
type HotReloadDirectories struct {
	Code   string
	Layers string
}

func normalizeHotReload(sources map[string]HotReloadDirectories) (map[string]HotReloadDirectories, error) {
	sources = maps.Clone(sources)
	for function, directories := range sources {
		key, err := arn.Parse(function)
		name, isFunction := strings.CutPrefix(key.Resource, "function:")
		if err != nil || key.Service != "lambda" || key.Partition == "" || key.Region == "" || key.AccountID == "" || !isFunction || name == "" || strings.Contains(name, ":") {
			return nil, fmt.Errorf("hot reload requires an unqualified Lambda function ARN: %q", function)
		}
		if directories.Code == "" && directories.Layers == "" {
			return nil, fmt.Errorf("hot reload for %s requires a code or layer directory", function)
		}
		for _, directory := range []*string{&directories.Code, &directories.Layers} {
			if *directory == "" {
				continue
			}
			if !filepath.IsAbs(*directory) {
				return nil, fmt.Errorf("hot reload directory must be absolute: %q", *directory)
			}
			resolved, err := filepath.EvalSymlinks(*directory)
			if err != nil {
				return nil, fmt.Errorf("resolving hot reload directory: %w", err)
			}
			info, err := os.Stat(resolved)
			if err != nil {
				return nil, fmt.Errorf("reading hot reload directory: %w", err)
			}
			if !info.IsDir() {
				return nil, fmt.Errorf("hot reload path is not a directory: %s", resolved)
			}
			*directory = resolved
		}
		sources[function] = directories
	}
	return sources, nil
}

// Each environment owns its watcher through its existing lifetime. Native
// notifications avoid rescanning or hashing dependency trees on every invoke.
type hotReloadWatcher struct {
	watcher  *fsnotify.Watcher
	roots    []string
	done     <-chan struct{}
	mu       sync.Mutex
	revision uint64
	modified time.Time
	changed  chan struct{}
	err      error
}

func newHotReloadWatcher(ctx context.Context, directories HotReloadDirectories) (*hotReloadWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating Lambda hot reload watcher: %w", err)
	}
	source := &hotReloadWatcher{watcher: watcher, done: ctx.Done(), changed: make(chan struct{})}
	for _, directory := range []string{directories.Code, directories.Layers} {
		if directory == "" {
			continue
		}
		source.roots = append(source.roots, directory)
		// Watch the parent too: replacing the root directory must rebind the
		// next runtime rather than retaining the deleted directory's inode.
		if err := watcher.Add(filepath.Dir(directory)); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("watching hot reload parent: %w", err)
		}
		if err := source.addTree(directory); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("watching hot reload tree: %w", err)
		}
	}
	go source.watch()
	return source, nil
}

func (s *hotReloadWatcher) addTree(path string) error {
	return filepath.WalkDir(path, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return s.watcher.Add(path)
		}
		return nil
	})
}

func (s *hotReloadWatcher) contains(path string) bool {
	for _, root := range s.roots {
		if suffix, ok := strings.CutPrefix(path, root); ok && (suffix == "" || os.IsPathSeparator(suffix[0]) || root == string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func (s *hotReloadWatcher) signal(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
	s.revision++
	s.modified = time.Now()
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *hotReloadWatcher) watch() {
	defer s.watcher.Close()
	for {
		select {
		case <-s.done:
			return
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			s.signal(fmt.Errorf("watching Lambda hot reload directories: %w", err))
			return
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if !s.contains(event.Name) {
				continue
			}
			if event.Has(fsnotify.Create) {
				if err := s.addTree(event.Name); err != nil && !errors.Is(err, fs.ErrNotExist) {
					s.signal(fmt.Errorf("watching new Lambda hot reload directory: %w", err))
					return
				}
			}
			s.signal(nil)
		}
	}
}

func (s *hotReloadWatcher) stable(ctx context.Context, previous uint64) (uint64, error) {
	for {
		s.mu.Lock()
		revision, modified, changed, err := s.revision, s.modified, s.changed, s.err
		s.mu.Unlock()
		if err != nil || revision == previous {
			return revision, err
		}
		remaining := time.Until(modified.Add(500 * time.Millisecond))
		if remaining <= 0 {
			return revision, nil
		}
		timer := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-s.done:
			timer.Stop()
			return 0, context.Canceled
		case <-changed:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// Invoke calls this only after acquiring the environment's execution gate.
// Active functions and extensions finish before a development reload; the
// existing reset boundary preserves /tmp and the keeper's network namespace.
func (e *dockerEnvironment) reloadSource(ctx context.Context) error {
	if e.hotReload == nil {
		return nil
	}
	revision, err := e.hotReload.stable(ctx, e.sourceRevision)
	if err != nil || revision == e.sourceRevision {
		return err
	}
	resetCtx, cancel := context.WithTimeout(ctx, e.startupTimeout)
	defer cancel()
	if err := e.resetRuntime(resetCtx, "spindown"); err != nil {
		return fmt.Errorf("reloading Lambda development runtime: %w", err)
	}
	e.initAttempted = false
	e.sourceRevision = revision
	return nil
}

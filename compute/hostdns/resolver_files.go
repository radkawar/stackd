package hostdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// fileBackend uses the same filesystem operations in production and tests;
// only the resolver directory differs. Existing unowned files are never adopted.
type fileBackend struct{ directory string }

type fileState struct {
	Exists bool
	Data   []byte
	Mode   uint32
	UID    uint32
	GID    uint32
}

func resolverState(c Config) fileState {
	endpoint := netip.MustParseAddrPort(c.Address)
	text := "# Owned by stackd hostdns; restore with stackd network dns teardown.\n" +
		"nameserver " + endpoint.Addr().String() + "\nport " + strconv.Itoa(int(endpoint.Port())) + "\n"
	return fileState{Exists: true, Data: []byte(text), Mode: 0644, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
}

func (b fileBackend) prepareDirectory(create bool) error {
	if create {
		if err := os.Mkdir(b.directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	info, err := os.Lstat(b.directory)
	if errors.Is(err, os.ErrNotExist) && !create {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("hostdns: resolver directory must be a real, non-writable-by-others directory")
	}
	return checkOwner(info)
}

func (b fileBackend) plan(ctx context.Context, c Config) (string, []change, error) {
	if err := b.prepareDirectory(false); err != nil {
		return "", nil, err
	}
	r := receipt{Config: c, Target: b.directory}
	conflicts, err := b.conflicts(ctx, r)
	if err != nil {
		return "", nil, err
	}
	if len(conflicts) != 0 {
		return "", nil, fmt.Errorf("hostdns: unowned resolver conflict: %s", strings.Join(conflicts, "; "))
	}
	var changes []change
	for _, domain := range c.Domains {
		before, err := b.read(ctx, r, domain)
		if err != nil {
			return "", nil, err
		}
		if !bytes.Equal(before, encoded(fileState{})) {
			return "", nil, fmt.Errorf("hostdns: refusing existing unowned resolver %s", domain)
		}
		changes = append(changes, change{Key: domain, Before: before, After: encoded(resolverState(c))})
	}
	return b.directory, changes, nil
}

func (b fileBackend) validate(r receipt) error {
	if r.Target != b.directory || len(r.Changes) != len(r.Config.Domains) {
		return errors.New("hostdns: invalid resolver file receipt target")
	}
	for i, domain := range r.Config.Domains {
		ch := r.Changes[i]
		if ch.Key != domain || !bytes.Equal(ch.Before, encoded(fileState{})) || !bytes.Equal(ch.After, encoded(resolverState(r.Config))) {
			return errors.New("hostdns: invalid resolver file receipt settings")
		}
	}
	return nil
}

func (b fileBackend) read(ctx context.Context, r receipt, key string) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := b.prepareDirectory(false); err != nil {
		return nil, err
	}
	if domain, err := validDomain(key); err != nil || domain != key {
		return nil, errors.New("hostdns: unsafe resolver filename")
	}
	path := filepath.Join(b.directory, key)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return encoded(fileState{}), nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, fmt.Errorf("hostdns: unsafe resolver file %s", key)
	}
	uid, gid, err := fileOwner(info)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return encoded(fileState{Exists: true, Data: data, Mode: uint32(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)), UID: uid, GID: gid}), nil
}

func (b fileBackend) write(ctx context.Context, r receipt, key string, expected, desired json.RawMessage) error {
	if err := b.prepareDirectory(true); err != nil {
		return err
	}
	current, err := b.read(ctx, r, key)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return conflict(key)
	}
	var state fileState
	if err := json.Unmarshal(desired, &state); err != nil {
		return err
	}
	path := filepath.Join(b.directory, key)
	if !state.Exists {
		if err := os.Remove(path); err != nil {
			return err
		}
		return syncDirectory(b.directory)
	}
	// Link publishes an already fsynced file only if the target is still absent.
	// An external creator racing installation is never overwritten by rename.
	file, err := os.CreateTemp(b.directory, ".stackd-hostdns-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(os.FileMode(state.Mode)); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(state.Data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(file.Name(), path); err != nil {
		return fmt.Errorf("hostdns: publish resolver without overwriting: %w", err)
	}
	return syncDirectory(b.directory)
}

func (b fileBackend) conflicts(ctx context.Context, r receipt) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := b.prepareDirectory(false); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(b.directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	owned := make(map[string]bool)
	for _, ch := range r.Changes {
		owned[ch.Key] = true
	}
	var conflicts []string
	for _, entry := range entries {
		if owned[entry.Name()] {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".stackd-hostdns-") {
			continue
		}
		scopes := []string{entry.Name()}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return nil, fmt.Errorf("hostdns: cannot inspect resolver %s safely", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(b.directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(fields) >= 2 && fields[0] == "domain" {
				scopes = append(scopes, fields[1])
			}
		}
		for _, domain := range r.Config.Domains {
			for _, scope := range scopes {
				if overlaps(domain, scope) {
					conflicts = append(conflicts, entry.Name()+" overlaps "+domain)
					break
				}
			}
		}
	}
	return conflicts, nil
}

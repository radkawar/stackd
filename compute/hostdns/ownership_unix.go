//go:build linux || darwin

package hostdns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func fileOwner(info os.FileInfo) (uint32, uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("hostdns: cannot inspect native file ownership")
	}
	return stat.Uid, stat.Gid, nil
}

func checkOwner(info os.FileInfo) error {
	uid, _, err := fileOwner(info)
	if err != nil {
		return err
	}
	if uid != uint32(os.Geteuid()) {
		return errors.New("hostdns: state/resolver directory or receipt is not owned by the invoking user")
	}
	return nil
}

func lockHost(ctx context.Context) (func(), error) {
	// One host-wide lock prevents separate state directories from concurrently
	// claiming the same link or resolver file. Never unlink the flock inode.
	fd, err := unix.Open("/var/run/stackd-hostdns.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("hostdns: acquire host ownership lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), "stackd-hostdns.lock")
	info, err := file.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600) {
		err = errors.New("hostdns: unsafe host lock")
	}
	if err == nil {
		err = checkOwner(info)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = file.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			file.Close()
			return nil, err
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

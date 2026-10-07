//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package devtls

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func openNoFollow(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, errors.New("devtls: state filename must be a single component")
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	// os.Root follows in-root symlinks even with O_NOFOLLOW. Use the retained
	// directory descriptor and a single-component openat to reject the final
	// symlink atomically. Nonblocking opens also reject FIFOs without hanging.
	fd, err := unix.Openat(int(directory.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func ownedFile(info os.FileInfo, regular bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("devtls: private authority state must belong to the current user")
	}
	if regular && stat.Nlink != 1 {
		return errors.New("devtls: authority state must not have hard links")
	}
	return nil
}

func lockState(ctx context.Context, root *os.Root) (func(), error) {
	file, err := openNoFollow(root, lockFile, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("devtls: open authority lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("devtls: inspect authority lock: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, errors.New("devtls: authority lock must be a regular private file (0600)")
	}
	if err := ownedFile(info, true); err != nil {
		file.Close()
		return nil, err
	}
	var ticker *time.Ticker
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			file.Close()
			return nil, fmt.Errorf("devtls: wait for authority lock: %w", err)
		}
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			// Closing the descriptor releases the lock even after an error.
			return func() { _ = file.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			file.Close()
			return nil, fmt.Errorf("devtls: acquire authority lock: %w", err)
		}
		if ticker == nil {
			ticker = time.NewTicker(20 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, fmt.Errorf("devtls: wait for authority lock: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

package network

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// nativeNetworkIdentity requires the controller to see the daemon-host inode.
// The daemon-side operation, not the disposable controller, owns its flock.
func nativeNetworkIdentity(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	const path = "/run/lock/stackd-public-network.lock"
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		file, err = os.OpenFile(path, os.O_RDONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0644)
		if errors.Is(err, os.ErrExist) {
			file, err = os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		}
	}
	if err != nil {
		return "", fmt.Errorf("open daemon-host public network lock (share /run/lock with the controller): %w", err)
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return "", fmt.Errorf("inspect public network lock: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", errors.New("public network lock must be a regular daemon-host file")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("identify public network lock host: %w", err)
	}
	return fmt.Sprintf("%s %d:%d", strings.TrimSpace(string(boot)), stat.Dev, stat.Ino), nil
}

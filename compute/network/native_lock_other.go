//go:build !linux

package network

import (
	"context"
	"errors"
)

func nativeNetworkIdentity(context.Context) (string, error) {
	// TODO: Comeback: native public/private admission requires a Linux controller
	// sharing the daemon host's lock inode; remote/Desktop hosts are unsupported.
	return "", errors.New("native public/private network admission requires a local Linux controller and daemon-host /run/lock")
}

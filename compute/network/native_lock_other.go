//go:build !linux

package network

import (
	"context"
	"errors"
)

func nativeNetworkIdentity(context.Context) (string, error) {
	// Default local admission requires a Linux controller sharing the daemon's
	// inode. NewDaemonBridges explicitly owns this witness inside the Engine.
	return "", errors.New("native public/private network admission requires a local Linux controller and daemon-host /run/lock")
}

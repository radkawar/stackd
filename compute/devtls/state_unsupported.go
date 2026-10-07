//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package devtls

import (
	"context"
	"errors"
	"os"
)

var errPlatform = errors.New("devtls: secure private CA persistence is unsupported on this platform")

func openNoFollow(*os.Root, string, int, os.FileMode) (*os.File, error) {
	return nil, errPlatform
}

func ownedFile(os.FileInfo, bool) error { return errPlatform }

func lockState(context.Context, *os.Root) (func(), error) { return nil, errPlatform }

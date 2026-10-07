//go:build !linux && !darwin

package hostdns

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

func unsupported() error                            { return fmt.Errorf("hostdns: unsupported platform %s", runtime.GOOS) }
func nativeBackend() (backend, error)               { return nil, unsupported() }
func fileOwner(os.FileInfo) (uint32, uint32, error) { return 0, 0, unsupported() }
func checkOwner(os.FileInfo) error                  { return unsupported() }
func lockHost(context.Context) (func(), error)      { return nil, unsupported() }

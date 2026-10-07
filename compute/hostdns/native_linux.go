package hostdns

import (
	"fmt"
	"os"
)

func nativeBackend() (backend, error) {
	const path = "/usr/bin/busctl"
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("hostdns: systemd-resolved requires installed %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, fmt.Errorf("hostdns: %s is not executable", path)
	}
	ip := ""
	for _, candidate := range []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			ip = candidate
			break
		}
	}
	return resolvedBackend{busctl: path, ip: ip}, nil
}

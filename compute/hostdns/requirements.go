package hostdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

func localDNSAddress(address netip.Addr, assigned []netip.Prefix) bool {
	if address.IsLoopback() {
		return true
	}
	for _, prefix := range assigned {
		if prefix.Addr().Unmap() == address.Unmap() {
			return true
		}
	}
	return false
}

func systemdVersion(output []byte) (int, error) {
	fields := strings.Fields(string(output))
	if len(fields) < 2 || fields[0] != "systemd" {
		return 0, errors.New("hostdns: cannot identify running systemd-resolved version")
	}
	digits := 0
	for digits < len(fields[1]) && fields[1][digits] >= '0' && fields[1][digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return 0, errors.New("hostdns: invalid systemd-resolved version")
	}
	return strconv.Atoi(fields[1][:digits])
}

func assignedDNSAddress(address netip.Addr) (bool, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false, fmt.Errorf("hostdns: inspect local DNS addresses: %w", err)
	}
	var assigned []netip.Prefix
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			assigned = append(assigned, prefix)
		}
	}
	return localDNSAddress(address, assigned), nil
}

func (b resolvedBackend) automaticRequirements(ctx context.Context, c Config) error {
	if b.ip == "" {
		return errors.New("hostdns: automatic interfaces require installed native iproute2 ip")
	}
	local, err := assignedDNSAddress(netip.MustParseAddrPort(c.Address).Addr())
	if err != nil {
		return err
	}
	if !local {
		return errors.New("hostdns: automatic dummy link requires DNS on loopback or an IP assigned to this host; remote DNS requires an explicit routed interface")
	}
	return b.localDNSVersion(ctx)
}

func (b resolvedBackend) localDNSVersion(ctx context.Context) error {
	// Ask the bus for the running server, rather than trusting a potentially
	// different installed client's version. The proc executable also survives
	// package upgrades while an older resolved process is still running.
	output, err := b.command(ctx, "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixProcessID", "s", resolvedService)
	if err != nil {
		return err
	}
	value, err := decodeMethodReply(output, "u")
	if err != nil {
		return err
	}
	var pid uint32
	if err := json.Unmarshal(value, &pid); err != nil || pid == 0 {
		return errors.New("hostdns: cannot identify running resolved process")
	}
	output, err = exec.CommandContext(ctx, "/proc/"+strconv.FormatUint(uint64(pid), 10)+"/exe", "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("hostdns: inspect running resolved version: %w: %s", err, strings.TrimSpace(string(output)))
	}
	version, err := systemdVersion(output)
	if err != nil {
		return err
	}
	if version < 256 {
		return fmt.Errorf("hostdns: local DNS through a per-link resolver requires systemd-resolved >=256 (running %d); older versions bind local DNS to the wrong interface", version)
	}
	return nil
}

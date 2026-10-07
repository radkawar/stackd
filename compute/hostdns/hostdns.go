// Package hostdns installs explicit, reversible domain-scoped host DNS routes.
// It never replaces resolv.conf or the host's global resolver configuration.
package hostdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
)

// Config describes an opt-in native resolver installation. Address is a literal
// IP or IP:port (IPv6 ports require brackets). Linux creates an owned dummy link
// when Interface is empty; an explicit link must have no DNS/domains and must
// already have DefaultRoute=no. StateDirectory must remain private and retained
// until teardown succeeds; its receipt is the authority to restore settings.
type Config struct {
	Address        string
	Domains        []string
	Interface      string
	StateDirectory string
}

// Report describes observed settings, not DNS server reachability. Installed is
// true only when every owned setting still matches and no scope conflicts exist.
type Report struct {
	Platform  string
	Target    string
	Config    Config
	Owned     bool
	Installed bool
	Phase     string
	Conflicts []string
}

type change struct {
	Key    string
	Before json.RawMessage
	After  json.RawMessage
}

type receipt struct {
	Version  int
	Platform string
	Config   Config
	Target   string
	Phase    string
	Changes  []change
}

type backend interface {
	plan(context.Context, Config) (string, []change, error)
	validate(receipt) error
	read(context.Context, receipt, string) (json.RawMessage, error)
	write(context.Context, receipt, string, json.RawMessage, json.RawMessage) error
	conflicts(context.Context, receipt) ([]string, error)
}

func normalize(c Config, platform string) (Config, error) {
	if c.StateDirectory == "" {
		return c, errors.New("hostdns: state directory is required")
	}
	absolute, err := filepath.Abs(c.StateDirectory)
	if err != nil {
		return c, err
	}
	c.StateDirectory = filepath.Clean(absolute)
	var endpoint netip.AddrPort
	if addr, err := netip.ParseAddr(c.Address); err == nil {
		endpoint = netip.AddrPortFrom(addr, 53)
	} else {
		endpoint, err = netip.ParseAddrPort(c.Address)
		if err != nil {
			return c, errors.New("hostdns: address must be a literal IP or IP:port")
		}
	}
	addr := endpoint.Addr().Unmap()
	if endpoint.Addr().Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || endpoint.Port() == 0 {
		return c, errors.New("hostdns: scoped, unspecified, multicast addresses and zero ports are unsupported")
	}
	c.Address = netip.AddrPortFrom(addr, endpoint.Port()).String()
	if len(c.Domains) == 0 {
		return c, errors.New("hostdns: at least one domain is required")
	}
	seen := make(map[string]bool)
	domains := make([]string, 0, len(c.Domains))
	for _, input := range c.Domains {
		domain, err := validDomain(input)
		if err != nil {
			return c, err
		}
		if !seen[domain] {
			domains = append(domains, domain)
			seen[domain] = true
		}
	}
	sort.Strings(domains)
	c.Domains = domains
	switch platform {
	case "linux":
		if c.Interface != "" && (len(c.Interface) > 15 || strings.ContainsAny(c.Interface, "/\\\x00\n\r\t ") || c.Interface[0] == '-') {
			return c, errors.New("hostdns: invalid dedicated interface name")
		}
	case "darwin":
		if c.Interface != "" {
			return c, errors.New("hostdns: macOS per-domain resolvers do not accept an interface")
		}
	default:
		return c, fmt.Errorf("hostdns: unsupported platform %s", platform)
	}
	return c, nil
}

func validDomain(input string) (string, error) {
	domain := strings.ToLower(strings.TrimSuffix(input, "."))
	if len(domain) == 0 || len(domain) > 253 || domain == "localhost" || domain == "local" {
		return "", fmt.Errorf("hostdns: invalid or reserved domain %q", input)
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return "", fmt.Errorf("hostdns: domain cannot be an IP: %q", input)
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("hostdns: invalid domain %q", input)
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", fmt.Errorf("hostdns: invalid domain %q", input)
			}
		}
	}
	return domain, nil
}

func overlaps(a, b string) bool {
	a = strings.ToLower(strings.TrimSuffix(a, "."))
	b = strings.ToLower(strings.TrimSuffix(b, "."))
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// Setup explicitly installs routes. Repeating the same configuration is safe;
// changing an owned installation requires successful teardown first.
func Setup(ctx context.Context, config Config) error {
	c, err := normalize(config, runtime.GOOS)
	if err != nil {
		return err
	}
	if err := requirePrivilege(); err != nil {
		return err
	}
	unlock, err := lockHost(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	b, err := nativeBackend()
	if err != nil {
		return err
	}
	return setup(ctx, c, runtime.GOOS, b)
}

func setup(ctx context.Context, c Config, platform string, b backend) error {
	if err := privateDirectory(c.StateDirectory, true); err != nil {
		return err
	}
	r, err := loadReceipt(c.StateDirectory)
	if err != nil {
		return err
	}
	if r == nil {
		target, changes, err := b.plan(ctx, c)
		if err != nil {
			return err
		}
		r = &receipt{Version: 1, Platform: platform, Config: c, Target: target, Phase: "installing", Changes: changes}
		if err := b.validate(*r); err != nil {
			return err
		}
		if err := saveReceipt(*r); err != nil {
			return err
		}
	} else {
		if r.Platform != platform || !reflect.DeepEqual(r.Config, c) {
			return errors.New("hostdns: owned receipt differs; teardown the previous configuration first")
		}
		if r.Phase == "removing" {
			return errors.New("hostdns: interrupted teardown; complete teardown before setup")
		}
		if err := b.validate(*r); err != nil {
			return err
		}
	}
	conflicts, err := b.conflicts(ctx, *r)
	if err != nil {
		return err
	}
	if len(conflicts) != 0 {
		return fmt.Errorf("hostdns: conflicting native resolver scopes: %s", strings.Join(conflicts, "; "))
	}
	if _, err := observe(ctx, b, *r, r.Phase == "active"); err != nil {
		return err
	}
	if r.Phase == "active" {
		return nil
	}
	for _, ch := range r.Changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := b.read(ctx, *r, ch.Key)
		if err != nil {
			return err
		}
		if bytes.Equal(current, ch.After) {
			continue
		}
		if !bytes.Equal(current, ch.Before) {
			return conflict(ch.Key)
		}
		if err := b.write(ctx, *r, ch.Key, ch.Before, ch.After); err != nil {
			return err
		}
	}
	if _, err := observe(ctx, b, *r, true); err != nil {
		return err
	}
	r.Phase = "active"
	return saveReceipt(*r)
}

// Teardown restores the exact recorded prior settings. Any externally changed
// setting blocks restoration, retains the receipt, and is never overwritten.
func Teardown(ctx context.Context, stateDirectory string) error {
	if stateDirectory == "" {
		return errors.New("hostdns: state directory is required")
	}
	if err := requirePrivilege(); err != nil {
		return err
	}
	unlock, err := lockHost(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	b, err := nativeBackend()
	if err != nil {
		return err
	}
	return teardown(ctx, stateDirectory, runtime.GOOS, b)
}

func teardown(ctx context.Context, directory, platform string, b backend) error {
	r, err := loadReceipt(directory)
	if err != nil || r == nil {
		return err
	}
	if r.Platform != platform {
		return errors.New("hostdns: receipt belongs to another platform")
	}
	if err := b.validate(*r); err != nil {
		return err
	}
	strict := false
	if r.Platform == "linux" && r.Config.Interface == "" && r.Phase == "active" {
		current, err := b.read(ctx, *r, "Interface")
		if err != nil {
			return err
		}
		// A live owned interface is deleted only while the entire active
		// installation remains unchanged. If it is already absent, restoring
		// the original absence requires no native mutation.
		strict = !bytes.Equal(current, encoded(nil))
	}
	if _, err := observe(ctx, b, *r, strict); err != nil {
		return err
	}
	r.Phase = "removing"
	if err := saveReceipt(*r); err != nil {
		return err
	}
	for i := len(r.Changes) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		ch := r.Changes[i]
		current, err := b.read(ctx, *r, ch.Key)
		if err != nil {
			return err
		}
		if bytes.Equal(current, ch.Before) {
			continue
		}
		if !bytes.Equal(current, ch.After) {
			return conflict(ch.Key)
		}
		if err := b.write(ctx, *r, ch.Key, ch.After, ch.Before); err != nil {
			return err
		}
	}
	for _, ch := range r.Changes {
		current, err := b.read(ctx, *r, ch.Key)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, ch.Before) {
			return conflict(ch.Key)
		}
	}
	if err := os.Remove(filepath.Join(r.Config.StateDirectory, "receipt.json")); err != nil {
		return err
	}
	return syncDirectory(r.Config.StateDirectory)
}

func conflict(key string) error {
	return fmt.Errorf("hostdns: external change to %s; refusing to overwrite (receipt retained)", key)
}

func observe(ctx context.Context, b backend, r receipt, onlyAfter bool) ([]string, error) {
	var conflicts []string
	for _, ch := range r.Changes {
		current, err := b.read(ctx, r, ch.Key)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(current, ch.After) && (onlyAfter || !bytes.Equal(current, ch.Before)) {
			conflicts = append(conflicts, ch.Key)
		}
	}
	if len(conflicts) != 0 {
		return conflicts, conflict(strings.Join(conflicts, ", "))
	}
	return nil, nil
}

// Status is read-only, including when no receipt exists. It reports conflicts
// without attempting to repair them or probing the configured DNS server.
func Status(ctx context.Context, stateDirectory string) (Report, error) {
	return status(ctx, stateDirectory, runtime.GOOS, nativeBackend)
}

func status(ctx context.Context, directory, platform string, makeBackend func() (backend, error)) (Report, error) {
	report := Report{Platform: platform}
	if platform != "linux" && platform != "darwin" {
		return report, fmt.Errorf("hostdns: unsupported platform %s", platform)
	}
	if directory == "" {
		return report, errors.New("hostdns: state directory is required")
	}
	r, err := loadReceipt(directory)
	if err != nil || r == nil {
		return report, err
	}
	report.Config, report.Owned, report.Phase, report.Target = r.Config, true, r.Phase, r.Target
	if r.Platform != platform {
		return report, errors.New("hostdns: receipt belongs to another platform")
	}
	b, err := makeBackend()
	if err != nil {
		return report, err
	}
	if err := b.validate(*r); err != nil {
		return report, err
	}
	for _, ch := range r.Changes {
		current, err := b.read(ctx, *r, ch.Key)
		if err != nil {
			return report, err
		}
		if !bytes.Equal(current, ch.After) {
			report.Conflicts = append(report.Conflicts, ch.Key)
		}
	}
	scopes, err := b.conflicts(ctx, *r)
	if err != nil {
		return report, err
	}
	report.Conflicts = append(report.Conflicts, scopes...)
	report.Installed = r.Phase == "active" && len(report.Conflicts) == 0
	return report, nil
}

func requirePrivilege() error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return fmt.Errorf("hostdns: unsupported platform %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("hostdns: native DNS setup/teardown requires root (explicit sudo invocation)")
	}
	return nil
}

func privateDirectory(path string, create bool) error {
	if create {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("hostdns: create private state directory: %w", err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("hostdns: state directory must be a real private directory (mode 0700)")
	}
	return checkOwner(info)
}

func loadReceipt(directory string) (*receipt, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err := privateDirectory(absolute, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	path := filepath.Join(absolute, "receipt.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, errors.New("hostdns: unsafe receipt file")
	}
	if err := checkOwner(info); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r receipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return nil, fmt.Errorf("hostdns: invalid receipt: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil || !errors.Is(err, io.EOF) {
		return nil, errors.New("hostdns: trailing receipt data")
	}
	c, err := normalize(r.Config, r.Platform)
	if err != nil || !reflect.DeepEqual(c, r.Config) || c.StateDirectory != absolute || r.Version != 1 || len(r.Changes) == 0 || (r.Phase != "installing" && r.Phase != "active" && r.Phase != "removing") {
		return nil, errors.New("hostdns: receipt has invalid ownership/configuration")
	}
	return &r, nil
}

func saveReceipt(r receipt) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(data)+1 > 1<<20 {
		return errors.New("hostdns: receipt exceeds durable ownership size limit")
	}
	return replaceFile(filepath.Join(r.Config.StateDirectory, "receipt.json"), append(data, '\n'), 0600)
}

func replaceFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".stackd-hostdns-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
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
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func encoded(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}

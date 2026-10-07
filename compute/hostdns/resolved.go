package hostdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const resolvedService = "org.freedesktop.resolve1"
const resolvedPath = "/org/freedesktop/resolve1"
const resolvedManager = "org.freedesktop.resolve1.Manager"

type resolvedBackend struct{ busctl, ip string }

func (b resolvedBackend) command(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, b.busctl, append([]string{"--system", "--no-pager", "--json=short", "--timeout=10s"}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("hostdns: systemd-resolved native call failed (requires active resolved, system bus and DNSEx support): %w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func decodeProperty(data []byte, signature string) (json.RawMessage, error) {
	var result struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("hostdns: decode native property: %w", err)
	}
	if result.Type != signature || len(result.Data) == 0 || bytes.Equal(result.Data, []byte("null")) {
		return nil, fmt.Errorf("hostdns: unexpected native property signature %s, expected %s", result.Type, signature)
	}
	if signature == "b" {
		var value bool
		if err := json.Unmarshal(result.Data, &value); err != nil {
			return nil, fmt.Errorf("hostdns: decode native boolean: %w", err)
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, result.Data); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

func decodeMethodReply(data []byte, signature string) (json.RawMessage, error) {
	message, err := decodeProperty(data, signature)
	if err != nil {
		return nil, err
	}
	// busctl wraps method arguments in a message array, while get-property
	// emits the property's value directly.
	var values []json.RawMessage
	if err := json.Unmarshal(message, &values); err != nil || len(values) != 1 {
		return nil, errors.New("hostdns: expected one native method reply argument")
	}
	return values[0], nil
}

func (b resolvedBackend) property(ctx context.Context, path, iface, property, signature string) (json.RawMessage, error) {
	data, err := b.command(ctx, "get-property", resolvedService, path, iface, property)
	if err != nil {
		return nil, err
	}
	return decodeProperty(data, signature)
}

func (b resolvedBackend) link(ctx context.Context, r receipt) (int, string, error) {
	name := r.Config.Interface
	if name == "" {
		name = r.Target
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, "", fmt.Errorf("hostdns: interface %s unavailable: %w", name, err)
	}
	index := iface.Index
	if r.Config.Interface != "" {
		prior, err := strconv.Atoi(r.Target)
		if err != nil || prior != index {
			return 0, "", errors.New("hostdns: interface identity changed; refusing to reuse ownership receipt")
		}
	}
	data, err := b.discoverLink(ctx, index, r.Config.Interface == "" && r.Phase == "installing")
	if err != nil {
		return 0, "", err
	}
	value, err := decodeMethodReply(data, "o")
	if err != nil {
		return 0, "", err
	}
	var path string
	if err := json.Unmarshal(value, &path); err != nil {
		return 0, "", err
	}
	if !strings.HasPrefix(path, resolvedPath+"/link/") {
		return 0, "", errors.New("hostdns: invalid resolved link object")
	}
	return index, path, nil
}

func (b resolvedBackend) discoverLink(ctx context.Context, index int, newlyCreated bool) ([]byte, error) {
	if !newlyCreated {
		return b.command(ctx, "call", resolvedService, resolvedPath, resolvedManager, "GetLink", "i", strconv.Itoa(index))
	}
	// Native creation and resolved's netlink observation are asynchronous. Wait
	// only for a newly owned link to enter resolved's object inventory.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for {
		data, err := b.command(ctx, "call", resolvedService, resolvedPath, resolvedManager, "GetLink", "i", strconv.Itoa(index))
		if err == nil {
			return data, nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("hostdns: waiting for owned link in resolved: %w", err)
		case <-timer.C:
		}
	}
}

func resolvedAfter(c Config) []change {
	endpoint := netip.MustParseAddrPort(c.Address)
	family := 2
	if endpoint.Addr().Is6() {
		family = 10
	}
	// Numeric byte arrays are D-Bus ay, not Go's base64 encoding of []byte.
	var address []int
	for _, octet := range endpoint.Addr().AsSlice() {
		address = append(address, int(octet))
	}
	servers := [][]any{{family, address, endpoint.Port(), ""}}
	domains := make([][]any, 0, len(c.Domains))
	for _, domain := range c.Domains {
		domains = append(domains, []any{domain, true})
	}
	return []change{{Key: "Domains", After: encoded(domains)}, {Key: "DNSEx", After: encoded(servers)}}
}

func (b resolvedBackend) plan(ctx context.Context, c Config) (string, []change, error) {
	if c.Interface == "" {
		if err := b.automaticRequirements(ctx, c); err != nil {
			return "", nil, err
		}
		link, err := plannedLink(c)
		if err != nil {
			return "", nil, err
		}
		r := receipt{Config: c, Target: link.Name}
		actual, _, err := b.inspectLink(ctx, r)
		if err != nil {
			return "", nil, err
		}
		if !bytes.Equal(actual, encoded(nil)) {
			return "", nil, errors.New("hostdns: automatic interface name already exists without an owned receipt")
		}
		conflicts, err := b.conflicts(ctx, r)
		if err != nil {
			return "", nil, err
		}
		if len(conflicts) != 0 {
			return "", nil, fmt.Errorf("hostdns: unowned resolver scopes: %s", strings.Join(conflicts, "; "))
		}
		return r.Target, automaticChanges(c, link), nil
	}
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return "", nil, fmt.Errorf("hostdns: dedicated interface unavailable: %w", err)
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return "", nil, errors.New("hostdns: resolved requires a dedicated non-loopback interface (for example an explicitly created dummy link)")
	}
	if iface.Flags&net.FlagUp == 0 {
		return "", nil, errors.New("hostdns: explicit dedicated interface must already be up")
	}
	local, err := assignedDNSAddress(netip.MustParseAddrPort(c.Address).Addr())
	if err != nil {
		return "", nil, err
	}
	if local {
		if err := b.localDNSVersion(ctx); err != nil {
			return "", nil, err
		}
	}
	r := receipt{Config: c, Target: strconv.Itoa(iface.Index)}
	defaultRoute, err := b.read(ctx, r, "DefaultRoute")
	if err != nil {
		return "", nil, err
	}
	if !bytes.Equal(defaultRoute, encoded(false)) {
		return "", nil, errors.New("hostdns: dedicated interface must already have DefaultRoute=no; prepare explicitly with resolvectl default-route INTERFACE no")
	}
	conflicts, err := b.conflicts(ctx, r)
	if err != nil {
		return "", nil, err
	}
	if len(conflicts) != 0 {
		return "", nil, fmt.Errorf("hostdns: unowned resolver domains: %s", strings.Join(conflicts, "; "))
	}
	changes := resolvedAfter(c)
	for i := range changes {
		before, err := b.read(ctx, r, changes[i].Key)
		if err != nil {
			return "", nil, err
		}
		changes[i].Before = before
		if !bytes.Equal(before, encoded([]any{})) {
			return "", nil, fmt.Errorf("hostdns: dedicated interface already has unowned %s; refusing to replace its resolver", changes[i].Key)
		}
	}
	return r.Target, changes, nil
}

func (b resolvedBackend) validate(r receipt) error {
	if r.Config.Interface == "" {
		return validateAutomatic(r)
	}
	index, err := strconv.Atoi(r.Target)
	if err != nil || index <= 0 || len(r.Changes) != 2 {
		return errors.New("hostdns: invalid resolved receipt target")
	}
	expected := resolvedAfter(r.Config)
	for i, ch := range r.Changes {
		if ch.Key != expected[i].Key || !bytes.Equal(ch.After, expected[i].After) {
			return errors.New("hostdns: invalid resolved receipt settings")
		}
		if !bytes.Equal(ch.Before, encoded([]any{})) {
			return errors.New("hostdns: receipt cannot own preexisting resolver settings")
		}
	}
	return nil
}

func (b resolvedBackend) read(ctx context.Context, r receipt, key string) (json.RawMessage, error) {
	if r.Config.Interface == "" {
		value, exists, err := b.automaticRead(ctx, r, key)
		if err != nil || !exists || key == "Interface" || key == "Activated" {
			return value, err
		}
	}
	_, path, err := b.link(ctx, r)
	if err != nil {
		return nil, err
	}
	signature := map[string]string{"DefaultRoute": "b", "DNSEx": "a(iayqs)", "Domains": "a(sb)"}[key]
	if signature == "" {
		return nil, errors.New("hostdns: unrecognized resolved property")
	}
	return b.property(ctx, path, "org.freedesktop.resolve1.Link", key, signature)
}

func resolvedWriteArgs(key string, value json.RawMessage) ([]string, error) {
	switch key {
	case "DefaultRoute":
		var enabled bool
		if err := json.Unmarshal(value, &enabled); err != nil {
			return nil, err
		}
		return []string{"SetLinkDefaultRoute", "ib", strconv.FormatBool(enabled)}, nil
	case "DNSEx":
		var servers [][]json.RawMessage
		if err := json.Unmarshal(value, &servers); err != nil {
			return nil, err
		}
		args := []string{"SetLinkDNSEx", "ia(iayqs)", strconv.Itoa(len(servers))}
		for _, server := range servers {
			if len(server) != 4 {
				return nil, errors.New("hostdns: invalid native DNSEx entry")
			}
			var family int
			var address []int
			var port uint16
			var name string
			for i, dest := range []any{&family, &address, &port, &name} {
				if err := json.Unmarshal(server[i], dest); err != nil {
					return nil, err
				}
			}
			if !(family == 2 && len(address) == 4 || family == 10 && len(address) == 16) {
				return nil, errors.New("hostdns: invalid native DNS address family")
			}
			args = append(args, strconv.Itoa(family), strconv.Itoa(len(address)))
			for _, octet := range address {
				if octet < 0 || octet > 255 {
					return nil, errors.New("hostdns: invalid native DNS address byte")
				}
				args = append(args, strconv.Itoa(octet))
			}
			args = append(args, strconv.Itoa(int(port)), name)
		}
		return args, nil
	case "Domains":
		var domains [][]json.RawMessage
		if err := json.Unmarshal(value, &domains); err != nil {
			return nil, err
		}
		args := []string{"SetLinkDomains", "ia(sb)", strconv.Itoa(len(domains))}
		for _, entry := range domains {
			if len(entry) != 2 {
				return nil, errors.New("hostdns: invalid native domain entry")
			}
			var domain string
			var route bool
			if err := json.Unmarshal(entry[0], &domain); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(entry[1], &route); err != nil {
				return nil, err
			}
			args = append(args, domain, strconv.FormatBool(route))
		}
		return args, nil
	}
	return nil, errors.New("hostdns: unsupported native setting")
}

func (b resolvedBackend) write(ctx context.Context, r receipt, key string, expected, desired json.RawMessage) error {
	current, err := b.read(ctx, r, key)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return conflict(key)
	}
	if key == "Interface" || key == "Activated" {
		return b.automaticWrite(ctx, r, key, desired)
	}
	args, err := resolvedWriteArgs(key, desired)
	if err != nil {
		return err
	}
	// Insert the native link index before all method-specific arguments.
	index, _, err := b.link(ctx, r)
	if err != nil {
		return err
	}
	args = append(args[:2], append([]string{strconv.Itoa(index)}, args[2:]...)...)
	_, err = b.command(ctx, append([]string{"call", resolvedService, resolvedPath, resolvedManager}, args...)...)
	if err != nil {
		return err
	}
	actual, err := b.read(ctx, r, key)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, desired) {
		return fmt.Errorf("hostdns: native resolved did not retain %s (receipt retained)", key)
	}
	return nil
}

func (b resolvedBackend) conflicts(ctx context.Context, r receipt) ([]string, error) {
	value, err := b.property(ctx, resolvedPath, resolvedManager, "Domains", "a(isb)")
	if err != nil {
		return nil, err
	}
	var entries [][]json.RawMessage
	if err := json.Unmarshal(value, &entries); err != nil {
		return nil, err
	}
	var conflicts []string
	if r.Config.Interface != "" || len(r.Changes) != 0 {
		defaultRoute, err := b.read(ctx, r, "DefaultRoute")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(defaultRoute, encoded(false)) && (r.Config.Interface != "" || r.Phase == "active") {
			conflicts = append(conflicts, "dedicated interface became a default DNS route")
		}
	}
	for _, entry := range entries {
		if len(entry) != 3 {
			return nil, errors.New("hostdns: malformed native routing domain")
		}
		var index int
		var scope string
		if err := json.Unmarshal(entry[0], &index); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(entry[1], &scope); err != nil {
			return nil, err
		}
		// A catch-all route is the ordinary fallback, not an owned domain scope.
		if scope == "." {
			continue
		}
		if r.Config.Interface != "" && strconv.Itoa(index) == r.Target && len(r.Changes) != 0 {
			continue
		}
		if r.Config.Interface == "" && len(r.Changes) != 0 {
			if owned, err := net.InterfaceByName(r.Target); err == nil && owned.Index == index {
				continue
			}
		}
		for _, domain := range r.Config.Domains {
			if overlaps(scope, domain) {
				conflicts = append(conflicts, fmt.Sprintf("link %d domain %s overlaps %s", index, scope, domain))
			}
		}
	}
	return conflicts, nil
}

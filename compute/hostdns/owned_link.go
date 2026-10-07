package hostdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
)

// An alias carries a random incarnation, not a public name-only ownership claim.
// The receipt also fences native address, kind, MTU, master, flags and routes.
type ownedLink struct {
	Name        string
	Alias       string
	Address     string
	Kind        string
	MTU         int
	TXQueueLen  int
	Group       string
	Master      string
	Flags       []string
	Addresses   []json.RawMessage
	Routes      []json.RawMessage
	Promiscuity int
}

func automaticName(c Config) string {
	digest := sha256.Sum256([]byte(c.StateDirectory))
	return "sdns" + hex.EncodeToString(digest[:5])
}

func plannedLink(c Config) (ownedLink, error) {
	var token [21]byte
	if _, err := rand.Read(token[:]); err != nil {
		return ownedLink{}, err
	}
	var mac [6]byte
	mac[0] = 0x02
	copy(mac[1:], token[:5])
	return ownedLink{Name: automaticName(c), Alias: "stackd-hostdns:" + hex.EncodeToString(token[5:]), Address: net.HardwareAddr(mac[:]).String(), Kind: "dummy", MTU: 1500, TXQueueLen: 1000, Group: "0", Flags: []string{"BROADCAST", "NOARP"}, Addresses: []json.RawMessage{}, Routes: []json.RawMessage{}}, nil
}

func automaticChanges(c Config, link ownedLink) []change {
	changes := []change{{Key: "Interface", Before: encoded(nil), After: encoded(link)}, {Key: "Activated", Before: encoded(false), After: encoded(true)}, {Key: "DefaultRoute", Before: encoded(true), After: encoded(false)}}
	for _, ch := range resolvedAfter(c) {
		ch.Before = encoded([]any{})
		changes = append(changes, ch)
	}
	return changes
}

func validateAutomatic(r receipt) error {
	if r.Target != automaticName(r.Config) || len(r.Changes) != 5 {
		return errors.New("hostdns: invalid automatic interface receipt")
	}
	var link ownedLink
	if err := json.Unmarshal(r.Changes[0].After, &link); err != nil {
		return err
	}
	mac, err := net.ParseMAC(link.Address)
	if err != nil || len(mac) != 6 || mac[0] != 0x02 || !strings.HasPrefix(link.Alias, "stackd-hostdns:") {
		return errors.New("hostdns: invalid owned link incarnation")
	}
	if token, err := hex.DecodeString(strings.TrimPrefix(link.Alias, "stackd-hostdns:")); err != nil || len(token) != 16 {
		return errors.New("hostdns: invalid owned link alias")
	}
	baseline := ownedLink{Name: r.Target, Alias: link.Alias, Address: mac.String(), Kind: "dummy", MTU: 1500, TXQueueLen: 1000, Group: "0", Flags: []string{"BROADCAST", "NOARP"}, Addresses: []json.RawMessage{}, Routes: []json.RawMessage{}}
	expected := automaticChanges(r.Config, baseline)
	for i, ch := range r.Changes {
		if ch.Key != expected[i].Key || !bytes.Equal(ch.Before, expected[i].Before) || !bytes.Equal(ch.After, expected[i].After) {
			return errors.New("hostdns: altered automatic interface ownership receipt")
		}
	}
	return nil
}

func (b resolvedBackend) ipCommand(ctx context.Context, args ...string) ([]byte, error) {
	if b.ip == "" {
		return nil, errors.New("hostdns: automatic interfaces require installed native iproute2 ip")
	}
	output, err := exec.CommandContext(ctx, b.ip, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("hostdns: native iproute2 call failed (requires root/CAP_NET_ADMIN and dummy-link support): %w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func parseOwnedLink(data []byte) (ownedLink, bool, error) {
	var links []struct {
		Name        string   `json:"ifname"`
		Alias       string   `json:"ifalias"`
		Address     string   `json:"address"`
		MTU         int      `json:"mtu"`
		TXQueueLen  int      `json:"txqlen"`
		Group       string   `json:"group"`
		Master      string   `json:"master"`
		Flags       []string `json:"flags"`
		Promiscuity int      `json:"promiscuity"`
		Info        struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(data, &links); err != nil {
		return ownedLink{}, false, err
	}
	if len(links) != 1 {
		return ownedLink{}, false, errors.New("hostdns: expected one native link")
	}
	item := links[0]
	state := ownedLink{Name: item.Name, Alias: item.Alias, Address: item.Address, Kind: item.Info.Kind, MTU: item.MTU, TXQueueLen: item.TXQueueLen, Group: item.Group, Master: item.Master, Addresses: []json.RawMessage{}, Routes: []json.RawMessage{}, Promiscuity: item.Promiscuity}
	up := false
	for _, flag := range item.Flags {
		switch flag {
		case "UP":
			up = true
		case "LOWER_UP", "RUNNING": // Operational flags track the separately owned UP bit.
		default:
			state.Flags = append(state.Flags, flag)
		}
	}
	sort.Strings(state.Flags)
	return state, up, nil
}

func (b resolvedBackend) inspectLink(ctx context.Context, r receipt) (json.RawMessage, bool, error) {
	// Enumerate instead of interpreting localized ip error text for absence.
	data, err := b.ipCommand(ctx, "-json", "-details", "-N", "link", "show")
	if err != nil {
		return nil, false, err
	}
	var all []json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, false, err
	}
	var state ownedLink
	up, found := false, false
	ownedAlias := ""
	if len(r.Changes) != 0 {
		var expected ownedLink
		if err := json.Unmarshal(r.Changes[0].After, &expected); err != nil {
			return nil, false, err
		}
		ownedAlias = expected.Alias
	}
	for _, item := range all {
		var named struct {
			Name  string `json:"ifname"`
			Alias string `json:"ifalias"`
		}
		if err := json.Unmarshal(item, &named); err != nil {
			return nil, false, err
		}
		if named.Name != r.Target && (ownedAlias == "" || named.Alias != ownedAlias) {
			continue
		}
		if found {
			return nil, false, errors.New("hostdns: duplicate native ownership incarnation")
		}
		state, up, err = parseOwnedLink(append(append([]byte{'['}, item...), ']'))
		if err != nil {
			return nil, false, err
		}
		found = true
	}
	if !found {
		return encoded(nil), false, nil
	}
	data, err = b.ipCommand(ctx, "-json", "address", "show", "dev", state.Name)
	if err != nil {
		return nil, false, err
	}
	var addresses []struct {
		Info []json.RawMessage `json:"addr_info"`
	}
	if err := json.Unmarshal(data, &addresses); err != nil {
		return nil, false, err
	}
	if len(addresses) != 1 {
		return nil, false, errors.New("hostdns: malformed native interface addresses")
	}
	state.Addresses = append(state.Addresses, addresses[0].Info...)
	for _, family := range []string{"-4", "-6"} {
		data, err := b.ipCommand(ctx, "-json", family, "route", "show", "table", "all", "dev", state.Name)
		if err != nil {
			return nil, false, err
		}
		var routes []json.RawMessage
		if err := json.Unmarshal(data, &routes); err != nil {
			return nil, false, err
		}
		for _, route := range routes {
			var fields struct {
				Destination string `json:"dst"`
				Protocol    string `json:"protocol"`
				Table       string `json:"table"`
			}
			if err := json.Unmarshal(route, &fields); err != nil {
				return nil, false, err
			}
			// Linux creates this local multicast route merely by activating IPv6.
			if family == "-6" && fields.Destination == "ff00::/8" && fields.Protocol == "kernel" && fields.Table == "local" {
				continue
			}
			state.Routes = append(state.Routes, route)
		}
	}
	return encoded(state), up, nil
}

func (b resolvedBackend) automaticRead(ctx context.Context, r receipt, key string) (json.RawMessage, bool, error) {
	actual, up, err := b.inspectLink(ctx, r)
	if err != nil {
		return nil, false, err
	}
	exists := !bytes.Equal(actual, encoded(nil))
	if key == "Interface" {
		return actual, exists, nil
	}
	if exists && !bytes.Equal(actual, r.Changes[0].After) {
		return nil, exists, conflict("Interface identity/settings")
	}
	if key == "Activated" {
		return encoded(up), exists, nil
	}
	if !exists {
		if key == "DefaultRoute" {
			return encoded(true), false, nil
		}
		return encoded([]any{}), false, nil
	}
	return nil, true, nil
}

func (b resolvedBackend) automaticWrite(ctx context.Context, r receipt, key string, desired json.RawMessage) error {
	if key == "Activated" {
		var up bool
		if err := json.Unmarshal(desired, &up); err != nil {
			return err
		}
		state := "down"
		if up {
			state = "up"
		}
		_, err := b.ipCommand(ctx, "link", "set", "dev", r.Target, "addrgenmode", "none", state)
		return err
	}
	if bytes.Equal(desired, encoded(nil)) {
		_, err := b.ipCommand(ctx, "link", "delete", "dev", r.Target)
		return err
	}
	var link ownedLink
	if err := json.Unmarshal(desired, &link); err != nil {
		return err
	}
	_, err := b.ipCommand(ctx, "link", "add", "name", link.Name, "address", link.Address, "alias", link.Alias, "mtu", "1500", "txqueuelen", "1000", "group", "0", "multicast", "off", "type", "dummy")
	return err
}

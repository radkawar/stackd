package valkey

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var userName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var passwordHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ValidateUsers rejects authentication rules inside the access string: service
// credentials are supplied separately and cannot be overridden by ACL text.
func ValidateUsers(users []User) error {
	seen := map[string]bool{}
	for _, u := range users {
		if !userName.MatchString(u.Name) || u.Name == controllerUser || seen[u.Name] {
			return errors.New("invalid, reserved or duplicate native username")
		}
		seen[u.Name] = true
		if strings.TrimSpace(u.AccessString) == "" || strings.ContainsAny(u.AccessString, "\x00\r\n\"\\") {
			return errors.New("invalid native access string")
		}
		if u.NoPassword && len(u.PasswordHashes) > 0 {
			return errors.New("passwordless users cannot have password hashes")
		}
		if !u.NoPassword && len(u.PasswordHashes) == 0 {
			return errors.New("native user requires a password or explicit no-password mode")
		}
		for _, h := range u.PasswordHashes {
			if !passwordHash.MatchString(h) {
				return errors.New("invalid native password hash")
			}
		}
		for _, token := range strings.Fields(u.AccessString) {
			if strings.HasPrefix(token, "+") {
				command := strings.ToLower(strings.TrimPrefix(token, "+"))
				switch strings.Split(command, "|")[0] {
				case "config", "shutdown", "module", "debug", "replicaof", "slaveof", "save", "bgsave", "bgrewriteaof", "sync", "psync", "migrate":
					return fmt.Errorf("reserved native administration command %q", token)
				case "acl":
					if command != "acl|whoami" && command != "acl|cat" {
						return fmt.Errorf("unsupported native ACL inspection or mutation %q", token)
					}
				case "cluster":
					switch command {
					case "cluster|slots", "cluster|shards", "cluster|nodes", "cluster|info", "cluster|keyslot", "cluster|myid", "cluster|replicas", "cluster|countkeysinslot", "cluster|getkeysinslot":
					default:
						return fmt.Errorf("unsupported native cluster mutation %q", token)
					}
				}
			}
			if token == "on" || token == "off" || token == "allkeys" || token == "resetkeys" || token == "allchannels" || token == "resetchannels" || token == "allcommands" || token == "nocommands" {
				continue
			}
			if len(token) > 1 && strings.ContainsAny(token[:1], "~&+-") {
				continue
			}
			return fmt.Errorf("unsupported native access token %q", token)
		}
	}
	return nil
}

var parameterDefaults = map[string]string{"maxmemory": "0", "maxmemory-policy": "noeviction", "timeout": "0", "tcp-keepalive": "300", "notify-keyspace-events": ""}

// ValidateParameters admits only settings that preserve ownership, durable AOF,
// protected listener configuration and authentication.
func ValidateParameters(parameters map[string]string) error {
	for name, value := range parameters {
		switch name {
		case "maxmemory", "timeout", "tcp-keepalive":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				return fmt.Errorf("invalid %s value", name)
			}
			if name == "timeout" && n > 0 && n < 20 {
				return errors.New("timeout must be zero or at least 20 seconds")
			}
		case "maxmemory-policy":
			switch value {
			case "noeviction", "allkeys-lru", "allkeys-lfu", "allkeys-random", "volatile-lru", "volatile-lfu", "volatile-random", "volatile-ttl":
			default:
				return errors.New("invalid maxmemory-policy")
			}
		case "notify-keyspace-events":
			for _, c := range value {
				if !strings.ContainsRune("AKEg$lshzxetmdn", c) {
					return errors.New("invalid notify-keyspace-events")
				}
			}
		default:
			return fmt.Errorf("unsupported native parameter %q", name)
		}
	}
	return nil
}
func validateSpecification(s Specification) error {
	if s.ID == "" {
		return errors.New("native Valkey incarnation is required")
	}
	if s.Shards < 1 || s.Shards > 16 || s.Replicas < 0 || s.Replicas > 5 || s.Shards*(s.Replicas+1) > 32 {
		return errors.New("unsupported Valkey local topology")
	}
	if !s.ClusterMode && s.Shards != 1 {
		return errors.New("multiple shards require cluster mode")
	}
	if s.MemoryBytes < 0 {
		return errors.New("invalid native memory capacity")
	}
	if value, ok := s.Parameters["maxmemory"]; ok && s.MemoryBytes > 0 {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n == 0 || n > s.MemoryBytes {
			return errors.New("maxmemory cannot disable or exceed native node capacity")
		}
	}
	if err := ValidateUsers(s.Users); err != nil {
		return err
	}
	return ValidateParameters(s.Parameters)
}
func effectiveParameters(s Specification) map[string]string {
	out := make(map[string]string, len(parameterDefaults))
	for k, v := range parameterDefaults {
		out[k] = v
	}
	if s.MemoryBytes > 0 {
		out["maxmemory"] = strconv.FormatInt(s.MemoryBytes, 10)
	}
	for k, v := range s.Parameters {
		out[k] = v
	}
	return out
}
func aclFile(users []User, secret string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "user %s on >%s ~* &* +@all\n", controllerUser, secret)
	hasDefault := false
	for _, u := range users {
		if u.Name == "default" {
			hasDefault = true
		}
		fmt.Fprintf(&b, "user %s reset %s", u.Name, u.AccessString)
		if u.NoPassword {
			b.WriteString(" nopass")
		} else {
			for _, hash := range u.PasswordHashes {
				b.WriteString(" #" + hash)
			}
		}
		// AWS reserves engine administration even for +@all. Subtract only:
		// granting discovery here would bypass a user's explicit command denial.
		// TODO: Comeback expose AWS's filtered ACL GETUSER/LIST output without
		// disclosing the private native controller identity or credential hash.
		b.WriteString(" -acl|setuser -acl|deluser -acl|load -acl|save -acl|getuser -acl|list -acl|users -acl|log -acl|dryrun -config -shutdown -module -debug -replicaof -slaveof -save -bgsave -bgrewriteaof -sync -psync -migrate -cluster|addslots -cluster|addslotsrange -cluster|delslots -cluster|delslotsrange -cluster|setslot -cluster|meet -cluster|forget -cluster|replicate -cluster|reset -cluster|failover -cluster|set-config-epoch -cluster|bumpepoch\n")
	}
	if !hasDefault {
		b.WriteString("user default reset off\n")
	}
	return b.String()
}
func sortedParameters(parameters map[string]string) []string {
	names := make([]string, 0, len(parameters))
	for name := range parameters {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

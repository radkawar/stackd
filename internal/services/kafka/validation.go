package kafka

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseProperties accepts only native broker settings whose effects are applied.
// Listener, storage-path, authentication and quorum settings remain runtime-owned.
func ParseProperties(raw string) (map[string]string, error) { return parseProperties(raw, true) }

// AWS configurations retain property values verbatim; values are validated when
// a revision is applied to a live cluster, not when the revision is created.
func parseProperties(raw string, effective bool) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || k == "" || v == "" || strings.ContainsAny(v, "\r\n\\") {
			return nil, fmt.Errorf("invalid Kafka property %q", k)
		}
		if _, ok := out[k]; ok {
			return nil, fmt.Errorf("duplicate Kafka property %q", k)
		}
		switch k {
		case "auto.create.topics.enable", "delete.topic.enable":
			if !effective {
				break
			}
			if v != "true" && v != "false" {
				return nil, fmt.Errorf("%s requires true or false", k)
			}
		case "log.cleanup.policy":
			if !effective {
				break
			}
			if v != "delete" && v != "compact" && v != "compact,delete" && v != "delete,compact" {
				return nil, fmt.Errorf("invalid cleanup policy")
			}
		case "compression.type":
			if !effective {
				break
			}
			if v != "producer" && v != "uncompressed" && v != "gzip" && v != "snappy" && v != "lz4" && v != "zstd" {
				return nil, fmt.Errorf("invalid compression type")
			}
		case "log.retention.hours", "log.retention.ms", "log.retention.bytes":
			if !effective {
				break
			}
			n, e := strconv.ParseInt(v, 10, 64)
			if e != nil || n < -1 {
				return nil, fmt.Errorf("invalid %s", k)
			}
			v = strconv.FormatInt(n, 10)
		case "group.initial.rebalance.delay.ms":
			if !effective {
				break
			}
			n, e := strconv.ParseInt(v, 10, 64)
			if e != nil || n < 0 {
				return nil, fmt.Errorf("invalid %s", k)
			}
			v = strconv.FormatInt(n, 10)
		case "num.partitions", "default.replication.factor", "min.insync.replicas", "log.segment.bytes", "log.roll.ms", "message.max.bytes", "replica.fetch.max.bytes", "offsets.retention.minutes":
			if !effective {
				break
			}
			n, e := strconv.ParseInt(v, 10, 32)
			if e != nil || n < 1 {
				return nil, fmt.Errorf("invalid %s", k)
			}
			v = strconv.FormatInt(n, 10)
		default:
			return nil, fmt.Errorf("kafka property %q is not supported", k)
		}
		out[k] = v
	}
	return out, nil
}
func ValidateSpecification(v Specification) error {
	if v.ARN == "" || v.Incarnation == "" || v.Partition == "" || v.AccountID == "" || v.Region == "" {
		return fmt.Errorf("complete immutable Kafka ownership is required")
	}
	if v.KafkaVersion != "3.7.1" {
		return fmt.Errorf("only installed Kafka 3.7.1 is supported")
	}
	if v.Brokers < 1 || v.Brokers > 3 {
		return fmt.Errorf("only one to three native Kafka brokers are supported")
	}
	if v.SecurityMode != "PLAINTEXT" && v.SecurityMode != "TLS" && v.SecurityMode != "SASL_SCRAM" {
		return fmt.Errorf("unsupported Kafka authentication mode")
	}
	p, e := ParseProperties(v.ServerProperties)
	if e != nil {
		return e
	}
	for _, k := range []string{"default.replication.factor", "min.insync.replicas"} {
		if p[k] != "" {
			n, _ := strconv.Atoi(p[k])
			if n > int(v.Brokers) {
				return fmt.Errorf("%s exceeds broker count", k)
			}
		}
	}
	seen := map[string]bool{}
	for _, u := range v.Users {
		if u.Username == "" || u.Username == "__stackd_native_admin" || u.Password == "" || strings.ContainsAny(u.Username, "\r\n,=[]") || strings.ContainsAny(u.Password, "\r\n") {
			return fmt.Errorf("invalid SCRAM credential")
		}
		if seen[u.Username] {
			return fmt.Errorf("duplicate SCRAM username")
		}
		seen[u.Username] = true
	}
	return nil
}

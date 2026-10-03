// Package managed provides immutable, partition-specific AWS managed policies.
// The checked-in catalogue is generated from read-only IAM APIs by awspolicies.
package managed

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
)

// Version is an unmodified IAM version document with acquisition evidence.
type Version struct {
	ID        string    `json:"id"`
	Default   bool      `json:"default"`
	Created   time.Time `json:"created"`
	Document  string    `json:"document"`
	SHA256    string    `json:"sha256"`
	RequestID string    `json:"request_id"`
	Retrieved time.Time `json:"retrieved"`
}

// Policy contains public, account-independent metadata and retained versions.
// Attachment and boundary counts belong to the emulator's account state.
type Policy struct {
	ARN                string    `json:"arn"`
	Name               string    `json:"name"`
	ID                 string    `json:"id"`
	Path               string    `json:"path"`
	DefaultVersion     string    `json:"default_version"`
	Attachable         bool      `json:"attachable"`
	Description        string    `json:"description,omitempty"`
	Created            time.Time `json:"created"`
	Updated            time.Time `json:"updated"`
	MetadataRequestID  string    `json:"metadata_request_id"`
	VersionsRequestIDs []string  `json:"versions_request_ids"`
	Retrieved          time.Time `json:"retrieved"`
	Versions           []Version `json:"versions"`
}

// Snapshot records one complete ListPolicies(Scope=AWS) traversal and each
// returned policy's metadata and retained documents. It contains no credentials
// or source-account attachment counts.
type Snapshot struct {
	Schema         int       `json:"schema"`
	Partition      string    `json:"partition"`
	Endpoint       string    `json:"endpoint"`
	Region         string    `json:"region"`
	Source         string    `json:"source"`
	SDK            string    `json:"sdk"`
	Started        time.Time `json:"started"`
	Completed      time.Time `json:"completed"`
	ListRequestIDs []string  `json:"list_request_ids"`
	Policies       []Policy  `json:"policies"`
}

// Validate rejects incomplete, mixed-partition or corrupt snapshots.
func (s Snapshot) Validate() error {
	if s.Schema != 1 || s.Partition == "" || len(s.Policies) == 0 || s.Endpoint == "" || s.Source == "" || s.Started.IsZero() || s.Completed.Before(s.Started) || len(s.ListRequestIDs) == 0 {
		return fmt.Errorf("incomplete managed policy snapshot provenance")
	}
	seen := make(map[string]bool, len(s.Policies))
	for _, p := range s.Policies {
		if !strings.HasPrefix(p.ARN, "arn:"+s.Partition+":iam::aws:policy/") || seen[p.ARN] || p.Name == "" || p.ID == "" || p.MetadataRequestID == "" || len(p.VersionsRequestIDs) == 0 {
			return fmt.Errorf("invalid policy metadata: %s", p.ARN)
		}
		seen[p.ARN] = true
		versions := make(map[string]bool, len(p.Versions))
		defaults := 0
		for _, v := range p.Versions {
			if versions[v.ID] || v.ID == "" || !json.Valid([]byte(v.Document)) || v.RequestID == "" || v.Retrieved.IsZero() || Digest([]byte(v.Document)) != v.SHA256 {
				return fmt.Errorf("invalid policy version: %s/%s", p.ARN, v.ID)
			}
			versions[v.ID] = true
			if v.Default {
				defaults++
				if v.ID != p.DefaultVersion {
					return fmt.Errorf("default version mismatch: %s", p.ARN)
				}
			}
		}
		if defaults != 1 {
			return fmt.Errorf("missing or duplicate default version: %s", p.ARN)
		}
	}
	return nil
}

// Digest is the SHA256 of the exact URL-decoded document bytes from IAM.
func Digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// Encode produces deterministic JSON and gzip bytes for a captured snapshot.
func Encode(s Snapshot) ([]byte, error) {
	s.Policies = slices.Clone(s.Policies)
	slices.SortFunc(s.Policies, func(a, b Policy) int { return strings.Compare(a.ARN, b.ARN) })
	for i := range s.Policies {
		s.Policies[i].Versions = slices.Clone(s.Policies[i].Versions)
		slices.SortFunc(s.Policies[i].Versions, func(a, b Version) int { return strings.Compare(a.ID, b.ID) })
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	w, err := gzip.NewWriterLevel(&b, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(raw); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Decode validates a compressed catalogue before making its contents available.
func Decode(data []byte) (Snapshot, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return Snapshot{}, err
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, 512<<20))
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	if err = json.Unmarshal(raw, &s); err != nil {
		return Snapshot{}, err
	}
	return s, s.Validate()
}

//go:embed data/*
var data embed.FS

var load = sync.OnceValues(func() (map[string]Snapshot, error) {
	entries, err := data.ReadDir("data")
	if err != nil {
		return nil, err
	}
	result := make(map[string]Snapshot)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json.gz") {
			continue
		}
		raw, err := data.ReadFile("data/" + entry.Name())
		if err != nil {
			return nil, err
		}
		s, err := Decode(raw)
		if err != nil {
			return nil, fmt.Errorf("embedded %s: %w", entry.Name(), err)
		}
		result[s.Partition] = s
	}
	return result, nil
})

// List returns detached account-independent metadata for a captured partition.
// Versions are omitted: use Lookup to obtain a complete policy.
func List(partition string) []Policy {
	catalogues, err := load()
	if err != nil {
		return nil
	}
	s := catalogues[partition]
	result := make([]Policy, len(s.Policies))
	for i, p := range s.Policies {
		p.Versions = nil
		p.VersionsRequestIDs = slices.Clone(p.VersionsRequestIDs)
		result[i] = p
	}
	return result
}

// Lookup returns a detached immutable-source policy. ARNs are never rewritten
// between partitions: a missing authoritative snapshot cannot prove parity.
func Lookup(partition, arn string) (Policy, bool) {
	catalogues, err := load()
	if err != nil {
		return Policy{}, false
	}
	for _, p := range catalogues[partition].Policies {
		if p.ARN == arn {
			p.Versions = slices.Clone(p.Versions)
			p.VersionsRequestIDs = slices.Clone(p.VersionsRequestIDs)
			return p, true
		}
	}
	return Policy{}, false
}

// Check validates all embedded snapshots without accessing a network.
func Check() error {
	catalogues, err := load()
	if err == nil && len(catalogues) == 0 {
		return fmt.Errorf("no authoritative managed policy snapshots embedded")
	}
	return err
}

// Available reports whether a partition has its own authoritative snapshot.
func Available(partition string) bool {
	catalogues, err := load()
	if err != nil {
		return false
	}
	_, ok := catalogues[partition]
	return ok
}

// ResourceAccount returns the actual service-managed account used by IAM's
// aws:ResourceAccount authorization context, which differs from the public
// ARN namespace alias "aws". Commercial conditional GetPolicy observations and
// exact-value confirmation are recorded in testdata/resource_account*.json.
// Commercial role-template reads use the same account; their direct and
// AcquireRole observations are in testdata/aws/iam/template_account.json.
// No account value is inferred for a partition without direct evidence.
func ResourceAccount(partition string) (string, bool) {
	if partition == "aws" && Available(partition) {
		return "639982225848", true
	}
	return "", false
}

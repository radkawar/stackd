package ssmdocuments

import (
	"context"
	_ "embed"
	"errors"
	"strconv"
	"time"
)

// Captured from AWS GetDocument on 2026-09-27; see managed_execution_native.json.
//
//go:embed aws_run_shell_script.json
var shellContent string

// BuiltinOwner returns the account positively observed through native IAM
// resource-account conditions, not the account-less public document ARN.
func BuiltinOwner(partition, region, name string) string {
	if partition == "aws" && region == "us-east-1" && name == "AWS-RunShellScript" {
		// managed_execution_admission_accounting.json.gz includes exact-match proof.
		return "187340769485"
	}
	// TODO: Comeback calibrate AWS-owned document resource-account authority in other regions/partitions.
	return ""
}

func builtinRecord(k Key) Record {
	return Record{Key: k, Type: "Command", DefaultVersion: 1, LatestVersion: 1, Tags: map[string]string{}}
}
func builtinVersion(k Key) Version {
	return Version{Key: VersionKey{k, 1}, Content: shellContent, Format: "JSON", Hash: "99749de5e62f71e5ebe9a55c2321e2c394796afe7208cff048696541e6f6771e", Created: time.Date(2017, 8, 21, 20, 25, 2, 29000000, time.UTC), Status: "Active"}
}
func versionsFor(r Reader, d Record) ([]Version, error) {
	if d.Key.AccountID == "" && d.Key.Name == "AWS-RunShellScript" {
		return []Version{builtinVersion(d.Key)}, nil
	}
	return r.Versions(d.Key)
}
func selectVersion(r Reader, d Record, selector, versionName string) (Version, error) {
	var n int64
	var err error
	switch selector {
	case "", "$DEFAULT":
		n = d.DefaultVersion
	case "$LATEST":
		n = d.LatestVersion
	default:
		n, err = strconv.ParseInt(selector, 10, 64)
		if err != nil || n < 1 {
			return Version{}, failure("InvalidDocumentVersion", "Invalid document version.")
		}
	}
	if versionName != "" {
		versions, e := versionsFor(r, d)
		if e != nil {
			return Version{}, e
		}
		found := false
		for _, v := range versions {
			if v.VersionName == versionName {
				if selector != "" && n != v.Key.Version {
					return Version{}, failure("InvalidDocumentVersion", "DocumentVersion and VersionName identify different versions.")
				}
				n = v.Key.Version
				found = true
				break
			}
		}
		if !found {
			return Version{}, failure("InvalidDocumentVersion", "The version name does not exist.")
		}
	}
	if !sharedVersionAllowed(r, d, n) {
		return Version{}, failure("InvalidDocumentVersion", "The document version does not exist or is not shared with you.")
	}
	if d.Key.AccountID == "" && d.Key.Name == "AWS-RunShellScript" {
		if n != 1 {
			return Version{}, failure("InvalidDocumentVersion", "The document version does not exist.")
		}
		return builtinVersion(d.Key), nil
	}
	v, err := r.Version(VersionKey{d.Key, n})
	if errors.Is(err, ErrNotFound) {
		return Version{}, failure("InvalidDocumentVersion", "The document version does not exist.")
	}
	return v, err
}
func resolved(v Version) (Document, error) {
	content, err := decodeContent(v.Content, v.Format)
	if err != nil {
		return Document{}, err
	}
	k := v.Key.Document
	owner := k.AccountID
	if owner == "" {
		owner = "Amazon"
	}
	out := Document{Name: k.Name, Version: strconv.FormatInt(v.Key.Version, 10), Content: v.Content, Hash: v.Hash, ARN: documentARN(k), Owner: owner, Format: v.Format, SchemaVersion: content.SchemaVersion, Description: content.Description, TargetType: v.TargetType, Parameters: content.Parameters, MainSteps: content.executionSteps()}
	return out, nil
}

// Resolve selects content under the current caller scope. The consuming SendCommand
// command authorizes ssm:SendCommand against ARN; this is not a GetDocument API call.
func (s *Service) Resolve(ctx context.Context, name, version string) (Document, error) {
	var out Document
	err := s.repository.View(ctx, func(r Reader) error {
		k, e := documentKey(ctx, name)
		if e != nil {
			return e
		}
		record, e := loadRecord(r, k)
		if e != nil {
			return e
		}
		if record.Type != "Command" {
			return failure("InvalidDocument", "Run Command requires a Command document.")
		}
		v, e := selectVersion(r, record, version, "")
		if e != nil {
			return e
		}
		out, e = resolved(v)
		out.Tags = record.Tags
		out.Shared = record.Key.AccountID != "" && record.Key.AccountID != scopeFor(ctx).AccountID
		return e
	})
	if err != nil {
		return Document{}, wireError(err)
	}
	return out, nil
}

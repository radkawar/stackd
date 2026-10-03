// Package ecr provides the explicitly configured native image scanner. Private
// registry semantics and retained scan intent remain in the service owner.
package ecr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	api "stackd/internal/awsapi/ecr"
	service "stackd/internal/services/ecr"
)

// TrivyVersion is the tested native CLI contract, not the vulnerability database
// version. Provision the schema-2 database separately; Scan never downloads it.
const TrivyVersion = "0.74.0"

type TrivyConfig struct{ Executable, CacheDir string }
type Trivy struct {
	executable, cache string
	versionMu         sync.Mutex
	versionChecked    bool
}

// NewTrivy requires explicit paths and never resolves a scanner through PATH,
// Docker, ambient cloud credentials or a remote scanning service.
func NewTrivy(config TrivyConfig) (*Trivy, error) {
	if config.Executable == "" || config.CacheDir == "" {
		return nil, errors.New("ECR scanning requires a pinned Trivy executable and offline database cache directory")
	}
	executable, err := filepath.Abs(config.Executable)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(executable)
	if err != nil {
		return nil, fmt.Errorf("Trivy executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("Trivy executable must be an executable regular file")
	}
	cache, err := filepath.Abs(config.CacheDir)
	if err != nil {
		return nil, err
	}
	info, err = os.Stat(cache)
	if err != nil {
		return nil, fmt.Errorf("Trivy offline cache: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("Trivy offline cache must be a directory")
	}
	return &Trivy{executable: executable, cache: cache}, nil
}

func (t *Trivy) command(ctx context.Context, dir string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, t.executable, args...)
	command.Dir = dir
	// Do not inherit AWS/registry credentials, TRIVY_* options, plugin paths,
	// proxies, ignore files or the caller's home/configuration.
	command.Env = []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH=/usr/bin:/bin", "LANG=C", "TRIVY_DISABLE_TELEMETRY=true"}
	command.WaitDelay = 2 * time.Second
	return command
}
func (t *Trivy) checkVersion(ctx context.Context, dir string) error {
	t.versionMu.Lock()
	defer t.versionMu.Unlock()
	if t.versionChecked {
		return nil
	}
	output, err := t.command(ctx, dir, "--version").Output()
	if err != nil {
		return fmt.Errorf("Trivy version check: %w", err)
	}
	first, _, _ := strings.Cut(string(output), "\n")
	if strings.TrimSpace(first) != "Version: "+TrivyVersion {
		return fmt.Errorf("ECR scanner requires Trivy %s; executable reports %q", TrivyVersion, first)
	}
	t.versionChecked = true
	return nil
}

func (t *Trivy) Scan(ctx context.Context, input service.ScanInput) (service.ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	directory, err := os.MkdirTemp("", "stackd-ecr-scan-")
	if err != nil {
		return service.ScanResult{}, err
	}
	defer os.RemoveAll(directory)
	if err = t.checkVersion(ctx, directory); err != nil {
		return service.ScanResult{}, err
	}
	layout := filepath.Join(directory, "image")
	if err = writeScanLayout(layout, input); err != nil {
		return service.ScanResult{}, err
	}
	// The empty YAML file suppresses discovery of trivy.yaml in either cwd or
	// HOME. An explicit empty ignore file likewise cannot inherit suppression.
	config := filepath.Join(directory, "config.yaml")
	if err = os.WriteFile(config, []byte("{}\n"), 0600); err != nil {
		return service.ScanResult{}, err
	}
	ignore := filepath.Join(directory, "ignore")
	if err = os.WriteFile(ignore, nil, 0600); err != nil {
		return service.ScanResult{}, err
	}
	outputPath := filepath.Join(directory, "findings.json")
	command := t.command(ctx, directory, "image", "--config", config, "--cache-dir", t.cache, "--input", layout, "--format", "json", "--output", outputPath, "--scanners", "vuln", "--pkg-types", "os", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-version-check", "--disable-telemetry", "--ignorefile", ignore, "--parallel", "1", "--timeout", "5m", "--no-progress")
	var stderr boundedDiagnostic
	command.Stderr = &stderr
	if err = command.Run(); err != nil {
		return service.ScanResult{}, fmt.Errorf("Trivy scan failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	file, err := os.Open(outputPath)
	if err != nil {
		return service.ScanResult{}, fmt.Errorf("Trivy produced no findings document: %w", err)
	}
	defer file.Close()
	var report trivyReport
	if err = json.NewDecoder(file).Decode(&report); err != nil {
		return service.ScanResult{}, fmt.Errorf("Trivy findings document: %w", err)
	}
	if report.SchemaVersion != 2 {
		return service.ScanResult{}, fmt.Errorf("unsupported Trivy report schema %d", report.SchemaVersion)
	}
	osPackages := false
	for _, result := range report.Results {
		if result.Class == "os-pkgs" {
			osPackages = true
			break
		}
	}
	if report.Metadata.OS == nil || report.Metadata.OS.Family == "" || !osPackages {
		return service.ScanResult{}, errors.New("UnsupportedImageError: Trivy did not detect a supported operating system and package manager in the image layers")
	}
	metadataBytes, err := os.ReadFile(filepath.Join(t.cache, "db", "metadata.json"))
	if err != nil {
		return service.ScanResult{}, fmt.Errorf("Trivy database metadata: %w", err)
	}
	var metadata struct {
		Version   int
		UpdatedAt time.Time
	}
	if err = json.Unmarshal(metadataBytes, &metadata); err != nil {
		return service.ScanResult{}, fmt.Errorf("Trivy database metadata: %w", err)
	}
	if metadata.Version != 2 || metadata.UpdatedAt.IsZero() {
		return service.ScanResult{}, errors.New("Trivy requires explicit schema-2 database metadata with an update timestamp")
	}
	return service.ScanResult{Findings: scanFindings(report), VulnerabilityUpdated: metadata.UpdatedAt}, nil
}

type scanDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func writeScanLayout(directory string, input service.ScanInput) error {
	var manifest struct {
		SchemaVersion int              `json:"schemaVersion"`
		MediaType     string           `json:"mediaType"`
		Config        scanDescriptor   `json:"config"`
		Layers        []scanDescriptor `json:"layers"`
	}
	if err := json.Unmarshal(input.Manifest, &manifest); err != nil {
		return fmt.Errorf("scan manifest: %w", err)
	}
	media := input.MediaType
	if media == "" {
		media = manifest.MediaType
	}
	if manifest.SchemaVersion != 2 || (media != "application/vnd.oci.image.manifest.v1+json" && media != "application/vnd.docker.distribution.manifest.v2+json") {
		return &service.ScanError{Status: "UNSUPPORTED_IMAGE", Err: errors.New("scanner requires an OCI or Docker schema-2 platform image manifest")}
	}
	if err := os.MkdirAll(filepath.Join(directory, "blobs", "sha256"), 0700); err != nil {
		return err
	}
	writeBlob := func(descriptor scanDescriptor) error {
		data, ok := input.Blobs[descriptor.Digest]
		if !ok {
			return fmt.Errorf("scan image is missing blob %s", descriptor.Digest)
		}
		if descriptor.Size != int64(len(data)) {
			return fmt.Errorf("scan blob %s has incorrect size", descriptor.Digest)
		}
		digest := sha256.Sum256(data)
		expected := "sha256:" + hex.EncodeToString(digest[:])
		if descriptor.Digest != expected {
			return fmt.Errorf("scan blob %s does not match its SHA256 digest", descriptor.Digest)
		}
		return os.WriteFile(filepath.Join(directory, "blobs", "sha256", hex.EncodeToString(digest[:])), data, 0600)
	}
	if err := writeBlob(manifest.Config); err != nil {
		return err
	}
	written := map[string]bool{manifest.Config.Digest: true}
	for _, layer := range manifest.Layers {
		if written[layer.Digest] {
			continue
		}
		if err := writeBlob(layer); err != nil {
			return err
		}
		written[layer.Digest] = true
	}
	digest := sha256.Sum256(input.Manifest)
	hexDigest := hex.EncodeToString(digest[:])
	if err := os.WriteFile(filepath.Join(directory, "blobs", "sha256", hexDigest), input.Manifest, 0600); err != nil {
		return err
	}
	index := struct {
		SchemaVersion int              `json:"schemaVersion"`
		Manifests     []scanDescriptor `json:"manifests"`
	}{2, []scanDescriptor{{MediaType: media, Digest: "sha256:" + hexDigest, Size: int64(len(input.Manifest))}}}
	raw, err := json.Marshal(index)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(directory, "index.json"), raw, 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0600)
}

type trivyReport struct {
	SchemaVersion int
	Metadata      struct {
		OS *struct {
			Family, Name string
			EOSL         bool
		}
	}
	Results []struct {
		Class, Target   string
		Vulnerabilities []struct{ VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Title, Description, Severity, PrimaryURL string }
	}
}

func scanFindings(report trivyReport) api.ImageScanFindingList {
	findings := api.ImageScanFindingList{}
	for _, result := range report.Results {
		if result.Class != "os-pkgs" {
			continue
		}
		for _, vulnerability := range result.Vulnerabilities {
			severity := strings.ToUpper(vulnerability.Severity)
			switch severity {
			case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNDEFINED":
			default:
				severity = "UNDEFINED"
			}
			description := vulnerability.Description
			if description == "" {
				description = vulnerability.Title
			}
			finding := api.ImageScanFinding{Name: new(api.FindingName(vulnerability.VulnerabilityID)), Description: new(api.FindingDescription(description)), Severity: new(api.FindingSeverity(severity)), Attributes: api.AttributeList{{Key: new(api.AttributeKey("package_name")), Value: new(api.AttributeValue(vulnerability.PkgName))}, {Key: new(api.AttributeKey("package_version")), Value: new(api.AttributeValue(vulnerability.InstalledVersion))}}}
			if vulnerability.FixedVersion != "" {
				finding.Attributes = append(finding.Attributes, api.Attribute{Key: new(api.AttributeKey("fixed_version")), Value: new(api.AttributeValue(vulnerability.FixedVersion))})
			}
			if vulnerability.PrimaryURL != "" {
				finding.Uri = new(api.Url(vulnerability.PrimaryURL))
			}
			findings = append(findings, finding)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if *findings[i].Name != *findings[j].Name {
			return *findings[i].Name < *findings[j].Name
		}
		if *findings[i].Attributes[0].Value != *findings[j].Attributes[0].Value {
			return *findings[i].Attributes[0].Value < *findings[j].Attributes[0].Value
		}
		return *findings[i].Attributes[1].Value < *findings[j].Attributes[1].Value
	})
	return findings
}

// Native diagnostics can be much larger than an ECR status description. Keep
// a bounded prefix without allowing stderr volume to deadlock the child.
type boundedDiagnostic struct{ bytes.Buffer }

func (b *boundedDiagnostic) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 4096 - b.Len()
	if remaining > 0 {
		_, _ = b.Buffer.Write(p[:min(remaining, n)])
	}
	return n, nil
}

var _ service.Scanner = (*Trivy)(nil)

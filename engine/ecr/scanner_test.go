package ecr

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	service "stackd/internal/services/ecr"
)

func scannerFixture(t *testing.T) service.ScanInput {
	t.Helper()
	var layer bytes.Buffer
	archive := tar.NewWriter(&layer)
	files := []struct{ name, data string }{
		{"etc/os-release", "ID=alpine\nNAME=\"Alpine Linux\"\nVERSION_ID=3.16.0\n"},
		{"lib/apk/db/installed", "P:busybox\nV:1.35.0-r0\nA:x86_64\nS:800000\nI:900000\nT:Size optimized toolbox of many common UNIX utilities\nU:https://busybox.net\nL:GPL-2.0-only\no:busybox\nm:Alpine Developers\nt:1650000000\nc:fixture\n\n"},
	}
	for _, file := range files {
		if err := archive.WriteHeader(&tar.Header{Name: file.name, Mode: 0644, Size: int64(len(file.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(file.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	layerBytes := layer.Bytes()
	layerHash := sha256.Sum256(layerBytes)
	layerDigest := "sha256:" + hex.EncodeToString(layerHash[:])
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["` + layerDigest + `"]},"config":{}}`)
	configHash := sha256.Sum256(config)
	configDigest := "sha256:" + hex.EncodeToString(configHash[:])
	manifest := struct {
		SchemaVersion int              `json:"schemaVersion"`
		MediaType     string           `json:"mediaType"`
		Config        scanDescriptor   `json:"config"`
		Layers        []scanDescriptor `json:"layers"`
	}{2, "application/vnd.oci.image.manifest.v1+json", scanDescriptor{"application/vnd.oci.image.config.v1+json", configDigest, int64(len(config))}, []scanDescriptor{{"application/vnd.oci.image.layer.v1.tar", layerDigest, int64(len(layerBytes))}}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return service.ScanInput{Manifest: raw, MediaType: manifest.MediaType, Blobs: map[string][]byte{configDigest: config, layerDigest: layerBytes}}
}

func TestScannerRejectsCorruptOrMissingLayerBytes(t *testing.T) {
	for _, test := range []struct {
		name    string
		corrupt func(*service.ScanInput)
	}{
		{"missing", func(input *service.ScanInput) {
			for key := range input.Blobs {
				delete(input.Blobs, key)
				return
			}
		}},
		{"wrong digest", func(input *service.ScanInput) {
			for key, data := range input.Blobs {
				changed := bytes.Clone(data)
				changed[0] ^= 1
				input.Blobs[key] = changed
				return
			}
		}},
		{"wrong size", func(input *service.ScanInput) {
			for key, data := range input.Blobs {
				input.Blobs[key] = data[:len(data)-1]
				return
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := scannerFixture(t)
			test.corrupt(&input)
			if err := writeScanLayout(filepath.Join(t.TempDir(), "image"), input); err == nil {
				t.Fatal("scanner accepted content that does not satisfy manifest descriptors")
			}
		})
	}
}
func TestScannerDoesNotSelectArbitraryPlatformFromIndex(t *testing.T) {
	input := service.ScanInput{Manifest: []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`), MediaType: "application/vnd.oci.image.index.v1+json"}
	err := writeScanLayout(filepath.Join(t.TempDir(), "image"), input)
	var rejected *service.ScanError
	if !errors.As(err, &rejected) || rejected.Status != "UNSUPPORTED_IMAGE" {
		t.Fatalf("index scan error = %v", err)
	}
}

// A real pinned scanner, not a shell imitation, must reject an absent database.
// This catches accidental removal of skip-db-update/offline isolation. The
// integrating owner supplies the executable explicitly after provisioning it.
func TestNativeTrivyRequiresOfflineDatabase(t *testing.T) {
	executable := os.Getenv("STACKD_TEST_TRIVY")
	if executable == "" {
		t.Skip("set STACKD_TEST_TRIVY to the provisioned pinned executable")
	}
	scanner, err := NewTrivy(TrivyConfig{Executable: executable, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = scanner.Scan(context.Background(), scannerFixture(t))
	if err == nil {
		t.Fatal("native scanner succeeded without an offline vulnerability database")
	}
	if !strings.Contains(err.Error(), "Trivy scan failed:") || !strings.Contains(strings.ToLower(err.Error()), "database") {
		t.Fatalf("expected a native database error, got %v", err)
	}
}

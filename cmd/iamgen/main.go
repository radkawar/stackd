// Command iamgen generates IAM authorization and report metadata from the
// pinned AWS service reference. It never downloads files or makes AWS API calls.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"stackd/internal/iam/catalog/schema"
)

type options struct {
	Source, Out, LastAccessServices string
	ResourceControls                string
	Check                           bool
}

func main() {
	var o options
	flag.StringVar(&o.Source, "source", "internal/iam/catalog/data/service_reference.json.gz", "pinned AWS service reference")
	flag.StringVar(&o.Out, "out", "internal/iam/catalog", "generated catalog directory")
	flag.StringVar(&o.LastAccessServices, "last-access-services", "testdata/aws/iam/organizations_access_metadata_20260927.json", "captured AWS report service names, default regions and time ordering")
	flag.StringVar(&o.ResourceControls, "resource-control-source", "internal/iam/catalog/data/resource_control_source.json", "captured AWS RCP service coverage and action exceptions")
	flag.BoolVar(&o.Check, "check", false, "check generated output without changing files")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "iamgen: unexpected positional arguments")
		os.Exit(2)
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "iamgen:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	source, err := readSource(o.Source)
	if err != nil {
		return err
	}
	dataset, err := convert(source)
	if err != nil {
		return err
	}
	output, err := render(dataset)
	if err != nil {
		return err
	}
	lastAccess, err := renderLastAccess(source, o.LastAccessServices)
	if err != nil {
		return err
	}
	resourceControls, err := renderResourceControls(source, o.ResourceControls)
	if err != nil {
		return err
	}
	conditionTypes, err := renderConditionTypes(source)
	if err != nil {
		return err
	}
	return writeFiles(map[string][]byte{filepath.Join(o.Out, "data", "catalog.json.gz"): output, filepath.Join(o.Out, "last_access_generated.go"): lastAccess, filepath.Join(o.Out, "resource_control_generated.go"): resourceControls, filepath.Join(o.Out, "condition_types_generated.go"): conditionTypes}, o.Check)
}

func render(dataset []schema.Service) ([]byte, error) {
	data, err := json.Marshal(dataset)
	if err != nil {
		return nil, err
	}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	// The default zero timestamp and empty filename make the archive reproducible.
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}

func writeFiles(files map[string][]byte, check bool) error {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	var drift []string
	for _, path := range paths {
		current, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if bytes.Equal(current, files[path]) {
			continue
		}
		if check {
			drift = append(drift, path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := writeAtomic(path, files[path]); err != nil {
			return err
		}
	}
	if len(drift) != 0 {
		return fmt.Errorf("generated IAM metadata differs: %s; run go run ./cmd/iamgen", strings.Join(drift, ", "))
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".iamgen-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

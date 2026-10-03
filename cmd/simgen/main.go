// Command simgen generates IAM simulation metadata from a pinned AWS capture.
// Capture is an explicit network operation; this command is entirely offline.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	source := flag.String("source", "testdata/aws/iam/simulation_catalog.json", "completed AWS simulation capture")
	handling := flag.String("resource-handling-source", "testdata/aws/iam/service_reference.json", "captured AWS resource-handling scenarios")
	output := flag.String("out", "internal/iam/simcatalog/data_generated.go", "generated Go metadata")
	check := flag.Bool("check", false, "check generation drift without writing")
	flag.Parse()
	if err := run(*source, *handling, *output, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(sourcePath, handlingPath, outputPath string, check bool) error {
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	handling, err := os.ReadFile(handlingPath)
	if err != nil {
		return err
	}
	output, err := generate(source, handling)
	if err != nil {
		return err
	}
	if check {
		current, err := os.ReadFile(outputPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, output) {
			return fmt.Errorf("IAM simulation metadata is stale; run make generate-simulation")
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, output, 0o644)
}

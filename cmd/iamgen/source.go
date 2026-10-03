package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
)

// AWS publishes additional operation and annotation fields in the retained
// source. Decode only the metadata consumed by authorization and reports.
type sourceSnapshot struct {
	Source      string          `json:"source"`
	RetrievedAt string          `json:"retrieved_at"`
	Services    []sourceService `json:"services"`
}

type sourceService struct {
	Name          string
	Version       string
	Actions       []sourceAction
	Resources     []sourceResource
	ConditionKeys []struct {
		Name  string
		Types []string
	}
}

type sourceAction struct {
	Name                string
	ActionConditionKeys []string
	Resources           []struct{ Name string }
	SupportedBy         map[string]bool
}

type sourceResource struct {
	Name          string
	ARNFormats    []string
	ConditionKeys []string
}

func readSource(path string) (sourceSnapshot, error) {
	var source sourceSnapshot
	data, err := os.ReadFile(path)
	if err != nil {
		return source, err
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return source, err
	}
	defer reader.Close()
	if err := json.NewDecoder(reader).Decode(&source); err != nil {
		return source, err
	}
	if source.Source == "" || source.RetrievedAt == "" || len(source.Services) == 0 {
		return source, fmt.Errorf("AWS service reference has no source, capture time or services")
	}
	return source, nil
}

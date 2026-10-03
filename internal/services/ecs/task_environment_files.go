package ecs

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
)

func validateTaskEnvironmentFiles(files api.EnvironmentFiles) *awswire.Error {
	if len(files) > 10 {
		return failure("InvalidParameterException", "A container supports at most ten environment files.")
	}
	for _, file := range files {
		resource, err := arn.Parse(value(file.Value))
		bucket, key, found := strings.Cut(resource.Resource, "/")
		if value(file.Type) != "s3" || err != nil || resource.Service != "s3" || resource.Region != "" || resource.AccountID != "" || bucket == "" || !found || !strings.HasSuffix(key, ".env") || strings.ContainsRune(resource.Resource, 0) {
			return failure("InvalidParameterException", "Environment files require type s3 and an S3 object ARN ending in .env.")
		}
	}
	return nil
}

// Values are literal: no shell expansion, quote removal or escape processing.
// A malformed line is reported by number only, never by sensitive file content.
func parseTaskEnvironmentFile(body []byte, variables map[string]string) error {
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return fmt.Errorf("task environment file must be UTF-8 without NUL")
	}
	lineNumber := 0
	for line := range strings.SplitSeq(strings.TrimPrefix(string(body), "\ufeff"), "\n") {
		lineNumber++
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimLeft(line, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, content, found := strings.Cut(line, "=")
		if !found || name == "" || strings.ContainsAny(name, " \t\r") {
			return fmt.Errorf("invalid task environment file assignment at line %d", lineNumber)
		}
		if content == "" {
			continue
		}
		if _, exists := variables[name]; !exists {
			variables[name] = content
		}
	}
	return nil
}

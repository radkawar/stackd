package lambda

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func recursionResource(key FunctionKey) string {
	hash := sha256.Sum256([]byte(key.ARN()))
	return hex.EncodeToString(hash[:4])
}

// Lineage carries a total hop count, followed by resource-specific zero-based
// visit counters. The leading integer is not a fixed format-version marker.
func lineageEntries(value string) (int, string, bool) {
	hops, entries, ok := strings.Cut(value, ":")
	if !ok {
		return 0, "", false
	}
	count, err := strconv.Atoi(hops)
	return count, entries, err == nil && count > 0 && count < 2147483647
}

func recursionCount(trace, resource string) int {
	for field := range strings.SplitSeq(trace, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || name != "Lineage" {
			continue
		}
		_, value, supported := lineageEntries(value)
		if !supported {
			continue
		}
		for entry := range strings.SplitSeq(value, ",") {
			id, count, ok := strings.Cut(entry, ":")
			if !ok || id != resource {
				continue
			}
			n, err := strconv.Atoi(count)
			if err == nil && n >= 0 {
				return n
			}
		}
	}
	return -1
}
func (s *Service) checkRecursion(r Reader, key FunctionKey) *awswire.Error {
	if recursionCount(awsctx.FromContext(r.Context()).TraceHeader, recursionResource(key)) < 15 {
		return nil
	}
	mode, err := r.RecursiveLoop(key)
	if err != nil {
		return wireError(err)
	}
	if mode == "Allow" {
		return nil
	}
	return failure("RecursiveInvocationException", "Lambda detected a recursive invocation chain and stopped this invocation.", 400)
}

// Runtime SDKs forward this ordinary X-Ray header through supported services.
// Counts belong to the triggering event, never a process-global function count.
func recursionTrace(trace string, key FunctionKey, now time.Time) string {
	resource := recursionResource(key)
	count := recursionCount(trace, resource)
	fields := make([]string, 0, 4)
	entries := make([]string, 0, 4)
	root := false
	hops := 0
	for field := range strings.SplitSeq(trace, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		if name == "Lineage" {
			if count, value, supported := lineageEntries(value); supported {
				hops = count
				for entry := range strings.SplitSeq(value, ",") {
					id, _, ok := strings.Cut(entry, ":")
					if ok && id != resource {
						entries = append(entries, entry)
					}
				}
			}
		} else {
			fields = append(fields, field)
			if name == "Root" {
				root = true
			}
		}
	}
	if !root {
		fields = append(fields, "Root="+awsctx.NewTraceID(now), "Sampled=0")
	}
	entries = append(entries, resource+":"+strconv.Itoa(min(count+1, 2147483647)))
	fields = append(fields, "Lineage="+strconv.Itoa(hops+1)+":"+strings.Join(entries, ","))
	return strings.Join(fields, ";")
}

func (s *Service) sqsRecursionContext(ctx context.Context, key FunctionKey, records []sqsEventRecord) context.Context {
	resource := recursionResource(key)
	trace, largest := "", -1
	for _, record := range records {
		candidate := string(record.Attributes["AWSTraceHeader"])
		if count := recursionCount(candidate, resource); candidate != "" && (trace == "" || count > largest) {
			trace, largest = candidate, count
		}
	}
	if trace == "" {
		return ctx
	}
	metadata := awsctx.FromContext(ctx)
	metadata.TraceHeader = trace
	return awsctx.WithMetadata(ctx, metadata)
}

package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// Only generator-consumed dimensions are decoded. The complete native shape
// remains raw JSON, so generation neither depends on nor truncates its own output.
type instanceDimensions struct {
	InstanceType                                     string
	SupportedInRegion, BurstablePerformanceSupported bool
	VCpuInfo                                         struct{ DefaultVCpus int32 }
	MemoryInfo                                       struct{ SizeInMiB int64 }
}

// renderInstanceTypeMetadata projects immutable native responses into an offline,
// versioned catalog. Account-owned credit defaults and location offerings are
// deliberately not projected: neither is a universal instance-type property.
func renderInstanceTypeMetadata(catalogBytes, creditBytes []byte) ([]byte, error) {
	var capture struct {
		SchemaVersion int             `json:"schema_version"`
		Region        string          `json:"region"`
		CapturedAt    string          `json:"captured_at"`
		Complete      bool            `json:"complete"`
		Catalog       json.RawMessage `json:"catalog"`
	}
	if err := json.Unmarshal(catalogBytes, &capture); err != nil {
		return nil, err
	}
	if capture.SchemaVersion != 1 || !capture.Complete || capture.Region != "us-east-1" || capture.CapturedAt == "" {
		return nil, fmt.Errorf("instance type capture is not a complete version-1 us-east-1 catalog")
	}
	var catalog struct{ InstanceTypes []json.RawMessage }
	if err := json.Unmarshal(capture.Catalog, &catalog); err != nil {
		return nil, err
	}
	if len(catalog.InstanceTypes) == 0 {
		return nil, fmt.Errorf("empty instance type catalog")
	}
	byName := make(map[string]instanceDimensions, len(catalog.InstanceTypes))
	var previous string
	for i, raw := range catalog.InstanceTypes {
		var info instanceDimensions
		if err := json.Unmarshal(raw, &info); err != nil {
			return nil, err
		}
		if info.InstanceType == "" || !info.SupportedInRegion || info.VCpuInfo.DefaultVCpus <= 0 || info.MemoryInfo.SizeInMiB <= 0 {
			return nil, fmt.Errorf("instance type row %d lacks supported regional dimensions", i)
		}
		if i > 0 && previous >= info.InstanceType {
			return nil, fmt.Errorf("instance type catalog is not strictly sorted")
		}
		previous = info.InstanceType
		byName[info.InstanceType] = info
	}
	var credits struct {
		SchemaVersion int `json:"schema_version"`
		CreditTable   struct {
			SourceURL string `json:"source_url"`
			Rows      []struct {
				InstanceType                                  string
				CpuCreditsEarnedPerHour, MaximumEarnedCredits json.Number
				VCpus                                         int32
				BaselineUtilizationPerVCpuPercent             json.Number
			}
		} `json:"credit_table"`
	}
	if err := json.Unmarshal(creditBytes, &credits); err != nil {
		return nil, err
	}
	table := credits.CreditTable
	if credits.SchemaVersion != 1 || table.SourceURL == "" {
		return nil, fmt.Errorf("credit metadata requires version 1 and its source URL")
	}
	type creditRate struct {
		EarnedCPUTimePerHour time.Duration
		MaximumEarnedCPUTime time.Duration
		VCpus                int32
	}
	rates := make(map[string]creditRate, len(table.Rows))
	for _, row := range table.Rows {
		info, ok := byName[row.InstanceType]
		if !ok || !info.BurstablePerformanceSupported || row.VCpus != info.VCpuInfo.DefaultVCpus {
			return nil, fmt.Errorf("credit row %s does not match captured burstable dimensions", row.InstanceType)
		}
		if _, exists := rates[row.InstanceType]; exists {
			return nil, fmt.Errorf("duplicate credit row %s", row.InstanceType)
		}
		earned, err := exactCreditCPUTime(row.CpuCreditsEarnedPerHour)
		if err != nil {
			return nil, fmt.Errorf("%s earned credits: %w", row.InstanceType, err)
		}
		maximum, err := exactCreditCPUTime(row.MaximumEarnedCredits)
		if err != nil {
			return nil, fmt.Errorf("%s maximum credits: %w", row.InstanceType, err)
		}
		baseline, ok := new(big.Rat).SetString(string(row.BaselineUtilizationPerVCpuPercent))
		if !ok {
			return nil, fmt.Errorf("%s invalid baseline percentage", row.InstanceType)
		}
		baseline.Mul(baseline, big.NewRat(int64(row.VCpus)*int64(time.Hour), 100))
		if !baseline.IsInt() || !baseline.Num().IsInt64() || baseline.Num().Int64() != int64(earned) {
			return nil, fmt.Errorf("%s baseline disagrees with earned CPU time", row.InstanceType)
		}
		rates[row.InstanceType] = creditRate{earned, maximum, row.VCpus}
	}
	for name, info := range byName {
		if info.BurstablePerformanceSupported {
			if _, ok := rates[name]; !ok {
				return nil, fmt.Errorf("burstable instance type %s has no official credit rate", name)
			}
		}
	}
	output := struct {
		SchemaVersion                       int
		Region, CapturedAt, CreditSourceURL string
		InstanceTypes                       []json.RawMessage
		CreditRates                         map[string]creditRate
	}{1, capture.Region, capture.CapturedAt, table.SourceURL, catalog.InstanceTypes, rates}
	out, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// AWS defines one CPU credit as one vCPU-minute. Parse decimal source values
// as rationals, never through float64 (t2.2xlarge earns 81.6 credits/hour).
func exactCreditCPUTime(value json.Number) (time.Duration, error) {
	rational, ok := new(big.Rat).SetString(string(value))
	if !ok || rational.Sign() <= 0 {
		return 0, fmt.Errorf("invalid credit value %q", value)
	}
	rational.Mul(rational, big.NewRat(int64(time.Minute), 1))
	if !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, fmt.Errorf("credit value %q is not representable in nanoseconds", value)
	}
	return time.Duration(rational.Num().Int64()), nil
}

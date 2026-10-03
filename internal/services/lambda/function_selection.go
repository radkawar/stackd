package lambda

import (
	"errors"
	"hash/fnv"
	"strconv"
	"strings"
)

// loadFunction projects primary metadata. Routing is only sampled when a request
// actually starts an invocation attempt, never for reads or async admission.
func loadFunction(r Reader, ref FunctionReference) (FunctionRecord, error) {
	version, _, err := resolveFunctionVersion(r, ref)
	if err != nil {
		return FunctionRecord{}, err
	}
	return loadDeployment(r, FunctionVersionKey{FunctionKey: ref.FunctionKey, Version: version})
}

func selectFunction(r Reader, ref FunctionReference, requestID string, attempt int) (FunctionRecord, error) {
	version, alias, err := resolveFunctionVersion(r, ref)
	if err != nil {
		return FunctionRecord{}, err
	}
	if ref.Qualifier == "" {
		latest, err := r.Function(ref.FunctionKey)
		if err != nil {
			return FunctionRecord{}, err
		}
		if latest.Capacity == nil {
			return latest, nil
		}
		version = LatestPublishedVersion
	}
	if alias.AdditionalVersion != 0 && alias.AdditionalWeight > 0 {
		// As with EventBridge retry jitter, retained request identity and attempt
		// make the draw stable across storage reopen and scheduler recovery.
		h := fnv.New64a()
		_, _ = h.Write([]byte(requestID + ":" + strconv.Itoa(attempt)))
		draw := float64(h.Sum64()>>11) / (1 << 53)
		if draw < alias.AdditionalWeight {
			version = alias.AdditionalVersion
		}
	}
	selected, err := loadDeployment(r, FunctionVersionKey{FunctionKey: ref.FunctionKey, Version: version})
	if version == LatestPublishedVersion && errors.Is(err, ErrNotFound) {
		return FunctionRecord{}, failure("NoPublishedVersionException", "The managed function has no published version to invoke.", 400)
	}
	return selected, err
}

func resolveFunctionVersion(r Reader, ref FunctionReference) (uint64, AliasRecord, error) {
	if ref.Qualifier == "" || ref.Qualifier == "$LATEST" {
		return 0, AliasRecord{}, nil
	}
	if ref.Qualifier == "$LATEST.PUBLISHED" {
		latest, err := r.Function(ref.FunctionKey)
		if err != nil {
			return 0, AliasRecord{}, err
		}
		if latest.Capacity == nil {
			return 0, AliasRecord{}, failure("InvalidParameterValueException", "$LATEST.PUBLISHED is only supported for Lambda Managed Instances.", 400)
		}
		return LatestPublishedVersion, AliasRecord{}, nil
	}
	if strings.Trim(ref.Qualifier, "0123456789") == "" {
		version, err := strconv.ParseUint(ref.Qualifier, 10, 64)
		if err != nil || version == 0 || version >= LatestPublishedVersion {
			return 0, AliasRecord{}, ErrNotFound
		}
		return version, AliasRecord{}, nil
	}
	alias, err := r.Alias(ref)
	return alias.FunctionVersion, alias, err
}

func loadDeployment(r Reader, key FunctionVersionKey) (FunctionRecord, error) {
	if key.Version == 0 {
		return r.Function(key.FunctionKey)
	}
	// DLQ settings belong to the published deployment too: native fixed-version
	// and alias deliveries keep them after $LATEST changes. Do not overlay the
	// root's DLQ here (testdata/aws/lambda/dlq_ownership_20261001.json).
	return r.FunctionVersion(key)
}

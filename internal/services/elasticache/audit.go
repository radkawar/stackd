package elasticache

import api "stackd/internal/awsapi/elasticache"

// Native CloudTrail includes server-applied page defaults for these parameter
// and engine descriptions. Preserve the caller DTO; audit does not mutate input.
func auditInput(in any) any {
	switch v := in.(type) {
	case *api.DescribeCacheParameterGroupsMessage:
		if v != nil && v.MaxRecords == nil {
			copied := *v
			copied.MaxRecords = new(api.IntegerOptional(100))
			return &copied
		}
	case *api.DescribeCacheParametersMessage:
		if v != nil && v.MaxRecords == nil {
			copied := *v
			copied.MaxRecords = new(api.IntegerOptional(100))
			return &copied
		}
	case *api.DescribeCacheEngineVersionsMessage:
		if v != nil && v.MaxRecords == nil {
			copied := *v
			copied.MaxRecords = new(api.IntegerOptional(100))
			return &copied
		}
	}
	return in
}

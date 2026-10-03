package opensearch

import (
	"stackd/internal/awswire"
	"stackd/journal"
)

// TODO: Comeback calibrate successful domain provisioning, configuration and
// tagging audit projections with bounded owned native infrastructure.

// Native fixtures correlate these projections by exact AWS request ID. Data
// engine APIs are not CloudTrail configuration events and never enter this path.
func projectNativeAudit(call *journal.APICallCompleted, rejected *awswire.Error) {
	call.EventSource = "es.amazonaws.com"
	if call.EventName == "ListDomainNames" && string(call.RequestParameters) == "{}" {
		call.RequestParameters = nil
	}
	if rejected == nil {
		return
	}
	if rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" {
		call.ErrorCode = "AccessDenied"
		call.RequestParameters = nil
		return
	}
	if rejected.Code == "ValidationException" {
		switch call.EventName {
		case "DescribeDomain", "DescribeDomainConfig", "DeleteDomain", "DescribeElasticsearchDomain", "DescribeElasticsearchDomainConfig", "DeleteElasticsearchDomain":
			call.RequestParameters = nil
		}
	}
	if rejected.Code == "ResourceNotFoundException" && (call.EventName == "DeleteDomain" || call.EventName == "DeleteElasticsearchDomain") {
		call.ResponseElements = []byte(`{"isElasticsearchDomain":true}`)
	}
}

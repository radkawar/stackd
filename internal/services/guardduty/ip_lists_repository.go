package guardduty

import "time"

// IPListKind distinguishes the two legacy IPv4 list owners and their ARN paths.
type IPListKind string

const (
	TrustedIPList IPListKind = "ipset"
	ThreatIPList  IPListKind = "threatintelset"
)

// IPList retains source intent separately from the last ingested range snapshot.
// Only ACTIVE lists participate in detection. Version fences asynchronous work.
type IPList struct {
	CFNOwnership CloudFormationOwnership
	Scope
	DetectorID, ID, ARN, Name, Format          string
	Kind                                       IPListKind
	Location, ExpectedBucketOwner, ClientToken string
	Status                                     string
	Version                                    int64
	Due                                        time.Time
	Tags                                       map[string]string
}

// IPRange is an inclusive IPv4 interval in network byte order. Ingested ranges
// are sorted and disjoint, allowing indexed SQL and binary-search memory lookup.
type IPRange struct {
	First, Last uint32
}

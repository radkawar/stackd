package eventbridge

import "time"

// APIDestinationKey identifies a regional name; ID fences its incarnation.
type APIDestinationKey struct {
	Scope
	Name string
}

type APIDestinationRecord struct {
	Key                                              APIDestinationKey
	ID, Description, ConnectionARN, Endpoint, Method string
	Rate                                             int
	Created, Modified, RateWindow                    time.Time
	RateCount                                        int
	Version                                          uint64
}

func (v APIDestinationRecord) ARN() string {
	return "arn:" + v.Key.Partition + ":events:" + v.Key.Region + ":" + v.Key.Account + ":api-destination/" + v.Key.Name + "/" + v.ID
}

type APIDestinationReader interface {
	APIDestination(APIDestinationKey) (APIDestinationRecord, error)
	APIDestinations(Scope) ([]APIDestinationRecord, error)
}

type APIDestinationWriter interface {
	PutAPIDestination(APIDestinationRecord) error
	DeleteAPIDestination(APIDestinationKey) error
}

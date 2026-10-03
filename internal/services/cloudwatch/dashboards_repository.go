package cloudwatch

import "time"

// DashboardKey is account-global: changing the endpoint Region does not change
// dashboard identity or its resource ARN.
type DashboardKey struct {
	Partition, AccountID, Name string
}

func (k DashboardKey) ARN() string {
	return "arn:" + k.Partition + ":cloudwatch::" + k.AccountID + ":dashboard/" + k.Name
}

// DashboardEntry excludes the potentially large body and tags from list reads.
type DashboardEntry struct {
	Key     DashboardKey
	Updated time.Time
	Size    int64
}

type DashboardRecord struct {
	DashboardEntry
	Body string
	Tags map[string]string
	// Native size accounting retains tagging metadata even after the last tag
	// is removed. Deleting the dashboard removes that metadata as well.
	TaggingInitialized bool
}

type DashboardQuery struct {
	Partition, AccountID, Prefix, After string
	Limit                               int
}

package cloudwatch

import (
	"encoding/json"
	"time"
)

// Native ListDashboards counts an HTML-safe JSON representation plus fixed
// metadata. The retained tag metadata survives an empty tag set. These offsets
// and escaping rules are measured by dashboard_size.json; they do not describe
// the emulator's physical storage format or imply an encryption implementation.
func storeDashboard(tx Transaction, record DashboardRecord, at time.Time) error {
	record.Updated = at.Truncate(time.Second)
	record.Size = dashboardSerializedSize(record.Body) + 37
	if record.TaggingInitialized {
		record.Size += 149
		if len(record.Tags) != 0 {
			tags, _ := json.Marshal(record.Tags)
			record.Size += 8 + dashboardSerializedSize(string(tags)) // ,"tags": plus the object
		}
	}
	return tx.PutDashboard(record)
}

func dashboardSerializedSize(document string) int64 {
	size := int64(len(document))
	for i := range len(document) {
		switch document[i] {
		case '<', '>', '&', '=', '\'':
			size += 5 // one ASCII byte becomes a six-byte Unicode escape
		}
	}
	return size
}

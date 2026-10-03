package s3

func tieringNotificationRecord(record map[string]any, object ObjectRecord) {
	record["intelligentTieringEventData"] = map[string]any{"destinationAccessTier": object.Tiering.ArchiveTier}
}

func tieringEventBridgeDetail(detail map[string]any, object ObjectRecord) string {
	delete(detail, "reason")
	delete(detail, "source-ip-address")
	detail["destination-access-tier"] = object.Tiering.ArchiveTier
	return "Object Access Tier Changed"
}

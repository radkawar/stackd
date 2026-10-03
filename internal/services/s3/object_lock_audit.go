package s3

// recordObjectLock projects the stored metadata, independently of permission to
// expose it in a payload-read response. Native metadata GETs select one facet;
// retention mutations include an existing legal hold, while legal-hold calls do
// not include retention. Modification times belong to the version, not the read.
func (s *Service) recordObjectLock(c *apiCall, object ObjectRecord) {
	retention, legal := object.Retention.Mode != "", object.LegalHold != ""
	switch c.name {
	case "GetObjectLegalHold", "PutObjectLegalHold":
		retention = false
	case "GetObjectRetention":
		legal = false
	}
	if !retention && !legal {
		return
	}
	info := map[string]any{}
	if retention {
		info["retentionInfo"] = map[string]any{
			"retainUntilMode":  object.Retention.Mode,
			"retainUntilTime":  object.Retention.until(s.clock.Now()).UnixMilli(),
			"lastModifiedTime": object.Retention.Modified.UnixMilli(),
		}
	}
	if legal {
		info["legalHoldInfo"] = map[string]any{
			"isUnderLegalHold": object.LegalHold == "ON",
			"lastModifiedTime": object.LegalHoldModified.UnixMilli(),
		}
	}
	c.additional["objectRetentionInfo"] = info
}

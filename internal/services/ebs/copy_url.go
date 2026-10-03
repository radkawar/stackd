package ebs

import "net/url"

// copyURL validates copy parameters without authenticating or fetching the URL.
func copyURL(rawURL, sourceRegion, sourceSnapshotID, destinationRegion string) error {
	if rawURL == "" {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ec2Failure("InvalidParameterValue", "The protocol in PresignedUrl should be http or https")
	}
	query := parsed.Query()
	if source := query.Get("SourceSnapshotId"); source != sourceSnapshotID {
		return ec2Failure("InvalidParameterValue", "The source snapshot specified in PresignedUrl '"+source+"' does not match the source snapshot in the request: '"+sourceSnapshotID+"'")
	}
	if destination := query.Get("DestinationRegion"); destination != destinationRegion {
		return ec2Failure("InvalidParameterValue", "The destination region specified in PresignedUrl: '"+destination+"' is incorrect")
	}
	return nil
}

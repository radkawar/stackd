-- Private native incarnation claims. Existing controls remain unclaimed.
ALTER TABLE guardduty_detectors ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE guardduty_detectors ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE guardduty_filters ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE guardduty_filters ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE guardduty_ip_lists ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE guardduty_ip_lists ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE guardduty_publishing_destinations ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE guardduty_publishing_destinations ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';

ALTER TABLE sns_topics ADD COLUMN cfn_topic_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_topics ADD COLUMN cfn_topic_token TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_topics ADD COLUMN cfn_policy_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_topics ADD COLUMN cfn_policy_identifier TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_topics ADD COLUMN cfn_policy_type TEXT NOT NULL DEFAULT '';

-- Private CloudFormation incarnation claim shared by the OpenSearch and legacy
-- ES frontends. Public domain tags never carry ownership; empty is unowned.
ALTER TABLE opensearch_domain ADD COLUMN ownership TEXT NOT NULL DEFAULT '';

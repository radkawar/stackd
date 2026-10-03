-- Retain published documents independently of mutations and persist pending work.
CREATE TABLE org_effective_policies (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    content TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    due TIMESTAMP,
    request_id TEXT NOT NULL,
    request_region TEXT NOT NULL,
    actor_arn TEXT NOT NULL,
    PRIMARY KEY (partition, org_id, account_id, policy_type),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

-- Earlier versions derived content on reads. Regenerate their enabled account
-- views through the ordinary worker; no published content or origin is invented.
INSERT INTO org_effective_policies (partition, org_id, account_id, policy_type, content, updated_at, due, request_id, request_region, actor_arn)
SELECT a.partition, a.org_id, a.id, p.type, '', '0001-01-01 00:00:00+00:00', '0001-01-01 00:00:00+00:00', '', '', ''
FROM org_members a JOIN org_root_policy_types p ON a.partition = p.partition AND a.org_id = p.org_id
WHERE p.status = 'ENABLED' AND p.type NOT IN ('SERVICE_CONTROL_POLICY', 'RESOURCE_CONTROL_POLICY');
DROP TABLE org_effective_policy_generations;

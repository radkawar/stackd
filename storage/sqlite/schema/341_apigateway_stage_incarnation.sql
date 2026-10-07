ALTER TABLE apigateway_stages ADD COLUMN incarnation INTEGER NOT NULL DEFAULT 0;

CREATE TABLE apigateway_stage_sequence (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 value INTEGER NOT NULL CHECK (value > 0 AND typeof(value) = 'integer'),
 PRIMARY KEY (partition, account_id, region)
);

-- Backfill distinct private identities for preexisting stages, then initialize
-- each scope's persistent sequence above those identities. API/stage deletion
-- deliberately does not cascade to this counter.
WITH identities AS (
 SELECT rowid AS stage_rowid,
        ROW_NUMBER() OVER (PARTITION BY partition, account_id, region ORDER BY api_id, name) AS incarnation
 FROM apigateway_stages
)
UPDATE apigateway_stages
SET incarnation = (SELECT incarnation FROM identities WHERE stage_rowid = apigateway_stages.rowid);

INSERT INTO apigateway_stage_sequence (partition, account_id, region, value)
SELECT partition, account_id, region, MAX(incarnation)
FROM apigateway_stages
GROUP BY partition, account_id, region;

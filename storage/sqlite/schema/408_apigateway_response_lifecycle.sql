-- Existing MOCK rows represented an active response, including an empty body.
-- New integrations explicitly record the absence of a configured response.
ALTER TABLE apigateway_mock_integrations ADD COLUMN response_deleted BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE apigateway_mock_integrations ADD COLUMN template_present BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE apigateway_mock_routes ADD COLUMN response_deleted BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE apigateway_mock_routes ADD COLUMN template_present BOOLEAN NOT NULL DEFAULT 0;

-- Older storage did not distinguish an absent template from an empty one.
-- Only nonempty retained bodies establish that a template was configured.
UPDATE apigateway_mock_integrations SET template_present = 1 WHERE body <> '';
UPDATE apigateway_mock_routes SET template_present = 1 WHERE body <> '';

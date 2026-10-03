-- Enrichment HTTP parameters follow the existing modeled target components.
ALTER TABLE pipes_pipes ADD COLUMN enrichment_http_present BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE pipes_pipes ADD COLUMN enrichment_http_headers TEXT NOT NULL DEFAULT 'null';
ALTER TABLE pipes_pipes ADD COLUMN enrichment_http_paths TEXT NOT NULL DEFAULT 'null';
ALTER TABLE pipes_pipes ADD COLUMN enrichment_http_query TEXT NOT NULL DEFAULT 'null';

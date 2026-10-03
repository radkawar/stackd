ALTER TABLE api_call_events ADD COLUMN service_event INTEGER NOT NULL DEFAULT 0 CHECK (service_event IN (0, 1));
ALTER TABLE api_call_events ADD COLUMN service_event_details TEXT NOT NULL DEFAULT 'null' CHECK (json_valid(service_event_details));

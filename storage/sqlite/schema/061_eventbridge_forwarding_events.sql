ALTER TABLE eventbridge_accepted_events ADD COLUMN wire_event_id TEXT NOT NULL DEFAULT '';
UPDATE eventbridge_accepted_events SET wire_event_id=event_id;

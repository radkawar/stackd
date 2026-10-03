CREATE TABLE cloudtrail_trails (
    partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
    id TEXT NOT NULL UNIQUE,
    bucket TEXT NOT NULL, prefix TEXT NOT NULL,
    include_global BOOLEAN NOT NULL, multi_region BOOLEAN NOT NULL, recursive_logging BOOLEAN NOT NULL, logging BOOLEAN NOT NULL,
    created TIMESTAMP NOT NULL, modified TIMESTAMP NOT NULL, started TIMESTAMP, stopped TIMESTAMP,
    stop_after TIMESTAMP,
    PRIMARY KEY (partition, account_id, region, name)
);
CREATE TABLE cloudtrail_tags (
    trail_id TEXT NOT NULL REFERENCES cloudtrail_trails(id) ON DELETE CASCADE,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (trail_id, key)
);
CREATE TABLE cloudtrail_basic_selectors (
    trail_id TEXT NOT NULL REFERENCES cloudtrail_trails(id) ON DELETE CASCADE,
    position INTEGER NOT NULL, read_only BOOLEAN, include_management BOOLEAN NOT NULL,
    PRIMARY KEY (trail_id, position)
);
CREATE TABLE cloudtrail_excluded_sources (
    trail_id TEXT NOT NULL, selector_position INTEGER NOT NULL, position INTEGER NOT NULL, source TEXT NOT NULL,
    PRIMARY KEY (trail_id, selector_position, position),
    FOREIGN KEY (trail_id, selector_position) REFERENCES cloudtrail_basic_selectors(trail_id, position) ON DELETE CASCADE
);
CREATE TABLE cloudtrail_data_resources (
    trail_id TEXT NOT NULL, selector_position INTEGER NOT NULL, position INTEGER NOT NULL, type TEXT NOT NULL,
    PRIMARY KEY (trail_id, selector_position, position),
    FOREIGN KEY (trail_id, selector_position) REFERENCES cloudtrail_basic_selectors(trail_id, position) ON DELETE CASCADE
);
CREATE TABLE cloudtrail_data_prefixes (
    trail_id TEXT NOT NULL, selector_position INTEGER NOT NULL, resource_position INTEGER NOT NULL,
    position INTEGER NOT NULL, prefix TEXT NOT NULL,
    PRIMARY KEY (trail_id, selector_position, resource_position, position),
    FOREIGN KEY (trail_id, selector_position, resource_position) REFERENCES cloudtrail_data_resources(trail_id, selector_position, position) ON DELETE CASCADE
);
CREATE TABLE cloudtrail_advanced_selectors (
    trail_id TEXT NOT NULL REFERENCES cloudtrail_trails(id) ON DELETE CASCADE,
    position INTEGER NOT NULL, name TEXT NOT NULL,
    PRIMARY KEY (trail_id, position)
);
CREATE TABLE cloudtrail_fields (
    trail_id TEXT NOT NULL, selector_position INTEGER NOT NULL, position INTEGER NOT NULL, field TEXT NOT NULL,
    PRIMARY KEY (trail_id, selector_position, position),
    FOREIGN KEY (trail_id, selector_position) REFERENCES cloudtrail_advanced_selectors(trail_id, position) ON DELETE CASCADE
);
CREATE TABLE cloudtrail_tests (
    trail_id TEXT NOT NULL, selector_position INTEGER NOT NULL, field_position INTEGER NOT NULL,
    position INTEGER NOT NULL, operator TEXT NOT NULL,
    PRIMARY KEY (trail_id, selector_position, field_position, position),
    FOREIGN KEY (trail_id, selector_position, field_position) REFERENCES cloudtrail_fields(trail_id, selector_position, position) ON DELETE CASCADE
);
CREATE TABLE cloudtrail_test_values (
    trail_id TEXT NOT NULL, selector_position INTEGER NOT NULL, field_position INTEGER NOT NULL, test_position INTEGER NOT NULL,
    position INTEGER NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (trail_id, selector_position, field_position, test_position, position),
    FOREIGN KEY (trail_id, selector_position, field_position, test_position) REFERENCES cloudtrail_tests(trail_id, selector_position, field_position, position) ON DELETE CASCADE
);
CREATE TABLE cloudtrail_delivery_status (
    trail_id TEXT PRIMARY KEY REFERENCES cloudtrail_trails(id) ON DELETE CASCADE,
    last_attempt TIMESTAMP, last_success TIMESTAMP, last_error TEXT NOT NULL
);
CREATE TABLE cloudtrail_deliveries (
    id TEXT PRIMARY KEY,
    trail_id TEXT NOT NULL REFERENCES cloudtrail_trails(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL, region TEXT NOT NULL, bucket TEXT NOT NULL, object_key TEXT NOT NULL,
    created TIMESTAMP NOT NULL, due TIMESTAMP NOT NULL, expires TIMESTAMP NOT NULL,
    sealed BOOLEAN NOT NULL, event_count INTEGER NOT NULL, attempts INTEGER NOT NULL, version BLOB NOT NULL
);
CREATE INDEX cloudtrail_deliveries_due ON cloudtrail_deliveries(due, id);
CREATE INDEX cloudtrail_deliveries_open ON cloudtrail_deliveries(trail_id, region, sealed, due, id);
CREATE TABLE cloudtrail_delivery_events (
    delivery_id TEXT NOT NULL REFERENCES cloudtrail_deliveries(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    event_id TEXT NOT NULL REFERENCES api_call_events(event_id),
    PRIMARY KEY (delivery_id, position)
);

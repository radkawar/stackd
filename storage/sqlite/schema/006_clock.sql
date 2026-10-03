-- One active stack owns the database and its modeled service timeline.
CREATE TABLE clock_state (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    instant TIMESTAMP NOT NULL
);

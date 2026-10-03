-- name: CurrentTime :one
SELECT instant FROM clock_state WHERE id = 1;

-- name: InitializeTime :exec
INSERT INTO clock_state (id, instant) VALUES (1, ?);

-- name: SetTime :exec
UPDATE clock_state SET instant = ? WHERE id = 1;

-- name: ReadGroupMembershipClaims :many
SELECT owner FROM iam_group_membership_claims WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY owner;

-- name: WriteGroupMembershipClaim :exec
INSERT INTO iam_group_membership_claims (partition, account, resource_key, owner) VALUES (?, ?, ?, ?);

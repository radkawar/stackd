-- name: GetParameter :one
SELECT * FROM ssm_parameters WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetParameterID :one
SELECT id FROM ssm_parameters WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListParameters :many
SELECT * FROM ssm_parameters WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;

-- name: DeleteParameter :exec
DELETE FROM ssm_parameters WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutParameter :one
INSERT INTO ssm_parameters (partition, account_id, region, name, arn, type, tier, data_type, description, allowed_pattern, current_version, tags_present, policies_present, resource_policies_present, incarnation, cloudformation_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET
 arn = excluded.arn, type = excluded.type, tier = excluded.tier, data_type = excluded.data_type, description = excluded.description, allowed_pattern = excluded.allowed_pattern, current_version = excluded.current_version, tags_present = excluded.tags_present, policies_present = excluded.policies_present, resource_policies_present = excluded.resource_policies_present
RETURNING id;

-- name: ListTags :many
SELECT * FROM ssm_tags WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteTags :exec
DELETE FROM ssm_tags WHERE parent_id = ?;

-- name: PutTags :exec
INSERT INTO ssm_tags (parent_id, map_key, value)
VALUES (?, ?, ?);

-- name: ListResourcePolicies :many
SELECT * FROM ssm_resource_policies WHERE parent_id = ? ORDER BY position;

-- name: DeleteResourcePolicies :exec
DELETE FROM ssm_resource_policies WHERE parent_id = ?;

-- name: PutResourcePolicies :one
INSERT INTO ssm_resource_policies (parent_id, position, policy_id, hash, document, trust_policy, principals_present, cloudformation_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: ListResourcePolicyBindings :many
SELECT * FROM ssm_resource_policy_bindings WHERE parent_id = ? ORDER BY arn;

-- name: PutResourcePolicyBindings :exec
INSERT INTO ssm_resource_policy_bindings (parent_id, arn, principal_id)
VALUES (?, ?, ?);

-- name: GetVersion :one
SELECT * FROM ssm_versions WHERE parent_id = ? AND version = ?;

-- name: ListVersions :many
SELECT * FROM ssm_versions WHERE parent_id = ? ORDER BY version;

-- name: DeleteVersion :exec
DELETE FROM ssm_versions WHERE parent_id = (SELECT id FROM ssm_parameters WHERE partition = ? AND account_id = ? AND region = ? AND name = ?) AND version = ?;

-- name: PutVersion :one
INSERT INTO ssm_versions (parent_id, version, type, tier, data_type, description, allowed_pattern, key_id, key_arn, modified_user, modified, labels_present, policies_present)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (parent_id, version) DO UPDATE SET
 type = excluded.type, tier = excluded.tier, data_type = excluded.data_type, description = excluded.description, allowed_pattern = excluded.allowed_pattern, key_id = excluded.key_id, key_arn = excluded.key_arn, modified_user = excluded.modified_user, modified = excluded.modified, labels_present = excluded.labels_present, policies_present = excluded.policies_present
RETURNING id;

-- name: GetValue :one
SELECT value, wrapped_key FROM ssm_values WHERE parent_id = ?;

-- name: PutValue :exec
INSERT INTO ssm_values (parent_id, value, wrapped_key)
VALUES (?, ?, ?)
ON CONFLICT (parent_id) DO UPDATE SET
 value = excluded.value, wrapped_key = excluded.wrapped_key;

-- name: ListLabels :many
SELECT * FROM ssm_labels WHERE parent_id = ? ORDER BY position;

-- name: DeleteLabels :exec
DELETE FROM ssm_labels WHERE parent_id = ?;

-- name: PutLabels :exec
INSERT INTO ssm_labels (parent_id, position, value)
VALUES (?, ?, ?);

-- name: ListParameterPolicies :many
SELECT * FROM ssm_parameter_policies WHERE parent_id = ? ORDER BY position;

-- name: DeleteParameterPolicies :exec
DELETE FROM ssm_parameter_policies WHERE parent_id = ?;

-- name: PutParameterPolicies :one
INSERT INTO ssm_parameter_policies (parent_id, position, type, version, attributes_present, due, fired)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: ListParameterPoliciesAttributes :many
SELECT * FROM ssm_parameter_policy_attributes WHERE parent_id = ? ORDER BY map_key;

-- name: PutParameterPoliciesAttributes :exec
INSERT INTO ssm_parameter_policy_attributes (parent_id, map_key, value)
VALUES (?, ?, ?);

-- name: ListVersionPolicies :many
SELECT * FROM ssm_version_policies WHERE parent_id = ? ORDER BY position;

-- name: DeleteVersionPolicies :exec
DELETE FROM ssm_version_policies WHERE parent_id = ?;

-- name: PutVersionPolicies :one
INSERT INTO ssm_version_policies (parent_id, position, type, version, attributes_present, due, fired)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: ListVersionPoliciesAttributes :many
SELECT * FROM ssm_version_policy_attributes WHERE parent_id = ? ORDER BY map_key;

-- name: PutVersionPoliciesAttributes :exec
INSERT INTO ssm_version_policy_attributes (parent_id, map_key, value)
VALUES (?, ?, ?);

-- name: NextPolicy :one
SELECT p.* FROM ssm_parameters p JOIN ssm_parameter_policies policy ON policy.parent_id = p.id
WHERE policy.due IS NOT NULL AND policy.fired = 0
ORDER BY policy.due, p.partition, p.account_id, p.region, p.name LIMIT 1;

-- name: ListSettings :many
SELECT * FROM ssm_settings WHERE partition = ? AND account_id = ? AND region = ? ORDER BY setting_id;

-- name: PutSetting :exec
INSERT INTO ssm_settings (partition, account_id, region, setting_id, value, modified_user, modified)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, setting_id) DO UPDATE SET
 value = excluded.value, modified_user = excluded.modified_user, modified = excluded.modified;

-- name: PutValidationJob :one
INSERT INTO ssm_validation_jobs (parent_id, due, caller_account_id, caller_region, caller_partition, caller_access_key_id, caller_request_id, caller_parent_event_id, caller_trace_header, caller_principal_arn, caller_principal_id, caller_user_name, caller_session_type, caller_issuer_arn, caller_issuer_id, caller_has_session_policy, caller_federated_provider, caller_source_identity, caller_mfa_present, caller_mfa_authenticated_at, caller_token_issue_time, caller_transport_known, caller_source_ip, caller_secure_transport, caller_user_agent, caller_signature_version, caller_authentication_method, caller_service_principal_name, caller_service_principal_source_arn, caller_service_principal_type, caller_invoked_by, caller_in_scope_of_issuer_type, caller_in_scope_of_credentials_issued_to, caller_session_policies_present, caller_session_policy_arns_present, caller_transitive_tag_keys_present, caller_called_via_present, caller_service_principal_aliases_present, caller_session_context_present, caller_session_tags_present)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (parent_id) DO UPDATE SET
 due = excluded.due, caller_account_id = excluded.caller_account_id, caller_region = excluded.caller_region, caller_partition = excluded.caller_partition, caller_access_key_id = excluded.caller_access_key_id, caller_request_id = excluded.caller_request_id, caller_parent_event_id = excluded.caller_parent_event_id, caller_trace_header = excluded.caller_trace_header, caller_principal_arn = excluded.caller_principal_arn, caller_principal_id = excluded.caller_principal_id, caller_user_name = excluded.caller_user_name, caller_session_type = excluded.caller_session_type, caller_issuer_arn = excluded.caller_issuer_arn, caller_issuer_id = excluded.caller_issuer_id, caller_has_session_policy = excluded.caller_has_session_policy, caller_federated_provider = excluded.caller_federated_provider, caller_source_identity = excluded.caller_source_identity, caller_mfa_present = excluded.caller_mfa_present, caller_mfa_authenticated_at = excluded.caller_mfa_authenticated_at, caller_token_issue_time = excluded.caller_token_issue_time, caller_transport_known = excluded.caller_transport_known, caller_source_ip = excluded.caller_source_ip, caller_secure_transport = excluded.caller_secure_transport, caller_user_agent = excluded.caller_user_agent, caller_signature_version = excluded.caller_signature_version, caller_authentication_method = excluded.caller_authentication_method, caller_service_principal_name = excluded.caller_service_principal_name, caller_service_principal_source_arn = excluded.caller_service_principal_source_arn, caller_service_principal_type = excluded.caller_service_principal_type, caller_invoked_by = excluded.caller_invoked_by, caller_in_scope_of_issuer_type = excluded.caller_in_scope_of_issuer_type, caller_in_scope_of_credentials_issued_to = excluded.caller_in_scope_of_credentials_issued_to, caller_session_policies_present = excluded.caller_session_policies_present, caller_session_policy_arns_present = excluded.caller_session_policy_arns_present, caller_transitive_tag_keys_present = excluded.caller_transitive_tag_keys_present, caller_called_via_present = excluded.caller_called_via_present, caller_service_principal_aliases_present = excluded.caller_service_principal_aliases_present, caller_session_context_present = excluded.caller_session_context_present, caller_session_tags_present = excluded.caller_session_tags_present
RETURNING id;

-- name: GetValidationJob :one
SELECT j.*, p.partition, p.account_id, p.region, p.name, v.version
FROM ssm_validation_jobs j JOIN ssm_versions v ON j.parent_id = v.id JOIN ssm_parameters p ON v.parent_id = p.id
WHERE p.partition = ? AND p.account_id = ? AND p.region = ? AND p.name = ? AND v.version = ?;

-- name: NextValidationJob :one
SELECT j.*, p.partition, p.account_id, p.region, p.name, v.version
FROM ssm_validation_jobs j JOIN ssm_versions v ON j.parent_id = v.id JOIN ssm_parameters p ON v.parent_id = p.id
ORDER BY j.due, p.partition, p.account_id, p.region, p.name, v.version LIMIT 1;

-- name: DeleteValidationJob :exec
DELETE FROM ssm_validation_jobs WHERE parent_id = (SELECT v.id FROM ssm_versions v JOIN ssm_parameters p ON v.parent_id = p.id WHERE p.partition = ? AND p.account_id = ? AND p.region = ? AND p.name = ? AND v.version = ?);

-- name: ListCallerSessionPolicies :many
SELECT * FROM ssm_caller_session_policies WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerSessionPolicies :exec
DELETE FROM ssm_caller_session_policies WHERE parent_id = ?;

-- name: PutCallerSessionPolicies :exec
INSERT INTO ssm_caller_session_policies (parent_id, position, value)
VALUES (?, ?, ?);

-- name: ListCallerSessionPolicyARNs :many
SELECT * FROM ssm_caller_session_policy_arns WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerSessionPolicyARNs :exec
DELETE FROM ssm_caller_session_policy_arns WHERE parent_id = ?;

-- name: PutCallerSessionPolicyARNs :exec
INSERT INTO ssm_caller_session_policy_arns (parent_id, position, value)
VALUES (?, ?, ?);

-- name: ListCallerTransitiveTagKeys :many
SELECT * FROM ssm_caller_transitive_tag_keys WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerTransitiveTagKeys :exec
DELETE FROM ssm_caller_transitive_tag_keys WHERE parent_id = ?;

-- name: PutCallerTransitiveTagKeys :exec
INSERT INTO ssm_caller_transitive_tag_keys (parent_id, position, value)
VALUES (?, ?, ?);

-- name: ListCallerCalledVia :many
SELECT * FROM ssm_caller_called_via WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerCalledVia :exec
DELETE FROM ssm_caller_called_via WHERE parent_id = ?;

-- name: PutCallerCalledVia :exec
INSERT INTO ssm_caller_called_via (parent_id, position, value)
VALUES (?, ?, ?);

-- name: ListCallerServicePrincipalAliases :many
SELECT * FROM ssm_caller_service_principal_aliases WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerServicePrincipalAliases :exec
DELETE FROM ssm_caller_service_principal_aliases WHERE parent_id = ?;

-- name: PutCallerServicePrincipalAliases :exec
INSERT INTO ssm_caller_service_principal_aliases (parent_id, position, value)
VALUES (?, ?, ?);

-- name: ListCallerSessionTags :many
SELECT * FROM ssm_caller_session_tags WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteCallerSessionTags :exec
DELETE FROM ssm_caller_session_tags WHERE parent_id = ?;

-- name: PutCallerSessionTags :exec
INSERT INTO ssm_caller_session_tags (parent_id, map_key, value)
VALUES (?, ?, ?);

-- name: ListCallerSessionContext :many
SELECT * FROM ssm_caller_session_context WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteCallerSessionContext :exec
DELETE FROM ssm_caller_session_context WHERE parent_id = ?;

-- name: PutCallerSessionContext :one
INSERT INTO ssm_caller_session_context (parent_id, map_key, value_present)
VALUES (?, ?, ?)
RETURNING id;

-- name: ListCallerSessionContextValues :many
SELECT * FROM ssm_caller_session_context_values WHERE parent_id = ? ORDER BY position;

-- name: PutCallerSessionContextValues :exec
INSERT INTO ssm_caller_session_context_values (parent_id, position, value)
VALUES (?, ?, ?);

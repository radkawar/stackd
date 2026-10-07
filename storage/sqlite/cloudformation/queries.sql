-- name: PutStack :exec
INSERT INTO cloudformation_stacks (id, partition, account, region, name, status, status_reason, description, template, role_arn, operation_id, created, updated, deleted, parameters_present, tags_present, capabilities_present, outputs_present, imports_present, disable_rollback, termination_protection, event_sequence, nested_owner, parent_id, root_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    partition = excluded.partition,
    account = excluded.account,
    region = excluded.region,
    name = excluded.name,
    status = excluded.status,
    status_reason = excluded.status_reason,
    description = excluded.description,
    template = excluded.template,
    role_arn = excluded.role_arn,
    operation_id = excluded.operation_id,
    created = excluded.created,
    updated = excluded.updated,
    deleted = excluded.deleted,
    parameters_present = excluded.parameters_present,
    tags_present = excluded.tags_present,
    capabilities_present = excluded.capabilities_present,
    outputs_present = excluded.outputs_present,
    imports_present = excluded.imports_present,
    disable_rollback = excluded.disable_rollback,
    termination_protection = excluded.termination_protection,
    event_sequence = excluded.event_sequence,
    nested_owner = excluded.nested_owner,
    parent_id = excluded.parent_id,
    root_id = excluded.root_id;

-- name: PutResource :exec
INSERT INTO cloudformation_resources (stack_id, logical_id, type, physical_id, ref, token, generation, current, status, status_reason, deletion_policy, update_replace_policy, properties, event_properties, attributes, updated)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (stack_id, logical_id, generation) DO UPDATE SET
    type = excluded.type,
    physical_id = excluded.physical_id,
    ref = excluded.ref,
    token = excluded.token,
    current = excluded.current,
    status = excluded.status,
    status_reason = excluded.status_reason,
    deletion_policy = excluded.deletion_policy,
    update_replace_policy = excluded.update_replace_policy,
    properties = excluded.properties,
    event_properties = excluded.event_properties,
    attributes = excluded.attributes,
    updated = excluded.updated;

-- name: PutEvent :exec
INSERT INTO cloudformation_events (stack_id, id, logical_id, type, physical_id, status, reason, token, sequence, timestamp, properties)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (stack_id, sequence) DO UPDATE SET
    id = excluded.id,
    logical_id = excluded.logical_id,
    type = excluded.type,
    physical_id = excluded.physical_id,
    status = excluded.status,
    reason = excluded.reason,
    token = excluded.token,
    timestamp = excluded.timestamp,
    properties = excluded.properties;

-- name: PutOperation :exec
INSERT INTO cloudformation_operations (id, stack_id, kind, phase, token, request_hash, change_set_id, reason, template, parameters_present, tags_present, capabilities_present, role_arn, caller_account_id, caller_region, caller_partition, caller_access_key_id, caller_request_id, caller_parent_event_id, caller_trace_header, caller_principal_arn, caller_principal_id, caller_user_name, caller_session_type, caller_issuer_arn, caller_issuer_id, caller_session_policies_present, caller_session_policy_arns_present, caller_has_session_policy, caller_session_context_present, caller_federated_provider, caller_session_tags_present, caller_transitive_tag_keys_present, caller_source_identity, caller_mfa_present, caller_mfa_authenticated_at, caller_token_issue_time, caller_called_via_present, caller_transport_known, caller_source_ip, caller_secure_transport, caller_user_agent, caller_signature_version, caller_authentication_method, caller_service_principal_name, caller_service_principal_source_arn, caller_service_principal_type, caller_service_principal_aliases_present, caller_invoked_by, caller_in_scope_of_issuer_type, caller_in_scope_of_credentials_issued_to, steps_present, cursor, revision, due, started, cancel, disable_rollback)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    stack_id = excluded.stack_id,
    kind = excluded.kind,
    phase = excluded.phase,
    token = excluded.token,
    request_hash = excluded.request_hash,
    change_set_id = excluded.change_set_id,
    reason = excluded.reason,
    template = excluded.template,
    parameters_present = excluded.parameters_present,
    tags_present = excluded.tags_present,
    capabilities_present = excluded.capabilities_present,
    role_arn = excluded.role_arn,
    caller_account_id = excluded.caller_account_id,
    caller_region = excluded.caller_region,
    caller_partition = excluded.caller_partition,
    caller_access_key_id = excluded.caller_access_key_id,
    caller_request_id = excluded.caller_request_id,
    caller_parent_event_id = excluded.caller_parent_event_id,
    caller_trace_header = excluded.caller_trace_header,
    caller_principal_arn = excluded.caller_principal_arn,
    caller_principal_id = excluded.caller_principal_id,
    caller_user_name = excluded.caller_user_name,
    caller_session_type = excluded.caller_session_type,
    caller_issuer_arn = excluded.caller_issuer_arn,
    caller_issuer_id = excluded.caller_issuer_id,
    caller_session_policies_present = excluded.caller_session_policies_present,
    caller_session_policy_arns_present = excluded.caller_session_policy_arns_present,
    caller_has_session_policy = excluded.caller_has_session_policy,
    caller_session_context_present = excluded.caller_session_context_present,
    caller_federated_provider = excluded.caller_federated_provider,
    caller_session_tags_present = excluded.caller_session_tags_present,
    caller_transitive_tag_keys_present = excluded.caller_transitive_tag_keys_present,
    caller_source_identity = excluded.caller_source_identity,
    caller_mfa_present = excluded.caller_mfa_present,
    caller_mfa_authenticated_at = excluded.caller_mfa_authenticated_at,
    caller_token_issue_time = excluded.caller_token_issue_time,
    caller_called_via_present = excluded.caller_called_via_present,
    caller_transport_known = excluded.caller_transport_known,
    caller_source_ip = excluded.caller_source_ip,
    caller_secure_transport = excluded.caller_secure_transport,
    caller_user_agent = excluded.caller_user_agent,
    caller_signature_version = excluded.caller_signature_version,
    caller_authentication_method = excluded.caller_authentication_method,
    caller_service_principal_name = excluded.caller_service_principal_name,
    caller_service_principal_source_arn = excluded.caller_service_principal_source_arn,
    caller_service_principal_type = excluded.caller_service_principal_type,
    caller_service_principal_aliases_present = excluded.caller_service_principal_aliases_present,
    caller_invoked_by = excluded.caller_invoked_by,
    caller_in_scope_of_issuer_type = excluded.caller_in_scope_of_issuer_type,
    caller_in_scope_of_credentials_issued_to = excluded.caller_in_scope_of_credentials_issued_to,
    steps_present = excluded.steps_present,
    cursor = excluded.cursor,
    revision = excluded.revision,
    due = excluded.due,
    started = excluded.started,
    cancel = excluded.cancel,
    disable_rollback = excluded.disable_rollback;

-- name: PutChangeSet :exec
INSERT INTO cloudformation_change_sets (id, partition, account, region, name, stack_id, stack_name, type, status, execution_status, reason, description, template, role_arn, token, request_hash, parameters_present, tags_present, capabilities_present, changes_present, created, disable_rollback)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    partition = excluded.partition,
    account = excluded.account,
    region = excluded.region,
    name = excluded.name,
    stack_id = excluded.stack_id,
    stack_name = excluded.stack_name,
    type = excluded.type,
    status = excluded.status,
    execution_status = excluded.execution_status,
    reason = excluded.reason,
    description = excluded.description,
    template = excluded.template,
    role_arn = excluded.role_arn,
    token = excluded.token,
    request_hash = excluded.request_hash,
    parameters_present = excluded.parameters_present,
    tags_present = excluded.tags_present,
    capabilities_present = excluded.capabilities_present,
    changes_present = excluded.changes_present,
    created = excluded.created,
    disable_rollback = excluded.disable_rollback;

-- name: PutExport :exec
INSERT INTO cloudformation_exports (partition, account, region, name, value, stack_id)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account, region, name) DO UPDATE SET
    value = excluded.value,
    stack_id = excluded.stack_id;

-- name: Stack :one
SELECT * FROM cloudformation_stacks WHERE id = ?;

-- name: Stacks :many
SELECT * FROM cloudformation_stacks WHERE partition = ? AND account = ? AND region = ? ORDER BY id;

-- name: Resources :many
SELECT * FROM cloudformation_resources WHERE stack_id = ? ORDER BY logical_id, generation;

-- name: Events :many
SELECT * FROM cloudformation_events WHERE stack_id = ? ORDER BY sequence DESC;

-- name: Operation :one
SELECT * FROM cloudformation_operations WHERE id = ?;

-- name: NextOperation :one
SELECT * FROM cloudformation_operations WHERE phase <> 'DONE' ORDER BY due, id LIMIT 1;

-- name: ChangeSet :one
SELECT * FROM cloudformation_change_sets WHERE id = ?;

-- name: ChangeSets :many
SELECT * FROM cloudformation_change_sets WHERE stack_id = ? ORDER BY id;

-- name: DeleteChangeSet :exec
DELETE FROM cloudformation_change_sets WHERE id = ?;

-- name: Exports :many
SELECT * FROM cloudformation_exports WHERE partition = ? AND account = ? AND region = ? ORDER BY name;

-- name: DeleteExport :exec
DELETE FROM cloudformation_exports WHERE partition = ? AND account = ? AND region = ? AND name = ?;

-- name: StackParameters :many
SELECT * FROM cloudformation_stacks_parameters WHERE parent_id = ? ORDER BY key;

-- name: DeleteStackParameters :exec
DELETE FROM cloudformation_stacks_parameters WHERE parent_id = ?;

-- name: PutStackParameter :exec
INSERT INTO cloudformation_stacks_parameters (parent_id, key, value, resolved_value)
VALUES (?, ?, ?, ?)
ON CONFLICT (parent_id, key) DO UPDATE SET
    value = excluded.value, resolved_value = excluded.resolved_value;

-- name: StackTags :many
SELECT * FROM cloudformation_stacks_tags WHERE parent_id = ? ORDER BY key;

-- name: DeleteStackTags :exec
DELETE FROM cloudformation_stacks_tags WHERE parent_id = ?;

-- name: PutStackTag :exec
INSERT INTO cloudformation_stacks_tags (parent_id, key, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, key) DO UPDATE SET
    value = excluded.value;

-- name: StackCapabilities :many
SELECT * FROM cloudformation_stacks_capabilities WHERE parent_id = ? ORDER BY position;

-- name: DeleteStackCapabilities :exec
DELETE FROM cloudformation_stacks_capabilities WHERE parent_id = ?;

-- name: PutStackCapability :exec
INSERT INTO cloudformation_stacks_capabilities (parent_id, position, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    value = excluded.value;

-- name: OperationParameters :many
SELECT * FROM cloudformation_operations_parameters WHERE parent_id = ? ORDER BY key;

-- name: DeleteOperationParameters :exec
DELETE FROM cloudformation_operations_parameters WHERE parent_id = ?;

-- name: PutOperationParameter :exec
INSERT INTO cloudformation_operations_parameters (parent_id, key, value, resolved_value)
VALUES (?, ?, ?, ?)
ON CONFLICT (parent_id, key) DO UPDATE SET
    value = excluded.value, resolved_value = excluded.resolved_value;

-- name: OperationTags :many
SELECT * FROM cloudformation_operations_tags WHERE parent_id = ? ORDER BY key;

-- name: DeleteOperationTags :exec
DELETE FROM cloudformation_operations_tags WHERE parent_id = ?;

-- name: PutOperationTag :exec
INSERT INTO cloudformation_operations_tags (parent_id, key, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, key) DO UPDATE SET
    value = excluded.value;

-- name: OperationCapabilities :many
SELECT * FROM cloudformation_operations_capabilities WHERE parent_id = ? ORDER BY position;

-- name: DeleteOperationCapabilities :exec
DELETE FROM cloudformation_operations_capabilities WHERE parent_id = ?;

-- name: PutOperationCapability :exec
INSERT INTO cloudformation_operations_capabilities (parent_id, position, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    value = excluded.value;

-- name: ChangeSetParameters :many
SELECT * FROM cloudformation_change_sets_parameters WHERE parent_id = ? ORDER BY key;

-- name: DeleteChangeSetParameters :exec
DELETE FROM cloudformation_change_sets_parameters WHERE parent_id = ?;

-- name: PutChangeSetParameter :exec
INSERT INTO cloudformation_change_sets_parameters (parent_id, key, value, resolved_value)
VALUES (?, ?, ?, ?)
ON CONFLICT (parent_id, key) DO UPDATE SET
    value = excluded.value, resolved_value = excluded.resolved_value;

-- name: ChangeSetTags :many
SELECT * FROM cloudformation_change_sets_tags WHERE parent_id = ? ORDER BY key;

-- name: DeleteChangeSetTags :exec
DELETE FROM cloudformation_change_sets_tags WHERE parent_id = ?;

-- name: PutChangeSetTag :exec
INSERT INTO cloudformation_change_sets_tags (parent_id, key, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, key) DO UPDATE SET
    value = excluded.value;

-- name: ChangeSetCapabilities :many
SELECT * FROM cloudformation_change_sets_capabilities WHERE parent_id = ? ORDER BY position;

-- name: DeleteChangeSetCapabilities :exec
DELETE FROM cloudformation_change_sets_capabilities WHERE parent_id = ?;

-- name: PutChangeSetCapability :exec
INSERT INTO cloudformation_change_sets_capabilities (parent_id, position, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    value = excluded.value;

-- name: StackOutputs :many
SELECT * FROM cloudformation_stack_outputs WHERE parent_id = ? ORDER BY key;

-- name: DeleteStackOutputs :exec
DELETE FROM cloudformation_stack_outputs WHERE parent_id = ?;

-- name: PutStackOutput :exec
INSERT INTO cloudformation_stack_outputs (parent_id, key, value, description, export_name)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (parent_id, key) DO UPDATE SET
    value = excluded.value,
    description = excluded.description,
    export_name = excluded.export_name;

-- name: StackImports :many
SELECT * FROM cloudformation_stack_imports WHERE parent_id = ? ORDER BY position;

-- name: DeleteStackImports :exec
DELETE FROM cloudformation_stack_imports WHERE parent_id = ?;

-- name: PutStackImport :exec
INSERT INTO cloudformation_stack_imports (parent_id, position, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    value = excluded.value;

-- name: CallerPolicies :many
SELECT * FROM cloudformation_caller_policies WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerPolicies :exec
DELETE FROM cloudformation_caller_policies WHERE parent_id = ?;

-- name: PutCallerPolicy :exec
INSERT INTO cloudformation_caller_policies (parent_id, position, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    value = excluded.value;

-- name: CallerPolicyARNs :many
SELECT * FROM cloudformation_caller_policy_arns WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerPolicyARNs :exec
DELETE FROM cloudformation_caller_policy_arns WHERE parent_id = ?;

-- name: PutCallerPolicyARN :exec
INSERT INTO cloudformation_caller_policy_arns (parent_id, position, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    value = excluded.value;

-- name: CallerTransitiveTagKeys :many
SELECT * FROM cloudformation_caller_transitive_tag_keys WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerTransitiveTagKeys :exec
DELETE FROM cloudformation_caller_transitive_tag_keys WHERE parent_id = ?;

-- name: PutCallerTransitiveTagKey :exec
INSERT INTO cloudformation_caller_transitive_tag_keys (parent_id, position, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    value = excluded.value;

-- name: CallerCalledVias :many
SELECT * FROM cloudformation_caller_called_vias WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerCalledVias :exec
DELETE FROM cloudformation_caller_called_vias WHERE parent_id = ?;

-- name: PutCallerCalledVia :exec
INSERT INTO cloudformation_caller_called_vias (parent_id, position, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    value = excluded.value;

-- name: CallerServiceAliases :many
SELECT * FROM cloudformation_caller_service_aliases WHERE parent_id = ? ORDER BY position;

-- name: DeleteCallerServiceAliases :exec
DELETE FROM cloudformation_caller_service_aliases WHERE parent_id = ?;

-- name: PutCallerServiceAlias :exec
INSERT INTO cloudformation_caller_service_aliases (parent_id, position, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    value = excluded.value;

-- name: CallerTags :many
SELECT * FROM cloudformation_caller_tags WHERE parent_id = ? ORDER BY key;

-- name: DeleteCallerTags :exec
DELETE FROM cloudformation_caller_tags WHERE parent_id = ?;

-- name: PutCallerTag :exec
INSERT INTO cloudformation_caller_tags (parent_id, key, value)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, key) DO UPDATE SET
    value = excluded.value;

-- name: CallerContextKeys :many
SELECT * FROM cloudformation_caller_context_keys WHERE parent_id = ? ORDER BY key;

-- name: DeleteCallerContextKeys :exec
DELETE FROM cloudformation_caller_context_keys WHERE parent_id = ?;

-- name: PutCallerContextKey :exec
INSERT INTO cloudformation_caller_context_keys (parent_id, key, values_present)
VALUES (?, ?, ?)
ON CONFLICT (parent_id, key) DO UPDATE SET
    values_present = excluded.values_present;

-- name: CallerContextValues :many
SELECT * FROM cloudformation_caller_context_values WHERE parent_id = ? ORDER BY key, position;

-- name: DeleteCallerContextValues :exec
DELETE FROM cloudformation_caller_context_values WHERE parent_id = ?;

-- name: PutCallerContextValue :exec
INSERT INTO cloudformation_caller_context_values (parent_id, key, position, value)
VALUES (?, ?, ?, ?)
ON CONFLICT (parent_id, key, position) DO UPDATE SET
    value = excluded.value;

-- name: Changes :many
SELECT * FROM cloudformation_changes WHERE parent_id = ? ORDER BY position;

-- name: DeleteChanges :exec
DELETE FROM cloudformation_changes WHERE parent_id = ?;

-- name: PutChange :exec
INSERT INTO cloudformation_changes (parent_id, position, logical_id, type, action, replacement, physical_id, before_context, after_context)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (parent_id, position) DO UPDATE SET
    logical_id = excluded.logical_id,
    type = excluded.type,
    action = excluded.action,
    replacement = excluded.replacement,
    physical_id = excluded.physical_id,
    before_context = excluded.before_context,
    after_context = excluded.after_context;

-- name: Steps :many
SELECT * FROM cloudformation_steps WHERE parent_id = ? ORDER BY ordinal;

-- name: DeleteSteps :exec
DELETE FROM cloudformation_steps WHERE parent_id = ?;

-- name: PutStep :exec
INSERT INTO cloudformation_steps (parent_id, ordinal, position, logical_id, action, state, error, delete_failures, before_stack_id, before_logical_id, before_type, before_physical_id, before_ref, before_token, before_generation, before_current, before_status, before_status_reason, before_deletion_policy, before_update_replace_policy, before_properties, before_event_properties, before_attributes, before_updated, after_stack_id, after_logical_id, after_type, after_physical_id, after_ref, after_token, after_generation, after_current, after_status, after_status_reason, after_deletion_policy, after_update_replace_policy, after_properties, after_event_properties, after_attributes, after_updated)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (parent_id, ordinal) DO UPDATE SET
    position = excluded.position,
    logical_id = excluded.logical_id,
    action = excluded.action,
    state = excluded.state,
    error = excluded.error,
    delete_failures = excluded.delete_failures,
    before_stack_id = excluded.before_stack_id,
    before_logical_id = excluded.before_logical_id,
    before_type = excluded.before_type,
    before_physical_id = excluded.before_physical_id,
    before_ref = excluded.before_ref,
    before_token = excluded.before_token,
    before_generation = excluded.before_generation,
    before_current = excluded.before_current,
    before_status = excluded.before_status,
    before_status_reason = excluded.before_status_reason,
    before_deletion_policy = excluded.before_deletion_policy,
    before_update_replace_policy = excluded.before_update_replace_policy,
    before_properties = excluded.before_properties,
    before_event_properties = excluded.before_event_properties,
    before_attributes = excluded.before_attributes,
    before_updated = excluded.before_updated,
    after_stack_id = excluded.after_stack_id,
    after_logical_id = excluded.after_logical_id,
    after_type = excluded.after_type,
    after_physical_id = excluded.after_physical_id,
    after_ref = excluded.after_ref,
    after_token = excluded.after_token,
    after_generation = excluded.after_generation,
    after_current = excluded.after_current,
    after_status = excluded.after_status,
    after_status_reason = excluded.after_status_reason,
    after_deletion_policy = excluded.after_deletion_policy,
    after_update_replace_policy = excluded.after_update_replace_policy,
    after_properties = excluded.after_properties,
    after_event_properties = excluded.after_event_properties,
    after_attributes = excluded.after_attributes,
    after_updated = excluded.after_updated;


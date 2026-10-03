-- Typed CloudFormation lifecycle state; JSON columns contain only customer property
-- and attribute documents. Action before/after images and caller authority are durable.

CREATE TABLE cloudformation_stacks (
    id TEXT NOT NULL,
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    status_reason TEXT NOT NULL,
    description TEXT NOT NULL,
    template TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    created DATETIME NOT NULL,
    updated DATETIME NOT NULL,
    deleted DATETIME,
    parameters_present BOOLEAN NOT NULL,
    tags_present BOOLEAN NOT NULL,
    capabilities_present BOOLEAN NOT NULL,
    outputs_present BOOLEAN NOT NULL,
    imports_present BOOLEAN NOT NULL,
    disable_rollback BOOLEAN NOT NULL,
    termination_protection BOOLEAN NOT NULL,
    event_sequence INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE cloudformation_resources (
    stack_id TEXT NOT NULL,
    logical_id TEXT NOT NULL,
    type TEXT NOT NULL,
    physical_id TEXT NOT NULL,
    ref TEXT NOT NULL,
    token TEXT NOT NULL,
    generation INTEGER NOT NULL,
    current BOOLEAN NOT NULL,
    status TEXT NOT NULL,
    status_reason TEXT NOT NULL,
    deletion_policy TEXT NOT NULL,
    update_replace_policy TEXT NOT NULL,
    properties TEXT NOT NULL,
    event_properties TEXT NOT NULL,
    attributes TEXT NOT NULL,
    updated DATETIME NOT NULL,
    PRIMARY KEY (stack_id, logical_id, generation)
);

CREATE TABLE cloudformation_events (
    stack_id TEXT NOT NULL,
    id TEXT NOT NULL,
    logical_id TEXT NOT NULL,
    type TEXT NOT NULL,
    physical_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    token TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    timestamp DATETIME NOT NULL,
    properties TEXT NOT NULL,
    PRIMARY KEY (stack_id, sequence)
);

CREATE TABLE cloudformation_operations (
    id TEXT NOT NULL,
    stack_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    phase TEXT NOT NULL,
    token TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    change_set_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    template TEXT NOT NULL,
    parameters_present BOOLEAN NOT NULL,
    tags_present BOOLEAN NOT NULL,
    capabilities_present BOOLEAN NOT NULL,
    role_arn TEXT NOT NULL,
    caller_account_id TEXT NOT NULL,
    caller_region TEXT NOT NULL,
    caller_partition TEXT NOT NULL,
    caller_access_key_id TEXT NOT NULL,
    caller_request_id TEXT NOT NULL,
    caller_parent_event_id TEXT NOT NULL,
    caller_trace_header TEXT NOT NULL,
    caller_principal_arn TEXT NOT NULL,
    caller_principal_id TEXT NOT NULL,
    caller_user_name TEXT NOT NULL,
    caller_session_type TEXT NOT NULL,
    caller_issuer_arn TEXT NOT NULL,
    caller_issuer_id TEXT NOT NULL,
    caller_session_policies_present BOOLEAN NOT NULL,
    caller_session_policy_arns_present BOOLEAN NOT NULL,
    caller_has_session_policy BOOLEAN NOT NULL,
    caller_session_context_present BOOLEAN NOT NULL,
    caller_federated_provider TEXT NOT NULL,
    caller_session_tags_present BOOLEAN NOT NULL,
    caller_transitive_tag_keys_present BOOLEAN NOT NULL,
    caller_source_identity TEXT NOT NULL,
    caller_mfa_present BOOLEAN NOT NULL,
    caller_mfa_authenticated_at DATETIME NOT NULL,
    caller_token_issue_time DATETIME NOT NULL,
    caller_called_via_present BOOLEAN NOT NULL,
    caller_transport_known BOOLEAN NOT NULL,
    caller_source_ip TEXT NOT NULL,
    caller_secure_transport BOOLEAN NOT NULL,
    caller_user_agent TEXT NOT NULL,
    caller_signature_version TEXT NOT NULL,
    caller_authentication_method TEXT NOT NULL,
    caller_service_principal_name TEXT NOT NULL,
    caller_service_principal_source_arn TEXT NOT NULL,
    caller_service_principal_type TEXT NOT NULL,
    caller_service_principal_aliases_present BOOLEAN NOT NULL,
    caller_invoked_by TEXT NOT NULL,
    caller_in_scope_of_issuer_type TEXT NOT NULL,
    caller_in_scope_of_credentials_issued_to TEXT NOT NULL,
    steps_present BOOLEAN NOT NULL,
    cursor INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    due DATETIME NOT NULL,
    started DATETIME NOT NULL,
    cancel BOOLEAN NOT NULL,
    disable_rollback BOOLEAN NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE cloudformation_change_sets (
    id TEXT NOT NULL,
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    stack_id TEXT NOT NULL,
    stack_name TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    execution_status TEXT NOT NULL,
    reason TEXT NOT NULL,
    description TEXT NOT NULL,
    template TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    token TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    parameters_present BOOLEAN NOT NULL,
    tags_present BOOLEAN NOT NULL,
    capabilities_present BOOLEAN NOT NULL,
    changes_present BOOLEAN NOT NULL,
    created DATETIME NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE cloudformation_exports (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    stack_id TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, name)
);

CREATE INDEX cloudformation_stacks_scope ON cloudformation_stacks(partition, account, region, id);
CREATE INDEX cloudformation_change_sets_stack ON cloudformation_change_sets(stack_id, id);
CREATE INDEX cloudformation_operations_due ON cloudformation_operations(due, id) WHERE phase <> 'DONE';

CREATE TABLE cloudformation_stacks_parameters (
    parent_id TEXT NOT NULL REFERENCES cloudformation_stacks(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, key)
);

CREATE TABLE cloudformation_stacks_tags (
    parent_id TEXT NOT NULL REFERENCES cloudformation_stacks(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, key)
);

CREATE TABLE cloudformation_stacks_capabilities (
    parent_id TEXT NOT NULL REFERENCES cloudformation_stacks(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_operations_parameters (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, key)
);

CREATE TABLE cloudformation_operations_tags (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, key)
);

CREATE TABLE cloudformation_operations_capabilities (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_change_sets_parameters (
    parent_id TEXT NOT NULL REFERENCES cloudformation_change_sets(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, key)
);

CREATE TABLE cloudformation_change_sets_tags (
    parent_id TEXT NOT NULL REFERENCES cloudformation_change_sets(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, key)
);

CREATE TABLE cloudformation_change_sets_capabilities (
    parent_id TEXT NOT NULL REFERENCES cloudformation_change_sets(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_stack_outputs (
    parent_id TEXT NOT NULL REFERENCES cloudformation_stacks(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    description TEXT NOT NULL,
    export_name TEXT NOT NULL,
    PRIMARY KEY (parent_id, key)
);

CREATE TABLE cloudformation_stack_imports (
    parent_id TEXT NOT NULL REFERENCES cloudformation_stacks(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_caller_policies (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_caller_policy_arns (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_caller_transitive_tag_keys (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_caller_called_vias (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_caller_service_aliases (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_caller_tags (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, key)
);

CREATE TABLE cloudformation_caller_context_keys (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    values_present BOOLEAN NOT NULL,
    PRIMARY KEY (parent_id, key)
);

CREATE TABLE cloudformation_caller_context_values (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, key, position)
);

CREATE TABLE cloudformation_changes (
    parent_id TEXT NOT NULL REFERENCES cloudformation_change_sets(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    logical_id TEXT NOT NULL,
    type TEXT NOT NULL,
    action TEXT NOT NULL,
    replacement TEXT NOT NULL,
    physical_id TEXT NOT NULL,
    before_context TEXT NOT NULL,
    after_context TEXT NOT NULL,
    PRIMARY KEY (parent_id, position)
);

CREATE TABLE cloudformation_steps (
    parent_id TEXT NOT NULL REFERENCES cloudformation_operations(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    position INTEGER NOT NULL,
    logical_id TEXT NOT NULL,
    action TEXT NOT NULL,
    state TEXT NOT NULL,
    error TEXT NOT NULL,
    delete_failures INTEGER NOT NULL DEFAULT 0,
    before_stack_id TEXT NOT NULL,
    before_logical_id TEXT NOT NULL,
    before_type TEXT NOT NULL,
    before_physical_id TEXT NOT NULL,
    before_ref TEXT NOT NULL,
    before_token TEXT NOT NULL,
    before_generation INTEGER NOT NULL,
    before_current BOOLEAN NOT NULL,
    before_status TEXT NOT NULL,
    before_status_reason TEXT NOT NULL,
    before_deletion_policy TEXT NOT NULL,
    before_update_replace_policy TEXT NOT NULL,
    before_properties TEXT NOT NULL,
    before_event_properties TEXT NOT NULL,
    before_attributes TEXT NOT NULL,
    before_updated DATETIME NOT NULL,
    after_stack_id TEXT NOT NULL,
    after_logical_id TEXT NOT NULL,
    after_type TEXT NOT NULL,
    after_physical_id TEXT NOT NULL,
    after_ref TEXT NOT NULL,
    after_token TEXT NOT NULL,
    after_generation INTEGER NOT NULL,
    after_current BOOLEAN NOT NULL,
    after_status TEXT NOT NULL,
    after_status_reason TEXT NOT NULL,
    after_deletion_policy TEXT NOT NULL,
    after_update_replace_policy TEXT NOT NULL,
    after_properties TEXT NOT NULL,
    after_event_properties TEXT NOT NULL,
    after_attributes TEXT NOT NULL,
    after_updated DATETIME NOT NULL,
    PRIMARY KEY (parent_id, ordinal)
);


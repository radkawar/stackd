ALTER TABLE cloudformation_stacks ADD COLUMN nested_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_stacks ADD COLUMN parent_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_stacks ADD COLUMN root_id TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX cloudformation_stack_nested_owner ON cloudformation_stacks (partition, account, region, nested_owner) WHERE nested_owner <> '';

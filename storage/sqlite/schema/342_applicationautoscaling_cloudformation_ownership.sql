-- Private native-row CloudFormation incarnation claims are not public tags.
ALTER TABLE aas_targets ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE aas_policies ADD COLUMN ownership TEXT NOT NULL DEFAULT '';

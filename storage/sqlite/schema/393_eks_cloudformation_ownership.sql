-- Trusted EKS deployment receipts, never reconstructed from public tags.
-- Native incarnation IDs fence delete/recreate even when names and clocks repeat.
-- Retained receipts prevent one deployment incarnation creating a second resource.
CREATE TABLE eks_cloudformation_creations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_type TEXT NOT NULL CHECK(resource_type IN ('AWS::EKS::Cluster', 'AWS::EKS::Nodegroup', 'AWS::EKS::Addon', 'AWS::EKS::FargateProfile', 'AWS::EKS::AccessEntry', 'AWS::EKS::PodIdentityAssociation')),
 owner TEXT NOT NULL CHECK(owner <> ''),
 cluster_name TEXT NOT NULL,
 native_name TEXT NOT NULL,
 native_id TEXT NOT NULL CHECK(native_id <> ''),
 physical_id TEXT NOT NULL,
 arn TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_type, owner),
 UNIQUE (partition, account_id, region, resource_type, native_id)
);

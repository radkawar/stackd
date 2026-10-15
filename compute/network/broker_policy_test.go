package network

import "testing"

func TestBrokerPolicyIdentityAdmission(t *testing.T) {
	for _, name := range []string{"stackd_msk_0123456789abcdef", "stackd_ec2_0123", "stackd_ecs_abcd", "stackd_elbv2_1234", "stackd_lambda_5678", "stackd_elasticache_0123456789abcdef"} {
		if !policyTableName.MatchString(name) {
			t.Fatalf("owned policy identity rejected: %s", name)
		}
	}
	for _, name := range []string{"stackd_msk_", "stackd_msk_NOTHEX", "stackd_msk_abc;drop", "stackd_msk_abc/def", "other_msk_abcd", "stackd_unknown_abcd", "stackd_elasticache_", "stackd_elasticache_NOTHEX", "stackd_elasticache_abc;drop", "stackd_elasticache_abc/def", "stackd_elasticache_abcd\n"} {
		if policyTableName.MatchString(name) {
			t.Fatalf("unowned policy identity admitted: %s", name)
		}
	}
}

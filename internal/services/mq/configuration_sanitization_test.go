package mq

import "testing"

func TestSanitizationPreservesNativeObjectBoundary(t *testing.T) {
	for _, test := range []struct{ name, xml string }{
		{"duplicate-removed-attribute", `<broker xmlns="http://activemq.apache.org/schema/core" unknown="one" unknown="two"/>`},
		{"directive", `<!DOCTYPE broker [<!ENTITY injected "true">]><broker xmlns="http://activemq.apache.org/schema/core" advisorySupport="&injected;"/>`},
		{"processing-instruction-in-removed-subtree", `<broker xmlns="http://activemq.apache.org/schema/core"><unknown><?execute external?></unknown></broker>`},
		{"foreign-root", `<broker xmlns="urn:not-activemq"/>`},
		{"permitted-unimplemented-child", `<broker xmlns="http://activemq.apache.org/schema/core"><destinationInterceptors><mirroredQueue prefix="mirror."/></destinationInterceptors></broker>`},
		{"removed-required-value", `<broker xmlns="http://activemq.apache.org/schema/core"><destinations><queue physicalName="${queue}"/></destinations></broker>`},
		{"second-root", `<broker xmlns="http://activemq.apache.org/schema/core"/><broker xmlns="http://activemq.apache.org/schema/core"/>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, warnings, err := sanitizeConfiguration("ACTIVEMQ", test.xml)
			if err == nil || data != "" || len(warnings) != 0 {
				t.Fatalf("unsafe or unapplied configuration escaped sanitization: data=%q warnings=%v err=%v", data, warnings, err)
			}
		})
	}
}

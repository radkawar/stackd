package mq

import "testing"

func TestActiveMQConfigurationBoundary(t *testing.T) {
	broker := func(content string) string {
		return `<broker xmlns="http://activemq.apache.org/schema/core">` + content + `</broker>`
	}
	cases := []struct {
		name, data string
		valid      bool
	}{
		{"group authorization", broker(`<plugins><authorizationPlugin><map><authorizationMap><authorizationEntries><authorizationEntry queue=">" read="writers,readers" write="writers" admin="writers"/><authorizationEntry topic=">" read="writers,readers" write="writers" admin="writers"/></authorizationEntries></authorizationMap></map></authorizationPlugin></plugins>`), true},
		{"destination policy", broker(`<destinationPolicy><policyMap><policyEntries><policyEntry queue=">" producerFlowControl="true" memoryLimit="128 mb" prioritizedMessages="true" expireMessagesPeriod="0"/></policyEntries></policyMap></destinationPolicy><destinations><queue physicalName="orders"/><topic physicalName="events"/></destinations>`), true},
		{"spring bean", broker(`<bean xmlns="http://www.springframework.org/schema/beans" class="java.lang.ProcessBuilder"/>`), false},
		{"owned authentication", broker(`<plugins><simpleAuthenticationPlugin anonymousAccessAllowed="true"/></plugins>`), false},
		{"owned TLS", broker(`<sslContext><sslContext keyStore="file:/tmp/foreign"/></sslContext>`), false},
		{"owned storage", broker(`<persistenceAdapter><kahaDB directory="/tmp/foreign"/></persistenceAdapter>`), false},
		{"owned listener", broker(`<transportConnectors><transportConnector uri="tcp://0.0.0.0:61616"/></transportConnectors>`), false},
		{"owned data directory", `<broker xmlns="http://activemq.apache.org/schema/core" dataDirectory="/tmp/foreign"/>`, false},
		{"destructive startup", `<broker xmlns="http://activemq.apache.org/schema/core" deleteAllMessagesOnStartup="true"/>`, false},
		{"external entity", `<!DOCTYPE broker [<!ENTITY external SYSTEM "file:///etc/passwd">]>` + broker(`&external;`), false},
		{"literal expression", broker(`<destinations><queue physicalName="${user.home}"/></destinations>`), false},
		{"encoded property", broker(`<destinations><queue physicalName="&#36;{user.home}"/></destinations>`), false},
		{"encoded spring expression", broker(`<destinations><queue physicalName="&#35;{T(java.lang.Runtime).getRuntime()}"/></destinations>`), false},
		{"wrong hierarchy", broker(`<policyEntry queue=">" producerFlowControl="true"/>`), false},
		{"empty authorization map", broker(`<plugins><authorizationPlugin><map/></authorizationPlugin></plugins>`), false},
		{"foreign namespace", `<broker xmlns="urn:foreign"/>`, false},
		{"foreign schema", `<broker xmlns="http://activemq.apache.org/schema/core" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:foreign https://example.invalid/beans.xsd"/>`, false},
		{"multiple roots", DefaultConfiguration("ACTIVEMQ") + DefaultConfiguration("ACTIVEMQ"), false},
		{"duplicate attributes", `<broker xmlns="http://activemq.apache.org/schema/core" advisorySupport="true" advisorySupport="false"/>`, false},
		{"ambiguous destination", broker(`<plugins><authorizationPlugin><map><authorizationMap><authorizationEntries><authorizationEntry queue=">" topic=">" read="users"/></authorizationEntries></authorizationMap></map></authorizationPlugin></plugins>`), false},
		{"oversized memory policy", broker(`<destinationPolicy><policyMap><policyEntries><policyEntry queue=">" memoryLimit="129 mb"/></policyEntries></policyMap></destinationPolicy>`), false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateConfiguration("ACTIVEMQ", test.data)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}

func TestActiveMQCompositeDestinationBoundary(t *testing.T) {
	for _, test := range []struct {
		name, composite string
	}{
		{"object reference", `<compositeQueue ref="foreign"/>`},
		{"class injection", `<compositeQueue name="source" class="java.lang.ProcessBuilder"><forwardTo><queue physicalName="sink"/></forwardTo></compositeQueue>`},
		{"missing name", `<compositeQueue><forwardTo><queue physicalName="sink"/></forwardTo></compositeQueue>`},
		{"missing targets", `<compositeQueue name="source"><forwardTo/></compositeQueue>`},
		{"foreign destination", `<compositeQueue name="source"><forwardTo><queue physicalName="tcp://foreign:61616"/></forwardTo></compositeQueue>`},
		{"expression", `<compositeQueue name="&#36;{user.home}"><forwardTo><queue physicalName="sink"/></forwardTo></compositeQueue>`},
		{"ambiguous filtered target", `<compositeQueue name="source"><forwardTo><filteredDestination queue="one" topic="two" selector="amount &gt; 10"/></forwardTo></compositeQueue>`},
		{"missing filtered target", `<compositeQueue name="source"><forwardTo><filteredDestination selector="amount &gt; 10"/></forwardTo></compositeQueue>`},
		{"filtered object reference", `<compositeQueue name="source"><forwardTo><filteredDestination queue="one" ref="foreign"/></forwardTo></compositeQueue>`},
		{"virtual topic class", `<virtualTopic name="Events.&gt;" class="java.lang.ProcessBuilder"/>`},
		{"virtual topic reference", `<virtualTopic ref="foreign"/>`},
		{"virtual topic transport prefix", `<virtualTopic name="Events.&gt;" prefix="tcp://foreign:61616/"/>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := `<broker xmlns="http://activemq.apache.org/schema/core"><destinationInterceptors><virtualDestinationInterceptor><virtualDestinations>` + test.composite + `</virtualDestinations></virtualDestinationInterceptor></destinationInterceptors></broker>`
			if err := ValidateConfiguration("ACTIVEMQ", data); err == nil {
				t.Fatal("unsafe or incomplete composite destination accepted")
			}
		})
	}
}

func TestActiveMQDeadLetterStrategyBoundary(t *testing.T) {
	for _, test := range []struct {
		name, strategy string
		valid          bool
	}{
		{"default shared queue", `<sharedDeadLetterStrategy processExpired="false"/>`, true},
		{"shared queue", `<sharedDeadLetterStrategy processNonPersistent="true"><deadLetterQueue><queue physicalName="failed.orders" DLQ="true"/></deadLetterQueue></sharedDeadLetterStrategy>`, true},
		{"shared topic", `<sharedDeadLetterStrategy><deadLetterQueue><topic physicalName="failed.events"/></deadLetterQueue></sharedDeadLetterStrategy>`, true},
		{"individual destinations", `<individualDeadLetterStrategy queuePrefix="failed." queueSuffix=".end" topicPrefix="" topicSuffix=".failed" useQueueForQueueMessages="true" useQueueForTopicMessages="false" destinationPerDurableSubscriber="true" expiration="0" maxAuditDepth="1024" maxProducersToAudit="32" enableAudit="true"/>`, true},
		{"discard", `<discarding/>`, true},
		{"ambiguous strategy", `<sharedDeadLetterStrategy/><individualDeadLetterStrategy/>`, false},
		{"repeated strategy", `<discarding/><discarding/>`, false},
		{"empty strategy", ``, false},
		{"empty destination", `<sharedDeadLetterStrategy><deadLetterQueue/></sharedDeadLetterStrategy>`, false},
		{"ambiguous destination", `<sharedDeadLetterStrategy><deadLetterQueue><queue physicalName="failed"/><topic physicalName="failed"/></deadLetterQueue></sharedDeadLetterStrategy>`, false},
		{"repeated destination", `<sharedDeadLetterStrategy><deadLetterQueue><queue physicalName="a"/><queue physicalName="b"/></deadLetterQueue></sharedDeadLetterStrategy>`, false},
		{"missing physical name", `<sharedDeadLetterStrategy><deadLetterQueue><queue/></deadLetterQueue></sharedDeadLetterStrategy>`, false},
		{"destination URI options", `<sharedDeadLetterStrategy><deadLetterQueue><queue physicalName="failed?consumer.exclusive=true"/></deadLetterQueue></sharedDeadLetterStrategy>`, false},
		{"wildcard prefix", `<individualDeadLetterStrategy queuePrefix=">"/>`, false},
		{"property expression", `<individualDeadLetterStrategy queuePrefix="&#36;{user.home}"/>`, false},
		{"bean expression", `<individualDeadLetterStrategy queuePrefix="&#35;{T(java.lang.Runtime).getRuntime()}"/>`, false},
		{"bean reference", `<sharedDeadLetterStrategy ref="foreign"/>`, false},
		{"object class", `<sharedDeadLetterStrategy class="java.lang.ProcessBuilder"/>`, false},
		{"negative expiration", `<sharedDeadLetterStrategy expiration="-1"/>`, false},
		{"expiration overflow", `<sharedDeadLetterStrategy expiration="9223372036854775808"/>`, false},
		{"invalid boolean", `<sharedDeadLetterStrategy processExpired="yes"/>`, false},
		{"zero audit capacity", `<sharedDeadLetterStrategy maxProducersToAudit="0"/>`, false},
		{"wrong owner attribute", `<sharedDeadLetterStrategy queuePrefix="failed."/>`, false},
		{"wrong owner destination", `<individualDeadLetterStrategy><deadLetterQueue><queue physicalName="failed"/></deadLetterQueue></individualDeadLetterStrategy>`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := `<broker xmlns="http://activemq.apache.org/schema/core"><destinationPolicy><policyMap><policyEntries><policyEntry queue="orders"><deadLetterStrategy>` + test.strategy + `</deadLetterStrategy></policyEntry></policyEntries></policyMap></destinationPolicy></broker>`
			err := ValidateConfiguration("ACTIVEMQ", data)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}

func TestRabbitMQConfigurationBoundary(t *testing.T) {
	cases := []struct {
		name, data string
		valid      bool
	}{
		{"minimum heartbeat", "heartbeat = 60", true},
		{"maximum heartbeat", "heartbeat = 3600", true},
		{"short heartbeat", "heartbeat = 59", false},
		{"long heartbeat", "heartbeat = 3601", false},
		{"minimum finite timeout", "consumer_timeout = 1", true},
		{"maximum timeout", "consumer_timeout = 2147483647", true},
		{"timeout overflow", "consumer_timeout = 2147483648", false},
		{"infinite timeout", "consumer_timeout = 0", true},
		{"negative timeout", "consumer_timeout = -1", false},
		{"numeric suffix", "heartbeat = 60seconds", false},
		{"relaxed quorum checks", "quorum_queue.property_equivalence.relaxed_checks_on_redeclaration = true", true},
		{"strict quorum checks", "quorum_queue.property_equivalence.relaxed_checks_on_redeclaration = false", true},
		{"invalid boolean", "quorum_queue.property_equivalence.relaxed_checks_on_redeclaration = yes", false},
		{"restrict operator policies", "management.restrictions.operator_policy_changes.disabled = true", true},
		{"permit operator policies", "management.restrictions.operator_policy_changes.disabled = false", true},
		{"invalid operator restriction", "management.restrictions.operator_policy_changes.disabled = 0", false},
		{"secure headers", "secure.management.http.headers.enabled = true", true},
		{"disable secure headers", "secure.management.http.headers.enabled = false", true},
		{"invalid secure header toggle", "secure.management.http.headers.enabled = TRUE", false},
		{"conflicting secure header toggle", "secure.management.http.headers.enabled = true\nsecure.management.http.headers.enabled = false", false},
		{"owned native header override", "management.headers.x-frame-options = SAMEORIGIN", false},
		{"comments", "# client negotiation\nheartbeat = 120 # seconds\nconsumer_timeout = 120000\n", true},
		{"duplicate key", "heartbeat = 120\nheartbeat = 60", false},
		{"owned TLS", "ssl_options.verify = verify_none", false},
		{"owned authentication", "auth_backends.1 = rabbit_auth_backend_ldap", false},
		{"owned bind", "listeners.tcp.default = 5672", false},
		{"owned storage", "mnesia.dir = /tmp/foreign", false},
		{"owned definitions", "definitions.local.path = /tmp/foreign", false},
		{"owned management", "management.ssl.keyfile = /tmp/foreign", false},
		{"substitution", "heartbeat = ${HEARTBEAT}", false},
		{"empty", "", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateConfiguration("RABBITMQ", test.data)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}

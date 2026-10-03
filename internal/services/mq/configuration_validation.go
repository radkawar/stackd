package mq

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const activeMQNamespace = "http://activemq.apache.org/schema/core"

// DefaultConfiguration returns a configuration whose settings are applied by the
// native engine. Unknown engines have no default.
func DefaultConfiguration(engine string) string {
	switch engine {
	case "ACTIVEMQ":
		return `<broker xmlns="http://activemq.apache.org/schema/core"/>`
	case "RABBITMQ":
		return "consumer_timeout = 1800000\nheartbeat = 60\n"
	default:
		return ""
	}
}

// ValidateConfiguration admits only implemented, native-effect configuration.
// This rejects unsupported AWS-permitted settings rather than silently losing
// them. API sanitization removes schema-disallowed input before this boundary.
// Storage, authentication, TLS and listeners are runtime-owned. AWS references:
// https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/permitted-attributes.html
// https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/permitted-collections.html
// https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configurable-values.html
// TODO: Comeback: implement the broader AWS-permitted XML/Cuttlefish settings;
// strict native-capability validation is not full Amazon MQ conformance.
func ValidateConfiguration(engine, data string) error {
	if strings.TrimSpace(data) == "" || len(data) > 1<<20 {
		return errors.New("configuration must contain between 1 and 1048576 bytes")
	}
	if strings.Contains(data, "${") || strings.Contains(data, "#{") {
		return errors.New("configuration expressions and substitutions are unsupported")
	}
	switch engine {
	case "ACTIVEMQ":
		return validateActiveMQConfiguration(data)
	case "RABBITMQ":
		return validateRabbitMQConfiguration(data)
	default:
		return errors.New("unsupported configuration engine")
	}
}

func validateRabbitMQConfiguration(data string) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || seen[key] {
			return errors.New("invalid or repeated RabbitMQ configuration key")
		}
		seen[key] = true
		switch key {
		case "heartbeat":
			if !configurationInteger(value, 60, 3600) {
				return errors.New("heartbeat must be an integer between 60 and 3600")
			}
		case "consumer_timeout":
			if !configurationInteger(value, 0, 2147483647) {
				return errors.New("consumer_timeout must be between 0 and 2147483647")
			}
		case "quorum_queue.property_equivalence.relaxed_checks_on_redeclaration",
			"management.restrictions.operator_policy_changes.disabled",
			"secure.management.http.headers.enabled":
			if value != "true" && value != "false" {
				return fmt.Errorf("%s must be true or false", key)
			}
		default:
			return fmt.Errorf("unsupported RabbitMQ configuration key %q", key)
		}
	}
	return nil
}

func configurationInteger(value string, minimum, maximum int64) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return err == nil && n >= minimum && n <= maximum
}

// The path allowlist is also the object-instantiation boundary: no Spring beans,
// references, arbitrary plugin classes, file paths, or transport URLs can enter.
var activeMQChildren = map[string]string{
	"broker":            "destinationPolicy destinations plugins destinationInterceptors",
	"destinationPolicy": "policyMap", "policyMap": "policyEntries defaultEntry",
	"policyEntries": "policyEntry", "defaultEntry": "policyEntry",
	"policyEntry":              "deadLetterStrategy",
	"deadLetterStrategy":       "discarding individualDeadLetterStrategy sharedDeadLetterStrategy",
	"sharedDeadLetterStrategy": "deadLetterQueue", "deadLetterQueue": "queue topic",
	"destinations": "queue topic", "plugins": "authorizationPlugin",
	"authorizationPlugin": "map", "map": "authorizationMap",
	"authorizationMap": "authorizationEntries", "authorizationEntries": "authorizationEntry",
	"destinationInterceptors":       "virtualDestinationInterceptor",
	"virtualDestinationInterceptor": "virtualDestinations",
	"virtualDestinations":           "compositeQueue compositeTopic virtualTopic",
	"compositeQueue":                "forwardTo", "compositeTopic": "forwardTo",
	"forwardTo": "queue topic filteredDestination",
}

func validateActiveMQConfiguration(data string) error {
	decoder := xml.NewDecoder(strings.NewReader(data))
	var stack []string
	var children []map[string]int
	rootSeen := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !rootSeen || len(stack) != 0 {
				return errors.New("configuration requires one broker element")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid ActiveMQ XML: %w", err)
		}
		switch t := token.(type) {
		case xml.StartElement:
			if len(stack) > 12 || t.Name.Space != activeMQNamespace {
				return errors.New("only the ActiveMQ core XML namespace is supported")
			}
			name := t.Name.Local
			if len(stack) == 0 {
				if rootSeen || name != "broker" {
					return errors.New("configuration requires one broker root")
				}
				rootSeen = true
			} else {
				parent := stack[len(stack)-1]
				if !strings.Contains(" "+activeMQChildren[parent]+" ", " "+name+" ") {
					return fmt.Errorf("unsupported ActiveMQ element %s/%s", parent, name)
				}
				counts := children[len(children)-1]
				counts[name]++
				if counts[name] > 1 && parent != "policyEntries" && parent != "destinations" && parent != "authorizationEntries" && parent != "virtualDestinations" && parent != "forwardTo" {
					return fmt.Errorf("repeated ActiveMQ element %s", name)
				}
			}
			attrs := map[string]string{}
			for _, a := range t.Attr {
				if a.Name.Local == "xmlns" && a.Name.Space == "" || a.Name.Space == "xmlns" {
					if a.Value != activeMQNamespace && a.Value != "http://www.w3.org/2001/XMLSchema-instance" {
						return errors.New("unsupported XML namespace declaration")
					}
					continue
				}
				if a.Name.Space == "http://www.w3.org/2001/XMLSchema-instance" && a.Name.Local == "schemaLocation" && name == "broker" {
					if strings.Join(strings.Fields(a.Value), " ") != activeMQNamespace+" "+activeMQNamespace+"/activemq-core.xsd" {
						return errors.New("unsupported XML schema location")
					}
					continue
				}
				if a.Name.Space != "" {
					return errors.New("namespaced configuration attributes are unsupported")
				}
				if _, exists := attrs[a.Name.Local]; exists {
					return errors.New("duplicate configuration attribute")
				}
				attrs[a.Name.Local] = a.Value
				if !activeMQAttribute(name, a.Name.Local, a.Value) {
					return fmt.Errorf("unsupported or invalid ActiveMQ attribute %s.%s", name, a.Name.Local)
				}
			}
			if name == "authorizationEntry" || name == "filteredDestination" || name == "policyEntry" && len(stack) > 0 && stack[len(stack)-1] == "policyEntries" {
				if (attrs["queue"] == "") == (attrs["topic"] == "") {
					return errors.New("destination entry requires exactly one queue or topic")
				}
			}
			if (name == "queue" || name == "topic") && attrs["physicalName"] == "" {
				return errors.New("destination requires physicalName")
			}
			if (name == "compositeQueue" || name == "compositeTopic") && attrs["name"] == "" {
				return errors.New("composite destination requires name")
			}
			stack = append(stack, name)
			children = append(children, map[string]int{})
		case xml.EndElement:
			name := stack[len(stack)-1]
			counts := children[len(children)-1]
			if allowed := activeMQChildren[name]; allowed != "" && name != "broker" && name != "policyEntry" && name != "sharedDeadLetterStrategy" && len(counts) == 0 {
				return fmt.Errorf("empty ActiveMQ collection %s", name)
			}
			if (name == "deadLetterStrategy" || name == "deadLetterQueue") && len(counts) != 1 {
				return fmt.Errorf("ActiveMQ %s requires exactly one child", name)
			}
			stack, children = stack[:len(stack)-1], children[:len(children)-1]
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return errors.New("configuration text content is unsupported")
			}
		case xml.Directive:
			return errors.New("XML directives and entities are unsupported")
		case xml.ProcInst:
			if t.Target != "xml" || rootSeen {
				return errors.New("XML processing instructions are unsupported")
			}
		}
	}
}

func activeMQAttribute(element, name, value string) bool {
	boolean := value == "true" || value == "false"
	switch element {
	case "virtualTopic":
		switch name {
		case "name":
			return configurationDestination(value, true)
		case "prefix", "postfix":
			return value == "" || configurationDestination(value, true)
		case "selectorAware", "concurrentSend", "transactedSend", "local", "dropOnResourceLimit", "setOriginalDestination":
			return boolean
		}
	case "filteredDestination":
		switch name {
		case "queue", "topic":
			return configurationDestination(value, false)
		case "selector":
			// JMS selector parsing and evaluation belong to the native engine.
			return true
		}
	case "compositeQueue", "compositeTopic":
		switch name {
		case "name":
			return configurationDestination(value, false)
		case "forwardOnly", "copyMessage", "concurrentSend", "sendWhenNotMatched":
			return boolean
		}
	case "broker":
		switch name {
		case "advisorySupport", "populateJMSXUserID", "useAuthenticatedPrincipalForJMSXUserID", "schedulerSupport", "rejectDurableConsumers":
			return boolean
		case "maxSchedulerRepeatAllowed":
			_, err := strconv.ParseInt(value, 10, 32)
			return err == nil
		}
	case "queue", "topic":
		return name == "physicalName" && configurationDestination(value, false) || name == "DLQ" && boolean
	case "authorizationEntry":
		switch name {
		case "queue", "topic":
			return configurationDestination(value, true)
		case "read", "write", "admin":
			for _, group := range strings.Split(value, ",") {
				if !configurationGroup(group) {
					return false
				}
			}
			return true
		}
	case "policyEntry":
		switch name {
		case "queue", "topic":
			return configurationDestination(value, true)
		case "producerFlowControl", "prioritizedMessages", "useCache", "sendAdvisoryIfNoConsumers", "persistJMSRedelivered", "enableAudit", "optimizedDispatch", "strictOrderDispatch", "allConsumersExclusiveByDefault", "sendFailIfNoSpace":
			return boolean
		case "sendFailIfNoSpaceAfterTimeout":
			_, err := strconv.ParseInt(value, 10, 64)
			return err == nil
		case "expireMessagesPeriod":
			return configurationInteger(value, 0, 2147483647)
		case "maxPageSize", "maxBrowsePageSize", "queuePrefetch", "topicPrefetch":
			return configurationInteger(value, 1, 2147483647)
		case "memoryLimit":
			parts := strings.Fields(strings.ToLower(value))
			if len(parts) == 1 {
				return configurationInteger(parts[0], 1, 128<<20)
			}
			if len(parts) != 2 {
				return false
			}
			switch parts[1] {
			case "b":
				return configurationInteger(parts[0], 1, 128<<20)
			case "kb":
				return configurationInteger(parts[0], 1, 128<<10)
			case "mb":
				return configurationInteger(parts[0], 1, 128)
			}
		}
	}
	if element == "individualDeadLetterStrategy" {
		switch name {
		case "destinationPerDurableSubscriber", "useQueueForQueueMessages", "useQueueForTopicMessages":
			return boolean
		case "queuePrefix", "queueSuffix", "topicPrefix", "topicSuffix":
			return value == "" || configurationDestination(value, false)
		}
	}
	switch element {
	case "discarding", "individualDeadLetterStrategy", "sharedDeadLetterStrategy":
		switch name {
		case "enableAudit", "processExpired", "processNonPersistent":
			return boolean
		case "expiration":
			return configurationInteger(value, 0, 9223372036854775807)
		case "maxAuditDepth", "maxProducersToAudit":
			return configurationInteger(value, 1, 2147483647)
		}
	}
	return false
}

func configurationDestination(value string, wildcard bool) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-/", c) || wildcard && strings.ContainsRune("*>", c) {
			continue
		}
		return false
	}
	return true
}

func configurationGroup(value string) bool {
	if value == "" || len(value) > 100 {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-*", c) {
			continue
		}
		return false
	}
	return true
}

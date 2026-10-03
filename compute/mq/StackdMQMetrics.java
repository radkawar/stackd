import java.io.ByteArrayInputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

// Runs in the installed broker's PID/network namespace, not in the controller.
// The local management agent is JVM-owned and admits only local connections.
public class StackdMQMetrics {
    static final int LIMIT = 8 << 20;

    static Map<String, Object> attributes(MBeanServerConnection server, ObjectName name, String... keys) throws Exception {
        AttributeList values = server.getAttributes(name, keys);
        Map<String, Object> result = new HashMap<>();
        for (Object value : values) {
            if (!(value instanceof Attribute)) throw new Exception("invalid native attribute");
            Attribute attribute = (Attribute) value;
            if (attribute.getValue() == null || result.put(attribute.getName(), attribute.getValue()) != null)
                throw new Exception("null or duplicate native attribute");
        }
        if (result.size() != keys.length || !result.keySet().equals(new HashSet<>(Arrays.asList(keys))))
            throw new Exception("incomplete native attributes");
        return result;
    }

    static String text(Object value) throws Exception {
        if (!(value instanceof String) || ((String) value).isEmpty()) throw new Exception("invalid native name");
        return (String) value;
    }

    static long count(Object value, Class<?> type) throws Exception {
        if (value == null || value.getClass() != type || ((Number) value).longValue() < 0)
            throw new Exception("invalid native counter");
        return ((Number) value).longValue();
    }

    static void enabled(Object value) throws Exception {
        if (!Boolean.TRUE.equals(value)) throw new Exception("native statistics disabled");
    }

    static String quote(String value) throws Exception {
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) throw new Exception("invalid native name encoding");
                result.append(c).append(value.charAt(i));
            } else if (Character.isLowSurrogate(c)) {
                throw new Exception("invalid native name encoding");
            } else if (c == '\\' || c == '"') {
                result.append('\\').append(c);
            } else if (c < 32) {
                result.append(String.format("\\u%04x", (int) c));
            } else result.append(c);
        }
        return result.append('"').toString();
    }

    static Set<ObjectName> inventory(MBeanServerConnection server, ObjectName broker) throws Exception {
        Map<String, Object> catalogs = attributes(server, broker, "Queues", "Topics", "TemporaryQueues", "TemporaryTopics");
        Set<ObjectName> result = new TreeSet<>();
        for (Map.Entry<String, Object> catalog : catalogs.entrySet()) {
            if (!(catalog.getValue() instanceof ObjectName[])) throw new Exception("invalid native destination inventory");
            String kind = catalog.getKey().endsWith("Queues") ? "Queue" : "Topic";
            for (ObjectName name : (ObjectName[]) catalog.getValue()) {
                if (name == null || name.isPattern() || !name.getDomain().equals(broker.getDomain())
                        || name.getKeyPropertyList().size() != 4 || !"Broker".equals(name.getKeyProperty("type"))
                        || !broker.getKeyProperty("brokerName").equals(name.getKeyProperty("brokerName"))
                        || !kind.equals(name.getKeyProperty("destinationType")) || name.getKeyProperty("destinationName") == null
                        || !result.add(name)) throw new Exception("invalid or duplicate native destination");
            }
        }
        ObjectName pattern = new ObjectName(broker.toString() + ",destinationType=*,destinationName=*");
        if (!result.equals(server.queryNames(pattern, null))) throw new Exception("incomplete native destination inventory");
        return result;
    }

    // ActiveMQ 5.18.7 BrokerView delegates this ObjectName[] to ManagedRegionBroker's
    // inactive subscription map. BrokerMBeanSupport.createSubscriptionName supplies
    // these seven properties; active and inactive durable names share that shape.
    static Set<ObjectName> inactiveDurableSubscribers(MBeanServerConnection server, ObjectName broker) throws Exception {
        Object value = attributes(server, broker, "InactiveDurableTopicSubscribers").get("InactiveDurableTopicSubscribers");
        if (!(value instanceof ObjectName[])) throw new Exception("invalid native inactive durable subscriber inventory");
        Set<ObjectName> result = new HashSet<>();
        for (ObjectName name : (ObjectName[]) value) {
            if (name == null || name.isPattern() || !name.getDomain().equals(broker.getDomain())
                    || name.getKeyPropertyList().size() != 7 || !"Broker".equals(name.getKeyProperty("type"))
                    || !broker.getKeyProperty("brokerName").equals(name.getKeyProperty("brokerName"))
                    || !"Topic".equals(name.getKeyProperty("destinationType")) || name.getKeyProperty("destinationName") == null
                    || !"Consumer".equals(name.getKeyProperty("endpoint")) || name.getKeyProperty("clientId") == null
                    || name.getKeyProperty("consumerId") == null || !name.getKeyProperty("consumerId").startsWith("Durable(")
                    || !name.getKeyProperty("consumerId").endsWith(")") || !result.add(name))
                throw new Exception("invalid or duplicate native inactive durable subscriber");
        }
        return result;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new Exception("expected broker identity and JVM PID");
        byte[] propertiesData = System.in.readNBytes(65537);
        if (propertiesData.length > 65536) throw new Exception("oversized native agent properties");
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(propertiesData));
        String address = properties.getProperty("com.sun.management.jmxremote.localConnectorAddress");
        if (address == null) throw new Exception("missing native local connector");
        try (JMXConnector connector = JMXConnectorFactory.connect(new JMXServiceURL(address))) {
            MBeanServerConnection server = connector.getMBeanServerConnection();
            String runtimeName = text(server.getAttribute(new ObjectName(ManagementFactory.RUNTIME_MXBEAN_NAME), "Name"));
            if (!runtimeName.startsWith(args[1] + "@")) throw new Exception("foreign native JVM");
            Set<ObjectName> brokers = server.queryNames(new ObjectName("org.apache.activemq:type=Broker,brokerName=*"), null);
            if (brokers.size() != 1) throw new Exception("missing or ambiguous native broker");
            ObjectName broker = brokers.iterator().next();
            Map<String, Object> values = attributes(server, broker, "BrokerName", "BrokerId", "StatisticsEnabled", "CurrentConnectionsCount", "TotalConsumerCount", "TotalMessageCount", "TotalProducerCount");
            if (!args[0].equals(text(values.get("BrokerName")))) throw new Exception("foreign native broker");
            String brokerID = text(values.get("BrokerId"));
            enabled(values.get("StatisticsEnabled"));
            Set<ObjectName> destinations = inventory(server, broker);
            Set<ObjectName> inactiveSubscribers = inactiveDurableSubscribers(server, broker);
            StringBuilder json = new StringBuilder("{\"connections\":").append(count(values.get("CurrentConnectionsCount"), Integer.class))
                .append(",\"consumers\":").append(count(values.get("TotalConsumerCount"), Long.class))
                .append(",\"messages\":").append(count(values.get("TotalMessageCount"), Long.class))
                .append(",\"producers\":").append(count(values.get("TotalProducerCount"), Long.class))
                .append(",\"inactive_durable_topic_subscribers\":").append(inactiveSubscribers.size()).append(",\"destinations\":[");
            boolean first = true;
            for (ObjectName destination : destinations) {
                String kind = destination.getKeyProperty("destinationType");
                String[] keys = kind.equals("Queue") ? new String[]{"Name", "ConsumerCount", "ProducerCount", "QueueSize"}
                    : new String[]{"Name", "ConsumerCount", "ProducerCount"};
                Map<String, Object> row = attributes(server, destination, keys);
                if (!first) json.append(',');
                first = false;
                json.append("{\"name\":").append(quote(text(row.get("Name")))).append(",\"kind\":").append(quote(kind))
                    .append(",\"consumers\":").append(count(row.get("ConsumerCount"), Long.class))
                    .append(",\"producers\":").append(count(row.get("ProducerCount"), Long.class));
                if (kind.equals("Queue")) json.append(",\"queue_size\":").append(count(row.get("QueueSize"), Long.class));
                json.append('}');
                if (json.length() > LIMIT) throw new Exception("oversized native metrics");
            }
            if (!destinations.equals(inventory(server, broker))) throw new Exception("native destination inventory changed");
            if (!inactiveSubscribers.equals(inactiveDurableSubscribers(server, broker)))
                throw new Exception("native inactive durable subscriber inventory changed");
            Map<String, Object> identity = attributes(server, broker, "BrokerName", "BrokerId", "StatisticsEnabled");
            if (!args[0].equals(text(identity.get("BrokerName"))) || !brokerID.equals(text(identity.get("BrokerId"))))
                throw new Exception("native broker identity changed");
            enabled(identity.get("StatisticsEnabled"));
            byte[] output = json.append("]}").toString().getBytes(StandardCharsets.UTF_8);
            if (output.length > LIMIT) throw new Exception("oversized native metrics");
            System.out.write(output);
        }
    }
}

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import javax.jms.*;
import javax.net.ssl.*;
import org.apache.activemq.ActiveMQSslConnectionFactory;

class ClientMQ {
    public static void main(String[] args) throws Exception {
        String[] f = new BufferedReader(new InputStreamReader(System.in)).readLine().split("\t", -1);
        for (int i = 0; i < f.length; i++) f[i] = new String(Base64.getDecoder().decode(f[i]), StandardCharsets.UTF_8);
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        trust.setCertificateEntry("broker", CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(f[4].getBytes(StandardCharsets.UTF_8))));
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        ActiveMQSslConnectionFactory factory = new ActiveMQSslConnectionFactory(f[0] + "?socket.verifyHostName=true");
        factory.setWatchTopicAdvisories(false);
        factory.setKeyAndTrustManagers(null, managers.getTrustManagers(), null);
        if (f[5].endsWith("-consumers") || f[5].startsWith("composite-")) factory.getPrefetchPolicy().setQueuePrefetch(1);
        if (f[5].equals("producer-pressure")) {
            factory.setSendTimeout(10000);
            factory.setAlwaysSyncSend(true);
            factory.getPrefetchPolicy().setQueuePrefetch(0);
        }
        Connection connection = factory.createConnection(f[1], f[2]);
        if (f[5].startsWith("durable-")) connection.setClientID("owned-durable-policy-client");
        try {
            connection.start();
            Session session = connection.createSession(false, f[5].equals("producer-pressure") ? Session.CLIENT_ACKNOWLEDGE : Session.AUTO_ACKNOWLEDGE);
            if (f[5].equals("publish")) {
                MessageProducer producer = session.createProducer(session.createQueue(f[3]));
                producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                producer.send(session.createTextMessage(f[6]));
            } else if (f[5].equals("consume")) {
                MessageConsumer consumer = session.createConsumer(session.createQueue(f[3]));
                Message message = consumer.receive(10000);
                if (!(message instanceof TextMessage) || !((TextMessage) message).getText().equals(f[6])) throw new Exception("Retained message mismatch");
            } else if (f[5].startsWith("composite-")) {
                compositeDestinations(session, f[3], f[5], f[6]);
            } else if (f[5].equals("producer-pressure")) {
                producerPressure(session, f[3], f[6], DeliveryMode.PERSISTENT);
                producerPressure(session, f[3], f[6], DeliveryMode.NON_PERSISTENT);
            } else if (f[5].equals("exclusive-consumers") || f[5].equals("shared-consumers")) {
                Queue queue = session.createQueue(f[3] + "." + f[6]);
                MessageConsumer first = session.createConsumer(queue);
                MessageConsumer second = session.createConsumer(queue);
                MessageProducer producer = session.createProducer(queue);
                producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                producer.send(session.createTextMessage("first-" + f[6]));
                producer.send(session.createTextMessage("second-" + f[6]));
                if (f[5].equals("exclusive-consumers")) {
                    requireText(first.receive(10000), "first-" + f[6]);
                    requireText(first.receive(10000), "second-" + f[6]);
                    if (second.receive(500) != null) throw new Exception("Standby consumer received exclusive queue delivery");
                } else {
                    Message a = first.receive(10000), b = second.receive(10000);
                    if (!(a instanceof TextMessage) || !(b instanceof TextMessage)) throw new Exception("Shared queue did not distribute to both consumers");
                    java.util.Set<String> actual = new java.util.HashSet<>(java.util.Arrays.asList(((TextMessage) a).getText(), ((TextMessage) b).getText()));
                    if (!actual.equals(new java.util.HashSet<>(java.util.Arrays.asList("first-" + f[6], "second-" + f[6])))) throw new Exception("Shared queue lost or duplicated payload");
                }
                first.close();
                producer.send(session.createTextMessage("handoff-" + f[6]));
                requireText(second.receive(10000), "handoff-" + f[6]);
                if (second.receive(500) != null) throw new Exception("Consumer handoff duplicated delivery");
                second.close();
                producer.close();
            } else if (f[5].equals("publish-scheduled") || f[5].equals("reject-scheduled")) {
                String[] schedule = f[6].split("\t", 4);
                MessageProducer producer = session.createProducer(session.createQueue(f[3]));
                producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                TextMessage message = session.createTextMessage(schedule[3]);
                message.setLongProperty("AMQ_SCHEDULED_DELAY", Long.parseLong(schedule[0]));
                message.setLongProperty("AMQ_SCHEDULED_PERIOD", Long.parseLong(schedule[1]));
                message.setIntProperty("AMQ_SCHEDULED_REPEAT", Integer.parseInt(schedule[2]));
                boolean rejected = false;
                try {
                    producer.send(message);
                } catch (MessageFormatException error) {
                    if (!f[5].equals("reject-scheduled") || !error.getMessage().contains("scheduled repeat value is too large")) throw error;
                    rejected = true;
                }
                if (f[5].equals("reject-scheduled") && !rejected) throw new Exception("Broker accepted excessive scheduled repeat");
            } else if (f[5].equals("expect-empty")) {
                MessageConsumer consumer = session.createConsumer(session.createQueue(f[3]));
                if (consumer.receive(Long.parseLong(f[6])) != null) throw new Exception("Scheduled message delivered before deadline");
            } else if (f[5].equals("consume-scheduled")) {
                String[] expected = f[6].split("\t", 6);
                long earliest = Long.parseLong(expected[0]);
                long timeout = Long.parseLong(expected[1]);
                int count = Integer.parseInt(expected[2]);
                boolean scheduled = Boolean.parseBoolean(expected[3]);
                long minimumSpacing = Long.parseLong(expected[4]);
                long previous = 0;
                MessageConsumer consumer = session.createConsumer(session.createQueue(f[3]));
                for (int i = 0; i < count; i++) {
                    Message message = consumer.receive(timeout);
                    long observed = System.currentTimeMillis();
                    if (!(message instanceof TextMessage) || !((TextMessage) message).getText().equals(expected[5])) throw new Exception("Scheduled payload mismatch");
                    if (message.getJMSDeliveryMode() != DeliveryMode.PERSISTENT) throw new Exception("Scheduled delivery lost persistence");
                    if (observed < earliest || (previous != 0 && observed - previous < minimumSpacing)) throw new Exception("Scheduled delivery timing violated");
                    if (message.propertyExists("scheduledJobId") != scheduled) throw new Exception("Native scheduled job identity mismatch");
                    previous = observed;
                    System.out.println("SCHEDULED_DELIVERY " + observed);
                }
                if (consumer.receive(2500) != null) throw new Exception("Unexpected extra scheduled delivery");
            } else if (f[5].equals("durable-register") || f[5].equals("durable-reject") || f[5].equals("durable-consume")) {
                TopicSubscriber subscriber = null;
                try {
                    subscriber = session.createDurableSubscriber(session.createTopic(f[3]), f[6].split("\t", 2)[0]);
                } catch (JMSException error) {
                    if (!f[5].equals("durable-reject") || !error.getMessage().contains("Durable Consumers are not allowed")) throw error;
                }
                if (f[5].equals("durable-reject")) {
                    if (subscriber != null) throw new Exception("Native broker accepted forbidden durable subscription");
                } else if (f[5].equals("durable-consume")) {
                    String expected = f[6].split("\t", 2)[1];
                    Message message = subscriber.receive(10000);
                    if (!(message instanceof TextMessage) || !((TextMessage) message).getText().equals(expected) || message.getJMSDeliveryMode() != DeliveryMode.PERSISTENT) throw new Exception("Durable policy lost retained message");
                    if (subscriber.receive(500) != null) throw new Exception("Duplicate durable policy message");
                    subscriber.close();
                    session.unsubscribe(f[6].split("\t", 2)[0]);
                }
            } else if (f[5].equals("topic-publish") || f[5].equals("topic-transient")) {
                Topic topic = session.createTopic(f[3] + (f[5].equals("topic-transient") ? ".transient" : ""));
                MessageConsumer consumer = f[5].equals("topic-transient") ? session.createConsumer(topic) : null;
                MessageProducer producer = session.createProducer(topic);
                producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                producer.send(session.createTextMessage(f[6]));
                if (consumer != null) {
                    Message message = consumer.receive(10000);
                    if (!(message instanceof TextMessage) || !((TextMessage) message).getText().equals(f[6])) throw new Exception("Non-durable topic delivery rejected by durable policy");
                }
            } else if (f[5].equals("publish-bytes")) {
                MessageProducer producer = session.createProducer(session.createQueue(f[3]));
                producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                BytesMessage message = session.createBytesMessage();
                message.writeBytes(Base64.getDecoder().decode(f[6]));
                producer.send(message);
            } else if (f[5].equals("consume-bytes")) {
                MessageConsumer consumer = session.createConsumer(session.createQueue(f[3]));
                Message message = consumer.receive(10000);
                byte[] expected = Base64.getDecoder().decode(f[6]);
                if (!(message instanceof BytesMessage)) throw new Exception("Retained bytes message missing");
                BytesMessage bytes = (BytesMessage) message;
                if (bytes.getJMSDeliveryMode() != DeliveryMode.PERSISTENT || bytes.getBodyLength() != expected.length) throw new Exception("Retained bytes message metadata mismatch");
                byte[] actual = new byte[expected.length];
                if (bytes.readBytes(actual) != actual.length || !java.util.Arrays.equals(actual, expected)) throw new Exception("Retained bytes message payload mismatch");
            } else if (!f[5].equals("connect")) throw new Exception("Unknown operation");
        } finally { connection.close(); }
        System.out.println("CLIENT_OK");
    }
    private static void requireText(Message message, String expected) throws Exception {
        if (!(message instanceof TextMessage) || !expected.equals(((TextMessage) message).getText())) throw new Exception("Consumer payload mismatch: " + expected);
    }
    private static void compositeDestinations(Session session, String prefix, String operation, String input) throws Exception {
        String[] fields = input.split("\t", 2);
        boolean only = Boolean.parseBoolean(fields[0]);
        for (String kind : new String[]{"queue", "topic"}) {
            String name = prefix + ".composite." + kind;
            Destination source = kind.equals("queue") ? session.createQueue(name) : session.createTopic(name);
            String payload = fields[1] + "-" + kind;
            java.util.List<MessageConsumer> consumers = new java.util.ArrayList<>();
            MessageConsumer sourceConsumer = null;
            if (!operation.equals("composite-store")) {
                consumers.add(session.createConsumer(session.createQueue(name + ".one")));
                consumers.add(session.createConsumer(session.createQueue(name + ".two")));
                if (operation.equals("composite-route")) {
                    consumers.add(session.createConsumer(session.createTopic(name + ".notifications")));
                }
                if (kind.equals("queue") || operation.equals("composite-route")) {
                    sourceConsumer = session.createConsumer(source);
                    if (!only) consumers.add(sourceConsumer);
                }
            }
            if (!operation.equals("composite-drain")) {
                MessageProducer producer = session.createProducer(source);
                producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                TextMessage message = session.createTextMessage(payload);
                message.setStringProperty("compositePayload", payload);
                producer.send(message);
                producer.close();
            }
            for (MessageConsumer consumer : consumers) {
                Message message = consumer.receive(10000);
                requireText(message, payload);
                if (message.getJMSDeliveryMode() != DeliveryMode.PERSISTENT || !payload.equals(message.getStringProperty("compositePayload"))) throw new Exception("Composite routing lost message metadata");
                if (consumer.receive(500) != null) throw new Exception("Composite routing duplicated delivery");
                consumer.close();
            }
            if (only && sourceConsumer != null) {
                if (sourceConsumer.receive(500) != null) throw new Exception("Forward-only source received a new message");
                sourceConsumer.close();
            }
        }
        filteredDestinations(session, prefix, operation, fields[1], only);
        virtualTopic(session, prefix, operation, fields[1], only);
    }
    private static void virtualTopic(Session session, String prefix, String operation, String input, boolean aware) throws Exception {
        String name = prefix + ".events.orders";
        String payload = input + "-virtual";
        Queue redQueue = session.createQueue("Groups.red." + name + ".work");
        Queue blueQueue = session.createQueue("Groups.blue." + name + ".work");
        Topic topic = session.createTopic(name);
        if (operation.equals("composite-drain")) {
            int[] retained = aware ? new int[]{} : new int[]{0, 1, 2, 3};
            consumeFiltered(session.createConsumer(redQueue), payload, retained);
            consumeFiltered(session.createConsumer(blueQueue), payload, retained);
            return;
        }
        if (operation.equals("composite-store")) {
            // Establish native durable queues without leaving active selectors.
            session.createConsumer(redQueue).close();
            session.createConsumer(blueQueue).close();
            publishVirtual(session, topic, payload);
            return;
        }
        MessageConsumer redFirst = session.createConsumer(redQueue, "route = 'red'");
        MessageConsumer redSecond = session.createConsumer(redQueue, "route = 'red'");
        MessageConsumer blue = session.createConsumer(blueQueue, "route = 'blue'");
        MessageConsumer direct = session.createConsumer(topic);
        MessageConsumer wrongPrefix = session.createConsumer(session.createQueue("Consumer.wrong." + name + ".work"));
        MessageConsumer wrongSuffix = session.createConsumer(session.createQueue("Groups.wrong." + name + ".other"));
        publishVirtual(session, topic, payload);
        Message first = redFirst.receive(10000), second = redSecond.receive(10000);
        if (!(first instanceof TextMessage) || !(second instanceof TextMessage)) throw new Exception("Virtual topic group did not distribute to both consumers");
        java.util.Set<String> redPayloads = new java.util.HashSet<>(java.util.Arrays.asList(((TextMessage) first).getText(), ((TextMessage) second).getText()));
        if (!redPayloads.equals(new java.util.HashSet<>(java.util.Arrays.asList(payload + "-0", payload + "-2")))) throw new Exception("Virtual topic group lost or duplicated matching payloads");
        if (redFirst.receive(500) != null || redSecond.receive(500) != null) throw new Exception("Virtual topic duplicated a group delivery");
        redFirst.close();
        redSecond.close();
        consumeFiltered(blue, payload, new int[]{1});
        consumeFiltered(direct, payload, new int[]{0, 1, 2, 3});
        consumeFiltered(wrongPrefix, payload, new int[]{});
        consumeFiltered(wrongSuffix, payload, new int[]{});
        consumeFiltered(session.createConsumer(redQueue), payload, aware ? new int[]{} : new int[]{1, 3});
        consumeFiltered(session.createConsumer(blueQueue), payload, aware ? new int[]{} : new int[]{0, 2, 3});
    }
    private static void publishVirtual(Session session, Topic topic, String payload) throws Exception {
        MessageProducer producer = session.createProducer(topic);
        producer.setDeliveryMode(DeliveryMode.PERSISTENT);
        for (int index = 0; index < 4; index++) {
            TextMessage message = session.createTextMessage(payload + "-" + index);
            if (index != 3) message.setStringProperty("route", index == 1 ? "blue" : "red");
            message.setIntProperty("amount", index == 2 ? 5 : 20);
            producer.send(message);
        }
        producer.close();
    }
    private static void filteredDestinations(Session session, String prefix, String operation, String input, boolean fallback) throws Exception {
        for (String kind : new String[]{"queue", "topic"}) {
            String name = prefix + ".filtered." + kind;
            String payload = input + "-filtered-" + kind;
            Destination source = kind.equals("queue") ? session.createQueue(name) : session.createTopic(name);
            MessageConsumer red = null, blue = null, original = null;
            if (!operation.equals("composite-store")) {
                red = session.createConsumer(session.createQueue(name + ".red"));
                if (operation.equals("composite-route")) blue = session.createConsumer(session.createTopic(name + ".blue"));
                if (kind.equals("queue") || operation.equals("composite-route")) original = session.createConsumer(source);
            }
            if (!operation.equals("composite-drain")) {
                MessageProducer producer = session.createProducer(source);
                producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                for (int index = 0; index < 4; index++) {
                    TextMessage message = session.createTextMessage(payload + "-" + index);
                    if (index != 3) message.setStringProperty("route", index == 1 ? "blue" : "red");
                    message.setIntProperty("amount", index == 2 ? 5 : 20);
                    producer.send(message);
                }
                producer.close();
            }
            if (red != null) consumeFiltered(red, payload, new int[]{0});
            if (blue != null) consumeFiltered(blue, payload, new int[]{1});
            if (original != null) consumeFiltered(original, payload, fallback ? new int[]{2, 3} : new int[]{0, 1, 2, 3});
        }
    }
    private static void consumeFiltered(MessageConsumer consumer, String payload, int[] indexes) throws Exception {
        for (int index : indexes) {
            Message message = consumer.receive(10000);
            requireText(message, payload + "-" + index);
            String route = index == 3 ? null : index == 1 ? "blue" : "red";
            if (message.getJMSDeliveryMode() != DeliveryMode.PERSISTENT || message.getIntProperty("amount") != (index == 2 ? 5 : 20) || !java.util.Objects.equals(route, message.getStringProperty("route"))) throw new Exception("Filtered delivery changed metadata");
        }
        if (consumer.receive(500) != null) throw new Exception("Filtered destination received a nonmatching or duplicate message");
        consumer.close();
    }
    private static void producerPressure(Session session, String prefix, String input, int deliveryMode) throws Exception {
        String[] fields = input.split("\t", 2);
        boolean delayed = Boolean.parseBoolean(fields[0]);
        Queue queue = session.createQueue(prefix + ".pressure." + fields[1] + "." + deliveryMode);
        MessageConsumer consumer = session.createConsumer(queue);
        MessageProducer producer = session.createProducer(queue);
        producer.setDeliveryMode(deliveryMode);
        Message last = null;
        String payload = fields[1] + "-" + "x".repeat(2048);
        int accepted = 0;
        boolean rejected = false;
        for (; accepted < 32; accepted++) {
            long started = System.nanoTime();
            try {
                producer.send(session.createTextMessage(accepted + "-" + payload));
            } catch (ResourceAllocationException error) {
                long millis = (System.nanoTime() - started) / 1000000;
                if (delayed ? millis < 900 : millis >= 900) throw new Exception("Incorrect pressure rejection timing: " + millis, error);
                System.out.println("NATIVE_PRESSURE_REJECTION accepted=" + accepted + " elapsed_ms=" + millis);
                rejected = true;
                break;
            } catch (JMSException error) {
                throw new Exception("Producer failed after " + accepted + " accepted messages", error);
            }
            last = consumer.receive(10000);
            requireText(last, accepted + "-" + payload);
        }
        // The default file cursor can offload non-persistent messages before
        // memory fills. Require exhaustion for the persistent path; check exact
        // delivery and recovery in both paths, including any native rejection.
        if (accepted == 0 || (deliveryMode == DeliveryMode.PERSISTENT && !rejected)) throw new Exception("Did not observe accepted persistent messages followed by resource exhaustion");
        last.acknowledge();
        if (consumer.receive(500) != null) throw new Exception("Rejected send left a message in the queue");
        producer.send(session.createTextMessage("recovered-" + fields[1]));
        Message recovered = consumer.receive(10000);
        requireText(recovered, "recovered-" + fields[1]);
        recovered.acknowledge();
        if (consumer.receive(500) != null) throw new Exception("Recovery duplicated delivery");
        consumer.close();
        producer.close();
    }
}

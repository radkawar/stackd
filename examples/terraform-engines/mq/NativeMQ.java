import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import javax.jms.BytesMessage;
import javax.jms.Connection;
import javax.jms.DeliveryMode;
import javax.jms.JMSException;
import javax.jms.JMSSecurityException;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.net.ssl.TrustManagerFactory;
import org.apache.activemq.ActiveMQConnection;
import org.apache.activemq.ActiveMQSslConnectionFactory;
import org.apache.activemq.command.ActiveMQQueue;

// An ordinary external TLS/OpenWire client. Neither publication nor delivery is
// routed through stackd's runtime or stored in its control-plane database.
public final class NativeMQ {
    private static String decode(String value) {
        return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 32) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private static boolean authenticationDenied(JMSException error) {
        if (error instanceof JMSSecurityException) return true;
        for (Throwable cause = error.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof SecurityException || cause instanceof JMSSecurityException) return true;
        }
        Exception linked = error.getLinkedException();
        return linked instanceof SecurityException || linked instanceof JMSSecurityException;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected one native operation");
        String action = args[0];
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String[] fields = input.readLine().split("\t", -1);
        if (fields.length != 7) throw new IllegalArgumentException("Invalid native connection input");
        String key = decode(fields[5]);
        if (!key.matches("[a-z0-9-]+")) throw new IllegalArgumentException("Invalid owned correlation key");

        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        CertificateFactory certificates = CertificateFactory.getInstance("X.509");
        int index = 0;
        for (java.security.cert.Certificate certificate : certificates.generateCertificates(
                new ByteArrayInputStream(Base64.getDecoder().decode(fields[4])))) {
            trust.setCertificateEntry("owned-ca-" + index++, certificate);
        }
        if (index == 0) throw new IllegalArgumentException("Missing explicit TLS trust");
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        ActiveMQSslConnectionFactory factory = new ActiveMQSslConnectionFactory(
                decode(fields[0]) + "?socket.verifyHostName=true");
        factory.setKeyAndTrustManagers(null, managers.getTrustManagers(), null);
        factory.setWatchTopicAdvisories(false);
        factory.getPrefetchPolicy().setQueuePrefetch(1);
        factory.getRedeliveryPolicy().setMaximumRedeliveries(-1);

        try (Connection connection = factory.createConnection(decode(fields[1]), decode(fields[2]))) {
            connection.start();
            if (action.equals("authenticate-negative")) {
                throw new IllegalStateException("The native broker accepted the wrong password");
            }
            ActiveMQQueue queue = new ActiveMQQueue(decode(fields[3]));
            if (action.equals("delete")) {
                ((ActiveMQConnection) connection).destroyDestination(queue);
                System.out.println("{\"deleted\":true}");
                return;
            }
            try (Session session = connection.createSession(true, Session.SESSION_TRANSACTED)) {
                if (action.equals("publish")) {
                    BytesMessage message = session.createBytesMessage();
                    message.writeBytes(Base64.getDecoder().decode(fields[6]));
                    message.setJMSCorrelationID(key);
                    try (MessageProducer producer = session.createProducer(queue)) {
                        producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                        producer.send(message);
                        session.commit();
                    }
                    System.out.println("{\"message_id\":" + quote(message.getJMSMessageID()) + "}");
                    return;
                }
                if (!action.equals("retain") && !action.equals("consume")) {
                    throw new IllegalArgumentException("Unknown native operation: " + action);
                }
                try (MessageConsumer consumer = session.createConsumer(queue, "JMSCorrelationID = '" + key + "'")) {
                    Message raw = consumer.receive(5000);
                    if (!(raw instanceof BytesMessage)) throw new JMSException("Missing owned native BytesMessage");
                    BytesMessage message = (BytesMessage) raw;
                    long length = message.getBodyLength();
                    if (length > 1048576) throw new JMSException("Unexpected owned payload length");
                    byte[] body = new byte[(int) length];
                    int count = message.readBytes(body);
                    if (count != body.length) throw new JMSException("Incomplete native BytesMessage");
                    String user = message.getStringProperty("JMSXUserID");
                    if (user == null) user = "";
                    String result = "{\"message_id\":" + quote(message.getJMSMessageID())
                            + ",\"data\":" + quote(Base64.getEncoder().encodeToString(body))
                            + ",\"persistent\":" + (message.getJMSDeliveryMode() == DeliveryMode.PERSISTENT)
                            + ",\"correlation_id\":" + quote(message.getJMSCorrelationID())
                            + ",\"user_id\":" + quote(user)
                            + ",\"redelivered\":" + message.getJMSRedelivered() + "}";
                    if (consumer.receive(250) != null) throw new JMSException("Duplicate owned native payload");
                    if (action.equals("retain")) session.rollback();
                    else session.commit();
                    System.out.println(result);
                }
            }
        } catch (JMSException error) {
            if (!action.equals("authenticate-negative") || !authenticationDenied(error)) throw error;
            System.out.println("{\"authentication_denied\":true}");
        }
    }
}

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.*;
import javax.jms.*;
import javax.net.ssl.*;
import org.apache.activemq.ActiveMQSession;
import org.apache.activemq.ActiveMQSslConnectionFactory;
import org.apache.activemq.command.ActiveMQMessage;

// The JVM is a protocol driver only. Broker delivery and acknowledgement state
// stays in ActiveMQ; Go owns source authority, batching, retries and invocation.
class StackdMQ {
    static String decode(String value) { return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8); }
    static String quote(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default: if (c < 32) out.append(String.format("\\u%04x", (int)c)); else out.append(c);
            }
        }
        return out.append('"').toString();
    }
    static String destination(Destination value) throws JMSException {
        if (value == null) return "null";
        if (!(value instanceof javax.jms.Queue)) throw new JMSException("Only queue destinations are supported");
        return "{\"physicalName\":" + quote(((javax.jms.Queue)value).getQueueName()) + "}";
    }
    static String record(Message message) throws Exception {
        byte[] data;
        String type;
        if (message instanceof TextMessage) {
            String text = ((TextMessage)message).getText();
            data = text == null ? new byte[0] : text.getBytes(StandardCharsets.UTF_8);
            type = "jms/text-message";
        } else if (message instanceof BytesMessage) {
            BytesMessage bytes = (BytesMessage)message;
            long length = bytes.getBodyLength();
            if (length > 6291456) throw new JMSException("Message exceeds Lambda payload size");
            data = new byte[(int)length];
            bytes.readBytes(data);
            type = "jms/bytes-message";
        } else throw new JMSException("Lambda supports TextMessage and BytesMessage only");
        StringBuilder properties = new StringBuilder("{");
        Enumeration<?> names = message.getPropertyNames();
        boolean first = true;
        while (names.hasMoreElements()) {
            String name = (String)names.nextElement();
            if (!first) properties.append(',');
            first = false;
            properties.append(quote(name)).append(':').append(quote(String.valueOf(message.getObjectProperty(name))));
        }
        properties.append('}');
        ActiveMQMessage nativeMessage = (ActiveMQMessage)message;
        return "{\"messageID\":" + quote(message.getJMSMessageID())
            + ",\"messageType\":" + quote(type)
            + ",\"deliveryMode\":" + message.getJMSDeliveryMode()
            + ",\"replyTo\":" + destination(message.getJMSReplyTo())
            + ",\"type\":" + quote(message.getJMSType())
            + ",\"expiration\":" + quote(Long.toString(message.getJMSExpiration()))
            + ",\"priority\":" + message.getJMSPriority()
            + ",\"correlationId\":" + quote(message.getJMSCorrelationID())
            + ",\"redelivered\":" + message.getJMSRedelivered()
            + ",\"destination\":" + destination(message.getJMSDestination())
            + ",\"data\":" + quote(Base64.getEncoder().encodeToString(data))
            + ",\"timestamp\":" + message.getJMSTimestamp()
            + ",\"brokerInTime\":" + nativeMessage.getBrokerInTime()
            + ",\"brokerOutTime\":" + nativeMessage.getBrokerOutTime()
            + ",\"properties\":" + properties + "}";
    }
    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line = input.readLine();
        if (line == null) return;
        String[] fields = line.split("\t", -1);
        if (fields.length != 5) throw new IllegalArgumentException("Invalid connection configuration");
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        CertificateFactory certificates = CertificateFactory.getInstance("X.509");
        int index = 0;
        for (java.security.cert.Certificate certificate : certificates.generateCertificates(new ByteArrayInputStream(Base64.getDecoder().decode(fields[4])))) trust.setCertificateEntry("ca-" + index++, certificate);
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        ActiveMQSslConnectionFactory factory = new ActiveMQSslConnectionFactory(decode(fields[0]) + "?socket.verifyHostName=true");
        factory.setKeyAndTrustManagers(null, managers.getTrustManagers(), null);
        factory.getPrefetchPolicy().setQueuePrefetch(100);
        boolean probe = args.length == 1 && args[0].equals("--probe");
        if (probe) factory.setWatchTopicAdvisories(false);
        Connection connection = factory.createConnection(decode(fields[1]), decode(fields[2]));
        try {
            if (probe) {
                // Sending a transport command waits for the real broker's
                // WireFormatInfo negotiation, without ConnectionInfo/session
                // creation or customer destination/advisory authorization.
                org.apache.activemq.ActiveMQConnection nativeConnection = (org.apache.activemq.ActiveMQConnection) connection;
                nativeConnection.getTransport().oneway(new org.apache.activemq.command.KeepAliveInfo());
                if (nativeConnection.isTransportFailed()) throw nativeConnection.getFirstFailureError();
                System.out.println("READY");
                return;
            }
            Session session = connection.createSession(false, ActiveMQSession.INDIVIDUAL_ACKNOWLEDGE);
            javax.jms.Queue queue = session.createQueue(decode(fields[3]));
            MessageConsumer consumer = session.createConsumer(queue);
            List<Message> pending = new ArrayList<>();
            connection.start();
            System.out.println("READY");
            while ((line = input.readLine()) != null) {
                String[] command = line.split("\t", -1);
                if (command[0].equals("FETCH")) {
                    int count = Integer.parseInt(command[1]);
                    for (int i = 0; i < count; i++) {
                        Message message = consumer.receive(i == 0 ? 100 : 1);
                        if (message == null) break;
                        pending.add(message);
                        System.out.println(record(message));
                    }
                    System.out.println("END");
                } else if (command[0].equals("ACK")) {
                    int count = Integer.parseInt(command[1]);
                    if (count < 1 || count > pending.size()) throw new IllegalArgumentException("Invalid acknowledgement range");
                    for (int i = 0; i < count; i++) pending.get(i).acknowledge();
                    pending.subList(0, count).clear();
                    System.out.println("OK");
                } else throw new IllegalArgumentException("Unknown native driver command");
            }
        } finally { connection.close(); }
    }
}

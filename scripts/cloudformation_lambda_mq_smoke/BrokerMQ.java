import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Enumeration;
import javax.jms.*;
import javax.net.ssl.*;
import org.apache.activemq.ActiveMQSslConnectionFactory;

class BrokerMQ {
    private static String quoted(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
    private static String message(Message message) throws Exception {
        if (!(message instanceof BytesMessage)) throw new Exception("Expected native JMS BytesMessage");
        BytesMessage bytes = (BytesMessage) message;
        byte[] body = new byte[(int) bytes.getBodyLength()];
        if (body.length > 0 && bytes.readBytes(body) != body.length) throw new Exception("Truncated native JMS message");
        return "{\"message_id\":" + quoted(message.getJMSMessageID()) + ",\"body\":" + quoted(Base64.getEncoder().encodeToString(body)) + ",\"persistent\":" + (message.getJMSDeliveryMode() == DeliveryMode.PERSISTENT) + ",\"redelivered\":" + message.getJMSRedelivered() + "}";
    }
    public static void main(String[] args) throws Exception {
        String[] f = new BufferedReader(new InputStreamReader(System.in)).readLine().split("\t", -1);
        for (int i = 0; i < f.length; i++) f[i] = new String(Base64.getDecoder().decode(f[i]), StandardCharsets.UTF_8);
        URI endpoint = new URI(f[0]);
        if (!endpoint.getScheme().equals("ssl") || !endpoint.getHost().equals("127.0.0.1")) throw new Exception("JMS endpoint must explicitly select loopback TLS");
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        trust.setCertificateEntry("broker", CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(f[4].getBytes(StandardCharsets.UTF_8))));
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        ActiveMQSslConnectionFactory factory = new ActiveMQSslConnectionFactory(f[0] + "?socket.verifyHostName=true");
        factory.setWatchTopicAdvisories(false);
        factory.setAlwaysSyncSend(true);
        factory.getPrefetchPolicy().setQueuePrefetch(0);
        factory.setKeyAndTrustManagers(null, managers.getTrustManagers(), null);
        Connection connection = factory.createConnection(f[1], f[2]);
        try {
            connection.start();
            Session session = connection.createSession(true, Session.SESSION_TRANSACTED);
            Queue queue = session.createQueue(f[3]);
            String result;
            if (f[5].equals("publish")) {
                MessageProducer producer = session.createProducer(queue);
                producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                BytesMessage bytes = session.createBytesMessage();
                bytes.writeBytes(Base64.getDecoder().decode(f[6]));
                producer.send(bytes);
                session.commit();
                bytes.reset();
                result = "\"published\":" + message(bytes) + ",\"native_commit\":true";
            } else if (f[5].equals("inspect") || f[5].equals("declare")) {
                QueueBrowser browser = session.createBrowser(queue);
                Enumeration<?> messages = browser.getEnumeration();
                StringBuilder rows = new StringBuilder();
                int count = 0;
                while (messages.hasMoreElements()) {
                    if (count++ > 0) rows.append(',');
                    rows.append(message((Message) messages.nextElement()));
                }
                browser.close();
                result = "\"messages\":" + count + ",\"rows\":[" + rows + "]";
            } else if (f[5].equals("consume")) {
                MessageConsumer consumer = session.createConsumer(queue);
                Message received = consumer.receive(1000);
                result = "\"present\":" + (received != null);
                if (received != null) result += ",\"message\":" + message(received);
                session.commit();
                result += ",\"native_commit\":true";
            } else throw new Exception("Unknown operation");
            System.out.println("{\"protocol\":\"OpenWire/JMS/TLS\",\"provider\":" + quoted(connection.getMetaData().getJMSProviderName()) + ",\"provider_version\":" + quoted(connection.getMetaData().getProviderVersion()) + "," + result + "}");
        } finally { connection.close(); }
    }
}

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import javax.jms.*;
import javax.net.ssl.*;
import org.apache.activemq.ActiveMQSslConnectionFactory;

class PublishMQ {
    public static void main(String[] args) throws Exception {
        String[] fields = new BufferedReader(new InputStreamReader(System.in)).readLine().split("\t", -1);
        for (int i = 0; i < fields.length; i++) fields[i] = new String(Base64.getDecoder().decode(fields[i]), StandardCharsets.UTF_8);
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        trust.setCertificateEntry("broker", CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(fields[4].getBytes(StandardCharsets.UTF_8))));
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        ActiveMQSslConnectionFactory factory = new ActiveMQSslConnectionFactory(fields[0] + "?socket.verifyHostName=true");
        factory.setKeyAndTrustManagers(null, managers.getTrustManagers(), null);
        Connection connection = factory.createConnection(fields[1], fields[2]);
        try {
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            MessageProducer producer = session.createProducer(session.createQueue(fields[3]));
            producer.setDeliveryMode(DeliveryMode.PERSISTENT);
            TextMessage message = session.createTextMessage(fields[5]);
            message.setStringProperty("producer", "signed-sdk-runtime-smoke");
            producer.send(message);
        } finally { connection.close(); }
    }
}

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import javax.jms.*;
import javax.net.ssl.*;
import org.apache.activemq.ActiveMQPrefetchPolicy;
import org.apache.activemq.ActiveMQSslConnectionFactory;

// A stdin-controlled client keeps real native inventory stable across complete
// CloudWatch minutes. It never reads management counters or publishes metrics.
class ActiveMetricClient {
    private static void acknowledged(String action) {
        System.out.println("ACTIVE_METRICS_ACK\t" + action);
        System.out.flush();
    }

    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String first = input.readLine();
        if (first == null) throw new Exception("Missing JMS connection settings");
        String[] fields = first.split("\t", -1);
        if (fields.length != 9) throw new Exception("Invalid JMS connection settings");
        for (int i = 0; i < fields.length; i++) {
            fields[i] = new String(Base64.getDecoder().decode(fields[i]), StandardCharsets.UTF_8);
        }
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        trust.setCertificateEntry("broker", CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(fields[5].getBytes(StandardCharsets.UTF_8))));
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        ActiveMQSslConnectionFactory factory = new ActiveMQSslConnectionFactory(fields[0] + "?socket.verifyHostName=true");
        factory.setWatchTopicAdvisories(false);
        factory.setAlwaysSyncSend(true);
        ActiveMQPrefetchPolicy prefetch = new ActiveMQPrefetchPolicy();
        prefetch.setAll(0);
        factory.setPrefetchPolicy(prefetch);
        factory.setKeyAndTrustManagers(null, managers.getTrustManagers(), null);
        Connection queueConnection = null;
        Connection topicConnection = null;
        try {
            queueConnection = factory.createConnection(fields[1], fields[2]);
            queueConnection.start();
            Session queueSession = queueConnection.createSession(true, Session.SESSION_TRANSACTED);
            Queue queue = queueSession.createQueue(fields[3]);
            MessageProducer queueProducer = queueSession.createProducer(queue);
            queueProducer.setDeliveryMode(DeliveryMode.PERSISTENT);
            MessageConsumer queueConsumer = queueSession.createConsumer(queue);

            topicConnection = factory.createConnection(fields[1], fields[2]);
            topicConnection.setClientID(fields[7]);
            topicConnection.start();
            Session topicSession = topicConnection.createSession(true, Session.SESSION_TRANSACTED);
            Topic topic = topicSession.createTopic(fields[4]);
            MessageProducer topicProducer = topicSession.createProducer(topic);
            MessageConsumer topicConsumer = topicSession.createDurableSubscriber(topic, fields[8]);
            int published = 0;
            int consumed = 0;
            acknowledged("ready");
            String action;
            while ((action = input.readLine()) != null) {
                if (action.startsWith("publish ")) {
                    int count = Integer.parseInt(action.substring("publish ".length()));
                    if (count <= 0) throw new Exception("Invalid publish count");
                    for (int i = 0; i < count; i++) {
                        queueProducer.send(queueSession.createTextMessage(fields[6] + "/" + published));
                        published++;
                    }
                    queueSession.commit();
                } else if (action.equals("publish-offline-topic")) {
                    if (topicConnection != null) throw new Exception("Durable subscriber must be offline before publication");
                    MessageProducer offlineProducer = queueSession.createProducer(topic);
                    try {
                        offlineProducer.setDeliveryMode(DeliveryMode.PERSISTENT);
                        offlineProducer.send(queueSession.createTextMessage(fields[7] + "/" + fields[8] + "/offline"));
                        queueSession.commit();
                    } finally {
                        offlineProducer.close();
                    }
                } else if (action.equals("receive-retained-topic")) {
                    if (topicConnection == null) throw new Exception("Durable subscriber is not active");
                    Message message = topicConsumer.receive(10000);
                    String expected = fields[7] + "/" + fields[8] + "/offline";
                    if (!(message instanceof TextMessage) || !((TextMessage) message).getText().equals(expected)) {
                        throw new Exception("Retained durable topic message mismatch");
                    }
                    topicSession.commit();
                    if (topicConsumer.receive(250) != null) throw new Exception("Duplicate retained durable topic message");
                    topicSession.commit();
                } else if (action.equals("drain")) {
                    while (consumed < published) {
                        Message message = queueConsumer.receive(10000);
                        String expected = fields[6] + "/" + consumed;
                        if (!(message instanceof TextMessage) || !((TextMessage) message).getText().equals(expected)) {
                            throw new Exception("Persistent queue message mismatch at " + consumed);
                        }
                        consumed++;
                    }
                    queueSession.commit();
                    if (queueConsumer.receive(250) != null) throw new Exception("Unexpected extra queue message");
                    queueSession.commit();
                } else if (action.equals("close-topic") || action.equals("unsubscribe-topic")) {
                    if (topicConnection == null) throw new Exception("Topic connection already closed");
                    topicProducer.close();
                    topicConsumer.close();
                    if (action.equals("unsubscribe-topic")) topicSession.unsubscribe(fields[8]);
                    topicSession.close();
                    topicConnection.close();
                    topicConnection = null;
                } else if (action.equals("close")) {
                    if (topicConnection != null) {
                        topicProducer.close();
                        topicConsumer.close();
                        topicSession.close();
                        topicConnection.close();
                        topicConnection = null;
                    }
                    queueProducer.close();
                    queueConsumer.close();
                    queueSession.close();
                    queueConnection.close();
                    queueConnection = null;
                    acknowledged(action);
                    return;
                } else {
                    throw new Exception("Unknown JMS action: " + action);
                }
                acknowledged(action);
            }
        } finally {
            try {
                if (topicConnection != null) topicConnection.close();
            } finally {
                if (queueConnection != null) queueConnection.close();
            }
        }
    }
}

-- Retain native broker identity and pending work while correcting the public
-- ActiveMQ engine version. The native runtime remains pinned to 5.18.7.
UPDATE mq_brokers SET engine_version = '5.18'
WHERE engine = 'ACTIVEMQ' AND engine_version = '5.18.7';
UPDATE mq_configurations SET engine_version = '5.18'
WHERE engine = 'ACTIVEMQ' AND engine_version = '5.18.7';

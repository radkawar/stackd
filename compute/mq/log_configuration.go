package mq

import (
	"fmt"
	service "stackd/internal/services/mq"
	"strings"
)

// ActiveMQ 5.18.7's HTTP AuditFilter requires exactly "true"; "all" only
// enables JMX auditing. Logger levels below gate recording, not this machinery.
const activeMQLoggingOptions = " -Dorg.apache.activemq.audit=true -Dlog4j.configurationFile=/stackd/log4j2.properties"

// JSON escaping is performed by the installed Log4j2 PatternLayout, not by a
// synthetic record producer. One physical line contains one complete native
// event, including multiline message bodies and exception stacks.
const activeMQLogPattern = `{"timestamp":"%d{yyyy-MM-dd'T'HH:mm:ss.SSS'Z'}{UTC}","message":"%enc{%p | %m | %c | %t%throwable{full}}{JSON}"}%n`

func writeActiveMQLogging(dir string, v service.BrokerRecord) error {
	var config strings.Builder
	config.WriteString("status=error\nname=StackdMQ\nmonitorInterval=0\nrootLogger.level=INFO\nrootLogger.appenderRef.console.ref=Console\nappender.console.type=Console\nappender.console.name=Console\nappender.console.layout.type=PatternLayout\nappender.console.layout.pattern=%p | %m%n\n")
	// Audit must never fall through to the console/general root appender.
	config.WriteString("logger.audit.name=org.apache.activemq.audit\nlogger.audit.additivity=false\n")
	if v.Logs.Audit {
		config.WriteString("logger.audit.level=INFO\nlogger.audit.appenderRef.audit.ref=Audit\n")
		writeActiveMQLogAppender(&config, "audit", "Audit", "audit.log")
	} else {
		config.WriteString("logger.audit.level=OFF\n")
	}
	if v.Logs.General {
		config.WriteString("rootLogger.appenderRef.general.ref=General\n")
		writeActiveMQLogAppender(&config, "general", "General", "activemq.log")
	}
	return atomicNativeFile(dir, "log4j2.properties", []byte(config.String()), 0644)
}

func writeActiveMQLogAppender(config *strings.Builder, key, name, file string) {
	prefix := "appender." + key + "."
	properties := [][2]string{
		{"type", "RollingFile"}, {"name", name},
		{"fileName", "${sys:activemq.data}/stackd-logs/" + file},
		{"filePattern", "${sys:activemq.data}/stackd-logs/" + file + ".%i"},
		{"append", "true"}, {"immediateFlush", "true"}, {"bufferedIO", "false"},
		{"layout.type", "PatternLayout"}, {"layout.charset", "UTF-8"},
		{"layout.alwaysWriteExceptions", "false"}, {"layout.pattern", activeMQLogPattern},
		{"policies.type", "Policies"}, {"policies.size.type", "SizeBasedTriggeringPolicy"},
		{"policies.size.size", "8MB"}, {"strategy.type", "DefaultRolloverStrategy"},
		{"strategy.fileIndex", "min"}, {"strategy.min", "1"}, {"strategy.max", "7"},
	}
	for _, property := range properties {
		fmt.Fprintf(config, "%s%s=%s\n", prefix, property[0], property[1])
	}
}

// RabbitMQ 3.13.7's rabbit_logger_json_fmt writes time/level/msg with JSON
// escaping and a newline per native event. rabbit_logger_std_h appends across
// restarts and renames archives newest-first as .0 through .6 (not .1-.7).
// Keep the files in the owned data volume, not the disposable container layer.
func rabbitLoggingConfiguration(v service.BrokerRecord) (string, error) {
	if v.Logs.Audit {
		return "", fmt.Errorf("RabbitMQ does not support audit logs")
	}
	if !v.Logs.General {
		return "log.console = true\nlog.file = false\n", nil
	}
	return "log.console = true\nlog.file = /var/lib/rabbitmq/stackd-logs/rabbit.log\nlog.file.level = info\nlog.file.formatter = json\nlog.file.formatter.time_format = rfc3339_T\nlog.file.rotation.size = 8388608\nlog.file.rotation.count = 7\nlog.file.rotation.compress = false\n", nil
}

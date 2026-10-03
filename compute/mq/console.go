package mq

import (
	"fmt"
	service "stackd/internal/services/mq"
	"strconv"
	"strings"
)

const activeMQConsoleEnvironment = "ACTIVEMQ_OPTS=-Xms64m -Xmx256m -Djava.awt.headless=true -Dwebconsole.type=invm" + activeMQLoggingOptions
const activeMQConsolePort = "8162/tcp"

func writeActiveMQConfiguration(dir string, v service.BrokerRecord, data, password string, old *nativeElement) error {
	users, err := effectiveActiveMQUsers(v, old)
	if err != nil {
		return err
	}
	config, err := activeMQConfiguration(v, data, password, users)
	if err != nil {
		return err
	}
	// The realm never hot-reloads: stage it before the atomic broker config,
	// and apply both only when the native process restarts.
	if err = atomicNativeFile(dir, "jetty-realm.properties", activeMQConsoleRealm(users), 0644); err != nil {
		return err
	}
	if err = writeActiveMQLogging(dir, v); err != nil {
		return err
	}
	return atomicNativeFile(dir, "activemq.xml", config, 0644)
}

// Jetty's native OBF encoding preserves whitespace, Unicode and property-file
// delimiters without interpreting a customer password as a credential scheme.
// This is encoding, not encryption; the owned parent directory protects secrets.
func jettyPassword(password string) string {
	var encoded strings.Builder
	encoded.Grow(4 + len(password)*5)
	encoded.WriteString("OBF:")
	for i := range len(password) {
		first, last := int(password[i]), int(password[len(password)-i-1])
		value := (127+first+last)*256 + 127 + first - last
		if first >= 128 || last >= 128 {
			encoded.WriteByte('U')
			value = first*256 + last
		}
		digits := strconv.FormatInt(int64(value), 36)
		encoded.WriteString("0000"[:4-len(digits)])
		encoded.WriteString(digits)
	}
	return encoded.String()
}

func activeMQConsoleRealm(users []service.UserRecord) []byte {
	var realm strings.Builder
	for _, user := range users {
		if !user.ConsoleAccess {
			continue
		}
		// Validated MQ usernames contain only ASCII alphanumerics and -._~.
		fmt.Fprintf(&realm, "%s: %s,admin\n", user.Username, jettyPassword(user.Password))
	}
	return []byte(realm.String())
}

// Use the installed webapp and its LocalBrokerFacade, not a second broker or a
// remote JMX connection. Protect every path (including actions and resources).
// The webapp's JMS operations still use the HTTP user's native JMS credentials.
func activeMQConsoleConfiguration(password string) string {
	return fmt.Sprintf(`
 <bean id="consoleLogin" class="org.eclipse.jetty.security.HashLoginService">
  <property name="name" value="ActiveMQRealm"/>
  <property name="config" value="/stackd/jetty-realm.properties"/>
  <property name="hotReload" value="false"/>
 </bean>
 <bean id="consoleConstraint" class="org.eclipse.jetty.util.security.Constraint">
  <property name="name" value="BASIC"/>
  <property name="roles" value="admin"/>
  <property name="authenticate" value="true"/>
 </bean>
 <bean id="consoleMapping" class="org.eclipse.jetty.security.ConstraintMapping">
  <property name="constraint" ref="consoleConstraint"/>
  <property name="pathSpec" value="/*"/>
 </bean>
 <bean id="consoleApps" class="org.eclipse.jetty.server.handler.HandlerCollection">
  <property name="handlers"><list>
   <bean class="org.eclipse.jetty.webapp.WebAppContext">
    <property name="contextPath" value="/admin"/>
    <property name="resourceBase" value="/opt/apache-activemq/webapps/admin"/>
    <property name="throwUnavailableOnStartupException" value="true"/>
   </bean>
  </list></property>
 </bean>
 <bean id="consoleSecurity" class="org.eclipse.jetty.security.ConstraintSecurityHandler">
  <property name="loginService" ref="consoleLogin"/>
  <property name="authenticator"><bean class="org.eclipse.jetty.security.authentication.BasicAuthenticator">
   <property name="charset"><bean class="java.nio.charset.Charset" factory-method="forName"><constructor-arg value="UTF-8"/></bean></property>
  </bean></property>
  <property name="constraintMappings"><list><ref bean="consoleMapping"/></list></property>
  <property name="handler" ref="consoleApps"/>
 </bean>
 <bean id="consoleServer" class="org.eclipse.jetty.server.Server" destroy-method="stop">
  <property name="handler" ref="consoleSecurity"/>
 </bean>
 <bean id="consoleTLS" class="org.eclipse.jetty.util.ssl.SslContextFactory$Server">
  <property name="keyStorePath" value="/stackd/broker.p12"/>
  <property name="keyStoreType" value="PKCS12"/>
  <property name="keyStorePassword" value="%s"/>
  <property name="includeProtocols"><list><value>TLSv1.2</value><value>TLSv1.3</value></list></property>
 </bean>
 <bean id="consoleHTTP" class="org.eclipse.jetty.server.HttpConfiguration">
  <property name="sendServerVersion" value="false"/>
  <property name="customizers"><list><bean class="org.eclipse.jetty.server.SecureRequestCustomizer"/></list></property>
 </bean>
 <bean id="consoleConnectors" class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
  <property name="targetObject" ref="consoleServer"/>
  <property name="targetMethod" value="setConnectors"/>
  <property name="arguments"><list><list>
   <bean class="org.eclipse.jetty.server.ServerConnector">
    <constructor-arg ref="consoleServer"/>
    <constructor-arg><list>
     <bean class="org.eclipse.jetty.server.SslConnectionFactory"><constructor-arg ref="consoleTLS"/><constructor-arg value="http/1.1"/></bean>
     <bean class="org.eclipse.jetty.server.HttpConnectionFactory"><constructor-arg ref="consoleHTTP"/></bean>
    </list></constructor-arg>
    <property name="host" value="0.0.0.0"/>
    <property name="port" value="8162"/>
   </bean>
  </list></list></property>
 </bean>
 <bean id="consoleJSP" class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
  <property name="staticMethod" value="org.apache.activemq.web.config.JspConfigurer.configureJetty"/>
  <property name="arguments"><list><ref bean="consoleServer"/><ref bean="consoleApps"/></list></property>
 </bean>
 <bean class="org.springframework.beans.factory.config.MethodInvokingFactoryBean" depends-on="consoleJSP,consoleConnectors">
  <property name="targetObject" ref="consoleServer"/>
  <property name="targetMethod" value="start"/>
 </bean>
`, escapeXML(password))
}

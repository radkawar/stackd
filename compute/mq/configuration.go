package mq

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	service "stackd/internal/services/mq"
	"strings"
)

const rabbitOwnedConfiguration = "listeners.tcp = none\nlisteners.ssl.default = 5671\nssl_options.cacertfile = /stackd/cert.pem\nssl_options.certfile = /stackd/cert.pem\nssl_options.keyfile = /stackd/key.pem\nssl_options.verify = verify_none\nssl_options.fail_if_no_peer_cert = false\nauth_mechanisms.1 = PLAIN\nloopback_users = none\nvm_memory_high_watermark.absolute = 256MiB\n"

// RabbitMQ 3.13 cannot disable its HTTP listener using "port = none"; confine
// it to container loopback and publish only the TLS management listener.
const rabbitManagementConfiguration = "management.tcp.ip = 127.0.0.1\nmanagement.ssl.port = 15671\nmanagement.ssl.cacertfile = /stackd/cert.pem\nmanagement.ssl.certfile = /stackd/cert.pem\nmanagement.ssl.keyfile = /stackd/key.pem\n"

// RabbitMQ 3.13.7 has no secure.management.http.headers.enabled setting.
// Its native management header settings are unset by default.
const rabbitSecureManagementHeaders = "management.headers.content_type_options = nosniff\nmanagement.headers.frame_options = DENY\nmanagement.hsts.policy = max-age=47304000; includeSubDomains\n"

const rabbitAdvancedConfigEnvironment = "RABBITMQ_ADVANCED_CONFIG_FILE=/stackd/advanced.config"

// writeRabbitConfiguration consumes validated AWS configuration and applies
// AWS's management and quorum defaults even when a revision omits the controls.
// AWS's zero acknowledgement timeout maps to upstream Erlang's undefined atom.
// Replace both files so a later revision cannot retain an earlier override.
func writeRabbitConfiguration(dir, base, data string) error {
	var config bytes.Buffer
	config.Grow(len(base) + len(data) + len(rabbitSecureManagementHeaders) + 160)
	config.WriteString(base)
	advanced := "[].\n"
	operatorPolicyChangesDisabled := "true"
	secureManagementHeaders := true
	relaxedQuorumRedeclaration := "true"
	for line := range strings.SplitSeq(data, "\n") {
		content, _, _ := strings.Cut(line, "#")
		key, value, _ := strings.Cut(content, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "quorum_queue.property_equivalence.relaxed_checks_on_redeclaration":
			relaxedQuorumRedeclaration = value
			continue
		case "management.restrictions.operator_policy_changes.disabled":
			operatorPolicyChangesDisabled = value
			continue
		case "secure.management.http.headers.enabled":
			secureManagementHeaders = value == "true"
			continue
		case "consumer_timeout":
			if strings.Trim(value, "0") == "" {
				advanced = "[{rabbit, [{consumer_timeout, undefined}]}].\n"
				continue
			}
		}
		config.WriteString(line)
		config.WriteByte('\n')
	}
	config.WriteString("management.restrictions.operator_policy_changes.disabled = ")
	config.WriteString(operatorPolicyChangesDisabled)
	config.WriteByte('\n')
	config.WriteString("quorum_queue.property_equivalence.relaxed_checks_on_redeclaration = ")
	config.WriteString(relaxedQuorumRedeclaration)
	config.WriteByte('\n')
	if secureManagementHeaders {
		config.WriteString(rabbitSecureManagementHeaders)
	}
	if err := atomicNativeFile(dir, "advanced.config", []byte(advanced), 0644); err != nil {
		return err
	}
	return atomicNativeFile(dir, "rabbitmq.conf", config.Bytes(), 0644)
}

// atomicNativeFile replaces only a single owned configuration file. The private
// parent directory and owner marker are checked by callers before any write.
func atomicNativeFile(dir, name string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(dir, ".mq-config-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temporary, filepath.Join(dir, name)); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (r *Runtime) ownedDirectory(v service.BrokerRecord) (string, error) {
	dir := filepath.Join(r.config.DataDir, r.name(v))
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("refusing non-directory MQ native state")
	}
	marker, err := os.Lstat(filepath.Join(dir, "owner"))
	if err != nil {
		return "", err
	}
	if !marker.Mode().IsRegular() {
		return "", errors.New("refusing non-regular MQ owner marker")
	}
	owner, err := os.ReadFile(filepath.Join(dir, "owner"))
	if err != nil {
		return "", err
	}
	if string(owner) != v.ARN {
		return "", errors.New("refusing foreign MQ native directory")
	}
	return dir, nil
}

func (r *Runtime) configure(ctx context.Context, dir string, v service.BrokerRecord) error {
	if _, err := r.ownedDirectory(v); err != nil {
		return err
	}
	data := v.Configuration.Data
	if data == "" {
		data = service.DefaultConfiguration(v.Engine)
	}
	if err := service.ValidateConfiguration(v.Engine, data); err != nil {
		return err
	}
	for name, contents := range map[string][]byte{"cert.pem": r.cert, "key.pem": r.key} {
		if err := atomicNativeFile(dir, name, contents, 0644); err != nil {
			return err
		}
	}
	if v.Engine == "RABBITMQ" {
		salt := make([]byte, 4)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		h := sha256.New()
		h.Write(salt)
		h.Write([]byte(v.Password))
		hashed := base64.StdEncoding.EncodeToString(append(salt, h.Sum(nil)...))
		definitions := map[string]any{"users": []map[string]any{{"name": v.Username, "password_hash": hashed, "hashing_algorithm": "rabbit_password_hashing_sha256", "tags": []string{"administrator"}}}, "vhosts": []map[string]string{{"name": "/"}}, "permissions": []map[string]string{{"user": v.Username, "vhost": "/", "configure": ".*", "write": ".*", "read": ".*"}}}
		raw, err := json.Marshal(definitions)
		if err != nil {
			return err
		}
		if err = atomicNativeFile(dir, "definitions.json", raw, 0644); err != nil {
			return err
		}
		if err = atomicNativeFile(dir, "enabled_plugins", []byte("[rabbitmq_management].\n"), 0644); err != nil {
			return err
		}
		base := rabbitOwnedConfiguration + rabbitManagementConfiguration + "definitions.import_backend = local_filesystem\ndefinitions.local.path = /stackd/definitions.json\n"
		logging, err := rabbitLoggingConfiguration(v)
		if err != nil {
			return err
		}
		return writeRabbitConfiguration(dir, base+logging, data)
	}
	passwordBytes := make([]byte, 24)
	if _, err := rand.Read(passwordBytes); err != nil {
		return err
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	file, err := os.CreateTemp(dir, ".mq-keystore-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	if err = file.Close(); err != nil {
		os.Remove(temporary)
		return err
	}
	defer os.Remove(temporary)
	cmd := exec.CommandContext(ctx, "openssl", "pkcs12", "-export", "-in", filepath.Join(dir, "cert.pem"), "-inkey", filepath.Join(dir, "key.pem"), "-out", temporary, "-name", "broker", "-passout", "stdin")
	cmd.Stdin = bytes.NewBufferString(password + "\n")
	if _, err = cmd.Output(); err != nil {
		return fmt.Errorf("creating ActiveMQ native TLS keystore: %w", err)
	}
	if err = os.Chmod(temporary, 0644); err != nil {
		return err
	}
	if err = os.Rename(temporary, filepath.Join(dir, "broker.p12")); err != nil {
		return err
	}
	return writeActiveMQConfiguration(dir, v, data, password, nil)
}

// applyConfiguration never recreates the keystore, credentials, volume, container
// or endpoint. All owned configuration files are staged before restarting the
// same container, which applies the settings together.
func (r *Runtime) applyConfiguration(v service.BrokerRecord) error {
	dir, err := r.ownedDirectory(v)
	if err != nil {
		return err
	}
	data := v.Configuration.Data
	if data == "" {
		data = service.DefaultConfiguration(v.Engine)
	}
	if err = service.ValidateConfiguration(v.Engine, data); err != nil {
		return err
	}
	if v.Engine == "RABBITMQ" {
		config := rabbitOwnedConfiguration
		if _, err = os.Stat(filepath.Join(dir, "enabled_plugins")); err == nil {
			config += rabbitManagementConfiguration
		} else if !os.IsNotExist(err) {
			return err
		}
		// Definitions are bootstrap-only: reimport would undo passwords and
		// permissions changed through the real RabbitMQ management API.
		logging, err := rabbitLoggingConfiguration(v)
		if err != nil {
			return err
		}
		return writeRabbitConfiguration(dir, config+logging, data)
	}
	old, err := readNativeXML(dir)
	if err != nil {
		return err
	}
	ssl := findNativeElement(old, "sslContext", "keyStorePassword")
	if ssl == nil {
		return errors.New("retained ActiveMQ TLS configuration is missing")
	}
	return writeActiveMQConfiguration(dir, v, data, ssl.attribute("keyStorePassword"), old)
}

type nativeElement struct {
	XMLName    xml.Name
	Attributes []xml.Attr      `xml:",any,attr"`
	Children   []nativeElement `xml:",any"`
}

func (n *nativeElement) normalizeNamespaces() {
	attributes := n.Attributes[:0]
	for _, attribute := range n.Attributes {
		if attribute.Name.Space == "" && attribute.Name.Local != "xmlns" {
			attributes = append(attributes, attribute)
		}
	}
	n.Attributes = attributes
	for i := range n.Children {
		n.Children[i].normalizeNamespaces()
	}
}
func (n *nativeElement) attribute(name string) string {
	for _, a := range n.Attributes {
		if a.Name.Local == name && a.Name.Space == "" {
			return a.Value
		}
	}
	return ""
}
func findNativeElement(n *nativeElement, name, attribute string) *nativeElement {
	if n.XMLName.Local == name && (attribute == "" || n.attribute(attribute) != "") {
		return n
	}
	for i := range n.Children {
		if found := findNativeElement(&n.Children[i], name, attribute); found != nil {
			return found
		}
	}
	return nil
}
func readNativeXML(dir string) (*nativeElement, error) {
	info, err := os.Lstat(filepath.Join(dir, "activemq.xml"))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("refusing non-regular ActiveMQ configuration")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "activemq.xml"))
	if err != nil {
		return nil, err
	}
	var document nativeElement
	if err = xml.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	return &document, nil
}
func effectiveActiveMQUsers(v service.BrokerRecord, old *nativeElement) ([]service.UserRecord, error) {
	users := v.Users
	if users == nil && v.Password != "" {
		users = []service.UserRecord{{Username: v.Username, Password: v.Password}}
	}
	retained := map[string]service.UserRecord{}
	if old != nil {
		if container := findNativeElement(old, "users", ""); container != nil {
			for _, user := range container.Children {
				retained[user.attribute("username")] = service.UserRecord{Username: user.attribute("username"), Password: user.attribute("password"), Groups: strings.Split(user.attribute("groups"), ",")}
			}
		}
	}
	if users == nil && v.Password == "" {
		user, ok := retained[v.Username]
		if !ok {
			return nil, errors.New("legacy ActiveMQ credentials are missing")
		}
		return []service.UserRecord{user}, nil
	}
	out := make([]service.UserRecord, 0, len(users))
	seen := map[string]bool{}
	for _, user := range users {
		// Readiness/reconciliation sees pending metadata too. A CREATE user is
		// not a native credential until the service commits a successful reboot.
		if user.PendingChange == "CREATE" {
			continue
		}
		if user.Password == "" {
			user.Password = retained[user.Username].Password
		}
		if user.Username == "" || user.Password == "" || seen[user.Username] {
			return nil, errors.New("ActiveMQ requires unique users with retained or supplied passwords")
		}
		seen[user.Username] = true
		out = append(out, user)
	}
	return out, nil
}
func activeMQConfiguration(v service.BrokerRecord, data, password string, users []service.UserRecord) ([]byte, error) {
	var custom nativeElement
	if err := xml.Unmarshal([]byte(data), &custom); err != nil {
		return nil, err
	}
	custom.normalizeNamespaces()
	var attributes, children, authorization, authentication strings.Builder
	schedulerSupport := "false"
	for _, a := range custom.Attributes {
		if a.Name.Space == "" && a.Name.Local == "schedulerSupport" {
			schedulerSupport = a.Value
			continue
		}
		if a.Name.Space == "" && a.Name.Local != "xmlns" {
			fmt.Fprintf(&attributes, " %s=\"%s\"", a.Name.Local, escapeXML(a.Value))
		}
	}
	for _, child := range custom.Children {
		if child.XMLName.Local == "plugins" {
			for _, plugin := range child.Children {
				raw, err := xml.Marshal(plugin)
				if err != nil {
					return nil, err
				}
				authorization.Write(raw)
			}
		} else {
			raw, err := xml.Marshal(child)
			if err != nil {
				return nil, err
			}
			children.Write(raw)
		}
	}
	for _, user := range users {
		if strings.Contains(user.Password, "${") || strings.Contains(user.Password, "#{") || strings.Contains(user.Username, "${") || strings.Contains(user.Username, "#{") {
			return nil, errors.New("ActiveMQ credentials cannot contain Spring expression sequences")
		}
		// All authenticated users retain the legacy default ACL unless an
		// explicit authorizationPlugin config supplies named-group ACLs.
		groups := user.Groups
		if authorization.Len() == 0 {
			groups = append([]string{"users"}, groups...)
		}
		for _, group := range groups {
			if strings.ContainsAny(group, ",\r\n") || strings.TrimSpace(group) == "" || strings.Contains(group, "${") || strings.Contains(group, "#{") {
				return nil, errors.New("unsupported ActiveMQ user group")
			}
		}
		fmt.Fprintf(&authentication, `<authenticationUser username="%s" password="%s" groups="%s"/>`, escapeXML(user.Username), escapeXML(user.Password), escapeXML(strings.Join(groups, ",")))
	}
	if authorization.Len() == 0 {
		authorization.WriteString(`<authorizationPlugin><map><authorizationMap><authorizationEntries><authorizationEntry queue=">" read="users" write="users" admin="users"/><authorizationEntry topic=">" read="users" write="users" admin="users"/></authorizationEntries></authorizationMap></map></authorizationPlugin>`)
	}
	config := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://activemq.apache.org/schema/core http://activemq.apache.org/schema/core/activemq-core.xsd">
 <broker xmlns="http://activemq.apache.org/schema/core" brokerName="%s" dataDirectory="/opt/apache-activemq/data" persistent="true" useJmx="true" schedulerSupport="%s"%s>
  <managementContext><managementContext createConnector="false"/></managementContext>
  <sslContext><sslContext keyStore="/stackd/broker.p12" keyStoreType="PKCS12" keyStorePassword="%s"/></sslContext>
  <persistenceAdapter><kahaDB directory="/opt/apache-activemq/data/kahadb"/></persistenceAdapter>
  <plugins><simpleAuthenticationPlugin anonymousAccessAllowed="false"><users>%s</users></simpleAuthenticationPlugin>%s</plugins>
  <transportConnectors><transportConnector name="ssl" uri="ssl://0.0.0.0:61617?maximumConnections=100&amp;wireFormat.maxFrameSize=6291456"/></transportConnectors>
  <systemUsage><systemUsage><memoryUsage><memoryUsage limit="128 mb"/></memoryUsage><storeUsage><storeUsage limit="1 gb"/></storeUsage><tempUsage><tempUsage limit="128 mb"/></tempUsage></systemUsage></systemUsage>
  %s
 </broker>
 %s
</beans>
`, escapeXML(v.ID), escapeXML(schedulerSupport), attributes.String(), escapeXML(password), authentication.String(), authorization.String(), children.String(), activeMQConsoleConfiguration(password))
	return []byte(config), nil
}
func escapeXML(v string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(v))
	return b.String()
}

package mq

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	service "stackd/internal/services/mq"
)

//go:embed StackdMQMetrics.java
var activeMQMetricsSource string

// The pinned image has a Java 11 JRE, without jdk.attach/libattach or javac.
// Its startup already enables the JVM's local-only management agent. Read its
// agentProperties through HotSpot's local attach socket, then query actual JMX
// attributes with a Java 11 class compiled by the installed controller JDK.
// Nothing enables a remote connector or changes the broker configuration.
func (r *Runtime) readActiveMQMetrics(ctx context.Context, v service.BrokerRecord, id string) (service.MetricSnapshot, error) {
	if err := r.installActiveMQMetrics(ctx, v); err != nil {
		return service.MetricSnapshot{}, err
	}
	data, err := r.execNative(ctx, id, []string{"timeout", "--signal=KILL", "25", "perl", "-e", activeMQMetricsAttach, v.ID}, mqMetricReadBytes)
	if err != nil {
		return service.MetricSnapshot{}, err
	}
	return parseActiveMQMetrics(data)
}

func (r *Runtime) installActiveMQMetrics(ctx context.Context, v service.BrokerRecord) error {
	dir, err := r.ownedDirectory(v)
	if err != nil {
		return err
	}
	cache := filepath.Join(r.config.DataDir, fmt.Sprintf("metrics-5.18.7-%x", sha256.Sum256([]byte(activeMQMetricsSource))))
	class := filepath.Join(cache, "StackdMQMetrics.class")
	data, err := os.ReadFile(class)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(cache, 0700); err != nil {
			return err
		}
		source := filepath.Join(cache, "StackdMQMetrics.java")
		if err = os.WriteFile(source, []byte(activeMQMetricsSource), 0600); err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, filepath.Join(filepath.Dir(r.config.Java), "javac"), "-J-Xmx64m", "--release", "11", "-d", cache, source)
		if err = cmd.Run(); err != nil {
			return fmt.Errorf("compiling native ActiveMQ metrics reader: %w", err)
		}
		data, err = os.ReadFile(class)
	}
	if err != nil {
		return err
	}
	// Existing containers retain this directory's read-only bind mount. Staging
	// here works after a controller restart without replacing the native broker.
	target := filepath.Join(dir, "StackdMQMetrics.class")
	if info, err := os.Lstat(target); err == nil && !info.Mode().IsRegular() {
		return errors.New("refusing non-regular native metrics helper")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	previous, err := os.ReadFile(target)
	if err == nil && bytes.Equal(previous, data) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return atomicNativeFile(dir, "StackdMQMetrics.class", data, 0644)
}

// This deliberately implements only HotSpot 11's agentProperties operation:
// https://github.com/openjdk/jdk11u/blob/jdk-11.0.26-ga/src/hotspot/os/linux/attachListener_linux.cpp
// https://github.com/openjdk/jdk11u/blob/jdk-11.0.26-ga/src/jdk.attach/linux/classes/sun/tools/attach/VirtualMachineImpl.java
// Trigger and socket remain inside the exact-owned container's PID/filesystem
// namespace. Only a positively identified native JVM may receive SIGQUIT.
const activeMQMetricsAttach = `
use strict;
use warnings;
use Fcntl qw(O_WRONLY O_CREAT O_EXCL S_ISSOCK);
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);
my $broker = shift @ARGV;
die "missing broker identity" unless defined($broker) && !@ARGV;
my @targets;
my %commands;
for my $path (glob('/proc/[0-9]*/cmdline')) {
    open(my $file, '<', $path) or next;
    my $command = do { local $/; <$file> };
    close($file);
    next unless defined($command);
    my @args = split(/\0/, $command);
    next unless @args && $args[0] eq '/opt/java/openjdk/bin/java';
    next unless grep { $_ eq '-Dactivemq.home=/opt/apache-activemq' } @args;
    next unless grep { $_ eq 'xbean:file:/stackd/activemq.xml' } @args;
    die "native local management unavailable" unless grep { $_ eq '-Dcom.sun.management.jmxremote' } @args;
    die "non-local native management configuration" if grep { /^-Dcom\.sun\.management\.(?:jmxremote\.(?:port|rmi\.port|local\.only)|config\.file)=/ } @args;
    die "native attach disabled" if grep { $_ eq '-XX:+DisableAttachMechanism' } @args;
    my $jar = 0;
    for (my $i = 0; $i + 1 < @args; $i++) {
        $jar = 1 if $args[$i] eq '-jar' && $args[$i+1] eq '/opt/apache-activemq/bin/activemq.jar';
    }
    next unless $jar;
    $path =~ m{^/proc/([1-9][0-9]*)/cmdline$} or die "invalid native PID";
    my $pid = $1;
    my @owner = stat("/proc/$pid");
    die "foreign JVM owner" unless @owner && $owner[4] == $<;
    die "foreign JVM executable" unless readlink("/proc/$pid/exe") eq '/opt/java/openjdk/bin/java';
    push(@targets, $pid);
    $commands{$pid} = $command;
}
die "missing or ambiguous native JVM" unless @targets == 1;
my $pid = $targets[0];
my $socket = "/tmp/.java_pid$pid";
my $trigger = "/tmp/.attach_pid$pid";
my @created;
sub remove_trigger {
    return unless @created;
    my @info = lstat($trigger);
    die "native attach trigger ownership changed" unless @info && $info[0] == $created[0] && $info[1] == $created[1] && $info[4] == $<;
    unlink($trigger) or die "removing native attach trigger: $!";
    @created = ();
}
END { remove_trigger(); }
sub owned_socket {
    my @info = lstat($socket);
    return 0 unless @info;
    die "foreign attach socket" unless S_ISSOCK($info[2]) && $info[4] == $< && ($info[2] & 0077) == 0;
    return 1;
}
if (!owned_socket()) {
    sysopen(my $file, $trigger, O_WRONLY | O_CREAT | O_EXCL, 0600) or die "creating native attach trigger: $!";
    @created = stat($file);
    close($file) or die "closing native attach trigger: $!";
    open(my $identity, '<', "/proc/$pid/cmdline") or die "native JVM disappeared";
    my $current = do { local $/; <$identity> };
    close($identity);
    die "native JVM changed before attach" unless defined($current) && $current eq $commands{$pid}
        && readlink("/proc/$pid/exe") eq '/opt/java/openjdk/bin/java';
    kill('QUIT', $pid) == 1 or die "signalling native JVM: $!";
    for (1..100) {
        last if owned_socket();
        select(undef, undef, undef, 0.05);
    }
    die "native attach timed out" unless owned_socket();
    remove_trigger();
}
my $client = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $socket) or die "connecting native attach: $!";
my $request = "1\0agentProperties\0\0\0\0";
my $offset = 0;
while ($offset < length($request)) {
    my $written = syswrite($client, $request, length($request) - $offset, $offset);
    die "writing native attach: $!" unless $written;
    $offset += $written;
}
my $response = '';
while (1) {
    my $count = sysread($client, my $part, 8192);
    die "reading native attach: $!" unless defined($count);
    last if $count == 0;
    $response .= $part;
    die "oversized native agent properties" if length($response) > 65536;
}
close($client) or die "closing native attach: $!";
$response =~ s/^0\n// or die "native attach failed";
open(my $java, '|-', '/opt/java/openjdk/bin/java', '-Xms16m', '-Xmx64m', '-cp', '/stackd', 'StackdMQMetrics', $broker, $pid)
    or die "starting native JMX reader: $!";
print {$java} $response or die "writing native agent properties: $!";
close($java) or die "native JMX reader failed";
`

func parseActiveMQMetrics(data []byte) (service.MetricSnapshot, error) {
	var output struct {
		Connections                     *int64 `json:"connections"`
		Consumers                       *int64 `json:"consumers"`
		Messages                        *int64 `json:"messages"`
		Producers                       *int64 `json:"producers"`
		InactiveDurableTopicSubscribers *int64 `json:"inactive_durable_topic_subscribers"`
		Destinations                    []struct {
			Name      *string `json:"name"`
			Kind      *string `json:"kind"`
			QueueSize *int64  `json:"queue_size"`
			Consumers *int64  `json:"consumers"`
			Producers *int64  `json:"producers"`
		} `json:"destinations"`
	}
	if len(data) > mqMetricReadBytes || !utf8.Valid(data) {
		return service.MetricSnapshot{}, errors.New("invalid or oversized native ActiveMQ metrics response")
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return service.MetricSnapshot{}, fmt.Errorf("invalid native ActiveMQ metrics response: %w", err)
	}
	if output.Connections == nil || output.Consumers == nil || output.Messages == nil || output.Producers == nil ||
		output.InactiveDurableTopicSubscribers == nil || output.Destinations == nil ||
		*output.Connections < 0 || *output.Consumers < 0 || *output.Messages < 0 || *output.Producers < 0 || *output.InactiveDurableTopicSubscribers < 0 {
		return service.MetricSnapshot{}, errors.New("incomplete native ActiveMQ broker metrics")
	}
	snapshot := &service.ActiveMQMetrics{
		Connections: *output.Connections, Consumers: *output.Consumers, Messages: *output.Messages, Producers: *output.Producers,
		InactiveDurableTopicSubscribers: *output.InactiveDurableTopicSubscribers,
		Destinations:                    make([]service.ActiveMQDestinationMetrics, 0, len(output.Destinations)),
	}
	for _, row := range output.Destinations {
		if row.Name == nil || *row.Name == "" || row.Kind == nil || (*row.Kind != "Queue" && *row.Kind != "Topic") ||
			row.Consumers == nil || *row.Consumers < 0 || row.Producers == nil || *row.Producers < 0 {
			return service.MetricSnapshot{}, errors.New("incomplete native ActiveMQ destination metrics")
		}
		destination := service.ActiveMQDestinationMetrics{Name: *row.Name, Kind: *row.Kind, Consumers: *row.Consumers, Producers: *row.Producers}
		if *row.Kind == "Queue" {
			if row.QueueSize == nil || *row.QueueSize < 0 {
				return service.MetricSnapshot{}, errors.New("missing or invalid native ActiveMQ queue size")
			}
			destination.QueueSize = *row.QueueSize
		} else if row.QueueSize != nil {
			return service.MetricSnapshot{}, errors.New("unexpected native ActiveMQ topic queue size")
		}
		snapshot.Destinations = append(snapshot.Destinations, destination)
	}
	slices.SortFunc(snapshot.Destinations, func(a, b service.ActiveMQDestinationMetrics) int {
		if order := strings.Compare(a.Kind, b.Kind); order != 0 {
			return order
		}
		return strings.Compare(a.Name, b.Name)
	})
	for index := 1; index < len(snapshot.Destinations); index++ {
		previous, current := snapshot.Destinations[index-1], snapshot.Destinations[index]
		if previous.Kind == current.Kind && previous.Name == current.Name {
			return service.MetricSnapshot{}, errors.New("duplicate native ActiveMQ destination")
		}
	}
	return service.MetricSnapshot{ActiveMQ: snapshot}, nil
}

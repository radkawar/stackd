package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	rabbitMetricDirectExchange = "owned-metrics-direct"
	rabbitMetricFanoutExchange = "owned-metrics-fanout"
	rabbitMetricOtherVhost     = "owned-metrics-other"
)

type rabbitMetricExchange struct {
	Name  string `json:"name"`
	Vhost string `json:"vhost"`
	Type  string `json:"type"`
}

func rabbitSetMetricExchange(ctx context.Context, traffic *rabbitMetricActivity, exchange rabbitMetricExchange, present bool, record func(string, any)) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stopDeadline := context.AfterFunc(bounded, func() { traffic.connection.CloseDeadline(time.Now().Add(time.Second)) })
	defer stopDeadline()
	if present {
		must(traffic.channel.ExchangeDeclare(exchange.Name, exchange.Type, true, false, false, false, nil))
	} else {
		must(traffic.channel.ExchangeDelete(exchange.Name, false, false))
	}
	record("custom exchange changed through native AMQP", map[string]any{"exchange": exchange, "present": present})
}

func rabbitMetricDefaultExchanges(ctx context.Context, management *rabbitManagementHTTP, record func(string, any)) []rabbitMetricExchange {
	management.expect(ctx, "create exact-owned second native virtual host", http.MethodPut, "/api/vhosts/"+rabbitMetricOtherVhost, "{}", true, http.StatusCreated)
	exchanges := rabbitMetricExchangeInventory(ctx, management, "independent default exchanges across virtual hosts")
	defaults := make(map[string]bool)
	counts := make(map[string]int)
	for _, exchange := range exchanges {
		if exchange.Vhost != "/" && exchange.Vhost != rabbitMetricOtherVhost {
			panic("fresh broker contained an unexpected virtual host")
		}
		if exchange.Name == rabbitMetricDirectExchange || exchange.Name == rabbitMetricFanoutExchange {
			panic("fresh broker already contained an owned custom exchange")
		}
		counts[exchange.Vhost]++
		if exchange.Name == "" {
			defaults[exchange.Vhost] = true
		}
	}
	if !defaults["/"] || !defaults[rabbitMetricOtherVhost] {
		panic("native inventory omitted a virtual host's default exchange")
	}
	record("independently observed exchange baseline includes every virtual host and nameless default", map[string]any{"perVhost": counts, "total": len(exchanges)})
	return exchanges
}

// Exchange definitions remain available with management statistics disabled.
// Discover all native defaults, including the nameless exchange, independently
// of the metric source instead of pinning an image-specific default count.
func rabbitMetricExchangeInventory(ctx context.Context, management *rabbitManagementHTTP, stage string) []rabbitMetricExchange {
	data := management.expect(ctx, stage+" native exchange inventory", http.MethodGet, "/api/exchanges", "", true, http.StatusOK)
	var exchanges []rabbitMetricExchange
	must(json.Unmarshal(data, &exchanges))
	seen := make(map[string]bool, len(exchanges))
	defaultExchange := false
	for _, exchange := range exchanges {
		key := exchange.Vhost + "\x00" + exchange.Name
		if seen[key] || exchange.Vhost == "" || exchange.Type == "" {
			panic("native exchange inventory contained duplicate or incomplete definitions")
		}
		seen[key] = true
		if exchange.Vhost == "/" && exchange.Name == "" {
			defaultExchange = true
		}
	}
	if !defaultExchange {
		panic("native exchange inventory omitted the default exchange")
	}
	rabbitSortMetricExchanges(exchanges)
	return exchanges
}

func rabbitSortMetricExchanges(exchanges []rabbitMetricExchange) {
	sort.Slice(exchanges, func(i, j int) bool {
		if exchanges[i].Vhost != exchanges[j].Vhost {
			return exchanges[i].Vhost < exchanges[j].Vhost
		}
		return exchanges[i].Name < exchanges[j].Name
	})
}

func rabbitAssertMetricExchanges(ctx context.Context, management *rabbitManagementHTTP, stage string, defaults []rabbitMetricExchange, custom ...rabbitMetricExchange) {
	expected := append(append([]rabbitMetricExchange(nil), defaults...), custom...)
	rabbitSortMetricExchanges(expected)
	actual := rabbitMetricExchangeInventory(ctx, management, stage)
	if !reflect.DeepEqual(actual, expected) {
		panic(fmt.Sprintf("%s: native exchange definitions differ: actual=%+v expected=%+v", stage, actual, expected))
	}
}

func rabbitMetricInventorySpecs(broker string, exchanges, connections, channels int) []rabbitMetricSpec {
	dimensions := []cwtypes.Dimension{{Name: aws.String("Broker"), Value: aws.String(broker)}}
	return []rabbitMetricSpec{{"ExchangeCount", dimensions, float64(exchanges)}, {"ConnectionCount", dimensions, float64(connections)}, {"ChannelCount", dimensions, float64(channels)}}
}

type rabbitMetricExtraConnection struct {
	connection   *amqp.Connection
	channels     []*amqp.Channel
	stopDeadline func() bool
}

// Each invocation opens a distinct AMQP socket, and each Channel call waits for
// the native channel-open reply. HTTP inspection opens no AMQP connections.
func rabbitOpenMetricConnection(ctx context.Context, cloud *controller, address, stage string, channels int, record func(string, any)) *rabbitMetricExtraConnection {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	activity := &rabbitMetricExtraConnection{connection: rabbitConnection(cloud, address)}
	activity.stopDeadline = context.AfterFunc(ctx, func() { activity.connection.CloseDeadline(time.Now().Add(time.Second)) })
	stopSetupDeadline := context.AfterFunc(bounded, func() { activity.connection.CloseDeadline(time.Now().Add(time.Second)) })
	defer stopSetupDeadline()
	complete := false
	defer func() {
		if !complete {
			activity.close()
		}
	}()
	for range channels {
		channel, err := activity.connection.Channel()
		must(err)
		activity.channels = append(activity.channels, channel)
	}
	record(stage+" opened distinct physical connection and channels", map[string]any{"local": activity.connection.LocalAddr().String(), "remote": activity.connection.RemoteAddr().String(), "channels": channels})
	complete = true
	return activity
}

func (activity *rabbitMetricExtraConnection) closeChannel(ctx context.Context, index int, stage string, record func(string, any)) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stopDeadline := context.AfterFunc(bounded, func() { activity.connection.CloseDeadline(time.Now().Add(time.Second)) })
	defer stopDeadline()
	must(activity.channels[index].Close())
	record(stage+" closed physical channel without closing connection", map[string]any{"local": activity.connection.LocalAddr().String(), "channelIndex": index})
	if activity.connection.IsClosed() {
		panic("closing one native channel also closed its AMQP connection")
	}
}

func (activity *rabbitMetricExtraConnection) close() {
	if activity.stopDeadline != nil {
		activity.stopDeadline()
	}
	if activity.connection != nil && !activity.connection.IsClosed() {
		must(activity.connection.CloseDeadline(time.Now().Add(3 * time.Second)))
	}
}

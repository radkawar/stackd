package mq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	service "stackd/internal/services/mq"
)

const mqMetricReadBytes = 8 << 20

var _ service.MetricSource = (*Runtime)(nil)

// ReadMetrics queries live native inventories and instantaneous counters. It
// never consumes messages, starts a broker or uses customer credentials.
func (r *Runtime) ReadMetrics(ctx context.Context, v service.BrokerRecord) (service.MetricSnapshot, error) {
	if v.Engine != "RABBITMQ" && v.Engine != "ACTIVEMQ" {
		return service.MetricSnapshot{}, errors.New("unsupported native MQ metrics engine")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := r.lock(ctx); err != nil {
		return service.MetricSnapshot{}, err
	}
	defer r.unlock()
	native, err := r.inspect(ctx, v)
	if err != nil {
		return service.MetricSnapshot{}, err
	}
	if err = r.checkNativeStorage(ctx, v, native); err != nil {
		return service.MetricSnapshot{}, err
	}
	if !native.State.Running || native.ID == "" || native.ID != v.Endpoint.NativeID {
		return service.MetricSnapshot{}, errors.New("native MQ metrics require the current owned container to be running")
	}
	if v.Engine == "ACTIVEMQ" {
		return r.readActiveMQMetrics(ctx, v, native.ID)
	}
	// Bound both the Docker request and the native CLI/remote evaluator: merely
	// cancelling an attached Docker exec does not terminate its process.
	data, err := r.execNative(ctx, native.ID, []string{"env", "RABBITMQ_CTL_ERL_ARGS=+S 2:2", "timeout", "--signal=KILL", "25", "rabbitmqctl", "--quiet", "--formatter", "json", "eval", rabbitQueueMetricsExpression}, mqMetricReadBytes)
	if err != nil {
		return service.MetricSnapshot{}, err
	}
	return parseRabbitQueueMetrics(data)
}

// RabbitMQ 3.13.7's list/info_all helpers filter unavailable queues or swallow
// per-queue exits. Instead merge durable and live inventories (live wins), then
// query each queue directly and require every counter. This covers all vhosts,
// including queues in an unavailable vhost: those must fail, not disappear.
// Compare inventory records and vhosts again after sampling to reject churn.
// Counters are per-queue observations, not an atomic cross-queue transaction.
// Quorum info/2 defaults missing ETS statistics to zero, so query the live Ra
// FIFO instead. Other queue types fail the entire snapshot; Amazon MQ does not
// support streams, and missing/stale management statistics are not live counters.
// Broker inventories target the pinned single-node Mnesia runtime. Read exchange
// keys directly: the table size helper can return zero for an unavailable table,
// and the Khepri list helper swallows errors. Reject another/changing backend.
// AMQP connections and channels come from their native process registry, not
// Erlang distribution peers or management counters. A fresh broker lazily has no
// registry: prove emptiness from AMQP listener and direct-channel supervisors
// without initializing it. Otherwise require the registry's identity to survive
// both reads; unavailable supervision or a registry change fails the snapshot.
// Native registry joins/leaves are asynchronous and include AMQP handshakes;
// these counts and exchange keys are not an atomic cross-inventory observation.
// The monitored worker also bounds native work if the client disconnects.
const rabbitQueueMetricsExpression = `
Parent = self(), Ref = make_ref(),
{Pid, Monitor} = spawn_monitor(fun() ->
    disabled = rabbit_khepri:get_feature_state(),
    true = rabbit_nodes:list_members() =:= [node()],
    Exchanges = mnesia:dirty_all_keys(rabbit_exchange),
    Inventory = fun() ->
        lists:sort(maps:to_list(maps:from_list(
            [{amqqueue:get_name(Q), Q} || Q <- rabbit_amqqueue:list_durable() ++ rabbit_db_queue:get_all()])))
    end,
    VHosts = lists:sort(rabbit_vhost:list_names()),
    Queues = Inventory(),
    Counter = fun(Key, Info) ->
        {Key, N} = lists:keyfind(Key, 1, Info),
        true = is_integer(N) andalso N >= 0,
        N
    end,
    Rows = lists:map(fun({Resource, Q}) ->
        VHost = rabbit_amqqueue:get_resource_vhost_name(Resource),
        true = lists:member(VHost, VHosts),
        Info = case amqqueue:get_type(Q) of
            rabbit_classic_queue ->
                rabbit_amqqueue:info(Q, [messages_ready, messages_unacknowledged, consumers]);
            rabbit_quorum_queue ->
                {ok, {_, Counts}, _} = ra:local_query(amqqueue:get_pid(Q), fun(State) ->
                    [{messages_ready, rabbit_fifo:query_messages_ready(State)},
                     {messages_unacknowledged, rabbit_fifo:query_messages_checked_out(State)},
                     {consumers, rabbit_fifo:query_consumer_count(State)}]
                end, 5000),
                Counts;
            Type ->
                error({unsupported_queue_type, Type})
        end,
        #{virtual_host => VHost,
          name => rabbit_amqqueue:get_resource_name(Resource),
          ready => Counter(messages_ready, Info),
          unacknowledged => Counter(messages_unacknowledged, Info),
          consumers => Counter(consumers, Info)}
    end, Queues),
    Queues = Inventory(),
    VHosts = lists:sort(rabbit_vhost:list_names()),
    {Connections, Channels} = case whereis(pg_local) of
        undefined ->
            Listeners = [rabbit_networking:ranch_ref(IP, Port)
                         || {listener, _, Protocol, _, IP, Port, _} <-
                                rabbit_networking:node_listeners(node()),
                            Protocol =:= amqp orelse Protocol =:= 'amqp/ssl'],
            true = Listeners =/= [],
            [] = lists:append([ranch:procs(L, connections) || L <- Listeners]),
            [] = supervisor:which_children(rabbit_direct_client_sup),
            undefined = whereis(pg_local),
            {[], []};
        Registry when is_pid(Registry) ->
            ConnectionPids = rabbit_networking:local_connections(),
            ChannelPids = rabbit_channel:list_local(),
            Registry = whereis(pg_local),
            true = is_process_alive(Registry),
            {ConnectionPids, ChannelPids}
    end,
    disabled = rabbit_khepri:get_feature_state(),
    true = rabbit_nodes:list_members() =:= [node()],
    Parent ! {Ref, #{queues => Rows, exchanges => length(Exchanges),
                    connections => length(Connections), channels => length(Channels)}}
end),
receive
    {Ref, Result} -> demonitor(Monitor, [flush]), Result;
    {'DOWN', Monitor, process, Pid, Reason} -> error({metrics_read_failed, Reason})
after 20000 ->
    exit(Pid, kill), error(metrics_read_timeout)
end.
`

func parseRabbitQueueMetrics(data []byte) (service.MetricSnapshot, error) {
	var output struct {
		Result string `json:"result"`
		Value  *struct {
			Queues []struct {
				VirtualHost    *string `json:"virtual_host"`
				Name           *string `json:"name"`
				Ready          *int64  `json:"ready"`
				Unacknowledged *int64  `json:"unacknowledged"`
				Consumers      *int64  `json:"consumers"`
			} `json:"queues"`
			Exchanges   *int64 `json:"exchanges"`
			Connections *int64 `json:"connections"`
			Channels    *int64 `json:"channels"`
		} `json:"value"`
	}
	if len(data) > mqMetricReadBytes || !utf8.Valid(data) {
		return service.MetricSnapshot{}, errors.New("invalid or oversized native MQ metrics response")
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return service.MetricSnapshot{}, fmt.Errorf("invalid native MQ metrics response: %w", err)
	}
	if output.Result != "ok" || output.Value == nil || output.Value.Queues == nil {
		return service.MetricSnapshot{}, errors.New("incomplete native MQ queue inventory")
	}
	if output.Value.Exchanges == nil || output.Value.Connections == nil || output.Value.Channels == nil || *output.Value.Exchanges < 0 || *output.Value.Connections < 0 || *output.Value.Channels < 0 {
		return service.MetricSnapshot{}, errors.New("missing or invalid native MQ broker counters")
	}
	snapshot := &service.RabbitMQMetrics{
		Queues:      make([]service.QueueMetrics, 0, len(output.Value.Queues)),
		Exchanges:   *output.Value.Exchanges,
		Connections: *output.Value.Connections,
		Channels:    *output.Value.Channels,
	}
	for _, row := range output.Value.Queues {
		if row.VirtualHost == nil || row.Name == nil || row.Ready == nil || row.Unacknowledged == nil || row.Consumers == nil || *row.Ready < 0 || *row.Unacknowledged < 0 || *row.Consumers < 0 {
			return service.MetricSnapshot{}, errors.New("missing or invalid native MQ queue counters")
		}
		snapshot.Queues = append(snapshot.Queues, service.QueueMetrics{VirtualHost: *row.VirtualHost, Name: *row.Name, Ready: *row.Ready, Unacknowledged: *row.Unacknowledged, Consumers: *row.Consumers})
	}
	slices.SortFunc(snapshot.Queues, func(a, b service.QueueMetrics) int {
		if order := strings.Compare(a.VirtualHost, b.VirtualHost); order != 0 {
			return order
		}
		return strings.Compare(a.Name, b.Name)
	})
	for index := 1; index < len(snapshot.Queues); index++ {
		previous, current := snapshot.Queues[index-1], snapshot.Queues[index]
		if previous.VirtualHost == current.VirtualHost && previous.Name == current.Name {
			return service.MetricSnapshot{}, errors.New("duplicate native MQ queue inventory entry")
		}
	}
	return service.MetricSnapshot{RabbitMQ: snapshot}, nil
}

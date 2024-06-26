package coord

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/benbjohnson/clock"
	"github.com/plprobelab/go-libdht/kad"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/exp/slog"

	"github.com/plprobelab/zikade/errs"
	"github.com/plprobelab/zikade/internal/coord/brdcst"
	"github.com/plprobelab/zikade/internal/coord/coordt"
	"github.com/plprobelab/zikade/internal/coord/routing"
	"github.com/plprobelab/zikade/kadt"
	"github.com/plprobelab/zikade/pb"
	"github.com/plprobelab/zikade/tele"
)

// A Coordinator coordinates the state machines that comprise a Kademlia DHT
type Coordinator struct {
	// self is the peer id of the system the dht is running on
	self kadt.PeerID

	// cancel is used to cancel all running goroutines when the coordinator is cleaning up
	cancel context.CancelFunc

	// done will be closed when the coordinator's eventLoop exits. Block-read
	// from this channel to wait until resources of this coordinator were
	// cleaned up
	done chan struct{}

	// cfg is a copy of the optional configuration supplied to the dht
	cfg CoordinatorConfig

	// rt is the routing table used to look up nodes by distance
	rt kad.RoutingTable[kadt.Key, kadt.PeerID]

	// rtr is the message router used to send messages
	rtr coordt.Router[kadt.Key, kadt.PeerID, *pb.Message]

	// networkBehaviour is the behaviour responsible for communicating with the network
	networkBehaviour *NetworkBehaviour

	// routingBehaviour is the behaviour responsible for maintaining the routing table
	routingBehaviour Behaviour[BehaviourEvent, BehaviourEvent]

	// queryBehaviour is the behaviour responsible for running user-submitted queries
	queryBehaviour Behaviour[BehaviourEvent, BehaviourEvent]

	// brdcstBehaviour is the behaviour responsible for running user-submitted queries to store records with nodes
	brdcstBehaviour Behaviour[BehaviourEvent, BehaviourEvent]

	// tele provides tracing and metric reporting capabilities
	tele *Telemetry

	// routingNotifierMu guards access to routingNotifier which may be changed during coordinator operation
	routingNotifierMu sync.RWMutex

	// routingNotifier receives routing notifications
	routingNotifier RoutingNotifier

	// lastQueryID holds the last numeric query id generated
	lastQueryID atomic.Uint64
}

type RoutingNotifier interface {
	Notify(context.Context, RoutingNotification)
}

type CoordinatorConfig struct {
	// Clock is a clock that may replaced by a mock when testing
	Clock clock.Clock

	// Logger is a structured logger that will be used when logging.
	Logger *slog.Logger

	// MeterProvider is the the meter provider to use when initialising metric instruments.
	MeterProvider metric.MeterProvider

	// TracerProvider is the tracer provider to use when initialising tracing
	TracerProvider trace.TracerProvider

	// Routing is the configuration used for the [RoutingBehaviour] which maintains the health of the routing table.
	Routing RoutingConfig

	// Query is the configuration used for the [PooledQueryBehaviour] which manages the execution of user queries.
	Query QueryConfig
}

// Validate checks the configuration options and returns an error if any have invalid values.
func (cfg *CoordinatorConfig) Validate() error {
	if cfg.Clock == nil {
		return &errs.ConfigurationError{
			Component: "CoordinatorConfig",
			Err:       fmt.Errorf("clock must not be nil"),
		}
	}

	if cfg.Logger == nil {
		return &errs.ConfigurationError{
			Component: "CoordinatorConfig",
			Err:       fmt.Errorf("logger must not be nil"),
		}
	}

	if cfg.MeterProvider == nil {
		return &errs.ConfigurationError{
			Component: "CoordinatorConfig",
			Err:       fmt.Errorf("meter provider must not be nil"),
		}
	}

	if cfg.TracerProvider == nil {
		return &errs.ConfigurationError{
			Component: "CoordinatorConfig",
			Err:       fmt.Errorf("tracer provider must not be nil"),
		}
	}

	return nil
}

func DefaultCoordinatorConfig() *CoordinatorConfig {
	cfg := &CoordinatorConfig{
		Clock: clock.New(),

		Logger:         tele.DefaultLogger("coord"),
		MeterProvider:  otel.GetMeterProvider(),
		TracerProvider: otel.GetTracerProvider(),
	}

	cfg.Query = *DefaultQueryConfig()
	cfg.Query.Clock = cfg.Clock
	cfg.Query.Logger = cfg.Logger.With("behaviour", "pooledquery")
	cfg.Query.Tracer = cfg.TracerProvider.Tracer(tele.TracerName)

	cfg.Routing = *DefaultRoutingConfig()
	cfg.Routing.Clock = cfg.Clock
	cfg.Routing.Logger = cfg.Logger.With("behaviour", "routing")
	cfg.Routing.Tracer = cfg.TracerProvider.Tracer(tele.TracerName)
	cfg.Routing.Meter = cfg.MeterProvider.Meter(tele.MeterName)

	return cfg
}

func NewCoordinator(self kadt.PeerID, rtr coordt.Router[kadt.Key, kadt.PeerID, *pb.Message], rt routing.RoutingTableCpl[kadt.Key, kadt.PeerID], cfg *CoordinatorConfig) (*Coordinator, error) {
	if cfg == nil {
		cfg = DefaultCoordinatorConfig()
	} else if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// initialize a new telemetry struct
	tele, err := NewTelemetry(cfg.MeterProvider, cfg.TracerProvider)
	if err != nil {
		return nil, fmt.Errorf("init telemetry: %w", err)
	}

	queryBehaviour, err := NewQueryBehaviour(self, &cfg.Query)
	if err != nil {
		return nil, fmt.Errorf("query behaviour: %w", err)
	}

	routingBehaviour, err := NewRoutingBehaviour(self, rt, &cfg.Routing)
	if err != nil {
		return nil, fmt.Errorf("routing behaviour: %w", err)
	}

	networkBehaviour := NewNetworkBehaviour(rtr, cfg.Logger, tele.Tracer)

	b, err := brdcst.NewPool[kadt.Key, kadt.PeerID, *pb.Message](self, nil)
	if err != nil {
		return nil, fmt.Errorf("broadcast: %w", err)
	}

	brdcstBehaviour := NewPooledBroadcastBehaviour(b, cfg.Logger, tele.Tracer)

	ctx, cancel := context.WithCancel(context.Background())

	d := &Coordinator{
		self:   self,
		tele:   tele,
		cfg:    *cfg,
		rtr:    rtr,
		rt:     rt,
		cancel: cancel,
		done:   make(chan struct{}),

		networkBehaviour: networkBehaviour,
		routingBehaviour: routingBehaviour,
		queryBehaviour:   queryBehaviour,
		brdcstBehaviour:  brdcstBehaviour,

		routingNotifier: nullRoutingNotifier{},
	}

	go d.eventLoop(ctx)

	return d, nil
}

// Close cleans up all resources associated with this Coordinator.
func (c *Coordinator) Close() error {
	c.cancel()
	<-c.done
	return nil
}

func (c *Coordinator) ID() kadt.PeerID {
	return c.self
}

func (c *Coordinator) eventLoop(ctx context.Context) {
	defer close(c.done)

	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.eventLoop")
	defer span.End()

	for {
		var ev BehaviourEvent
		var ok bool

		select {
		case <-ctx.Done():
			// coordinator is closing
			return
		case <-c.networkBehaviour.Ready():
			ev, ok = c.networkBehaviour.Perform(ctx)
		case <-c.routingBehaviour.Ready():
			ev, ok = c.routingBehaviour.Perform(ctx)
		case <-c.queryBehaviour.Ready():
			ev, ok = c.queryBehaviour.Perform(ctx)
		case <-c.brdcstBehaviour.Ready():
			ev, ok = c.brdcstBehaviour.Perform(ctx)
		}

		if ok {
			c.dispatchEvent(ctx, ev)
		}
	}
}

func (c *Coordinator) dispatchEvent(ctx context.Context, ev BehaviourEvent) {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.dispatchEvent", trace.WithAttributes(attribute.String("event_type", fmt.Sprintf("%T", ev))))
	defer span.End()

	switch ev := ev.(type) {
	case NetworkCommand:
		c.networkBehaviour.Notify(ctx, ev)
	case QueryCommand:
		c.queryBehaviour.Notify(ctx, ev)
	case BrdcstCommand:
		c.brdcstBehaviour.Notify(ctx, ev)
	case RoutingCommand:
		c.routingBehaviour.Notify(ctx, ev)
	case RoutingNotification:
		c.routingNotifierMu.RLock()
		rn := c.routingNotifier
		c.routingNotifierMu.RUnlock()
		rn.Notify(ctx, ev)
	default:
		panic(fmt.Sprintf("unexpected event: %T", ev))
	}
}

func (c *Coordinator) SetRoutingNotifier(rn RoutingNotifier) {
	c.routingNotifierMu.Lock()
	c.routingNotifier = rn
	c.routingNotifierMu.Unlock()
}

// IsRoutable reports whether the supplied node is present in the local routing table.
func (c *Coordinator) IsRoutable(ctx context.Context, id kadt.PeerID) bool {
	_, exists := c.rt.GetNode(id.Key())

	return exists
}

// GetClosestNodes requests the n closest nodes to the key from the node's local routing table.
func (c *Coordinator) GetClosestNodes(ctx context.Context, k kadt.Key, n int) ([]kadt.PeerID, error) {
	return c.rt.NearestNodes(k, n), nil
}

// QueryPrivate reimplements QueryMessage, when the message sent to each node may be different
// When privately retrieving peer records from other nodes, the PIR requests to each node are different.
// TODO: fn should be of the type coordt.QueryFunc and more specifically, it should process PIR responses.
func (c *Coordinator) QueryPrivate(ctx context.Context, msg *pb.Message, fn coordt.QueryFunc, numResults int) ([]kadt.PeerID, coordt.QueryStats, error) {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.QueryPrivate")
	defer span.End()
	if msg == nil {
		return nil, coordt.QueryStats{}, fmt.Errorf("no message supplied for query")
	}
	c.cfg.Logger.Debug("starting query with message", tele.LogAttrKey(msg.Target()), slog.String("type", msg.Type.String()))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if numResults < 1 {
		numResults = 20 // TODO: parameterize
	}

	// This is a local lookup. TODO: Make sure it doesn't go through NearestNodesAsServer, only normal NearestNodes
	seedIDs, err := c.GetClosestNodes(ctx, msg.Target(), numResults)
	if err != nil {
		return nil, coordt.QueryStats{}, err
	}

	waiter := NewQueryWaiter(numResults)
	queryID := c.newOperationID()

	// TODO: Generate a ciphertext message from plaintext msg
	//  For routing, generate the ciphertext PIR request
	//   using the target node's kadID and the plaintext msg
	cmd := &EventStartMessageQuery{
		QueryID:           queryID,
		Target:            msg.Target(),
		Message:           msg,
		KnownClosestNodes: seedIDs,
		Notify:            waiter,
		NumResults:        numResults,
	}

	// queue the start of the query
	c.queryBehaviour.Notify(ctx, cmd)

	closest, stats, err := c.waitForQuery(ctx, queryID, waiter, fn)
	return closest, stats, err
}

// QueryClosest starts a query that attempts to find the closest nodes to the target key.
// It returns the closest nodes found to the target key and statistics on the actions of the query.
//
// The supplied [QueryFunc] is called after each successful request to a node with the ID of the node,
// the response received from the find nodes request made to the node and the current query stats. The query
// terminates when [QueryFunc] returns an error or when the query has visited the configured minimum number
// of closest nodes (default 20)
//
// numResults specifies the minimum number of nodes to successfully contact before considering iteration complete.
// The query is considered to be exhausted when it has received responses from at least this number of nodes
// and there are no closer nodes remaining to be contacted. A default of 20 is used if this value is less than 1.
func (c *Coordinator) QueryClosest(ctx context.Context, target kadt.Key, fn coordt.QueryFunc, numResults int) ([]kadt.PeerID, coordt.QueryStats, error) {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.Query")
	defer span.End()
	c.cfg.Logger.Debug("starting query for closest nodes", tele.LogAttrKey(target))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	seedIDs, err := c.GetClosestNodes(ctx, target, 20)
	if err != nil {
		return nil, coordt.QueryStats{}, err
	}

	waiter := NewQueryWaiter(numResults)
	queryID := c.newOperationID()

	cmd := &EventStartFindCloserQuery{
		QueryID:           queryID,
		Target:            target,
		KnownClosestNodes: seedIDs,
		Notify:            waiter,
		NumResults:        numResults,
	}

	// queue the start of the query
	c.queryBehaviour.Notify(ctx, cmd)

	return c.waitForQuery(ctx, queryID, waiter, fn)
}

// QueryMessage starts a query that iterates over the closest nodes to the target key in the supplied message.
// The message is sent to each node that is visited.
//
// The supplied [QueryFunc] is called after each successful request to a node with the ID of the node,
// the response received from the find nodes request made to the node and the current query stats. The query
// terminates when [QueryFunc] returns an error or when the query has visited the configured minimum number
// of closest nodes (default 20)
//
// numResults specifies the minimum number of nodes to successfully contact before considering iteration complete.
// The query is considered to be exhausted when it has received responses from at least this number of nodes
// and there are no closer nodes remaining to be contacted. A default of 20 is used if this value is less than 1.
func (c *Coordinator) QueryMessage(ctx context.Context, msg *pb.Message, fn coordt.QueryFunc, numResults int) ([]kadt.PeerID, coordt.QueryStats, error) {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.QueryMessage")
	defer span.End()
	if msg == nil {
		return nil, coordt.QueryStats{}, fmt.Errorf("no message supplied for query")
	}
	c.cfg.Logger.Debug("starting query with message", tele.LogAttrKey(msg.Target()), slog.String("type", msg.Type.String()))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if numResults < 1 {
		numResults = 20 // TODO: parameterize
	}

	seedIDs, err := c.GetClosestNodes(ctx, msg.Target(), numResults)
	if err != nil {
		return nil, coordt.QueryStats{}, err
	}

	waiter := NewQueryWaiter(numResults)
	queryID := c.newOperationID()

	cmd := &EventStartMessageQuery{
		QueryID:           queryID,
		Target:            msg.Target(),
		Message:           msg,
		KnownClosestNodes: seedIDs,
		Notify:            waiter,
		NumResults:        numResults,
	}

	// queue the start of the query
	c.queryBehaviour.Notify(ctx, cmd)

	closest, stats, err := c.waitForQuery(ctx, queryID, waiter, fn)
	return closest, stats, err
}

func (c *Coordinator) BroadcastRecord(ctx context.Context, msg *pb.Message) error {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.BroadcastRecord")
	defer span.End()
	if msg == nil {
		return fmt.Errorf("no message supplied for broadcast")
	}
	c.cfg.Logger.Debug("starting broadcast with message", tele.LogAttrKey(msg.Target()), slog.String("type", msg.Type.String()))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	seeds, err := c.GetClosestNodes(ctx, msg.Target(), 20) // TODO: parameterize
	if err != nil {
		return err
	}
	return c.broadcast(ctx, msg, seeds, brdcst.DefaultConfigFollowUp())
}

func (c *Coordinator) BroadcastStatic(ctx context.Context, msg *pb.Message, seeds []kadt.PeerID) error {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.BroadcastStatic")
	defer span.End()
	return c.broadcast(ctx, msg, seeds, brdcst.DefaultConfigStatic())
}

func (c *Coordinator) broadcast(ctx context.Context, msg *pb.Message, seeds []kadt.PeerID, cfg brdcst.Config) error {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.broadcast")
	defer span.End()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	waiter := NewBroadcastWaiter(0) // zero capacity since waitForBroadcast ignores progress events
	queryID := c.newOperationID()

	cmd := &EventStartBroadcast{
		QueryID: queryID,
		Target:  msg.Target(),
		Message: msg,
		Seed:    seeds,
		Notify:  waiter,
		Config:  cfg,
	}

	// queue the start of the query
	c.brdcstBehaviour.Notify(ctx, cmd)

	contacted, _, err := c.waitForBroadcast(ctx, waiter)
	if err != nil {
		return err
	}

	if len(contacted) == 0 {
		return fmt.Errorf("no peers contacted")
	}

	// TODO: define threshold below which we consider the provide to have failed

	return nil
}

func (c *Coordinator) waitForQuery(ctx context.Context, queryID coordt.QueryID, waiter *QueryWaiter, fn coordt.QueryFunc) ([]kadt.PeerID, coordt.QueryStats, error) {
	var lastStats coordt.QueryStats
	for {
		select {
		case <-ctx.Done():
			return nil, lastStats, ctx.Err()

		case wev, more := <-waiter.Progressed():
			if !more {
				return nil, lastStats, ctx.Err()
			}
			ctx, ev := wev.Ctx, wev.Event
			c.cfg.Logger.Debug("query made progress", "query_id", queryID, tele.LogAttrPeerID(ev.NodeID), slog.Duration("elapsed", c.cfg.Clock.Since(ev.Stats.Start)), slog.Int("requests", ev.Stats.Requests), slog.Int("failures", ev.Stats.Failure))
			lastStats = coordt.QueryStats{
				Start:    ev.Stats.Start,
				Requests: ev.Stats.Requests,
				Success:  ev.Stats.Success,
				Failure:  ev.Stats.Failure,
			}
			err := fn(ctx, ev.NodeID, ev.Response, lastStats)
			if errors.Is(err, coordt.ErrSkipRemaining) {
				// done
				c.cfg.Logger.Debug("query done", "query_id", queryID)
				c.queryBehaviour.Notify(ctx, &EventStopQuery{QueryID: queryID})
				return nil, lastStats, nil
			}
			if err != nil {
				// user defined error that terminates the query
				c.queryBehaviour.Notify(ctx, &EventStopQuery{QueryID: queryID})
				return nil, lastStats, err
			}
		case wev, more := <-waiter.Finished():
			// drain the progress notification channel
			for pev := range waiter.Progressed() {
				ctx, ev := pev.Ctx, pev.Event
				c.cfg.Logger.Debug("query made progress", "query_id", queryID, tele.LogAttrPeerID(ev.NodeID), slog.Duration("elapsed", c.cfg.Clock.Since(ev.Stats.Start)), slog.Int("requests", ev.Stats.Requests), slog.Int("failures", ev.Stats.Failure))
				lastStats = coordt.QueryStats{
					Start:    ev.Stats.Start,
					Requests: ev.Stats.Requests,
					Success:  ev.Stats.Success,
					Failure:  ev.Stats.Failure,
				}
				if err := fn(ctx, ev.NodeID, ev.Response, lastStats); err != nil {
					return nil, lastStats, err
				}
			}
			if !more {
				return nil, lastStats, ctx.Err()
			}

			// query is done
			lastStats.Exhausted = true
			c.cfg.Logger.Debug("query ran to exhaustion", "query_id", queryID, slog.Duration("elapsed", wev.Event.Stats.End.Sub(wev.Event.Stats.Start)), slog.Int("requests", wev.Event.Stats.Requests), slog.Int("failures", wev.Event.Stats.Failure))
			return wev.Event.ClosestNodes, lastStats, nil

		}
	}
}

func (c *Coordinator) waitForBroadcast(ctx context.Context, waiter *BroadcastWaiter) ([]kadt.PeerID, map[string]struct {
	Node kadt.PeerID
	Err  error
}, error,
) {
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case wev, more := <-waiter.Finished():
			if !more {
				return nil, nil, ctx.Err()
			}
			return wev.Event.Contacted, wev.Event.Errors, nil
		}
	}
}

// AddNodes suggests new DHT nodes to be added to the routing table.
// If the routing table is updated as a result of this operation an EventRoutingUpdated notification
// is emitted on the routing notification channel.
func (c *Coordinator) AddNodes(ctx context.Context, ids []kadt.PeerID) error {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.AddNodes")
	defer span.End()
	for _, id := range ids {
		if id.Equal(c.self) {
			// skip self
			continue
		}

		c.routingBehaviour.Notify(ctx, &EventAddNode{
			NodeID: id,
		})

	}

	return nil
}

// Bootstrap instructs the dht to begin bootstrapping the routing table.
func (c *Coordinator) Bootstrap(ctx context.Context, seeds []kadt.PeerID) error {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.Bootstrap")
	defer span.End()

	c.routingBehaviour.Notify(ctx, &EventStartBootstrap{
		SeedNodes: seeds,
	})

	return nil
}

// NotifyConnectivity notifies the coordinator that a peer has passed a connectivity check
// which means it is connected and supports finding closer nodes
func (c *Coordinator) NotifyConnectivity(ctx context.Context, id kadt.PeerID) {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.NotifyConnectivity")
	defer span.End()

	c.cfg.Logger.Debug("peer has connectivity", tele.LogAttrPeerID(id), "source", "notify")
	c.routingBehaviour.Notify(ctx, &EventNotifyConnectivity{
		NodeID: id,
	})
}

// NotifyNonConnectivity notifies the coordinator that a peer has failed a connectivity check
// which means it is not connected and/or it doesn't support finding closer nodes
func (c *Coordinator) NotifyNonConnectivity(ctx context.Context, id kadt.PeerID) {
	ctx, span := c.tele.Tracer.Start(ctx, "Coordinator.NotifyNonConnectivity")
	defer span.End()

	c.cfg.Logger.Debug("peer has no connectivity", tele.LogAttrPeerID(id), "source", "notify")
	c.routingBehaviour.Notify(ctx, &EventNotifyNonConnectivity{
		NodeID: id,
	})
}

func (c *Coordinator) newOperationID() coordt.QueryID {
	next := c.lastQueryID.Add(1)
	return coordt.QueryID(fmt.Sprintf("%016x", next))
}

// A BufferedRoutingNotifier is a [RoutingNotifier] that buffers [RoutingNotification] events and provides methods
// to expect occurrences of specific events. It is designed for use in a test environment.
type BufferedRoutingNotifier struct {
	mu       sync.Mutex
	buffered []RoutingNotification
	signal   chan struct{}
}

func NewBufferedRoutingNotifier() *BufferedRoutingNotifier {
	return &BufferedRoutingNotifier{
		signal: make(chan struct{}, 1),
	}
}

func (w *BufferedRoutingNotifier) Notify(ctx context.Context, ev RoutingNotification) {
	w.mu.Lock()
	w.buffered = append(w.buffered, ev)
	select {
	case w.signal <- struct{}{}:
	default:
	}
	w.mu.Unlock()
}

func (w *BufferedRoutingNotifier) Expect(ctx context.Context, expected RoutingNotification) (RoutingNotification, error) {
	for {
		// look in buffered events
		w.mu.Lock()
		for i, ev := range w.buffered {
			if reflect.TypeOf(ev) == reflect.TypeOf(expected) {
				// remove first from buffer and return it
				w.buffered = w.buffered[:i+copy(w.buffered[i:], w.buffered[i+1:])]
				w.mu.Unlock()
				return ev, nil
			}
		}
		w.mu.Unlock()

		// wait to be signaled that there is a new event
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("test deadline exceeded while waiting for event %T", expected)
		case <-w.signal:
		}
	}
}

// ExpectRoutingUpdated blocks until an [EventRoutingUpdated] event is seen for the specified peer id
func (w *BufferedRoutingNotifier) ExpectRoutingUpdated(ctx context.Context, id kadt.PeerID) (*EventRoutingUpdated, error) {
	for {
		// look in buffered events
		w.mu.Lock()
		for i, ev := range w.buffered {
			if tev, ok := ev.(*EventRoutingUpdated); ok {
				if id.Equal(tev.NodeID) {
					// remove first from buffer and return it
					w.buffered = w.buffered[:i+copy(w.buffered[i:], w.buffered[i+1:])]
					w.mu.Unlock()
					return tev, nil
				}
			}
		}
		w.mu.Unlock()

		// wait to be signaled that there is a new event
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("test deadline exceeded while waiting for routing updated event")
		case <-w.signal:
		}
	}
}

// ExpectRoutingRemoved blocks until an [EventRoutingRemoved] event is seen for the specified peer id
func (w *BufferedRoutingNotifier) ExpectRoutingRemoved(ctx context.Context, id kadt.PeerID) (*EventRoutingRemoved, error) {
	for {
		// look in buffered events
		w.mu.Lock()
		for i, ev := range w.buffered {
			if tev, ok := ev.(*EventRoutingRemoved); ok {
				if id.Equal(tev.NodeID) {
					// remove first from buffer and return it
					w.buffered = w.buffered[:i+copy(w.buffered[i:], w.buffered[i+1:])]
					w.mu.Unlock()
					return tev, nil
				}
			}
		}
		w.mu.Unlock()

		// wait to be signaled that there is a new event
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("test deadline exceeded while waiting for routing removed event")
		case <-w.signal:
		}
	}
}

type nullRoutingNotifier struct{}

func (nullRoutingNotifier) Notify(context.Context, RoutingNotification) {}

// A QueryWaiter implements [QueryMonitor] for general queries
type QueryWaiter struct {
	progressed chan CtxEvent[*EventQueryProgressed]
	finished   chan CtxEvent[*EventQueryFinished]
}

var _ QueryMonitor[*EventQueryFinished] = (*QueryWaiter)(nil)

func NewQueryWaiter(n int) *QueryWaiter {
	w := &QueryWaiter{
		progressed: make(chan CtxEvent[*EventQueryProgressed], n),
		finished:   make(chan CtxEvent[*EventQueryFinished], 1),
	}
	return w
}

func (w *QueryWaiter) Progressed() <-chan CtxEvent[*EventQueryProgressed] {
	return w.progressed
}

func (w *QueryWaiter) Finished() <-chan CtxEvent[*EventQueryFinished] {
	return w.finished
}

func (w *QueryWaiter) NotifyProgressed() chan<- CtxEvent[*EventQueryProgressed] {
	return w.progressed
}

func (w *QueryWaiter) NotifyFinished() chan<- CtxEvent[*EventQueryFinished] {
	return w.finished
}

package coord

import (
	"context"
	"sync"
	"testing"

	"github.com/benbjohnson/clock"
	"github.com/plprobelab/zikade/internal/coord/coordt"
	"github.com/plprobelab/zikade/internal/kadtest"
	"github.com/plprobelab/zikade/internal/nettest"
	"github.com/plprobelab/zikade/kadt"
	"github.com/plprobelab/zikade/pb"

	"github.com/stretchr/testify/require"
)

func TestPooledQueryConfigValidate(t *testing.T) {
	t.Run("default is valid", func(t *testing.T) {
		cfg := DefaultPooledQueryConfig()

		require.NoError(t, cfg.Validate())
	})

	t.Run("clock is not nil", func(t *testing.T) {
		cfg := DefaultPooledQueryConfig()

		cfg.Clock = nil
		require.Error(t, cfg.Validate())
	})

	t.Run("logger not nil", func(t *testing.T) {
		cfg := DefaultPooledQueryConfig()
		cfg.Logger = nil
		require.Error(t, cfg.Validate())
	})

	t.Run("tracer not nil", func(t *testing.T) {
		cfg := DefaultPooledQueryConfig()
		cfg.Tracer = nil
		require.Error(t, cfg.Validate())
	})

	t.Run("query concurrency positive", func(t *testing.T) {
		cfg := DefaultPooledQueryConfig()

		cfg.Concurrency = 0
		require.Error(t, cfg.Validate())
		cfg.Concurrency = -1
		require.Error(t, cfg.Validate())
	})

	t.Run("query timeout positive", func(t *testing.T) {
		cfg := DefaultPooledQueryConfig()

		cfg.Timeout = 0
		require.Error(t, cfg.Validate())
		cfg.Timeout = -1
		require.Error(t, cfg.Validate())
	})

	t.Run("request concurrency positive", func(t *testing.T) {
		cfg := DefaultPooledQueryConfig()

		cfg.RequestConcurrency = 0
		require.Error(t, cfg.Validate())
		cfg.RequestConcurrency = -1
		require.Error(t, cfg.Validate())
	})

	t.Run("request timeout positive", func(t *testing.T) {
		cfg := DefaultPooledQueryConfig()

		cfg.RequestTimeout = 0
		require.Error(t, cfg.Validate())
		cfg.RequestTimeout = -1
		require.Error(t, cfg.Validate())
	})
}

func TestPooledQuery_deadlock_regression(t *testing.T) {
	ctx := kadtest.CtxShort(t)
	msg := &pb.Message{}
	queryID := coordt.QueryID("test")

	_, nodes, err := nettest.LinearTopology(3, clock.New())
	require.NoError(t, err)

	c, err := NewCoordinator(nodes[0].NodeID, nodes[0].Router, nodes[0].RoutingTable, nil)
	require.NoError(t, err)
	require.NoError(t, c.Close()) // close immediately so that we control the state machine progression

	// define a function that produces success messages
	successMsg := func(to kadt.PeerID, closer ...kadt.PeerID) *EventSendMessageSuccess {
		return &EventSendMessageSuccess{
			QueryID:     queryID,
			Request:     msg,
			To:          to,
			Response:    nil,
			CloserNodes: closer,
		}
	}

	// start query
	waiter := NewWaiter[BehaviourEvent]()

	waiterDone := make(chan struct{})
	waiterMsg := make(chan struct{})
	go func() {
		defer close(waiterDone)
		defer close(waiterMsg)
		_, _, err = c.waitForQuery(ctx, queryID, waiter, func(ctx context.Context, id kadt.PeerID, resp *pb.Message, stats coordt.QueryStats) error {
			waiterMsg <- struct{}{}
			return coordt.ErrSkipRemaining
		})
	}()

	// start the message query
	c.queryBehaviour.Notify(ctx, &EventStartMessageQuery{
		QueryID:           queryID,
		Target:            msg.Target(),
		Message:           msg,
		KnownClosestNodes: []kadt.PeerID{nodes[1].NodeID},
		Notify:            waiter,
		NumResults:        0,
	})

	// advance state machines and assert that the state machine
	// wants to send an outbound message to another peer
	ev, _ := c.queryBehaviour.Perform(ctx)
	require.IsType(t, &EventOutboundSendMessage{}, ev)

	// simulate a successful response from another node that returns one new node
	// This should result in a message for the waiter
	c.queryBehaviour.Notify(ctx, successMsg(nodes[1].NodeID, nodes[2].NodeID))

	// Because we're blocking on the waiterMsg channel in the waitForQuery
	// method above, we simulate a slow receiving waiter.

	// Advance the query pool state machine. Because we returned a new node
	// above, the query pool state machine wants to send another outbound query
	ev, _ = c.queryBehaviour.Perform(ctx)
	require.IsType(t, &EventAddNode{}, ev) // event to notify the routing table
	ev, _ = c.queryBehaviour.Perform(ctx)
	require.IsType(t, &EventOutboundSendMessage{}, ev)

	// Simulate a successful response from the new node. This node didn't return
	// any new nodes to contact. This means the query pool behaviour will notify
	// the waiter about a query progression and afterward about a finished
	// query. Because (at the time of writing) the waiter has a channel buffer
	// of 1, the channel cannot hold both events. At the same time, the waiter
	// doesn't consume the messages because it's busy processing the previous
	// query event (because we haven't released the blocking waiterMsg call above).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		wg.Done()
		c.queryBehaviour.Notify(ctx, successMsg(nodes[2].NodeID))
	}()

	wg.Wait()
	<-waiterMsg

	// At this point, the waitForQuery QueryFunc callback returned a
	// coordt.ErrSkipRemaining. This instructs the waitForQuery method to notify
	// the query behaviour with an EventStopQuery event. However, because the
	// query behaviour is busy sending a message to the waiter it is holding the
	// lock on the pending events to process. Therefore, this notify call will
	// also block. At the same time, the waiter cannot read the new messages
	// from the query behaviour because it tries to notify it.

	select {
	case <-waiterDone:
	case <-ctx.Done():
		t.Fatalf("tiemout")
	}
}

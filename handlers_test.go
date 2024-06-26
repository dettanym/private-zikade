package zikade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/plprobelab/zikade/pir"
	"github.com/plprobelab/zikade/private_routing"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/ipfs/boxo/ipns"
	ds "github.com/ipfs/go-datastore"
	record "github.com/libp2p/go-libp2p-record"
	recpb "github.com/libp2p/go-libp2p-record/pb"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/plprobelab/zikade/kadt"
	"github.com/plprobelab/zikade/pb"
)

func TestMessage_noKey(t *testing.T) {
	d := newTestDHT(t)
	for _, typ := range []pb.Message_MessageType{
		pb.Message_FIND_NODE,
		pb.Message_PUT_VALUE,
		pb.Message_GET_VALUE,
		pb.Message_ADD_PROVIDER,
		pb.Message_GET_PROVIDERS,
	} {
		t.Run(typ.String(), func(t *testing.T) {
			msg := &pb.Message{Type: typ} // no key
			_, err := d.handleMsg(context.Background(), peer.ID(""), msg)
			if err == nil {
				t.Error("expected processing message to fail")
			}
		})
	}
}

func BenchmarkDHT_handleFindPeer(b *testing.B) {
	d := newTestDHT(b)

	// build routing table
	peers := fillRoutingTable(b, d, 250)

	runs := 100
	ourResults := make([]results, runs)

	// build requests
	reqs := make([]*pb.Message, runs)
	for i := 0; i < runs; i++ {
		reqs[i] = &pb.Message{
			Type: pb.Message_FIND_NODE,
			Key:  []byte("random-key-" + strconv.Itoa(i)),
		}
		ourResults[i].requestLen = reqs[i].Size()
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < runs; i++ {
		start := time.Now()
		resp, err := d.handleFindPeer(ctx, peers[0], reqs[i])
		ourResults[i].responseLen = resp.Size()
		require.NoError(b, err)
		elapsed := time.Since(start)
		ourResults[i].serverRuntime = elapsed.Microseconds()
	}

	var avgReqLen float64
	var avgResLen float64
	var avgServerTime float64
	for _, res := range ourResults {
		// print("\n ", i, " ", res.requestLen, " ", res.responseLen, " ", res.serverRuntime, "\n")
		avgReqLen += float64(res.requestLen)
		avgResLen += float64(res.responseLen)
		avgServerTime += float64(res.serverRuntime)
	}
	avgReqLen = avgReqLen / float64(runs)
	avgResLen = avgResLen / float64(runs)
	avgServerTime = float64(int64(int(avgServerTime) / runs))
	print(avgReqLen, " ", avgResLen, " ", avgServerTime, "\n")

}

func TestDHT_handleFindPeer_happy_path(t *testing.T) {
	d := newTestDHT(t)

	queryingPeer := newPeerID(t)

	peers := fillRoutingTable(t, d, 250)

	assert.Equal(t, len(peers), d.host.Peerstore().PeersWithAddrs().Len())
	printCPLAndBucketSizes(d, peers)

	req := &pb.Message{
		Type: pb.Message_FIND_NODE,
		Key:  []byte("random-key"),
	}

	resp, err := d.handleFindPeer(context.Background(), queryingPeer, req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_FIND_NODE, resp.Type)
	assert.Nil(t, resp.Record)
	assert.Equal(t, req.Key, resp.Key)
	assert.Len(t, resp.CloserPeers, d.cfg.BucketSize)
	assert.Len(t, resp.ProviderPeers, 0)
	assert.Equal(t, len(resp.CloserPeers[0].Addrs), 1)
	printCloserPeers(resp)
}

func TestDHT_handleFindPeer_self_in_routing_table(t *testing.T) {
	// a case that shouldn't happen
	d := newTestDHT(t)

	d.rt.AddNode(kadt.PeerID(d.host.ID()))

	req := &pb.Message{
		Type: pb.Message_FIND_NODE,
		Key:  []byte("random-key"),
	}

	resp, err := d.handleFindPeer(context.Background(), newPeerID(t), req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_FIND_NODE, resp.Type)
	assert.Nil(t, resp.Record)
	assert.Equal(t, req.Key, resp.Key)
	assert.Len(t, resp.CloserPeers, 0)
	assert.Len(t, resp.ProviderPeers, 0)
}

func TestDHT_handleFindPeer_empty_routing_table(t *testing.T) {
	d := newTestDHT(t)

	req := &pb.Message{
		Type: pb.Message_FIND_NODE,
		Key:  []byte("random-key"),
	}

	resp, err := d.handleFindPeer(context.Background(), newPeerID(t), req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_FIND_NODE, resp.Type)
	assert.Nil(t, resp.Record)
	assert.Equal(t, req.Key, resp.Key)
	assert.Len(t, resp.CloserPeers, 0)
	assert.Len(t, resp.ProviderPeers, 0)
}

func TestDHT_handleFindPeer_unknown_addresses_but_in_routing_table(t *testing.T) {
	d := newTestDHT(t)

	// build routing table
	peers := make([]peer.ID, d.cfg.BucketSize)
	for i := 0; i < d.cfg.BucketSize; i++ {
		// generate peer ID
		pid := newPeerID(t)

		// add peer to routing table
		d.rt.AddNode(kadt.PeerID(pid))

		// keep track of peer
		peers[i] = pid

		if i == 0 {
			continue
		}

		// craft network address for peer
		a, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 2000+i))
		require.NoError(t, err)

		// add peer information to peer store
		d.host.Peerstore().AddAddr(pid, a, time.Hour)
	}

	_, pub, _ := crypto.GenerateEd25519Key(rng)
	requester, err := peer.IDFromPublicKey(pub)
	require.NoError(t, err)

	req := &pb.Message{
		Type: pb.Message_FIND_NODE,
		Key:  []byte("random-key"),
	}

	resp, err := d.handleFindPeer(context.Background(), requester, req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_FIND_NODE, resp.Type)
	assert.Nil(t, resp.Record)
	assert.Equal(t, req.Key, resp.Key)
	assert.Len(t, resp.ProviderPeers, 0)
	// should not return peer whose addresses we don't know
	require.Len(t, resp.CloserPeers, d.cfg.BucketSize-1)
	for _, cp := range resp.CloserPeers {
		assert.NotEqual(t, peer.ID(cp.Id), peers[0])
	}
}

func TestDHT_handleFindPeer_request_for_server(t *testing.T) {
	d := newTestDHT(t)

	req := &pb.Message{
		Type: pb.Message_FIND_NODE,
		Key:  []byte(d.host.ID()),
	}

	resp, err := d.handleFindPeer(context.Background(), newPeerID(t), req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_FIND_NODE, resp.Type)
	assert.Nil(t, resp.Record)
	assert.Equal(t, req.Key, resp.Key)
	assert.Len(t, resp.CloserPeers, 1)
	assert.Len(t, resp.ProviderPeers, 0)
	assert.Equal(t, d.host.ID(), peer.ID(resp.CloserPeers[0].Id))
}

func TestDHT_handleFindPeer_request_for_self(t *testing.T) {
	d := newTestDHT(t)

	// build routing table
	peers := make([]peer.ID, d.cfg.BucketSize)
	for i := 0; i < d.cfg.BucketSize; i++ {
		// generate peer ID
		pid := newPeerID(t)

		// add peer to routing table
		d.rt.AddNode(kadt.PeerID(pid))

		// keep track of peer
		peers[i] = pid

		// craft network address for peer
		a, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 2000+i))
		if err != nil {
			t.Fatal(err)
		}

		// add peer information to peer store
		d.host.Peerstore().AddAddr(pid, a, time.Hour)
	}

	req := &pb.Message{
		Type: pb.Message_FIND_NODE,
		Key:  []byte("random-key"),
	}

	resp, err := d.handleFindPeer(context.Background(), peers[0], req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_FIND_NODE, resp.Type)
	assert.Nil(t, resp.Record)
	assert.Equal(t, req.Key, resp.Key)
	assert.Len(t, resp.CloserPeers, d.cfg.BucketSize-1) // don't return requester
	assert.Len(t, resp.ProviderPeers, 0)
}

func TestDHT_handleFindPeer_request_for_known_but_far_peer(t *testing.T) {
	// tests if a peer that we know the addresses of but that isn't in
	// the routing table is returned
	d := newTestDHT(t)

	// build routing table
	peers := make([]peer.ID, 250)
	for i := 0; i < 250; i++ {
		// generate peer ID
		pid := newPeerID(t)

		// keep track of peer
		peers[i] = pid

		// craft network address for peer
		a, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 2000+i))
		if err != nil {
			t.Fatal(err)
		}

		// add peer information to peer store
		d.host.Peerstore().AddAddr(pid, a, time.Hour)

		// don't add first peer to routing table -> the one we're asking for
		// don't add second peer -> the one that's requesting
		if i > 1 {
			d.rt.AddNode(kadt.PeerID(pid))
		}
	}

	req := &pb.Message{
		Type: pb.Message_FIND_NODE,
		Key:  []byte(peers[0]), // not in routing table but in peer store
	}

	resp, err := d.handleFindPeer(context.Background(), peers[1], req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_FIND_NODE, resp.Type)
	assert.Nil(t, resp.Record)
	assert.Equal(t, req.Key, resp.Key)
	assert.Len(t, resp.CloserPeers, d.cfg.BucketSize+1) // return peer because we know it's addresses
	assert.Len(t, resp.ProviderPeers, 0)
}

func TestDHT_handlePing(t *testing.T) {
	d := newTestDHT(t)

	req := &pb.Message{Type: pb.Message_PING}
	res, err := d.handlePing(context.Background(), newPeerID(t), req)
	require.NoError(t, err)
	assert.Equal(t, pb.Message_PING, res.Type)
	assert.Len(t, res.CloserPeers, 0)
	assert.Len(t, res.ProviderPeers, 0)
	assert.Nil(t, res.Key)
	assert.Nil(t, res.Record)
}

func BenchmarkDHT_handlePing(b *testing.B) {
	d := newTestDHT(b)
	requester := newPeerID(b)

	ctx := context.Background()
	req := &pb.Message{Type: pb.Message_PING}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.handlePing(ctx, requester, req)
		if err != nil {
			b.Error(err)
		}
	}
}

func newPutIPNSRequest(t testing.TB, clk clock.Clock, priv crypto.PrivKey, seq uint64, ttl time.Duration) *pb.Message {
	t.Helper()

	keyStr, value := makeIPNSKeyValue(t, clk, priv, seq, ttl)

	req := &pb.Message{
		Type: pb.Message_PUT_VALUE,
		Key:  []byte(keyStr),
		Record: &recpb.Record{
			Key:          []byte(keyStr),
			Value:        value,
			TimeReceived: clk.Now().Format(time.RFC3339Nano),
		},
	}

	return req
}

func BenchmarkDHT_handlePutValue_unique_peers(b *testing.B) {
	d := newTestDHT(b)

	// build requests
	peers := make([]peer.ID, b.N)
	reqs := make([]*pb.Message, b.N)
	for i := 0; i < b.N; i++ {
		remote, priv := newIdentity(b)
		peers[i] = remote
		reqs[i] = newPutIPNSRequest(b, d.cfg.Clock, priv, uint64(i), time.Hour)
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.handlePutValue(ctx, peers[i], reqs[i])
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkDHT_handlePutValue_single_peer(b *testing.B) {
	d := newTestDHT(b)

	// build requests
	remote, priv := newIdentity(b)
	reqs := make([]*pb.Message, b.N)
	for i := 0; i < b.N; i++ {
		reqs[i] = newPutIPNSRequest(b, d.cfg.Clock, priv, uint64(i), time.Hour)
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.handlePutValue(ctx, remote, reqs[i])
		if err != nil {
			b.Error(err)
		}
	}
}

func TestDHT_handlePutValue_happy_path_ipns_record(t *testing.T) {
	ctx := context.Background()

	// init new DHT
	clk := clock.NewMock()
	clk.Set(time.Now()) // needed because record validators don't use mock clocks

	cfg := DefaultConfig()
	cfg.Clock = clk

	d := newTestDHTWithConfig(t, cfg)

	// generate new identity for the peer that issues the request
	remote, priv := newIdentity(t)

	// expired record
	req := newPutIPNSRequest(t, clk, priv, 0, time.Hour)
	ns, suffix, err := record.SplitKey(string(req.Key))
	require.NoError(t, err)

	_, err = d.backends[ns].Fetch(ctx, suffix)
	require.ErrorIs(t, err, ds.ErrNotFound)

	// advance the clock a bit so that TimeReceived values will be definitely different
	clk.Add(time.Minute)

	cloned := proto.Clone(req).(*pb.Message)
	_, err = d.handlePutValue(ctx, remote, cloned)
	require.NoError(t, err)

	dat, err := d.backends[ns].Fetch(ctx, suffix)
	require.NoError(t, err)

	r, ok := dat.(*recpb.Record)
	require.True(t, ok)

	assert.NotEqual(t, r.TimeReceived, req.Record.TimeReceived)

	r.TimeReceived = ""
	req.Record.TimeReceived = ""

	assert.True(t, reflect.DeepEqual(r, req.Record))
}

func TestDHT_handlePutValue_nil_records(t *testing.T) {
	d := newTestDHT(t)

	for _, ns := range []string{namespaceIPNS, namespacePublicKey} {
		req := &pb.Message{
			Type:   pb.Message_PUT_VALUE,
			Key:    []byte(fmt.Sprintf("/%s/random-key", ns)),
			Record: nil, // nil record
		}

		resp, err := d.handlePutValue(context.Background(), newPeerID(t), req)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "nil record")
	}
}

func TestDHT_handlePutValue_record_key_mismatch(t *testing.T) {
	d := newTestDHT(t)

	for _, ns := range []string{namespaceIPNS, namespacePublicKey} {
		t.Run(ns, func(t *testing.T) {
			key1 := []byte(fmt.Sprintf("/%s/key-1", ns))
			key2 := []byte(fmt.Sprintf("/%s/key-2", ns))

			req := &pb.Message{
				Type: pb.Message_PUT_VALUE,
				Key:  key1,
				Record: &recpb.Record{
					Key: key2,
				},
			}

			resp, err := d.handlePutValue(context.Background(), newPeerID(t), req)
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.ErrorContains(t, err, "key doesn't match record key")
		})
	}
}

func TestDHT_handlePutValue_bad_ipns_record(t *testing.T) {
	d := newTestDHT(t)

	remote, priv := newIdentity(t)

	// expired record
	req := newPutIPNSRequest(t, d.cfg.Clock, priv, 10, -time.Hour)

	resp, err := d.handlePutValue(context.Background(), remote, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "bad record")
}

func TestDHT_handlePutValue_worse_ipns_record_after_first_put(t *testing.T) {
	d := newTestDHT(t)

	remote, priv := newIdentity(t)

	goodReq := newPutIPNSRequest(t, d.cfg.Clock, priv, 10, time.Hour)
	worseReq := newPutIPNSRequest(t, d.cfg.Clock, priv, 0, time.Hour)

	for i, req := range []*pb.Message{goodReq, worseReq} {
		resp, err := d.handlePutValue(context.Background(), remote, req)
		switch i {
		case 0:
			assert.NoError(t, err)
			assert.Nil(t, resp)
		case 1:
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.ErrorContains(t, err, "received worse record")
		}
	}
}

func TestDHT_handlePutValue_probe_race_condition(t *testing.T) {
	// we're storing two sequential records simultaneously many times in a row.
	// After each insert, we check that indeed, the record with the higher
	// sequence number was stored. If the handler didn't use transactions,
	// this test fails.

	d := newTestDHT(t)

	remote, priv := newIdentity(t)

	for i := 0; i < 100; i++ {

		req1 := newPutIPNSRequest(t, d.cfg.Clock, priv, uint64(2*i), time.Hour)
		req2 := newPutIPNSRequest(t, d.cfg.Clock, priv, uint64(2*i+1), time.Hour)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			_, _ = d.handlePutValue(context.Background(), remote, req1)
			wg.Done()
		}()

		wg.Add(1)
		go func() {
			_, err := d.handlePutValue(context.Background(), remote, req2)
			assert.NoError(t, err)
			wg.Done()
		}()
		wg.Wait()

		// an IPNS record key has the form /ipns/$binary_id where $binary_id
		// is just the peer ID of the peer that belongs to the IPNS record.
		// Therefore, we can just string-cast the remote peer.ID here.
		val, err := d.backends[namespaceIPNS].Fetch(context.Background(), string(remote))
		require.NoError(t, err)

		r, ok := val.(*recpb.Record)
		require.True(t, ok)

		storedRec, err := ipns.UnmarshalRecord(r.Value)
		require.NoError(t, err)

		seq, err := storedRec.Sequence()
		require.NoError(t, err)

		// stored record must always be the newer one!
		assert.EqualValues(t, 2*i+1, seq)
	}
}

func TestDHT_handlePutValue_overwrites_corrupt_stored_ipns_record(t *testing.T) {
	d := newTestDHT(t)

	remote, priv := newIdentity(t)

	req := newPutIPNSRequest(t, d.cfg.Clock, priv, 10, time.Hour)

	dsKey := newDatastoreKey(namespaceIPNS, string(remote)) // string(remote) is the key suffix

	rbe, err := typedBackend[*RecordBackend](d, namespaceIPNS)
	require.NoError(t, err)

	err = rbe.datastore.Put(context.Background(), dsKey, []byte("corrupt-record"))
	require.NoError(t, err)

	// put the correct record through handler
	_, err = d.handlePutValue(context.Background(), remote, req)
	require.NoError(t, err)

	value, err := rbe.datastore.Get(context.Background(), dsKey)
	require.NoError(t, err)

	r := &recpb.Record{}
	require.NoError(t, r.Unmarshal(value))

	_, err = ipns.UnmarshalRecord(r.Value)
	require.NoError(t, err)
}

func TestDHT_handlePutValue_malformed_key(t *testing.T) {
	d := newTestDHT(t)

	keys := []string{
		"malformed-key",
		"     ",
		"/ipns/",
		"/pk/",
		"/ipns",
		"/pk",
		"ipns/",
		"pk/",
	}
	for _, k := range keys {
		t.Run("malformed key: "+k, func(t *testing.T) {
			req := &pb.Message{
				Type: pb.Message_PUT_VALUE,
				Key:  []byte(k),
				Record: &recpb.Record{
					Key: []byte(k),
				},
			}

			resp, err := d.handlePutValue(context.Background(), newPeerID(t), req)
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.ErrorContains(t, err, "invalid key")
		})
	}
}

func TestDHT_handlePutValue_unknown_backend(t *testing.T) {
	d := newTestDHT(t)

	req := &pb.Message{
		Type: pb.Message_PUT_VALUE,
		Key:  []byte("/other-namespace/record-key"),
		Record: &recpb.Record{
			Key: []byte("/other-namespace/record-key"),
		},
	}

	resp, err := d.handlePutValue(context.Background(), newPeerID(t), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "unsupported record type")
}

func TestDHT_handlePutValue_moved_from_v1_bad_proto_message(t *testing.T) {
	// Test moved from v1 to v2 - original name TestBadProtoMessages in dht_test.go
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := newTestDHT(t)

	nilrec := new(pb.Message)
	if _, err := d.handlePutValue(ctx, "testpeer", nilrec); err == nil {
		t.Fatal("should have errored on nil record")
	}
}

// atomicPutValidator moved from v1 to v2 - in support for [TestDHT_handlePutValue_atomic_operation]
type atomicPutValidator struct{}

var _ record.Validator = (*atomicPutValidator)(nil)

func (v atomicPutValidator) Validate(_ string, value []byte) error {
	if bytes.Equal(value, []byte("expired")) {
		return errors.New("expired")
	}
	return nil
}

// selects the entry with the 'highest' last byte
func (atomicPutValidator) Select(_ string, bs [][]byte) (int, error) {
	index := -1
	max := uint8(0)
	for i, b := range bs {
		if bytes.Equal(b, []byte("valid")) {
			if index == -1 {
				index = i
			}
			continue
		}

		str := string(b)
		n := str[len(str)-1]
		if n > max {
			max = n
			index = i
		}

	}
	if index == -1 {
		return -1, errors.New("no rec found")
	}
	return index, nil
}

func TestDHT_handlePutValue_moved_from_v1_atomic_operation(t *testing.T) {
	// Test moved from v1 to v2 - original name TestAtomicPut in dht_test.go

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dstore, err := InMemoryDatastore()
	require.NoError(t, err)

	cfg, err := DefaultRecordBackendConfig()
	require.NoError(t, err)

	recBackend := &RecordBackend{
		cfg:       cfg,
		log:       devnull,
		namespace: "test",
		datastore: dstore,
		validator: atomicPutValidator{},
	}

	d := newTestDHT(t)

	d.backends[recBackend.namespace] = recBackend

	// fnc to put a record
	key := "/test/testkey"
	putRecord := func(value []byte) error {
		rec := record.MakePutRecord(key, value)
		msg := &pb.Message{
			Type:   pb.Message_PUT_VALUE,
			Key:    rec.Key,
			Record: rec,
		}
		_, err := d.handlePutValue(ctx, "testpeer", msg)
		return err
	}

	// put a valid record
	if err := putRecord([]byte("valid")); err != nil {
		t.Fatal("should not have errored on a valid record")
	}

	// simultaneous puts for old & new values
	values := [][]byte{[]byte("newer1"), []byte("newer7"), []byte("newer3"), []byte("newer5")}
	var wg sync.WaitGroup
	for _, v := range values {
		wg.Add(1)
		go func(v []byte) {
			defer wg.Done()
			_ = putRecord(v) // we expect some of these to fail
		}(v)
	}
	wg.Wait()

	// get should return the newest value
	pmes := &pb.Message{
		Type: pb.Message_GET_VALUE,
		Key:  []byte(key),
	}
	msg, err := d.handleGetValue(ctx, "testpeer", pmes)
	if err != nil {
		t.Fatalf("should not have errored on final get, but got %+v", err)
	}
	if string(msg.GetRecord().Value) != "newer7" {
		t.Fatalf("Expected 'newer7' got '%s'", string(msg.GetRecord().Value))
	}
}

func BenchmarkDHT_handleGetValue(b *testing.B) {
	d := newTestDHT(b)

	fillRoutingTable(b, d, 250)

	rbe, ok := d.backends[namespaceIPNS].(*RecordBackend)
	require.True(b, ok)

	// fill datastore and build requests
	reqs := make([]*pb.Message, b.N)
	peers := make([]peer.ID, b.N)
	for i := 0; i < b.N; i++ {
		pid, priv := newIdentity(b)

		putReq := newPutIPNSRequest(b, d.cfg.Clock, priv, 0, time.Hour)

		data, err := putReq.Record.Marshal()
		require.NoError(b, err)

		dsKey := newDatastoreKey(namespaceIPNS, string(pid))

		err = rbe.datastore.Put(context.Background(), dsKey, data)
		require.NoError(b, err)

		peers[i] = pid
		reqs[i] = &pb.Message{
			Type: pb.Message_GET_VALUE,
			Key:  putReq.GetKey(),
		}
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := d.handleGetValue(ctx, peers[b.N-i-1], reqs[i])
		if err != nil {
			b.Error(err)
		}
	}
}

func TestDHT_handleGetValue_happy_path_ipns_record(t *testing.T) {
	d := newTestDHT(t)

	fillRoutingTable(t, d, 250)

	remote, priv := newIdentity(t)

	putReq := newPutIPNSRequest(t, d.cfg.Clock, priv, 0, time.Hour)

	rbe, err := typedBackend[*RecordBackend](d, namespaceIPNS)
	require.NoError(t, err)

	data, err := putReq.Record.Marshal()
	require.NoError(t, err)

	dsKey := newDatastoreKey(namespaceIPNS, string(remote))
	err = rbe.datastore.Put(context.Background(), dsKey, data)
	require.NoError(t, err)

	getReq := &pb.Message{
		Type: pb.Message_GET_VALUE,
		Key:  putReq.GetKey(),
	}

	resp, err := d.handleGetValue(context.Background(), remote, getReq)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_GET_VALUE, resp.Type)
	assert.Equal(t, putReq.Key, resp.Key)
	require.NotNil(t, putReq.Record)
	assert.Equal(t, putReq.Record.String(), resp.Record.String())
	assert.Len(t, resp.CloserPeers, 20)
	assert.Len(t, resp.ProviderPeers, 0)
}

func TestDHT_handleGetValue_record_not_found(t *testing.T) {
	d := newTestDHT(t)

	fillRoutingTable(t, d, 250)

	for _, ns := range []string{namespaceIPNS, namespacePublicKey} {
		t.Run(ns, func(t *testing.T) {
			req := &pb.Message{
				Type: pb.Message_GET_VALUE,
				Key:  []byte(fmt.Sprintf("/%s/unknown-record-key", ns)),
			}

			resp, err := d.handleGetValue(context.Background(), newPeerID(t), req)
			require.NoError(t, err)

			assert.Equal(t, pb.Message_GET_VALUE, resp.Type)
			assert.Equal(t, req.Key, resp.Key)
			assert.Nil(t, resp.Record)
			assert.Len(t, resp.CloserPeers, 20)
			assert.Len(t, resp.ProviderPeers, 0)
		})
	}
}

func TestDHT_handleGetValue_corrupt_record_in_datastore(t *testing.T) {
	d := newTestDHT(t)

	fillRoutingTable(t, d, 250)

	for _, ns := range []string{namespaceIPNS, namespacePublicKey} {
		t.Run(ns, func(t *testing.T) {
			rbe, err := typedBackend[*RecordBackend](d, ns)
			require.NoError(t, err)

			key := []byte(fmt.Sprintf("/%s/record-key", ns))

			dsKey := newDatastoreKey(ns, "record-key")
			err = rbe.datastore.Put(context.Background(), dsKey, []byte("corrupt-data"))
			require.NoError(t, err)

			req := &pb.Message{
				Type: pb.Message_GET_VALUE,
				Key:  key,
			}

			resp, err := d.handleGetValue(context.Background(), newPeerID(t), req)
			require.NoError(t, err)

			assert.Equal(t, pb.Message_GET_VALUE, resp.Type)
			assert.Equal(t, req.Key, resp.Key)
			assert.Nil(t, resp.Record)
			assert.Len(t, resp.CloserPeers, 20)
			assert.Len(t, resp.ProviderPeers, 0)

			// check that the record was deleted from the datastore
			data, err := rbe.datastore.Get(context.Background(), dsKey)
			assert.ErrorIs(t, err, ds.ErrNotFound)
			assert.Len(t, data, 0)
		})
	}
}

func TestDHT_handleGetValue_ipns_max_age_exceeded_in_datastore(t *testing.T) {
	clk := clock.NewMock()
	clk.Set(time.Now()) // needed because record validators don't use mock clocks

	cfg := DefaultConfig()
	cfg.Clock = clk

	d := newTestDHTWithConfig(t, cfg)

	fillRoutingTable(t, d, 250)

	remote, priv := newIdentity(t)

	putReq := newPutIPNSRequest(t, clk, priv, 0, time.Hour)

	rbe, err := typedBackend[*RecordBackend](d, namespaceIPNS)
	require.NoError(t, err)

	dsKey := newDatastoreKey(namespaceIPNS, string(remote))

	data, err := putReq.Record.Marshal()
	require.NoError(t, err)

	err = rbe.datastore.Put(context.Background(), dsKey, data)
	require.NoError(t, err)

	req := &pb.Message{
		Type: pb.Message_GET_VALUE,
		Key:  putReq.GetKey(),
	}

	// The following line is actually not necessary because we set the
	// MaxRecordAge to 0. However, this fixes time granularity bug in Windows
	clk.Add(time.Minute)

	rbe.cfg.MaxRecordAge = 0

	resp, err := d.handleGetValue(context.Background(), remote, req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_GET_VALUE, resp.Type)
	assert.Equal(t, req.Key, resp.Key)
	assert.Nil(t, resp.Record)
	assert.Len(t, resp.CloserPeers, 20)
	assert.Len(t, resp.ProviderPeers, 0)

	// check that the record was deleted from the datastore
	data, err = rbe.datastore.Get(context.Background(), dsKey)
	assert.ErrorIs(t, err, ds.ErrNotFound)
	assert.Len(t, data, 0)
}

func TestDHT_handleGetValue_does_not_validate_stored_record(t *testing.T) {
	d := newTestDHT(t)

	fillRoutingTable(t, d, 250)

	rbe, err := typedBackend[*RecordBackend](d, namespaceIPNS)
	require.NoError(t, err)

	remote, priv := newIdentity(t)

	// generate expired record (doesn't pass validation)
	putReq := newPutIPNSRequest(t, d.cfg.Clock, priv, 0, -time.Hour)

	data, err := putReq.Record.Marshal()
	require.NoError(t, err)

	dsKey := newDatastoreKey(namespaceIPNS, string(remote))

	err = rbe.datastore.Put(context.Background(), dsKey, data)
	require.NoError(t, err)

	req := &pb.Message{
		Type: pb.Message_GET_VALUE,
		Key:  putReq.GetKey(),
	}

	resp, err := d.handleGetValue(context.Background(), remote, req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_GET_VALUE, resp.Type)
	assert.Equal(t, req.Key, resp.Key)
	require.NotNil(t, putReq.Record)
	assert.Equal(t, putReq.Record.String(), resp.Record.String())
	assert.Len(t, resp.CloserPeers, 20)
	assert.Len(t, resp.ProviderPeers, 0)
}

func TestDHT_handleGetValue_malformed_key(t *testing.T) {
	d := newTestDHT(t)

	keys := []string{
		"malformed-key",
		"     ",
		"/ipns/",
		"/pk/",
		"/ipns",
		"/pk",
		"ipns/",
		"pk/",
	}
	for _, k := range keys {
		t.Run("malformed key: "+k, func(t *testing.T) {
			req := &pb.Message{
				Type: pb.Message_GET_VALUE,
				Key:  []byte(k),
			}

			resp, err := d.handleGetValue(context.Background(), newPeerID(t), req)
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.ErrorContains(t, err, "invalid key")
		})
	}
}

func TestDHT_handleGetValue_unknown_backend(t *testing.T) {
	d := newTestDHT(t)

	req := &pb.Message{
		Type: pb.Message_GET_VALUE,
		Key:  []byte("/other-namespace/record-key"),
	}

	resp, err := d.handleGetValue(context.Background(), newPeerID(t), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "unsupported record type")
}

func TestDHT_handleGetValue_supports_providers(t *testing.T) {
	ctx := context.Background()
	d := newTestDHT(t)

	p := newAddrInfo(t)
	key := []byte("random-key")

	fillRoutingTable(t, d, 250)

	// add to addresses peerstore
	d.host.Peerstore().AddAddrs(p.ID, p.Addrs, time.Hour)

	be, err := typedBackend[*ProvidersBackend](d, namespaceProviders)
	require.NoError(t, err)

	// write to datastore
	dsKey := newDatastoreKey(namespaceProviders, string(key), string(p.ID))
	rec := expiryRecord{expiry: time.Now()}
	err = be.datastore.Put(ctx, dsKey, rec.MarshalBinary())
	require.NoError(t, err)

	req := &pb.Message{
		Type: pb.Message_GET_VALUE,
		Key:  []byte("/providers/random-key"),
	}

	res, err := d.handleGetValue(context.Background(), newPeerID(t), req)
	assert.NoError(t, err)

	assert.Equal(t, pb.Message_GET_VALUE, res.Type)
	assert.Equal(t, req.Key, res.Key)
	assert.Nil(t, res.Record)
	assert.Len(t, res.CloserPeers, 20)
	require.Len(t, res.ProviderPeers, 1)
	for _, p := range res.ProviderPeers {
		assert.Len(t, p.Addresses(), 1)
	}

	cacheKey := newDatastoreKey(be.namespace, string(key))
	set, found := be.cache.Get(cacheKey.String())
	require.True(t, found)
	assert.Len(t, set.providers, 1)
}

func BenchmarkDHT_handleAddProvider_unique_peers(b *testing.B) {
	d := newTestDHT(b)

	// build requests
	peers := make([]peer.ID, b.N)
	reqs := make([]*pb.Message, b.N)
	for i := 0; i < b.N; i++ {
		addrInfo := newAddrInfo(b)
		req := newAddProviderRequest([]byte(fmt.Sprintf("key-%d", i)), addrInfo)
		peers[i] = addrInfo.ID
		reqs[i] = req
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.handleAddProvider(ctx, peers[i], reqs[i])
		if err != nil {
			b.Error(err)
		}
	}
}

func TestDHT_handleAddProvider_happy_path(t *testing.T) {
	ctx := context.Background()
	d := newTestDHT(t)

	// construct request
	addrInfo := newAddrInfo(t)
	key := []byte("random-key")
	req := newAddProviderRequest(key, addrInfo)

	// do the request
	_, err := d.handleAddProvider(ctx, addrInfo.ID, req)
	require.NoError(t, err)

	addrs := d.host.Peerstore().Addrs(addrInfo.ID)
	require.Len(t, addrs, 1)
	assert.Equal(t, addrs[0], addrInfo.Addrs[0])

	// check if the record was store in the datastore
	be, err := typedBackend[*ProvidersBackend](d, namespaceProviders)
	require.NoError(t, err)

	dsKey := newDatastoreKey(be.namespace, string(key), string(addrInfo.ID))

	val, err := be.datastore.Get(ctx, dsKey)
	assert.NoError(t, err)

	rec := expiryRecord{}
	err = rec.UnmarshalBinary(val)
	require.NoError(t, err)
	assert.False(t, rec.expiry.IsZero())

	cacheKey := newDatastoreKey(be.namespace, string(key)).String()
	_, found := be.cache.Get(cacheKey)
	assert.False(t, found) // only cache on Fetch, not on write
}

func TestDHT_handleAddProvider_key_size_check(t *testing.T) {
	d := newTestDHT(t)

	// construct request
	addrInfo := newAddrInfo(t)
	req := newAddProviderRequest(make([]byte, 81), addrInfo)

	_, err := d.handleAddProvider(context.Background(), addrInfo.ID, req)
	assert.Error(t, err)

	// same exercise with valid key length
	req = newAddProviderRequest(make([]byte, 80), addrInfo)

	_, err = d.handleAddProvider(context.Background(), addrInfo.ID, req)
	assert.NoError(t, err)
}

func TestDHT_handleAddProvider_unsupported_record_type(t *testing.T) {
	d := newTestDHT(t)

	addrInfo := newAddrInfo(t)
	req := newAddProviderRequest([]byte("random-key"), addrInfo)

	// remove backend
	delete(d.backends, namespaceProviders)

	_, err := d.handleAddProvider(context.Background(), addrInfo.ID, req)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unsupported record type")
}

func TestDHT_handleAddProvider_record_for_other_peer(t *testing.T) {
	ctx := context.Background()
	d := newTestDHT(t)

	// construct request
	addrInfo := newAddrInfo(t)
	req := newAddProviderRequest([]byte("random-key"), addrInfo)

	// do the request
	_, err := d.handleAddProvider(ctx, newPeerID(t), req) // other peer
	assert.Error(t, err)
	assert.ErrorContains(t, err, "attempted to store provider record for other peer")
}

func TestDHT_handleAddProvider_record_with_empty_addresses(t *testing.T) {
	ctx := context.Background()
	d := newTestDHT(t)

	// construct request
	addrInfo := newAddrInfo(t)
	addrInfo.Addrs = make([]ma.Multiaddr, 0) // overwrite

	req := newAddProviderRequest([]byte("random-key"), addrInfo)
	_, err := d.handleAddProvider(ctx, addrInfo.ID, req)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "no addresses for provider")
}

func TestDHT_handleAddProvider_empty_provider_peers(t *testing.T) {
	ctx := context.Background()
	d := newTestDHT(t)

	// construct request
	req := newAddProviderRequest([]byte("random-key"))

	req.ProviderPeers = make([]*pb.Message_Peer, 0) // overwrite

	// do the request
	_, err := d.handleAddProvider(ctx, newPeerID(t), req)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "no provider peers given")
}

func TestDHT_handleAddProvider_only_store_filtered_addresses(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultConfig()

	testMaddr := ma.StringCast("/dns/maddr.dummy")

	// define a filter that returns a completely different address and discards
	// every other
	cfg.AddressFilter = func(maddrs []ma.Multiaddr) []ma.Multiaddr {
		return []ma.Multiaddr{testMaddr}
	}

	d := newTestDHTWithConfig(t, cfg)

	addrInfo := newAddrInfo(t)
	require.True(t, len(addrInfo.Addrs) > 0, "need addr info with at least one address")

	// construct request
	req := newAddProviderRequest([]byte("random-key"), addrInfo)

	// do the request
	_, err := d.handleAddProvider(ctx, addrInfo.ID, req)
	assert.NoError(t, err)

	maddrs := d.host.Peerstore().Addrs(addrInfo.ID)
	require.Len(t, maddrs, 1)
	assert.True(t, maddrs[0].Equal(testMaddr), "address filter wasn't applied")
}

func BenchmarkDHT_handleGetProviders(b *testing.B) {
	ctx := context.Background()
	d := newTestDHT(b)

	fillRoutingTable(b, d, 250)

	be, ok := d.backends[namespaceIPNS].(*RecordBackend)
	require.True(b, ok)

	// fill datastore and build requests
	keys := make([][]byte, b.N)
	reqs := make([]*pb.Message, b.N)
	peers := make([]peer.ID, b.N)
	for i := 0; i < b.N; i++ {

		p := newAddrInfo(b)
		k := fmt.Sprintf("key-%d", i)
		keys[i] = []byte(k)

		// add to addresses peerstore
		d.host.Peerstore().AddAddrs(p.ID, p.Addrs, time.Hour)

		// write to datastore
		dsKey := newDatastoreKey(namespaceProviders, k, string(p.ID))
		rec := expiryRecord{expiry: time.Now()}
		err := be.datastore.Put(ctx, dsKey, rec.MarshalBinary())
		require.NoError(b, err)

		peers[i] = p.ID
		reqs[i] = &pb.Message{
			Type: pb.Message_GET_PROVIDERS,
			Key:  keys[i],
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := d.handleGetProviders(ctx, peers[b.N-i-1], reqs[i])
		if err != nil {
			b.Error(err)
		}
	}
}

func TestDHT_handleGetProviders_happy_path(t *testing.T) {
	ctx := context.Background()
	d := newTestDHT(t)

	fillRoutingTable(t, d, 250)

	key := []byte("random-key")

	be, err := typedBackend[*ProvidersBackend](d, namespaceProviders)
	require.NoError(t, err)

	providers := []peer.AddrInfo{
		newAddrInfo(t),
		newAddrInfo(t),
		newAddrInfo(t),
	}

	for _, p := range providers {
		// add to addresses peerstore
		d.host.Peerstore().AddAddrs(p.ID, p.Addrs, time.Hour)

		// write to datastore
		dsKey := newDatastoreKey(namespaceProviders, string(key), string(p.ID))
		rec := expiryRecord{expiry: time.Now()}
		err := be.datastore.Put(ctx, dsKey, rec.MarshalBinary())
		require.NoError(t, err)
	}

	req := &pb.Message{
		Type: pb.Message_GET_PROVIDERS,
		Key:  key,
	}

	res, err := d.handleGetProviders(ctx, newPeerID(t), req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_GET_PROVIDERS, res.Type)
	assert.Equal(t, req.Key, res.Key)
	assert.Nil(t, res.Record)
	assert.Len(t, res.CloserPeers, 20)
	require.Len(t, res.ProviderPeers, 3)
	for _, p := range res.ProviderPeers {
		assert.Len(t, p.Addresses(), 1)
	}

	cacheKey := newDatastoreKey(be.namespace, string(key))
	set, found := be.cache.Get(cacheKey.String())
	require.True(t, found)
	assert.Len(t, set.providers, 3)
}

func TestDHT_handleGetProviders_do_not_return_expired_records(t *testing.T) {
	ctx := context.Background()
	d := newTestDHT(t)

	fillRoutingTable(t, d, 250)

	key := []byte("random-key")

	// check if the record was store in the datastore
	be, err := typedBackend[*ProvidersBackend](d, namespaceProviders)
	require.NoError(t, err)

	provider1 := newAddrInfo(t)
	provider2 := newAddrInfo(t)

	d.host.Peerstore().AddAddrs(provider1.ID, provider1.Addrs, time.Hour)
	d.host.Peerstore().AddAddrs(provider2.ID, provider2.Addrs, time.Hour)

	// write valid record
	dsKey := newDatastoreKey(namespaceProviders, string(key), string(provider1.ID))
	rec := expiryRecord{expiry: time.Now()}
	err = be.datastore.Put(ctx, dsKey, rec.MarshalBinary())
	require.NoError(t, err)

	// write expired record
	dsKey = newDatastoreKey(namespaceProviders, string(key), string(provider2.ID))
	rec = expiryRecord{expiry: time.Now().Add(-be.cfg.ProvideValidity - time.Second)}
	err = be.datastore.Put(ctx, dsKey, rec.MarshalBinary())
	require.NoError(t, err)

	req := &pb.Message{
		Type: pb.Message_GET_PROVIDERS,
		Key:  key,
	}

	res, err := d.handleGetProviders(ctx, newPeerID(t), req)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_GET_PROVIDERS, res.Type)
	assert.Equal(t, req.Key, res.Key)
	assert.Nil(t, res.Record)
	assert.Len(t, res.CloserPeers, 20)
	require.Len(t, res.ProviderPeers, 1) // only one provider

	// record was deleted
	_, err = be.datastore.Get(ctx, dsKey)
	assert.ErrorIs(t, err, ds.ErrNotFound)
}

func TestDHT_handleGetProviders_only_serve_filtered_addresses(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultConfig()

	testMaddr := ma.StringCast("/dns/maddr.dummy")

	// define a filter that returns a completely different address and discards
	// every other
	cfg.AddressFilter = func(maddrs []ma.Multiaddr) []ma.Multiaddr {
		return []ma.Multiaddr{testMaddr}
	}

	d := newTestDHTWithConfig(t, cfg)

	fillRoutingTable(t, d, 250)

	key := []byte("random-key")

	be, err := typedBackend[*ProvidersBackend](d, namespaceProviders)
	require.NoError(t, err)

	p := newAddrInfo(t)
	require.True(t, len(p.Addrs) > 0, "need addr info with at least one address")

	// add to addresses peerstore
	d.host.Peerstore().AddAddrs(p.ID, p.Addrs, time.Hour)

	// write to datastore
	dsKey := newDatastoreKey(namespaceProviders, string(key), string(p.ID))
	rec := expiryRecord{expiry: time.Now()}
	err = be.datastore.Put(ctx, dsKey, rec.MarshalBinary())
	require.NoError(t, err)

	req := &pb.Message{
		Type: pb.Message_GET_PROVIDERS,
		Key:  key,
	}

	res, err := d.handleGetProviders(ctx, newPeerID(t), req)
	require.NoError(t, err)

	require.Len(t, res.ProviderPeers, 1)
	maddrs := res.ProviderPeers[0].Addresses()
	require.Len(t, maddrs, 1)
	assert.True(t, maddrs[0].Equal(testMaddr))
}

func TestDHT_normalizeRTJoinedWithPeerStore(t *testing.T) {
	d := newTestDHT(t)

	peers := fillRoutingTable(t, d, 250)

	normalizedRT, err := d.NormalizeRTJoinedWithPeerStore(kadt.PeerID(peers[0]).Key())
	require.NoError(t, err)

	for _, paddedMarshalledBucket := range normalizedRT {
		resp, err := private_routing.UnmarshallPlaintextToPB(paddedMarshalledBucket)
		require.NoError(t, err)

		assert.Len(t, resp.CloserPeers, d.cfg.BucketSize)
		assert.Len(t, resp.ProviderPeers, 0)
		for _, closerPeer := range resp.CloserPeers {
			// TODO: test is failing.
			// The buckets are padded with dummy peers, not actually peers
			assert.Equal(t, len(closerPeer.Addrs), 1) // this is 1 because fillRoutingTable assigns 1 multiaddr to each peer

			ID := peer.ID(closerPeer.Id)
			address := closerPeer.Addrs[0]
			exists := false
			for _, peer := range peers {
				if peer == ID {
					exists = true
					address_bytes := d.host.Peerstore().Addrs(peer)[0].Bytes()
					assert.Equal(t, address, address_bytes)
				}
			}
			assert.True(t, exists)
		}
		resp.Reset()
	}

}

type results struct {
	requestLen    int
	responseLen   int
	serverRuntime int64
}

func TestDHT_handlePrivateFindPeer(t *testing.T) {
	d := newTestDHT(t)

	serverPeer := newPeerID(t)

	peers := fillRoutingTable(t, d, 2000)

	assert.Equal(t, len(peers), d.host.Peerstore().PeersWithAddrs().Len())
	printCPLAndBucketSizes(d, peers)

	// First generate PIR request
	keyBytes := []byte("key")

	targetKey := kadt.PeerID(keyBytes).Key()
	serverKey := kadt.PeerID(serverPeer).Key()

	mode := pir.RLWE_Whispir_3_Keys
	pirClientPeerRouting := private_routing.NewPirClientPeerRouting(mode)
	pirRequestCloserPeers, err := pirClientPeerRouting.GenerateRequest(targetKey, serverKey)
	require.NoError(t, err)

	msg := &pb.Message{
		Type:               pb.Message_PRIVATE_FIND_NODE,
		PIR_Message_ID:     1234,
		CloserPeersRequest: pirRequestCloserPeers,
	}

	resp, err := d.handlePrivateFindPeer(context.Background(), peers[0], msg)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_PRIVATE_FIND_NODE, resp.Type)
	assert.Equal(t, resp.PIR_Message_ID, msg.PIR_Message_ID)
	assert.NotNil(t, resp.CloserPeersResponse)
	assert.Nil(t, resp.Record)

	plaintextPBCloserPeers, err := pirClientPeerRouting.ProcessResponse(resp.CloserPeersResponse)
	require.NoError(t, err)

	checkCloserPeers(t, plaintextPBCloserPeers, d.cfg.BucketSize)
	assert.Len(t, resp.ProviderPeers, 0)

}

// func TestDHT_compareHandleFindPeer_and_privateHandleFindPeer(t *testing.T) {
// 	// TODO: check that the output of PrivateFindPeer includes all nodes from FindPeer that have the same CPL as the target key
// }

func TestDHT_handlePrivateGetProviders(t *testing.T) {
	d := newTestDHT(t)

	queryingPeer := newPeerID(t)

	peers := fillRoutingTable(t, d, 250)

	assert.Equal(t, len(peers), d.host.Peerstore().PeersWithAddrs().Len())
	printCPLAndBucketSizes(d, peers)

	// First generate PIR pirRequestProviderPeers
	keyBytes := []byte("random-key")

	targetKey := kadt.PeerID(keyBytes).Key()
	serverKey := kadt.PeerID(queryingPeer).Key()

	mode := pir.RLWE_Whispir_3_Keys
	pirClientPeerRouting := private_routing.NewPirClientPeerRouting(mode)
	pirRequestCloserPeers, err := pirClientPeerRouting.GenerateRequest(targetKey, serverKey)
	require.NoError(t, err)

	log2_num_records := 10
	be, providers, cids := createProviders(t, d, 1<<log2_num_records)
	log2_num_Buckets := 8
	var lookupFileCID = cids[0]
	pirClientProviderRouting := private_routing.NewPirClientProviderRouting(log2_num_Buckets, mode)
	pirRequestProviderPeers, err := pirClientProviderRouting.GenerateRequest(lookupFileCID)
	require.NoError(t, err)

	msg := &pb.Message{
		Type:                 pb.Message_PRIVATE_FIND_NODE,
		PIR_Message_ID:       1234,
		CloserPeersRequest:   pirRequestCloserPeers,
		ProviderPeersRequest: pirRequestProviderPeers,
	}
	//
	resp, err := d.handlePrivateGetProviderRecords(context.Background(), queryingPeer, msg)
	require.NoError(t, err)

	assert.Equal(t, pb.Message_PRIVATE_FIND_NODE, resp.Type)
	assert.Equal(t, resp.PIR_Message_ID, msg.PIR_Message_ID)
	assert.NotNil(t, resp.CloserPeersResponse)
	assert.Nil(t, resp.Record)

	plaintextPBCloserPeers, err := pirClientPeerRouting.ProcessResponse(resp.CloserPeersResponse)
	require.NoError(t, err)

	checkCloserPeers(t, plaintextPBCloserPeers, d.cfg.BucketSize)

	plaintextPBProviderPeers, err := pirClientPeerRouting.ProcessResponse(resp.ProviderPeersResponse)
	require.NoError(t, err)

	checkProviderPeers(t, plaintextPBProviderPeers, be, providers)
}

func BenchmarkDHT_PrivateFindPeer(b *testing.B) {
	d := newTestDHT(b)

	// build routing table
	peers := fillRoutingTable(b, d, 250)

	serverPeer := newPeerID(b)
	serverKey := kadt.PeerID(serverPeer).Key()

	runs := 100
	ourResults := make([]results, runs)

	mode := pir.RLWE_Whispir_3_Keys
	pirClient := private_routing.NewPirClientPeerRouting(mode)

	// build requests
	reqs := make([]*pb.Message, runs)
	for i := 0; i < runs; i++ {
		keyBytes := []byte("random-key-" + strconv.Itoa(i))

		targetKey := kadt.PeerID(keyBytes).Key()

		pirRequest, err := pirClient.GenerateRequest(targetKey, serverKey)
		require.NoError(b, err)

		reqs[i] = &pb.Message{
			Type:               pb.Message_PRIVATE_FIND_NODE,
			PIR_Message_ID:     1234,
			CloserPeersRequest: pirRequest,
		}

		ourResults[i].requestLen = len(pirRequest.GetEncryptedQuery()) + len(pirRequest.GetParameters()) + len(pirRequest.GetRLWEEvaluationKeys())
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < runs; i++ {
		start := time.Now()
		resp, err := d.handlePrivateFindPeer(ctx, peers[0], reqs[i])
		ourResults[i].responseLen = len(resp.CloserPeersResponse.GetCiphertexts())
		require.NoError(b, err)
		elapsed := time.Since(start)
		ourResults[i].serverRuntime = elapsed.Milliseconds()
	}
	b.ReportAllocs()
	b.ResetTimer()

	printStats(ourResults)
}

func checkCloserPeers(t *testing.T, resp *pb.Message, bucketSize int) {
	assert.Len(t, resp.CloserPeers, bucketSize)
	assert.Equal(t, len(resp.CloserPeers[0].Addrs), 1)
	printCloserPeers(resp)
}

func checkProviderPeers(t *testing.T, resp *pb.Message, backend *ProvidersBackend, providers []peer.AddrInfo) {
	// check that each provider is one of the providers from the variable above
	// based on the multiaddresses
	for _, providerPeer := range resp.ProviderPeers {
		assert.Len(t, providerPeer.Addresses(), 1)
		multiaddr := providerPeer.Addresses()[0]
		matchFound := false
		for _, provider := range providers {
			if provider.Addrs[0] == multiaddr {
				matchFound = true
				break
			}
		}
		require.True(t, matchFound)
	}
	// TODO: check that there exists 2 providers
	//    for the given CID, in the response as in the normal handleGetProviders case.
	//     (There may be more providers, but for other CIDs.)
	// require.Len(t, resp.ProviderPeers, 2) // this is incorrect probably
}

package zikade

import (
	"context"
	"fmt"
	"github.com/ipfs/go-cid"
	"math/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/plprobelab/zikade/kadt"
	"github.com/plprobelab/zikade/pb"
)

var rng = rand.New(rand.NewSource(1337))

// newTestHost returns a libp2p host with the given options. It also applies
// options that are common to all test hosts.
func newTestHost(t testing.TB, opts ...libp2p.Option) host.Host {
	// If two peers simultaneously connect, they could end up in a state where
	// one peer is waiting on the connection for the other one, although there
	// already exists a valid connection. The libp2p dial loop doesn't recognize
	// the new connection immediately, but only after the local dial has timed
	// out. By default, the timeout is set to 5s which results in failing tests
	// as the tests time out. By setting the timeout to a much lower value, we
	// work around the timeout issue. Try to remove the following swarm options
	// after https://github.com/libp2p/go-libp2p/issues/2589 was resolved.
	// Also, the below should be changed to [swarm.WithDialTimeoutLocal]. Change
	// that after https://github.com/libp2p/go-libp2p/pull/2595 is resolved.
	dialTimeout := 500 * time.Millisecond
	swarmOpts := libp2p.SwarmOpts(swarm.WithDialTimeout(dialTimeout))

	// The QUIC transport leaks go-routines, so we're only enabling the TCP
	// transport for our tests. Remove after:
	// https://github.com/libp2p/go-libp2p/issues/2514 was fixed
	tcpTransport := libp2p.Transport(tcp.NewTCPTransport)

	h, err := libp2p.New(append(opts, swarmOpts, tcpTransport)...)
	require.NoError(t, err)

	return h
}

func newTestDHT(t testing.TB) *DHT {
	cfg := DefaultConfig()
	cfg.Logger = devnull

	return newTestDHTWithConfig(t, cfg)
}

func newTestDHTWithConfig(t testing.TB, cfg *Config) *DHT {
	t.Helper()

	h := newTestHost(t, libp2p.NoListenAddrs)

	d, err := New(h, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err = d.Close(); err != nil {
			t.Logf("closing dht: %s", err)
		}

		if err = h.Close(); err != nil {
			t.Logf("closing host: %s", err)
		}
	})

	return d
}

func newPeerID(t testing.TB) peer.ID {
	id, _ := newIdentity(t)
	return id
}

func newIdentity(t testing.TB) (peer.ID, crypto.PrivKey) {
	t.Helper()

	priv, pub, err := crypto.GenerateEd25519Key(rng)
	require.NoError(t, err)

	id, err := peer.IDFromPublicKey(pub)
	require.NoError(t, err)

	return id, priv
}

// fillRoutingTable populates d's routing table and peerstore with n random peers and addresses
func fillRoutingTable(t testing.TB, d *DHT, n int) []peer.ID {
	t.Helper()

	peers := make([]peer.ID, n)

	for i := 0; i < n; i++ {
		// generate peer ID
		pid := newPeerID(t)

		peers[i] = pid

		// add peer to routing table
		d.rt.AddNode(kadt.PeerID(pid))

		// craft random network address for peer
		// use IP suffix of 1.1 to not collide with actual test hosts that
		// choose a random IP address via 127.0.0.1:0.
		a, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.1.1/tcp/%d", (2000+i)%65536))
		require.NoError(t, err)

		// add peer information to peer store
		d.host.Peerstore().AddAddr(pid, a, time.Hour)
	}

	return peers
}

func newAddrInfo(t testing.TB) peer.AddrInfo {
	return peer.AddrInfo{
		ID: newPeerID(t),
		Addrs: []ma.Multiaddr{
			ma.StringCast("/ip4/99.99.99.99/tcp/2000"), // must be a public address
		},
	}
}

func newAddProviderRequest(key []byte, addrInfos ...peer.AddrInfo) *pb.Message {
	providerPeers := make([]*pb.Message_Peer, len(addrInfos))
	for i, addrInfo := range addrInfos {
		providerPeers[i] = pb.FromAddrInfo(addrInfo)
	}

	return &pb.Message{
		Type:          pb.Message_ADD_PROVIDER,
		Key:           key,
		ProviderPeers: providerPeers,
	}
}

func printCPLAndBucketSizes(d *DHT, peers []peer.ID) {
	actualCPLs := make([]int, 256)
	for i := 0; i < len(peers); i++ {
		cpl := d.rt.Cpl(kadt.PeerID(peers[i]).Key())
		actualCPLs[cpl] = actualCPLs[cpl] + 1
	}

	println("Common prefix lengths: ")
	for i := 0; i < len(actualCPLs); i++ {
		print(actualCPLs[i], ",")
	}

	println("\nBucket lengths: ")
	prevBucketSize := -1
	totalNumberOfEntriesInRT := 0

	for i := 0; i < len(peers); i++ {
		givenBucketSize := d.rt.CplSize(i)
		if givenBucketSize == prevBucketSize && givenBucketSize < d.cfg.BucketSize {
			print("Last bucket ID in the RT with # of elements: ", givenBucketSize)
			break
		} else {
			print(givenBucketSize, ",")
			totalNumberOfEntriesInRT += givenBucketSize
		}
		prevBucketSize = givenBucketSize
	}

	println("\nTotal number of entries in RT:", totalNumberOfEntriesInRT,
		"\nTotal number of peers inserted:", len(peers),
		"\nNumber of entries not inserted into RT:", len(peers)-totalNumberOfEntriesInRT)
}

func printCloserPeers(resp *pb.Message) {
	closerPeers := resp.CloserPeers
	for _, val := range closerPeers {
		fromBytes, err := peer.IDFromBytes(val.GetId())
		if err != nil {
			return
		}
		println(fromBytes.String())
		addrs := val.GetAddrs()
		for _, addr := range addrs {
			println(ma.Cast(addr).String())
		}
		// println(val.GetConnection().String())
	}
}

func createProviders(t *testing.T, d *DHT, numberOfCids int) (*ProvidersBackend, []peer.AddrInfo, []cid.Cid) {
	be, err := typedBackend[*ProvidersBackend](d, namespaceProviders)
	require.NoError(t, err)
	ctx := context.Background()

	// creates CIDs and inserts their providers into own provider store
	providers := []peer.AddrInfo{}
	for i := 0; i < numberOfCids; i++ {
		providers = append(providers, newAddrInfo(t))
	}

	// make half as many CIDs as providers
	cids := make([]cid.Cid, len(providers)/2)
	for i := 0; i < len(providers)/2; i++ {
		fileCID := NewRandomContent(t)
		cids[i] = fileCID
	}

	// advertise each CID by two providers
	for i, p := range providers {
		// add to addresses peerstore
		d.host.Peerstore().AddAddrs(p.ID, p.Addrs, time.Hour)

		var fileCID cid.Cid
		if i < len(providers)/2 {
			fileCID = cids[i]
		} else {
			fileCID = cids[i-len(providers)/2]
		}

		// write to datastore
		dsKey := newDatastoreKey(namespaceProviders, string(fileCID.Hash()), string(p.ID))
		rec := expiryRecord{expiry: time.Now()}
		err := be.datastore.Put(ctx, dsKey, rec.MarshalBinary())
		require.NoError(t, err)
	}

	return be, providers, cids

}

func printStats(ourResults []results) {
	var avgReqLen float64
	var avgResLen float64
	var avgServerTime float64
	runs := len(ourResults)
	for _, res := range ourResults {
		// print("\n ", i, " ", res.requestLen, " ", res.responseLen, " ", res.serverRuntime, "\n")
		avgReqLen += float64(res.requestLen)
		avgResLen += float64(res.responseLen)
		avgServerTime += float64(res.serverRuntime)
	}
	avgReqLen = avgReqLen / float64(runs)
	avgResLen = avgResLen / float64(runs)
	avgServerTime = float64(int64(int(avgServerTime) / runs))
	fmt.Printf("Averaged results over %d runs: Req Length %f, Response Length %f, Server time %f\n", runs, avgReqLen, avgResLen, avgServerTime)
}

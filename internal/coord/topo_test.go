package coord

import (
	"fmt"
	. "github.com/plprobelab/zikade/internal/coord/routing"
	"github.com/plprobelab/zikade/kadt"
	"math/rand"
	"sort"
	"testing"

	"github.com/benbjohnson/clock"
	"github.com/plprobelab/zikade/internal/nettest"
	"github.com/stretchr/testify/require"
)

func TestRoutingNormVsSimple(t *testing.T) {
	// ctx := kadtest.CtxShort(t)

	clk := clock.NewMock()
	_, nodesNormalizedRT, err := nettest.GenerateCrawledTopology(clk, true)
	require.NoError(t, err)

	_, nodesSimpleRT, err := nettest.GenerateCrawledTopology(clk, false)
	require.NoError(t, err)

	// self := nodesNormalizedRT[0].NodeID

	num_nodes := len(nodesNormalizedRT)
	fmt.Println("Number of nodesNormalizedRT: ", num_nodes)
	// select number from 0 to num_nodes-1 at random
	// generate random integer between 0 and num_nodes-1
	target_node := rand.Intn(num_nodes - 1)
	target := nodesNormalizedRT[target_node].NodeID

	simple_target := nodesSimpleRT[target_node].NodeID.Key()
	require.Equal(t, target.Key(), simple_target)

	clientPeerID := nodesSimpleRT[0].NodeID
	hopCountSimple := doLookup(nodesSimpleRT, target, clientPeerID)

	// TODO: Can remove the next line as they will be the same
	clientPeerID = nodesNormalizedRT[0].NodeID
	hopCountNormalized := doLookup(nodesSimpleRT, target, clientPeerID)

	// print difference in hop count
	fmt.Println("Norm: ", hopCountNormalized)
	fmt.Println("Simple: ", hopCountSimple)
	fmt.Println("Difference: ", hopCountNormalized-hopCountSimple)
}

func doLookup(nodes []*nettest.Peer, target kadt.PeerID, client kadt.PeerID) int {
	rt := nodes[0].RoutingTable
	seeds := rt.NearestNodes(target.Key(), 5) // 5 closest nodesNormalizedRT to target <- change if needed for various experiments
	targetFound := false
	// check if seeds list contains target
	for _, a := range seeds {
		if a == target {
			targetFound = true
			break
		}
	}
	hopCount := 1
	// while loop target_in_seeds is false
	for targetFound == false {
		// sort items in seeds list by distance to target
		sort.SliceStable(seeds, func(i, j int) bool {
			distI := seeds[i].Key().Xor(target.Key())
			distJ := seeds[j].Key().Xor(target.Key())

			cmp := distI.Compare(distJ)
			if cmp != 0 {
				return cmp < 0
			}
			return false
		})
		// for i = 3 closest nodesNormalizedRT in seeds, query nearestnodes on those rts
		// append results to seeds list
		for i := 0; i < 3; i++ {
			// get the routing table of the node
			for _, a := range nodes {
				if a.NodeID == seeds[i] {
					rt = a.RoutingTable
					break
				}
			}

			var nearestNodes []kadt.PeerID
			if rtNormalized, isRtNormalized := rt.(interface{}).(RoutingTableCplNormalized[kadt.Key, kadt.PeerID]); isRtNormalized {
				// TODO: NearestNodesAsServer returns the full d.cfg.Bucketsize (20) number of elements --- doesn't currently have a tunable parameter
				//  so I set the call to NearestNodes to return back 20
				nearestNodes = rtNormalized.NearestNodesAsServer(target.Key(), client.Key())
			} else {
				nearestNodes = rt.NearestNodes(target.Key(), 20)
			}

			// get the 5 closest nodesNormalizedRT to target from the routing table
			// append to seeds list
			seeds = append(seeds, nearestNodes...)
		}
	}

	hopCount++
	// check if seeds list contains target
	for _, a := range seeds {
		if a == target {
			targetFound = true
			break
		}
	}

	return hopCount
}

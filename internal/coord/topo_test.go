package coord

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"golang.org/x/exp/slices"

	"github.com/benbjohnson/clock"
	. "github.com/plprobelab/zikade/internal/coord/routing"
	"github.com/plprobelab/zikade/internal/nettest"
	"github.com/plprobelab/zikade/kadt"
	"github.com/stretchr/testify/require"
)

func TestRoutingNormVsTrie(t *testing.T) {
	clk := clock.NewMock()
	_, nodesTrieRT, err := nettest.GenerateCrawledTopology(clk, false)
	require.NoError(t, err)

	fmt.Println("Number of nodesTrieRT: ", len(nodesTrieRT))
	nodeIDs := make([]kadt.PeerID, len(nodesTrieRT))
	for i, node := range nodesTrieRT {
		nodeIDs[i] = node.NodeID
	}

	// select number from 0 to num_nodes-1 at random
	// generate random integer between 0 and num_nodes-1
	targetIndex := 6991 // rand.Intn(len(nodesTrieRT) - 1)
	fmt.Println(targetIndex)
	target := nodesTrieRT[targetIndex].NodeID

	fmt.Println("target: ", target.String())

	clientPeerID := nodesTrieRT[0].NodeID
	hopCountTrie, err := doLookupSimplified(nodesTrieRT, nodeIDs, target, clientPeerID)
	require.NoError(t, err)
	fmt.Println("Trie: ", hopCountTrie)

	// _, nodesNormalizedRT, err := nettest.GenerateCrawledTopology(clk, true)
	// hopCountNormalized, err := doLookup(nodesNormalizedRT, target, clientPeerID)
	// require.NoError(t, err)
	//	fmt.Println("Number of nodesNormalizedRT: ", len(nodesNormalizedRT))

	// // print difference in hop count
	// fmt.Println("Norm: ", hopCountNormalized)
	// fmt.Println("Trie: ", hopCountTrie)
	// fmt.Println("Difference: ", hopCountNormalized-hopCountTrie)
}

func doLookupSimplified(nodes []*nettest.Peer, nodeIDs []kadt.PeerID, target kadt.PeerID, client kadt.PeerID) (int, error) {
	var seeds []kadt.PeerID
	var nearestNodes []kadt.PeerID
	hopCount := 0
	peersVisited := 0

	// initialize seeds with results of running rt.NearestNodes on the client
	//  note the client continues to use NearestNodes, instead of NearestNodesAsServer
	index := slices.Index(nodeIDs, client)
	if index == -1 {
		return 0, fmt.Errorf("could not find one of the peers returned by a server in the global list of nodeIDs")
	}
	seeds = nodes[index].RoutingTable.NearestNodes(target.Key(), 20)
	var seedsNextRound []kadt.PeerID

	targetFound := slices.Contains(seeds, target)
	if targetFound {
		return 0, nil
	}

	for targetFound == false {
		//for _, peerID := range seeds {
		//	cpl := peerID.Key().CommonPrefixLength(target.Key())
		//}
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

		// unique after ordering
		for i := 1; i < len(seeds); i++ {
			if seeds[i] == seeds[i-1] {
				seeds = slices.Delete(seeds, i, i+1)
			}
		}

		// pick top 20 from seeds
		seeds = seeds[:20]

		for _, peerID := range seeds {
			cpl := peerID.Key().CommonPrefixLength(target.Key())
			fmt.Println(cpl)
		}
		fmt.Printf("maxCPL %d\n", target.Key().CommonPrefixLength(seeds[0].Key()))

		// as long as the target is not found,
		// for all nodes in seeds, get their RTs, query nearestnodes on those rts
		for i := 0; i < len(seeds) && !targetFound; i++ {
			// get the routing table of the node
			index := slices.Index(nodeIDs, seeds[i])
			if index == -1 {
				return 0, fmt.Errorf("could not find one of the peers returned by a server in the global list of nodeIDs")
			}
			rt := nodes[index].RoutingTable

			// query nearestnodes on those rts
			if rtNormalized, isRtNormalized := rt.(interface{}).(RoutingTableCplNormalized[kadt.Key, kadt.PeerID]); isRtNormalized {
				nearestNodes = rtNormalized.NearestNodesAsServer(target.Key(), client.Key())
			} else {
				nearestNodes = rt.NearestNodes(target.Key(), 20)
			}
			if len(nearestNodes) < 20 {
				return 0, fmt.Errorf("nearest nodes from node index %d returns less than 20 nodes: %d", index, len(nearestNodes))
			}

			peersVisited++

			// set targetFound to whether the nearestNodes output by this last peer, includes the target
			targetFound = slices.Contains(nearestNodes, target)
			if targetFound {
				fmt.Printf("target found on RT of node %s\n", nodes[index].NodeID.String())
			}
			// append to seeds list
			seedsNextRound = append(seedsNextRound, nearestNodes...)
		}

		for i, seed := range seedsNextRound {
			if slices.Contains(seeds, seed) {
				seedsNextRound = slices.Delete(seedsNextRound, i, i+1)
			}
		}

		seeds = seedsNextRound

		hopCount++
		fmt.Println(hopCount)
	}
	return hopCount, nil
}

func doLookup(nodes []*nettest.Peer, target kadt.PeerID, client kadt.PeerID) (int, error) {
	// TODO: rt should, for the first lookup, refer to the client peer's rt.
	//  Not just any random peer's RT for the seeds
	rt := nodes[0].RoutingTable
	var nearestNodes []kadt.PeerID
	if rtNormalized, isRtNormalized := rt.(interface{}).(RoutingTableCplNormalized[kadt.Key, kadt.PeerID]); isRtNormalized {
		nearestNodes = rtNormalized.NearestNodesAsServer(target.Key(), client.Key())
	} else {
		nearestNodes = rt.NearestNodes(target.Key(), 20)
	}

	var seeds []kadt.PeerID
	var closest_nodes []kadt.PeerID
	seeds = append(seeds, nearestNodes...)
	if len(seeds) < 20 {
		return 0, fmt.Errorf("nearest nodes returns less than 20 nodes: %d", len(seeds))
	}
	targetFound := false
	// check if seeds list contains target
	if slices.Contains(seeds, target) {
		return 1, nil
	}
	hopCount := 1
	sort.SliceStable(seeds, func(i, j int) bool {
		distI := seeds[i].Key().Xor(target.Key())
		distJ := seeds[j].Key().Xor(target.Key())

		cmp := distI.Compare(distJ)
		if cmp != 0 {
			return cmp < 0
		}
		return false
	})
	// select 3 closest nodes from seeds list
	closest_nodes = seeds[:3]
	fmt.Println(target.Key(), seeds[0].Key(), seeds[1].Key(), seeds[2].Key())
	fmt.Println("closest_nodes: ", closest_nodes)
	// while loop target_in_seeds is false
	for targetFound == false {
		// reset seeds list to empty
		seeds = []kadt.PeerID{}

		// for i = 3 closest nodesNormalizedRT in seeds, query nearestnodes on those rts
		// append results to seeds list
		for i := 0; i < 3; i++ {
			// get the routing table of the node
			for _, a := range nodes {
				if a.NodeID == closest_nodes[i] {
					rt = a.RoutingTable
					break
				}
			}

			if rtNormalized, isRtNormalized := rt.(interface{}).(RoutingTableCplNormalized[kadt.Key, kadt.PeerID]); isRtNormalized {
				// TODO: NearestNodesAsServer returns the full d.cfg.Bucketsize (20) number of elements --- doesn't currently have a tunable parameter
				//  so I set the call to NearestNodes to return back 20
				nearestNodes = rtNormalized.NearestNodesAsServer(target.Key(), client.Key())
			} else {
				nearestNodes = rt.NearestNodes(target.Key(), 20)
			}
			if len(nearestNodes) < 20 {
				return 0, fmt.Errorf("nearest nodes returns less than 20 nodes: %d", len(nearestNodes))
			}

			// append to seeds list
			seeds = append(seeds, nearestNodes...)
		}
		hopCount++

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

		closest_nodes = seeds[:3]

		// check if seeds list contains target
		if slices.Contains(seeds, target) {
			targetFound = true
		}
	}
	return hopCount, nil
}

package coord

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/benbjohnson/clock"
	"github.com/plprobelab/zikade/internal/kadtest"
	"github.com/plprobelab/zikade/internal/nettest"
	"github.com/stretchr/testify/require"
)

func TestRoutingNormVsSimple(t *testing.T) {
	ctx := kadtest.CtxShort(t)

	clk := clock.NewMock()
	_, nodes, err := nettest.NormCrawledTopology(clk)
	_, nodes_simple, err := nettest.SimpleCrawledTopology(clk)
	require.NoError(t, err)

	self := nodes[0].NodeID

	num_nodes := len(nodes)
	// select number from 0 to num_nodes-1 at random
	// generate random integer between 0 and num_nodes-1
	target_node := rand.Intn(num_nodes - 1)
	target := nodes[target_node].NodeID

	simple_target := nodes_simple[target_node].NodeID.Key()
	require.Equal(t, target.Key(), simple_target)

	rt := nodes[0].RoutingTable
	// define boolean to check if target is in seeds list
	// seeds is a list of PeerIDs
	seeds := rt.NearestNodes(target.Key(), 5) // 5 closest nodes to target <- change if needed for various experiments
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
		// for i = 3 closest nodes in seeds, query nearestnodes on those rts
		// append results to seeds list
		for i := 0; i < 3; i++ {
			// get the routing table of the node
			rt = seeds[i].RoutingTable

		}

		hopCount++

		// check if seeds list contains target
		for _, a := range seeds {
			if a == target {
				targetFound = true
				break
			}
		}
	}

	// repeat process with simplert and count number of hops. then return difference.
	// simple_seeds := nodes_simple[0].RoutingTable.NearestNodes(target, 5)

}

package coord

import (
	"fmt"
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
	_, nodes, err := nettest.GenerateCrawledTopology(clk, true)
	_, nodes_simple, err := nettest.GenerateCrawledTopology(clk, false)
	require.NoError(t, err)

	// self := nodes[0].NodeID

	num_nodes := len(nodes)
	fmt.Println("Number of nodes: ", num_nodes)
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
			for _, a := range nodes {
				if a.NodeID == seeds[i] {
					rt = a.RoutingTable
					break
				}
			}
			// get the 5 closest nodes to target from the routing table
			// append to seeds list
			seeds = append(seeds, rt.NearestNodes(target.Key(), 5)...)
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
	rt = nodes_simple[0].RoutingTable
	seeds_simple := rt.NearestNodes(target.Key(), 5) // 5 closest nodes to target <- change if needed for various experiments
	targetFound = false
	// check if seeds list contains target
	for _, a := range seeds_simple {
		if a == target {
			targetFound = true
			break
		}
	}
	hopCount_simple := 1
	// while loop target_in_seeds is false
	for targetFound == false {
		// sort items in seeds list by distance to target
		sort.SliceStable(seeds_simple, func(i, j int) bool {
			distI := seeds_simple[i].Key().Xor(target.Key())
			distJ := seeds_simple[j].Key().Xor(target.Key())

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
			for _, a := range nodes_simple {
				if a.NodeID == seeds_simple[i] {
					rt = a.RoutingTable
					break
				}
			}
			// get the 5 closest nodes to target from the routing table
			// append to seeds list
			seeds_simple = append(seeds_simple, rt.NearestNodes(target.Key(), 5)...)
		}
		hopCount_simple++
		// check if seeds list contains target
		for _, a := range seeds_simple {
			if a == target {
				targetFound = true
				break
			}
		}
	}

	// print difference in hop count
	fmt.Println("Norm: ", hopCount)
	fmt.Println("Simple: ", hopCount_simple)
	fmt.Println("Difference: ", hopCount-hopCount_simple)
}

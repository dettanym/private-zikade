package nettest

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/plprobelab/zikade/internal/coord/routing"
	"golang.org/x/exp/slices"
	"os"

	"github.com/benbjohnson/clock"
	"github.com/plprobelab/go-kademlia/routing/normalizedrt"
	"github.com/plprobelab/go-kademlia/routing/simplert"
	"github.com/plprobelab/go-libdht/kad/triert"

	"github.com/plprobelab/zikade/kadt"
)

// LinearTopology creates a network topology consisting of n nodes peered in a linear chain.
// The nodes are configured with routing tables that contain immediate neighbours.
// It returns the topology and the nodes ordered such that nodes[x] has nodes[x-1] and nodes[x+1] in its routing table
// The topology is not a ring: nodes[0] only has nodes[1] in its table and nodes[n-1] only has nodes[n-2] in its table.
// nodes[1] has nodes[0] and nodes[2] in its routing table.
// If n > 2 then the first and last nodes will not have one another in their routing tables.
func LinearTopology(n int, clk clock.Clock) (*Topology, []*Peer, error) {
	nodes := make([]*Peer, n)

	top := NewTopology(clk)
	for i := range nodes {

		id, err := NewPeerID()
		if err != nil {
			return nil, nil, err
		}

		rt, err := triert.New[kadt.Key, kadt.PeerID](id, nil)
		if err != nil {
			return nil, nil, err
		}

		nodes[i] = &Peer{
			NodeID:       id,
			Router:       NewRouter(id, top),
			RoutingTable: rt,
		}
	}

	// Define the network topology, with default network links between every node
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			top.ConnectPeers(nodes[i], nodes[j])
		}
	}

	// Connect nodes in a chain
	for i := 0; i < len(nodes); i++ {
		if i > 0 {
			nodes[i].Router.AddToPeerStore(context.Background(), nodes[i-1].NodeID)
			nodes[i].RoutingTable.AddNode(nodes[i-1].NodeID)
		}
		if i < len(nodes)-1 {
			nodes[i].Router.AddToPeerStore(context.Background(), nodes[i+1].NodeID)
			nodes[i].RoutingTable.AddNode(nodes[i+1].NodeID)
		}
	}

	return top, nodes, nil
}

type Neighbour_Data struct {
	PeerID     string   `json:"PeerID,omitempty"`
	Neighbours []string `json:"NeighborIDs,omitempty"`
	Errors     string   `json:"ErrorBits,omitempty"`
}

func GenerateCrawledTopology(clk clock.Clock, useNormalizedRT bool) (*Topology, []*Peer, error) {
	// this function will define the topology w.r.t how peers are distributed from the crawled data
	// read json file in nettest
	pwd, _ := os.Getwd()
	jsonFile, err := os.ReadFile(pwd + "/../nettest/2024-01-15T13:02_neighbors.json")
	if err != nil {
		return nil, nil, err
	}

	// unmarshal data into an array of neighbour_data
	var neighbours []Neighbour_Data
	err = json.Unmarshal(jsonFile, &neighbours)
	if err != nil {
		return nil, nil, fmt.Errorf("could not unmarshall crawled neighbours data to initialize simulation. Error: %s", err)
	}

	fmt.Println("Number of nodes: ", len(neighbours))
	fmt.Println(neighbours[0].PeerID)

	nodes := make([]*Peer, len(neighbours))
	top := NewTopology(clk)
	nodeIDs := make([]string, len(neighbours))
	// loop through neighbours array
	for i := range neighbours {
		if neighbours[i].Neighbours == nil || neighbours[i].PeerID == "" {
			return nil, nil, fmt.Errorf("unmarshalling crawled neighbours data returns an empty list of neighbours or an empty PeerID for index %d. Error: %s", i, err)
		}
		// for each neighbour, create a peer
		// and add it to the topology
		id := kadt.PeerID(neighbours[i].PeerID)
		nodeIDs[i] = id.String()
		var rt routing.RoutingTableCpl[kadt.Key, kadt.PeerID]
		if useNormalizedRT {
			rt = normalizedrt.New[kadt.Key, kadt.PeerID](id, i)
		} else {
			rt = simplert.New[kadt.Key, kadt.PeerID](id, i)
		}
		nodes[i] = &Peer{
			NodeID:       id,
			Router:       NewRouter(id, top),
			RoutingTable: rt,
		}
	}

	// define the network topology with links between nodes and their neighbours from the crawled data
	for i := range nodes {
		for j := range neighbours[i].Neighbours {
			// search for index of node with peerID neighbours[i]["neighbours"][j]
			// and connect the nodes. if index is not found, do nothing with that neighbour -- not in list of nodes
			k := slices.Index(nodeIDs, neighbours[i].Neighbours[j])
			if k != -1 {
				top.ConnectPeers(nodes[i], nodes[k])
				err := nodes[i].Router.AddToPeerStore(context.Background(), nodes[k].NodeID)
				if err != nil {
					return nil, nil, fmt.Errorf("error in adding a neighbour to node's simulated Router's PeerStore. Error: %s", err)
				}
				nodes[i].RoutingTable.AddNode(nodes[k].NodeID)
			}
		}
	}

	return top, nodes, nil
}

package nettest

import (
	"context"
	"encoding/json"
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
	PeerID     string
	Neighbours []string
	Errors     string
}

func NormCrawledTopology(clk clock.Clock) (*Topology, []*Peer, error) {
	// this function will define the topology w.r.t how peers are distributed from the crawled data
	jsonFile, err := os.ReadFile("coord/2024-01-15T13:02_neighbors.json")
	if err != nil {
		return nil, nil, err
	}

	// unmarshal data into an array of neighbour_data
	var neighbours []Neighbour_Data
	json.Unmarshal([]byte(jsonFile), &neighbours)

	nodes := make([]*Peer, len(neighbours))
	top := NewTopology(clk)

	// loop through neighbours array
	for i := range neighbours {
		// for each neighbour, create a peer
		// and add it to the topology
		id := kadt.PeerID(neighbours[i].PeerID)
		rt := normalizedrt.New[kadt.Key, kadt.PeerID](id, i)
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
			// and connect the nodes
			for k := range nodes {
				if nodes[k].NodeID.String() == neighbours[i].Neighbours[j] {
					top.ConnectPeers(nodes[i], nodes[k])
					nodes[i].Router.AddToPeerStore(context.Background(), nodes[k].NodeID)
					nodes[i].RoutingTable.AddNode(nodes[k].NodeID)
				}
				break
			}
		}
	}

	return top, nodes, nil
}

func SimpleCrawledTopology(clk clock.Clock) (*Topology, []*Peer, error) {
	// this function will define the topology w.r.t how peers are distributed from the crawled data
	jsonFile, err := os.ReadFile("coord/2024-01-15T13:02_neighbors.json")
	if err != nil {
		return nil, nil, err
	}

	// unmarshal data into an array of neighbour_data
	var neighbours []Neighbour_Data
	json.Unmarshal([]byte(jsonFile), &neighbours)

	nodes := make([]*Peer, len(neighbours))
	top := NewTopology(clk)

	// loop through neighbours array
	for i := range neighbours {
		// for each neighbour, create a peer
		// and add it to the topology
		id := kadt.PeerID(neighbours[i].PeerID)
		rt := simplert.New[kadt.Key, kadt.PeerID](id, i)
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
			// and connect the nodes
			for k := range nodes {
				if nodes[k].NodeID.String() == neighbours[i].Neighbours[j] {
					top.ConnectPeers(nodes[i], nodes[k])
					nodes[i].Router.AddToPeerStore(context.Background(), nodes[k].NodeID)
					nodes[i].RoutingTable.AddNode(nodes[k].NodeID)
				}
				break
			}
		}
	}

	return top, nodes, nil
}

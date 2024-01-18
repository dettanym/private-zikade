package nettest

import (
	"context"
	"encoding/json"
	"os"

	"github.com/benbjohnson/clock"

	"github.com/plprobelab/go-kademlia/routing/normalizedrt"
	"github.com/plprobelab/zikade/kadt"
)

type Neighbour_Data struct {
	PeerID     string
	Neighbours []string
	Errors     string
}

func CrawledTopology(n int, clk clock.Clock) (*Topology, []*Peer, error) {
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

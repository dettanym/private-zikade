package nettest

import (
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
	// change the array of neighbour_data into an array of maps
	// var neighbours_map []map[string]interface{}
	// for i := range neighbours {
	// 	neighbours_map[i] = map[string]interface{}{
	// 		"PeerID":     neighbours[i].PeerID,
	// 		"Neighbours": neighbours[i].Neighbours,
	// 		"Errors":     neighbours[i].Errors,
	// 	}
	// }

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

	// Define the network topology, with network links between every node and
	// their neighbours from the crawled data
	// for i := range nodes {
	// 	for j /* iterate through neighbours of neighbours[i]["neighbours"] */ {
	// 		k := // find peer with peerID neighbours[i]["neighbours"][j]
	// 			top.ConnectPeers(nodes[i], nodes[k])
	// 		nodes[i].Router.AddToPeerStore(context.Background(), nodes[i-1].NodeID)
	// 		nodes[i].RoutingTable.AddNode(nodes[i-1].NodeID)
	// 	}
	// }

	return top, nodes, nil
}

package private_routing

import (
	"fmt"

	"github.com/plprobelab/zikade/pb"
	pir "github.com/plprobelab/zikade/pir"
)

func RunPIRforCloserPeersRecords(req *pb.PIR_Request, ModifiedRT [][]byte) (*pb.PIR_Response, error) {

	var pir pir.PIR_Protocol_Simple_RLWE
	response, err := pir.ProcessRequestAndReturnResponse(req.SimpleRlweQuery)
	if err != nil {
		return nil, err
	}

	return &pb.PIR_Response{
		SimpleRlweResponse: response,
	}, nil

	// for bucketId, bucket := range ModifiedRT {
	// 	peersInBucket := make([]*pb.Message, 0)
	// 	for _, peer := range bucket {
	// 		*peer.Addrs
	// 	}
	// }

	// Import the simple_rlwe.go file and call the function that does the PIR
	return nil, fmt.Errorf("could not compute PIR response over ModifiedRT of peer records")
}

func RunPIRforProviderPeersRecords(req *pb.PIR_Request, mapCIDtoProviderPeers map[string][]byte) (*pb.PIR_Message, error) {
	// pir_request := req.Key
	// Maybe this method (runPIRforProviderPeerRecords) needs to be called from a PrivateFetch method on the Backend interface.
	// The PrivateFetch method can compute the join privately and then just run this method internally, returning the encrypted providerpeers.
	// The join would be computed as often as provider ads are requested.
	// We must do the join at least as frequent as the addressbook or the provider ads datastore is updated.
	return nil, fmt.Errorf("could not compute PIR response over mapCIDtoProviderPeers")
}

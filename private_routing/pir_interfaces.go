package private_routing

import (
	"fmt"

	"github.com/plprobelab/zikade/pb"
	"github.com/plprobelab/zikade/pir"
)

func RunPIRforCloserPeersRecords(req *pb.PIR_Request, ModifiedRT [][]byte) (*pb.PIR_Response, error) {
	simpleRLWEPIR := pir.SimpleRLWEPIR{}
	response, err := simpleRLWEPIR.ProcessRequestAndReturnResponse(req, ModifiedRT)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func RunPIRforProviderPeersRecords(req *pb.PIR_Request, mapCIDtoProviderPeers map[string][]byte) (*pb.PIR_Response, error) {
	// pir_request := req.Key
	// Maybe this method (runPIRforProviderPeerRecords) needs to be called from a PrivateFetch method on the Backend interface.
	// The PrivateFetch method can compute the join privately and then just run this method internally, returning the encrypted providerpeers.
	// The join would be computed as often as provider ads are requested.
	// We must do the join at least as frequent as the addressbook or the provider ads datastore is updated.
	return nil, fmt.Errorf("could not compute PIR response over mapCIDtoProviderPeers")
}

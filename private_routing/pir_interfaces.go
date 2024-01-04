package private_routing

import (
	"fmt"

	"github.com/plprobelab/zikade/kadt"
	"github.com/plprobelab/zikade/pir"

	"github.com/plprobelab/zikade/pb"
)

func RunPIRforCloserPeersRecords(req *pb.PIR_Request, ModifiedRT [][]byte) (*pb.PIR_Response, error) {
	simpleRLWEPIR := pir.NewSimpleRLWE_PIR_Protocol(int(len(ModifiedRT)))
	response, err := simpleRLWEPIR.ProcessRequestAndReturnResponse(req, ModifiedRT)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func RunPIRforProviderPeersRecords(req *pb.PIR_Request, mapCIDBucketToProviderPeers [][]byte) (*pb.PIR_Response, error) {

	simpleRLWEPIR := pir.NewSimpleRLWE_PIR_Protocol(int(len(mapCIDBucketToProviderPeers)))
	response, err := simpleRLWEPIR.ProcessRequestAndReturnResponse(req, mapCIDBucketToProviderPeers)
	if err != nil {
		return nil, fmt.Errorf("error in PIR: %v", err)
	}
	return response, nil
}

func GeneratePIRPlaintext(key kadt.Key) ([]byte, error) {
	return nil, nil
}

func ProcessPlaintextInPIRResponse(res []byte) ([]pb.Message_Peer, error) {
	return nil, nil
}

package private_routing

import (
	"encoding/binary"
	"fmt"
	"github.com/plprobelab/zikade/kadt"
	"github.com/plprobelab/zikade/pb"
	"google.golang.org/protobuf/proto"
)

type PIR_Client interface {
	GeneratePIRPlaintext(targetKey kadt.Key, serverKey kadt.Key) []byte

	// TODO: The implementations the unmarshalling code. Potentially just return pb.Message
	//  and have the caller extract the appropriate field?
	ProcessPlaintextInPIRResponse(res []byte) ([]*pb.Message_Peer, error)
}

type PIR_Client_ForPeerRouting struct {
	PIR_Client
}

func (*PIR_Client_ForPeerRouting) GeneratePIRPlaintext(targetKey kadt.Key, serverKey kadt.Key) []byte {
	cpl := uint64(targetKey.CommonPrefixLength(serverKey))
	cplBytes := make([]byte, 4) // CPL can be at most 256 bits = 1 byte long, can also use binary.MaxVarintLen64 instead of 4
	binary.LittleEndian.PutUint64(cplBytes, cpl)

	return cplBytes
}

func (*PIR_Client_ForPeerRouting) ProcessPlaintextInPIRResponse(res []byte) ([]*pb.Message_Peer, error) {
	mesg := &pb.Message{}

	// Inverse of marshalling implemented on server-side
	//  in NormalizeRTJoinedWithPeerStore in handlers.go

	err := proto.Unmarshal(res, mesg)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling:", err)
	}

	return mesg.GetCloserPeers(), nil
}

type PIR_Client_ForProviderRouting struct {
	PIR_Client
}

func (*PIR_Client_ForProviderRouting) GeneratePIRPlaintext(targetKey kadt.Key, serverKey kadt.Key) []byte {
	// TODO: Based on https://docs.ipfs.tech/concepts/dht/#routing-particulars,
	//  it should be HexString() and not MsgKey() (the pre-image of the key)
	//  confirm with routing.go (client-side), handlers.go (server-side)
	return []byte(targetKey.HexString())
}

func (*PIR_Client_ForProviderRouting) ProcessPlaintextInPIRResponse(res []byte) ([]*pb.Message_Peer, error) {
	mesg := &pb.Message{}

	// Inverse of marshalling implemented on server-side
	//  in MapCIDsToProviderPeersForPIR in backend_providers.go
	err := proto.Unmarshal(res, mesg)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling:", err)
	}

	return mesg.GetProviderPeers(), nil
}

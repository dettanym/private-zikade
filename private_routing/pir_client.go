package private_routing

import (
	"github.com/ipfs/go-cid"
	"github.com/plprobelab/zikade/kadt"
	"github.com/plprobelab/zikade/pb"
	"github.com/plprobelab/zikade/pir"
)

type PirClient struct {
	protocol pir.PIR_Protocol
}

func (client *PirClient) ProcessResponse(closerPeersResponse *pb.PIR_Response) (*pb.Message, error) {
	plaintext, err := client.protocol.ProcessResponseToPlaintext(closerPeersResponse)
	if err != nil {
		return nil, err
	}

	//println("Plaintext bucket")
	//for _, b := range plaintext {
	//	print(b, ",")
	//}

	return UnmarshallPlaintextToPB(plaintext)
}

type PirClientPeerRouting struct {
	PirClient
}

// TODO: Can pass a choice to the two constructors to choose which PIR algorithm e.g. RLWE or Paillier
func NewPirClientPeerRouting(mode string) *PirClientPeerRouting {
	return &PirClientPeerRouting{
		PirClient: PirClient{
			protocol: pir.NewSimpleRLWE_PIR_Protocol_mode(8, mode),
		},
	}
}
func (client *PirClientPeerRouting) GenerateRequest(targetKey kadt.Key, serverKey kadt.Key) (*pb.PIR_Request, error) {
	err := client.PirClient.protocol.CreatePrivateKeyMaterial()
	if err != nil {
		return nil, err
	}

	cpl := uint64(targetKey.CommonPrefixLength(serverKey))
	// println("CPL between server and target: ", cpl, "\n")

	return client.PirClient.protocol.GenerateRequestFromQuery(int(cpl))
}

type PirClientProviderRouting struct {
	PirClient

	log2_num_buckets int
}

func NewPirClientProviderRouting(log2_num_buckets int, mode string) *PirClientProviderRouting {
	return &PirClientProviderRouting{
		log2_num_buckets: log2_num_buckets,
		PirClient: PirClient{
			protocol: pir.NewSimpleRLWE_PIR_Protocol_mode(log2_num_buckets, mode), //NewSimpleRLWE_PIR_Protocol(log2_num_buckets),
		},
	}
}

// TODO: Fix this implementation to use the fileCID
func (client *PirClientProviderRouting) GenerateRequest(fileCID cid.Cid) (*pb.PIR_Request, error) {
	err := client.PirClient.protocol.CreatePrivateKeyMaterial()
	if err != nil {
		return nil, err
	}

	// M=2^m number of records
	// we set bucket size B = 2^b = 256 records in total i.e. overhead of 2^b - 1
	// number of buckets = 2^n = 2^m / (2^b) = 2^(m-b)
	// or 2^b = 2^(m-n)
	// can access the length of the hash by fileCID.Prefix().MhLength
	//cidHashed := fileCID.Hash()
	//bucketIndexStr := cidHashed[2 : client.log2_num_buckets+2].HexString() // skipping first two bytes for hash function code, length
	//// TODO: Check base here.
	//
	//bucketIndex, err := strconv.ParseInt(bucketIndexStr, 16, 64)
	//if err != nil {
	//	return nil, err
	//}
	//// fmt.Printf("%T, %v\n", bucketIndex, bucketIndex)
	bucketIndex := 0
	return client.PirClient.protocol.GenerateRequestFromQuery(int(bucketIndex))
}

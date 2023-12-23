package pir

import "github.com/plprobelab/zikade/pb"

type PIR_Protocol interface {
	ProcessRequestAndReturnResponse(request *pb.PIR_Request, database [][]byte) (*pb.PIR_Response, error)
	GenerateRequestFromQuery(int) (*pb.PIR_Request, error)
	ProcessResponseToPlaintext(res *pb.PIR_Response) ([]byte, error)

	marshalRequestToPB() (*pb.PIR_Request, error)
	unmarshallRequestFromPB(req *pb.PIR_Request) error
	marshalResponseToPB() (*pb.PIR_Response, error)
	unmarshallResponseFromPB(res *pb.PIR_Response) error
}
